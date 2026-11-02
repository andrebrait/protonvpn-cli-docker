"""Supervisor: signin wait, settings apply, connect/reconnect, NAT-PMP refresh, traffic samples.

One loop, one base wait of 1 s: every activity has a next-due time from the injected clock, so
tests drive `tick()` directly. Requests from other threads only set flags and make the next
check due; the loop thread does the work.
"""

import collections
import os
import sys
import threading
import time
import traceback

from . import cli
from .config import DEFAULTS, SETTINGS, SettingsStore, connect_args, is_true, settings_pairs
from .parsing import (
    Status,
    parse_account,
    parse_exit_ip,
    parse_natpmp_port,
    parse_status,
    parse_wg_transfer,
)

PORT_FILE = "/config/forwarded_port"
GATEWAY = "10.2.0.1"
TUNNEL = "proton0"
HINT = "Not signed in. Sign in from the WebUI or run: docker exec -it <name> protonvpn signin <username>"
HINT_EVERY = 60
BACKOFF = (30, 60, 120, 300)
NATPMP_EVERY = 45
TRAFFIC_EVERY = 5
TRAFFIC_KEEP = 180  # 15 minutes
# Cap for `protonvpn disconnect` during shutdown; the caller's total budget may be shorter.
STOP_DISCONNECT_TIMEOUT = 5
SIGNOUT_TIMEOUT = 30  # it holds the CLI lock: a hung signout must not block the loop for the default 120 s
KILL_SWITCH_KEY = "kill-switch"  # the CLI refuses it while a connection is up
CLI_REJECTED = (1, 2)  # click ClickException / UsageError; anything else (124, 127, ...) is transient
# Checks a connect waits for settings that keep failing transiently; the tunnel has priority.
SETTINGS_RETRIES = 3


def log(message: str) -> None:
    print(message, flush=True)


def say(out: str) -> None:
    for line in out.splitlines():
        log(f"[protonvpn] {line}")


def decide(signed_in: bool, connected: bool, user_disconnected: bool) -> str:
    if not signed_in:
        return "wait_signin"
    if connected:
        return "connected"
    return "idle" if user_disconnected else "connect"


class Supervisor:
    def __init__(
        self,
        store: SettingsStore,
        run=cli.run,
        tool=cli.run_tool,
        clock=time.monotonic,
        interval: float = 30,
        port_file: str = PORT_FILE,
        exit_fn=os._exit,
    ):
        self._store, self._run, self._tool, self._clock = store, run, tool, clock
        self._interval, self._port_file, self._exit = interval, port_file, exit_fn
        self._thread = None
        self._stop = threading.Event()
        self._cli_lock = threading.Lock()  # one CLI mutation at a time: tick vs apply_setting
        self._lock = threading.Lock()  # guards the state read by snapshot() and the request flags
        self._signed_in, self._account = False, ""
        self._st = Status()
        self._exit_ip, self._last_error = "", ""
        self._port, self._port_synced = None, False
        self._traffic = collections.deque(maxlen=TRAFFIC_KEEP)
        self._settings_errors: dict[str, str] = {}
        self._user_disconnected = self._disconnect_pending = False
        # Loop state, only touched under _cli_lock (or by single float stores from requests).
        self._was_connected = self._reapply = False
        self._applied: set[str] = set()  # CLI setting keys applied in this signed-in session
        self._failures = self._unapplied_checks = 0
        self._next_check = self._next_hint = self._next_traffic = self._next_natpmp = 0.0

    # --- lifecycle ---

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="supervisor", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 6.0) -> None:
        """Disconnect and stop the loop, within `timeout` seconds in total."""
        end = time.monotonic() + timeout
        self._stop.set()
        say(self._run("disconnect", timeout=min(STOP_DISCONNECT_TIMEOUT, timeout)).out)
        if self._thread is not None:
            self._thread.join(timeout=max(0.0, end - time.monotonic()))

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:  # a bug must not end supervision
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
            self._stop.wait(1)

    # --- requests from other threads ---

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "signed_in": self._signed_in,
                "account": self._account,
                "connected": self._st.connected,
                "server": self._st.server,
                "location": self._st.location,
                "load": self._st.load,
                "protocol": self._st.protocol,
                "exit_ip": self._exit_ip,
                "forwarded_port": self._port,
                "traffic": [list(sample) for sample in self._traffic],
                "last_error": self._last_error,
                "settings_errors": dict(self._settings_errors),
                "user_disconnected": self._user_disconnected,
            }

    def request_connect(self) -> None:
        with self._lock:
            self._user_disconnected = False
            self._failures = 0
        self._next_check = 0.0

    def request_disconnect(self) -> None:
        with self._lock:
            self._user_disconnected = self._disconnect_pending = True
        self._next_check = 0.0

    def notify_signed_in(self) -> None:
        self._reapply = True
        self._next_check = 0.0

    def sign_out(self) -> tuple[bool, str]:
        """`protonvpn signout`, never overlapping a connect or `config set`; the next check follows at once."""
        with self._cli_lock:
            res = self._run("signout", timeout=SIGNOUT_TIMEOUT)
            say(res.out)
            if res.rc != 0:
                return False, res.out.strip() or f"signout failed (exit code {res.rc})"
            self._new_session()  # Proton resets its settings on signout: all are applied again at the next signin
            with self._lock:
                self._signed_in, self._account = False, ""
            self._next_check = 0.0
            return True, res.out.strip()

    def apply_setting(self, env: str, value: str) -> tuple[bool, str]:
        setting = next((s for s in SETTINGS if s.env == env), None)
        if setting is None:
            return False, f"unknown setting {env}"
        if self._store.locked(env):
            return False, f"{env} is set in the environment and cannot be changed"
        with self._lock:
            signed_in = self._signed_in
        if not signed_in:
            self._store.save(env, value)
            return True, "saved; applied at sign in"
        with self._cli_lock:
            if setting.cli_key is None:
                return self._apply_target(setting, value)
            words = (value or DEFAULTS.get(env, "")).split()
            message = "saved; the CLI keeps its current value"
            if words:
                res = self._run("config", "set", setting.cli_key, *words)
                if res.rc != 0:
                    return False, res.out.strip() or f"config set {setting.cli_key} failed (exit code {res.rc})"
                message = res.out.strip()
            self._store.save(env, value)
            self._applied.add(setting.cli_key)
            with self._lock:
                self._settings_errors.pop(env, None)
            return True, message

    def _apply_target(self, setting, value: str) -> tuple[bool, str]:
        env = setting.env
        current = self._store.effective(env)
        if (is_true(value) == is_true(current)) if setting.kind == "bool" else (value == current):
            return True, "unchanged"
        previous = current if self._store.source(env) == "file" else ""
        self._store.save(env, value)
        with self._lock:
            connected, user_disconnected = self._st.connected, self._user_disconnected
        if not connected:
            if user_disconnected:
                return True, "saved; applies at next connect"
            # Waiting out a backoff with the old target: try the new one now.
            self._failures = 0
            self._next_check = 0.0
            return True, "saved; connecting"
        say(self._run("disconnect").out)
        if self._connect():
            return True, "reconnected"
        self._store.save(env, previous)
        with self._lock:
            return False, self._last_error

    # --- loop ---

    def tick(self) -> None:
        now = self._clock()
        with self._cli_lock:
            if now >= self._next_check:
                self._check(now)
            with self._lock:
                connected = self._st.connected
            if connected and now >= self._next_traffic:
                self._sample(now)
            if connected:
                if not is_true(self._store.effective("PORT_FORWARDING")):
                    self._set_port(None)
                elif now >= self._next_natpmp:
                    self._refresh_port(now)

    def _check(self, now: float) -> None:
        self._next_check = now + self._interval
        info, status = self._run("info"), self._run("status")
        if info.rc != 0 or status.rc != 0:
            failed = info if info.rc != 0 else status
            log(f"[protonvpn] state check failed (rc {failed.rc}): {failed.out.strip()}")
            return
        account, st = parse_account(info.out), parse_status(status.out)
        if self._reapply:
            self._reapply = False
            self._new_session()
        with self._lock:
            self._signed_in, self._account, self._st = bool(account), account, st
            disconnect, self._disconnect_pending = self._disconnect_pending, False
            user_disconnected = self._user_disconnected
        if disconnect and account and st.connected:
            say(self._run("disconnect").out)
            st = self._read_status()
        action = decide(bool(account), st.connected, user_disconnected)
        pending: list[str] = []
        if action == "wait_signin":
            self._new_session()
            if now >= self._next_hint:
                self._next_hint = now + HINT_EVERY
                log(f"[protonvpn] {HINT}")
        else:
            pending = self._apply_settings(st.connected)
            if pending:
                self._unapplied_checks += 1
            elif all(key in self._applied for key, _ in settings_pairs(self._store)):
                self._unapplied_checks = 0  # not while a kill-switch is only deferred: that is not a success
        hold = bool(pending) and self._unapplied_checks < SETTINGS_RETRIES
        if action == "connect" and hold:
            log(
                f"[protonvpn] settings not applied yet ({', '.join(pending)}); holding the connect, "
                f"check {self._unapplied_checks} of {SETTINGS_RETRIES}"
            )
        elif action == "connect":
            if pending:
                log(f"[protonvpn] connecting without {', '.join(pending)} (will keep retrying)")
            if not self._connect():
                delay = BACKOFF[min(self._failures, len(BACKOFF) - 1)]
                self._failures += 1
                # Counted from the end of the attempt, which can take minutes.
                self._next_check = self._clock() + delay
                log(f"[protonvpn] connect failed; retrying in {delay}s")
        with self._lock:
            connected = self._st.connected
        if connected:
            self._failures = 0
            if not self._was_connected:
                self._new_connection()
        else:
            self._set_port(None)
        self._was_connected = connected

    def _read_status(self) -> Status:
        st = parse_status(self._run("status").out)
        with self._lock:
            self._st = st
        return st

    def _connect(self) -> bool:
        res = self._run("connect", *connect_args(self._store))
        say(res.out)
        ok = res.rc == 0 and self._read_status().connected
        with self._lock:
            self._last_error = "" if ok else res.out.strip()
            if ok:
                self._exit_ip = parse_exit_ip(res.out)
        if ok:
            self._new_connection()
        return ok

    def _new_connection(self) -> None:
        with self._lock:
            self._traffic.clear()
        self._next_traffic = self._next_natpmp = 0.0

    def _new_session(self) -> None:
        self._applied = set()
        self._unapplied_checks = 0
        with self._lock:
            self._settings_errors = {}

    def _apply_settings(self, connected: bool) -> list[str]:
        """Apply the effective settings not yet applied in this session.

        Returns the CLI keys a transient CLI failure left pending; they are retried at every check.
        `kill-switch` waits for a disconnected moment, before the next connect.
        """
        env_of = {s.cli_key: s.env for s in SETTINGS if s.cli_key}
        pending = []
        for key, words in settings_pairs(self._store):
            if key in self._applied or (connected and key == KILL_SWITCH_KEY):
                continue
            env = env_of[key]
            res = self._run("config", "set", key, *words)
            message = res.out.strip()
            if res.rc == 0:
                say(res.out)
                with self._lock:
                    self._settings_errors.pop(env, None)
            elif res.rc in CLI_REJECTED:
                log(f"[protonvpn] setting {env} rejected: {message}")
                if self._store.source(env) == "env":
                    log(f"[protonvpn] {env} comes from the container environment; exiting")
                    self._exit(1)
                with self._lock:
                    self._settings_errors[env] = message
            else:
                log(f"[protonvpn] setting {env} not applied (rc {res.rc}); will retry: {message}")
                pending.append(key)
                continue  # one hung key must not starve the rest
            self._applied.add(key)
        return pending

    def _sample(self, now: float) -> None:
        self._next_traffic = now + TRAFFIC_EVERY
        transfer = parse_wg_transfer(self._tool("wg", "show", TUNNEL, "transfer").out)
        if transfer is not None:
            with self._lock:
                self._traffic.append([now, *transfer])

    def _refresh_port(self, now: float) -> None:
        self._next_natpmp = now + NATPMP_EVERY
        ports = []
        for proto in ("udp", "tcp"):
            res = self._tool("natpmpc", "-a", "1", "0", proto, "60", "-g", GATEWAY)
            port = parse_natpmp_port(res.out)
            if port is None:  # a silent gateway makes natpmpc wait minutes: do not try tcp as well
                log(f"[natpmp] refresh failed: {(res.out.strip().splitlines() or [''])[-1]}")
                self._set_port(None)
                return
            ports.append(port)
        self._set_port(ports[0])

    def _set_port(self, port: int | None) -> None:
        if port == self._port and self._port_synced:
            return
        with self._lock:
            self._port = port
        try:
            self._write_port_file("" if port is None else f"{port}\n")
        except OSError as exc:
            if self._port_synced is not None:  # log once per failure streak; the tick may retry every second
                log(f"[natpmp] cannot write {self._port_file}: {exc}")
            self._port_synced = None
            return
        self._port_synced = True
        if port is not None:
            log(f"[natpmp] forwarded port {port}")

    def _write_port_file(self, text: str) -> None:
        tmp = f"{self._port_file}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, 0o644)  # the entrypoint's umask is 077
        os.replace(tmp, self._port_file)
