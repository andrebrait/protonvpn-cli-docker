"""Supervisor: signin wait, settings apply, connect/reconnect, NAT-PMP refresh, traffic samples, tunnel health.

One loop, one base wait of 1 s: every activity has a next-due time from the injected clock, so
tests drive `tick()` directly. Requests from other threads only set flags and make the next
check due; the loop thread does the work.

The tunnel probe runs on a second thread, `health_tick()`, because it can take seconds: it never holds
`_cli_lock` and takes `_lock` only for state, so a slow probe delays neither the loop nor the port lease.
Its result is kept only while the connection it was made on is still the current one.
"""

import collections
import contextlib
import json
import os
import tempfile
import sys
import threading
import time
import traceback

from . import cli
from .config import DEFAULTS, SETTINGS, SettingsStore, connect_args, is_true, settings_pairs
from .health import FRESH_FOR, HEALTH_FILE, TUNNEL, ProbeError, active_handshake, probe, write_health
from .parsing import (
    Status,
    parse_account,
    parse_exit_ip,
    parse_natpmp_mapping,
    parse_status,
    parse_wg_transfer,
)

PORT_FILE = "/config/forwarded_port"
GATEWAY = "10.2.0.1"
HINT = "Not signed in. Sign in from the WebUI or run: docker exec -it <name> protonvpn signin <username>"
HINT_EVERY = 60
BACKOFF = (30, 60, 120, 300)
NATPMP_EVERY = 45
NATPMP_LEASE = 60  # seconds a mapping lives without a renewal
NATPMP_DELETE_TIMEOUT = 2
HEALTH_EVERY = 30  # seconds between probes, counted from the end of one
HEALTH_POLL = 1  # the worker looks for a newly connected tunnel this often
RECOVERY_AFTER = 180  # unchanged handshake despite active tunnel traffic, not an echo-service outage
TRAFFIC_EVERY = 5
TRAFFIC_KEEP = 180  # 15 minutes
# Cap for `protonvpn disconnect` during shutdown; the caller's total budget may be shorter.
STOP_DISCONNECT_TIMEOUT = 5
SIGNOUT_TIMEOUT = 30  # it holds the CLI lock: a hung signout must not block the loop for the default 120 s
KILL_SWITCH_KEY = "kill-switch"  # the CLI refuses it while a connection is up
# Always Proton's Standard kill switch, never a setting: the container's own firewall is what fails closed.
KILL_SWITCH_PAIR = (KILL_SWITCH_KEY, ["standard"])
CLI_USAGE_ERROR = 2  # click UsageError: the value is invalid. Any other rc (1: network, local agent; 124; 127) is transient
# Checks a connect waits for settings that keep failing transiently; the tunnel has priority.
SETTINGS_RETRIES = 3
# The only supported tunnel: the firewall, the tunnel check and the traffic sampler all assume WireGuard's proton0.
PROTOCOL = "wireguard"
# The CLI has no protocol command; Proton reads this JSON file (persisted under /config) on every invocation.
NATIVE_SETTINGS = "/etc/Proton/VPN/settings.json"


def log(message: str) -> None:
    print(message, flush=True)


def say(out: str) -> None:
    for line in out.splitlines():
        log(f"[protonvpn] {line}")


def pin_protocol(path: str) -> None:
    """Pin Proton's protocol without losing other settings; unreadable state blocks connecting."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}
    if not isinstance(data, dict):
        raise ValueError("native settings must be a JSON object")
    if data.get("protocol") == PROTOCOL:
        return
    data["protocol"] = PROTOCOL
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".settings-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


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
        timer=threading.Timer,
        health_file: str = HEALTH_FILE,
        native_settings: str = NATIVE_SETTINGS,
    ):
        self._store, self._run, self._tool, self._clock = store, run, tool, clock
        self._interval, self._port_file, self._exit, self._timer = interval, port_file, exit_fn, timer
        self._health_file, self._native_settings = health_file, native_settings
        self._thread = self._health_thread = None
        self._stop = threading.Event()
        self._cli_lock = threading.Lock()  # one CLI mutation at a time: tick vs apply_setting
        self._lock = threading.Lock()  # guards the state read by snapshot() and the request flags
        self._port_lock = threading.RLock()  # the published port, its lease and the file; taken before _lock
        self._signed_in, self._account = False, ""
        self._st = Status()
        self._exit_ip, self._last_error, self._check_error = "", "", ""
        self._port, self._port_synced = None, False
        # The tunnel probe's result, under _lock. A probe for an older connection finds `_health_gen` moved on and is dropped.
        self._health_gen = 0
        self._health_at: float | None = None  # when the current connection's last probe completed
        self._health_error = ""  # that probe's failure; "" when it passed
        self._next_probe = 0.0
        self._health_io = threading.Lock()  # serialises the file writes; taken before _lock
        self._health_published: bool | None = None  # what the file says; None: not written yet, or the write failed
        self._health_write_failed = False
        self._handshake = self._handshake_since = None
        self._recovery_gen: int | None = None
        self._recovery_retry_at: float | None = None
        self._lease_end = self._lease_timer = None  # of the published port: the timer clears it unless a renewal replaced it
        self._traffic = collections.deque(maxlen=TRAFFIC_KEEP)
        self._settings_errors: dict[str, str] = {}
        self._user_disconnected = self._disconnect_pending = False
        # Loop state, only touched under _cli_lock (or by single float stores from requests).
        self._mappings: dict[str, float] = {}  # known per-protocol leases, independent of API/file publication
        self._was_connected = False
        self._applied: set[str] = set()  # CLI setting keys applied in this signed-in session
        self._failures = self._unapplied_checks = 0
        self._next_check = self._next_hint = self._next_traffic = self._next_natpmp = 0.0

    # --- lifecycle ---

    def start(self) -> None:
        self._reset_health()  # whatever an earlier run left in the file no longer holds
        self._thread = threading.Thread(target=self._loop, args=(self.tick, 1), name="supervisor", daemon=True)
        self._health_thread = threading.Thread(
            target=self._loop, args=(self.health_tick, HEALTH_POLL), name="health", daemon=True
        )
        self._thread.start()
        self._health_thread.start()

    def stop(self, timeout: float = 6.0) -> None:
        """Disconnect and stop the loop and the health worker, within `timeout` seconds in total."""
        end = time.monotonic() + timeout
        self._stop.set()
        self._drop_connection()  # revoke status, health and port before a blocked connect can return
        say(self._run("disconnect", timeout=min(STOP_DISCONNECT_TIMEOUT, timeout)).out)
        for thread in (self._thread, self._health_thread):
            if thread is not None:
                thread.join(timeout=max(0.0, end - time.monotonic()))

    def _loop(self, step, wait: float) -> None:
        while not self._stop.is_set():
            try:
                step()
            except Exception:  # a bug must not end supervision
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
            self._stop.wait(wait)

    # --- requests from other threads ---

    def snapshot(self) -> dict:
        with self._lock:
            tunnel_healthy, health_error, health_checked_ago = self._health_view(self._clock())
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
                "last_error": self._check_error or self._last_error,
                "settings_errors": dict(self._settings_errors),
                "user_disconnected": self._user_disconnected,
                "tunnel_healthy": tunnel_healthy,
                "health_error": health_error,
                "health_checked_ago": health_checked_ago,
            }

    def request_connect(self) -> None:
        with self._lock:
            self._user_disconnected = self._disconnect_pending = False
            self._failures = 0
            self._recovery_gen = self._recovery_retry_at = None
            self._handshake = self._handshake_since = None
        self._next_check = 0.0
        self._next_natpmp = 0.0

    def request_disconnect(self) -> None:
        with self._lock:
            self._user_disconnected = self._disconnect_pending = True
        self._drop_connection()  # the loop may be busy for a while: the status and port must not outlive the request
        self._next_check = 0.0

    def notify_signed_in(self) -> None:
        """The WebUI's signin finished. The CLI saves the account before it exits, so the tick may have seen it already,
        applied the settings and connected: this only brings the next state check forward and never resets or drops anything.
        Lock-free on purpose: the tick can be in a minutes-long connect and the signin reply must not wait for it."""
        self._next_check = 0.0

    def sign_out(self) -> tuple[bool, str]:
        """`protonvpn signout`, never overlapping a connect or `config set`; the next check follows at once."""
        with self._cli_lock:
            res = self._run("signout", timeout=SIGNOUT_TIMEOUT)
            say(res.out)
            if res.rc != 0:
                return False, res.out.strip() or f"signout failed (exit code {res.rc})"
            self._new_session()  # Proton resets its settings on signout: all are applied again at the next signin
            self._mappings.clear()
            self._drop_connection()  # signing out ends the connection too
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
        with self._cli_lock:  # before reading the signin state: a tick must not sign in between that and the save
            with self._lock:
                signed_in = self._signed_in
            if not signed_in:
                self._store.save(env, value)
                return True, "saved; applied at sign in"
            if setting.cli_key is None:
                return self._apply_target(setting, value)
            words = (value or DEFAULTS.get(env, "")).split()
            if env == "PORT_FORWARDING" and not is_true(value or DEFAULTS.get(env, "")):
                self._withdraw_forwarding()  # native OFF disables the gateway endpoint needed for deletion
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
        self._withdraw_forwarding()  # cleanup needs the old tunnel's source identity
        self._drop_connection()  # reconnecting: the old connection and its port are gone from here on
        say(self._run("disconnect").out)
        if self._connect():
            with self._lock:
                return True, "reconnected" if self._st.connected else "saved; applies at next connect"
        self._store.save(env, previous)
        with self._lock:
            return False, self._last_error

    # --- loop ---

    def tick(self) -> None:
        with self._cli_lock:
            if self._stop.is_set():
                return
            if self._recover():
                return  # unresolved recovery owns its deadline; never re-adopt native's misleading Connected
            self._forward_port()  # first: a slow state check must not make the lease run out
            now = self._clock()
            if now >= self._next_check:
                self._check(now)
                self._forward_port()  # a connection that came up in this check
            now = self._clock()  # the check may have taken minutes
            with self._lock:
                connected = self._st.connected
            if connected and now >= self._next_traffic:
                self._sample(now)

    def _check(self, now: float) -> None:
        self._next_check = now + self._interval
        info, status = self._run("info"), self._run("status")
        if self._stop.is_set():
            self._drop_connection()
            return
        if info.rc != 0 or status.rc != 0:
            failed = info if info.rc != 0 else status
            message = f"state check failed (rc {failed.rc}): {failed.out.strip()}"
            log(f"[protonvpn] {message}")
            # The last good status and port must not pass for current ones. The signin state stays: one failed call says nothing about it.
            self._drop_connection(ended=False)
            self._was_connected = False
            with self._lock:
                self._traffic.clear()  # continuity is unknown: a replacement tunnel may have larger counters
                self._check_error = message
            self._next_natpmp = 0.0  # the port is requested again at the first good check
            return
        account, st = parse_account(info.out), parse_status(status.out)
        if self._reject_protocol(st):
            with self._lock:
                self._signed_in, self._account, self._check_error = bool(account), account, ""
            return
        with self._lock:
            if self._stop.is_set():
                return
            self._signed_in, self._account, self._st, self._check_error = bool(account), account, st, ""
            disconnect = self._disconnect_pending and self._user_disconnected
        disconnect_failed = False
        if disconnect and account and st.connected:
            self._withdraw_forwarding()  # delete while the old tunnel still reaches the gateway
            result = self._run("disconnect")
            say(result.out)
            disconnect_failed = result.rc != 0
            st = self._read_status()
        with self._lock:
            if not st.connected and not disconnect_failed:
                self._disconnect_pending = False
        if not st.connected:
            self._drop_connection()
        if account and not st.connected and not self._pin_protocol():
            return  # native config setters can rewrite malformed state too: validate before they run
        pending: list[str] = []
        if not account:
            self._new_session()
            if now >= self._next_hint:
                self._next_hint = now + HINT_EVERY
                log(f"[protonvpn] {HINT}")
        else:
            pending = self._apply_settings(st.connected)
            if pending:
                self._unapplied_checks += 1
            elif all(key in self._applied for key, _ in self._wanted()):
                self._unapplied_checks = 0  # not while a kill-switch is only deferred: that is not a success
        with self._lock:
            action = decide(bool(account), st.connected, self._user_disconnected)  # read intent after the CLI calls
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
            with self._lock:
                self._exit_ip = ""  # the next connection, ours or adopted, has its own
        self._was_connected = connected


    def _recover(self) -> bool:
        """Consume health evidence under _cli_lock; failed attempts retain their own completion-based backoff."""
        with self._lock:
            if self._stop.is_set() or self._user_disconnected or self._disconnect_pending or not self._signed_in:
                self._recovery_gen = self._recovery_retry_at = None
                return False
            if self._recovery_retry_at is not None:
                if self._clock() < self._recovery_retry_at:
                    return True
            elif not (
                self._recovery_gen == self._health_gen and self._st.connected and self._health_error
                and self._handshake_since is not None and self._clock() - self._handshake_since >= RECOVERY_AFTER
            ):
                self._recovery_gen = None
                return False
            self._recovery_retry_at = float("inf")  # requests can cancel while bounded CLI calls are running
        self._drop_connection(recovering=True)
        self._was_connected = False
        log("[protonvpn] tunnel handshake stalled; recovering without signing out")
        info = self._run("info")
        with self._lock:
            if self._stop.is_set() or self._user_disconnected or self._recovery_retry_at is None:
                return True
            if info.rc == 0 and not parse_account(info.out):
                self._signed_in, self._account = False, ""
                self._recovery_retry_at = None
                self._next_check = 0.0
                return True
        result = self._run("disconnect", timeout=STOP_DISCONNECT_TIMEOUT) if info.rc == 0 else info
        say(result.out)
        with self._lock:
            if self._stop.is_set() or self._user_disconnected or self._recovery_retry_at is None:
                return True
        if result.rc == 0 and self._pin_protocol():
            self._apply_settings(False)  # includes a kill-switch deferred while adopting a native connection
            if self._connect():
                with self._lock:
                    connected = self._st.connected
                    self._recovery_retry_at = None
                if connected:
                    self._failures = 0
                    self._was_connected = True
                    self._next_check = self._clock() + self._interval
                    self._forward_port()
                return True
        with self._lock:
            if self._stop.is_set() or self._user_disconnected:
                self._recovery_retry_at = None
                return True
            delay = BACKOFF[min(self._failures, len(BACKOFF) - 1)]
            self._failures += 1
            self._recovery_retry_at = self._clock() + delay
            self._last_error = result.out.strip() if result.rc else self._last_error
        log(f"[protonvpn] tunnel recovery failed; retrying in {delay}s")
        return True

    def _reject_protocol(self, st: Status) -> bool:
        if not st.connected or st.protocol.lower() == PROTOCOL:
            return False
        message = f"connected over {st.protocol or 'an unknown protocol'}, not {PROTOCOL}; disconnecting"
        self._drop_connection()  # revoke publication before a slow or unsuccessful native disconnect
        self._withdraw_forwarding()
        self._was_connected = False
        with self._lock:
            self._last_error = message
        log(f"[protonvpn] {message}")
        say(self._run("disconnect", timeout=STOP_DISCONNECT_TIMEOUT).out)
        return True

    def _read_status(self) -> Status:
        st = parse_status(self._run("status").out)
        if self._reject_protocol(st):
            return Status()
        with self._lock:
            if self._stop.is_set():
                st = Status()
            self._st = st
        return st

    def _pin_protocol(self) -> bool:
        try:
            pin_protocol(self._native_settings)
        except (OSError, ValueError) as exc:
            message = f"cannot set the {PROTOCOL} protocol in {self._native_settings}: {exc}"
            log(f"[protonvpn] {message}")
            with self._lock:
                self._last_error = message
            return False
        return True

    def _connect(self) -> bool:
        """False means a connection failure; a canceled attempt is handled without backoff or target rollback."""
        with self._lock:
            if self._stop.is_set() or self._user_disconnected:
                return True
        if not self._pin_protocol():  # target changes also enter here directly
            return False
        self._mappings.clear()  # a fresh connect may have a different Proton source identity
        res = self._run("connect", *connect_args(self._store))
        say(res.out)
        with self._lock:
            canceled = self._stop.is_set() or self._user_disconnected
        st = Status() if canceled or res.rc != 0 else parse_status(self._run("status").out)
        rejected = self._reject_protocol(st)
        with self._lock:
            canceled = canceled or self._stop.is_set() or self._user_disconnected
            if not canceled:
                if rejected:
                    return False
                self._st = st
                ok = res.rc == 0 and st.connected
                self._last_error = "" if ok else (res.out.strip() or f"connect failed (exit code {res.rc})")
                if ok:
                    self._exit_ip, self._check_error = parse_exit_ip(res.out), ""
        if canceled:  # stop or the user's disconnect may have preceded this late connect
            if not rejected:  # protocol rejection already made the bounded disconnect attempt
                say(self._run("disconnect", timeout=STOP_DISCONNECT_TIMEOUT).out)
            self._drop_connection()
            self._next_check = 0.0  # a newer Connect during compensation must not wait for the old check interval
            return True
        if ok:
            self._new_connection()
        return ok

    # --- tunnel health: its own thread, see the module docstring ---

    def health_tick(self) -> None:
        """Probe without the CLI lock. Echo failure alone is observational; active handshake evidence can queue recovery."""
        now = self._clock()
        with self._lock:
            if not self._st.connected or now < self._next_probe:
                return
            generation = self._health_gen
            self._next_probe = now + HEALTH_EVERY  # also when the probe breaks: it must not spin
        try:  # no lock held: this waits for the network
            ip, error = probe(self._tool), ""
        except ProbeError as exc:
            ip, error = "", str(exc)
        handshake = active_handshake(self._tool) if error else None
        found = ""
        with self._lock:
            if generation != self._health_gen or not self._st.connected or self._stop.is_set():
                return  # made on a connection that is gone, or shutdown began: not a result for the current one
            done = self._clock()
            previous, first = self._health_error, self._health_at is None
            self._health_at, self._health_error, self._next_probe = done, error, done + HEALTH_EVERY
            if not error or handshake is None or self._user_disconnected or self._disconnect_pending:
                self._handshake = self._handshake_since = self._recovery_gen = None
            elif handshake != self._handshake:
                self._handshake, self._handshake_since, self._recovery_gen = handshake, done, None
            elif self._handshake_since is not None and done - self._handshake_since >= RECOVERY_AFTER:
                if self._recovery_gen is None and self._recovery_retry_at is None and self._signed_in:
                    self._recovery_gen = generation
            if ip and not self._exit_ip:  # the connect output stays the primary source
                self._exit_ip = found = ip
        if error and error != previous:  # one line per change, not per probe
            log(f"[health] tunnel check failed: {error}")
        elif not error and previous:
            log("[health] tunnel check recovered")
        elif not error and first:
            log("[health] tunnel check passed")
        if found:
            log(f"[protonvpn] exit IP {found}")
        self._publish_health()

    def _health_view(self, now: float) -> tuple[bool | None, str, float | None]:
        """`tunnel_healthy`, `health_error` and `health_checked_ago`; call with _lock held.

        Never healthy without a native connection, nor on a pass older than FRESH_FOR; None: connected, not checked yet.
        """
        if not self._st.connected or self._stop.is_set():
            return False, "", None
        if self._health_at is None:
            return None, "", None
        ago = round(max(0.0, now - self._health_at), 1)
        if self._health_error:
            return False, self._health_error, ago
        if now - self._health_at > FRESH_FOR:
            return False, f"no successful check in the last {FRESH_FOR} s", ago
        return True, "", ago

    def _reset_health(self) -> None:
        """The tunnel is unchecked: its connection is new, gone, or no longer vouched for. A probe still running is dropped."""
        with self._lock:
            self._health_gen += 1
            self._health_at, self._health_error, self._next_probe = None, "", 0.0
            self._handshake = self._handshake_since = self._recovery_gen = None
        self._publish_health()

    def _publish_health(self) -> None:
        """Write the current verdict to the file Docker's healthcheck reads."""
        with self._health_io:  # the state is read inside it: whichever writer is last leaves the newest verdict
            with self._lock:
                now = self._clock()
                healthy = self._health_view(now)[0] is True
                stamp = self._health_at if healthy else now
            if not healthy and self._health_published is False:
                return  # already revoked; a disconnected loop revokes at every check
            try:
                write_health(self._health_file, healthy, stamp)
            except OSError as exc:
                if not self._health_write_failed:  # once per failure streak
                    log(f"[health] cannot write {self._health_file}: {exc}")
                self._health_write_failed, self._health_published = True, None
                return
            self._health_write_failed, self._health_published = False, healthy

    def _new_connection(self) -> None:
        with self._lock:
            self._traffic.clear()
        self._reset_health()
        self._next_traffic = self._next_natpmp = 0.0

    def _new_session(self) -> None:
        self._applied = set()
        self._unapplied_checks = 0
        with self._lock:
            self._settings_errors = {}

    def _wanted(self) -> list[tuple[str, list[str]]]:
        return [*settings_pairs(self._store), KILL_SWITCH_PAIR]

    def _apply_settings(self, connected: bool) -> list[str]:
        """Apply the effective settings, and the kill switch, not yet applied in this session.

        Returns the CLI keys a transient CLI failure left pending; they are retried at every check.
        `kill-switch` waits for a disconnected moment, before the next connect.
        """
        env_of = {s.cli_key: s.env for s in SETTINGS if s.cli_key}
        pending = []
        for key, words in self._wanted():
            if key in self._applied or (connected and key == KILL_SWITCH_KEY):
                continue
            env = env_of.get(key)  # None for the kill switch: a fixed valid value, so no rc is "the value is invalid"
            res = self._run("config", "set", key, *words)
            message = res.out.strip() or f"exit code {res.rc}"
            if res.rc == 0:
                say(res.out)
                with self._lock:
                    self._settings_errors.pop(env, None)
            elif res.rc == CLI_USAGE_ERROR and env:
                log(f"[protonvpn] setting {env} rejected: {message}")
                if self._store.source(env) == "env":
                    log(f"[protonvpn] {env} comes from the container environment; exiting")
                    self._exit(1)
                with self._lock:
                    self._settings_errors[env] = message
            else:
                log(f"[protonvpn] setting {env or key} not applied (rc {res.rc}); will retry: {message}")
                if env:
                    with self._lock:
                        self._settings_errors[env] = message  # shown until a retry works
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

    def _withdraw_forwarding(self) -> None:
        """Withdraw before bounded network calls; the caller owns _cli_lock, not the publication locks."""
        self._set_port(None)
        self._next_natpmp = 0.0
        mappings, self._mappings = self._mappings, {}  # one best-effort attempt, not a periodic delete poller
        for proto, lease_end in mappings.items():
            if lease_end <= self._clock():
                continue
            # RFC 6886 §3.4: private 0 deletes this source IP's protocol mappings, not a particular public port.
            res = self._tool("natpmpc", "-a", "0", "0", proto, "0", "-g", GATEWAY, timeout=NATPMP_DELETE_TIMEOUT)
            if res.rc != 0:
                log(f"[natpmp] {proto} deletion failed (rc {res.rc}); lease will expire: {res.out.strip()}")

    def _forward_port(self) -> None:
        """Request or renew the forwarded port when due, ahead of CLI calls that can be slow."""
        if not is_true(self._store.effective("PORT_FORWARDING")):
            self._withdraw_forwarding()
            return
        with self._lock:
            connected, leaving = self._st.connected, self._disconnect_pending
        if not connected or leaving or self._stop.is_set():
            return
        if self._clock() >= self._next_natpmp:
            self._refresh_port()

    def _drop_connection(self, ended: bool = True, recovering: bool = False) -> None:
        """Forget the status, forwarded port and tunnel check of a connection that is going away or can no longer be vouched for.

        `ended`: it really is going away, so its exit IP is forgotten too.
        """
        with self._lock:
            self._st = Status()
            if not recovering:
                self._recovery_retry_at = None
            if ended:
                self._exit_ip = ""
        self._reset_health()
        self._set_port(None)

    def _refresh_port(self) -> None:
        start = self._clock()  # the lease runs from the first request at the latest
        self._next_natpmp = start + NATPMP_EVERY
        mappings = []
        for proto in ("udp", "tcp"):
            res = self._tool("natpmpc", "-a", "1", "0", proto, str(NATPMP_LEASE), "-g", GATEWAY)
            mapping = parse_natpmp_mapping(res.out) if res.rc == 0 else None
            if mapping is None:  # a silent gateway makes natpmpc wait minutes: do not try tcp as well
                log(f"[natpmp] refresh failed (rc {res.rc}): {(res.out.strip().splitlines() or [''])[-1]}")
                self._set_port(None)
                return
            self._mappings[proto] = self._clock() + mapping[1]  # latest possible remote expiry, not publication's cap
            mappings.append(mapping)
        (udp_port, udp_lifetime), (tcp_port, tcp_lifetime) = mappings
        if udp_port != tcp_port:  # one number must serve both protocols
            log(f"[natpmp] the gateway mapped udp to {udp_port} but tcp to {tcp_port}; no port published")
            self._set_port(None)
            return
        self._set_port(udp_port, start + min(NATPMP_LEASE, udp_lifetime, tcp_lifetime))

    def _set_port(self, port: int | None, lease_end: float = 0.0) -> None:
        """Publish `port` (None: no port) until `lease_end`, when a timer clears it unless a renewal replaced the lease."""
        with self._port_lock:
            if self._lease_timer is not None:
                self._lease_timer.cancel()
                self._lease_timer = None
            with self._lock:
                if self._disconnect_pending or self._stop.is_set() or lease_end <= self._clock():
                    port = None
            self._lease_end = None if port is None else lease_end
            if port is not None:
                self._lease_timer = self._timer(max(0.0, lease_end - self._clock()), self._expire, (lease_end,))
                self._lease_timer.daemon = True
                self._lease_timer.start()
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
                try:
                    os.unlink(self._port_file)  # failed publication must not leave a usable old number
                except FileNotFoundError:
                    pass
                except OSError:
                    pass  # read-only storage cannot be revoked; the API remains authoritative until a write succeeds
                return
            self._port_synced = True
            if port is not None:
                log(f"[natpmp] forwarded port {port}")

    def _expire(self, lease_end: float) -> None:
        """Timer thread: the lease ran out unrenewed (the loop is stuck or renewals fail), so stop advertising its port."""
        with self._port_lock:
            if self._lease_end == lease_end:  # not renewed or cleared meanwhile
                log("[natpmp] the forwarded port's lease ran out without a renewal")
                self._set_port(None)

    def _write_port_file(self, text: str) -> None:
        tmp = f"{self._port_file}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, 0o644)  # the entrypoint's umask is 077
        os.replace(tmp, self._port_file)
