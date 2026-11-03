"""Container service: the supervisor and the WebUI."""

import math
import os
import select
import signal
import sys
import threading
import time

from .config import SettingsStore
from .signin import SigninFlow
from .supervisor import Supervisor
from .webui import make_server

DEFAULT_WEBUI_PORT = 8788
PID_DIR = "/run/protonvpn-container"
# NetworkManager first: it needs the system bus until it has exited.
DAEMON_PID_FILES = {
    "nm.pid": "NetworkManager",
    "dbus-session.pid": "dbus-daemon",
    "dbus-system.pid": "dbus-daemon",
}
SHUTDOWN_BUDGET = 9.0  # `docker stop` sends SIGKILL after 10 s
SUPERVISOR_SHARE = 2 / 3  # of the budget; the daemons get the rest


def terminate(pid_file: str, expected_daemon: str, timeout: float = 3.0) -> None:
    """Stop only the named daemon; pin its identity with a pidfd before checking procfs.

    SIGKILL after 80% of `timeout`; reserve the rest for exit and child reaping.
    """
    try:
        with open(pid_file, encoding="utf-8") as f:
            pid = int(f.read())
    except (OSError, ValueError):
        return
    if pid <= 1:  # 0 and -1 would signal whole process groups, 1 is tini
        return
    try:
        pidfd = os.pidfd_open(pid)
    except OSError:
        return
    try:
        try:
            with open(f"/proc/{pid}/comm", encoding="utf-8") as f:
                if f.read().rstrip("\n") != expected_daemon:
                    return
        except OSError:
            return
        # If the PID was reused during the name check, the fd still targets the old process.
        for sig, patience in ((signal.SIGTERM, 0.8 * timeout), (signal.SIGKILL, 0.2 * timeout)):
            try:
                signal.pidfd_send_signal(pidfd, sig)
            except ProcessLookupError:
                pass
            if select.select([pidfd], [], [], max(patience, 0.0))[0]:
                try:
                    os.waitpid(pid, os.WNOHANG)  # reap our own children, not just their pidfds
                except ChildProcessError:
                    pass
                return
    finally:
        os.close(pidfd)


def webui_port(environ=os.environ) -> int:
    raw = environ.get("WEBUI_PORT", "") or str(DEFAULT_WEBUI_PORT)
    try:
        port = int(raw)
    except ValueError:
        port = 0
    if not 1 <= port <= 65535 or str(port) != raw:
        raise ValueError(f"WEBUI_PORT must be a decimal port from 1 to 65535 without leading zeros (got {raw!r})")
    return port


def start_webui(supervisor, store, environ=os.environ):
    """Serve the WebUI from a thread; None when the port cannot be bound (logged: VPN supervision goes on)."""
    port = webui_port(environ)
    api_key = environ.get("API_KEY", "")
    if api_key and len(api_key) < 32:
        print("[webui] WARNING: API_KEY is shorter than 32 characters; generate one with: openssl rand -hex 32", flush=True)
    try:
        server = make_server(port, supervisor, store, SigninFlow(), environ.get("WEBUI_PASSWORD", ""), api_key)
    except OSError as exc:
        print(f"[webui] cannot listen on port {port}: {exc}; the WebUI is disabled", flush=True)
        return None
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, name="webui", daemon=True).start()
    return server


def reconnect_interval(environ=os.environ) -> float:
    raw = environ.get("RECONNECT_INTERVAL", "") or "30"
    try:
        value = float(raw)
    except ValueError:
        value = math.nan
    if not math.isfinite(value) or value < 1:  # nan/inf would stop the loop from ever ticking again
        print(f"[init] RECONNECT_INTERVAL must be a number of seconds, at least 1 (got {raw!r}); using 30", flush=True)
        return 30.0
    return value


def shutdown(supervisor, pid_dir: str = PID_DIR, budget: float = SHUTDOWN_BUDGET, webui=None) -> None:
    """Stop the WebUI, disconnect, then stop the daemons; everything finishes within `budget` seconds."""
    end = time.monotonic() + budget
    if webui is not None:
        webui.shutdown()  # returns within a poll interval; requests in flight are daemon threads
        webui.server_close()
    supervisor.stop(timeout=budget * SUPERVISOR_SHARE)
    for left, (name, command) in zip(range(len(DAEMON_PID_FILES), 0, -1), DAEMON_PID_FILES.items()):
        terminate(os.path.join(pid_dir, name), command, timeout=(end - time.monotonic()) / left)


def main() -> None:
    store = SettingsStore()
    supervisor = Supervisor(store, interval=reconnect_interval())
    stop_requested = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop_requested.set())
    webui = start_webui(supervisor, store)
    supervisor.start()
    stop_requested.wait()
    print("[init] stopping", flush=True)
    shutdown(supervisor, webui=webui)
    print("[init] stopped", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
