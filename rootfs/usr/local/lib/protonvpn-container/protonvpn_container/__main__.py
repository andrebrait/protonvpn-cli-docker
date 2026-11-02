"""Container service: supervisor (and, from the WebUI task on, the HTTP server)."""

import math
import os
import signal
import sys
import threading
import time

from .config import SettingsStore
from .supervisor import Supervisor

PID_DIR = "/run/protonvpn-container"
# NetworkManager first: it needs the system bus until it has exited.
DAEMON_PID_FILES = ("nm.pid", "dbus-session.pid", "dbus-system.pid")
SHUTDOWN_BUDGET = 9.0  # `docker stop` sends SIGKILL after 10 s
SUPERVISOR_SHARE = 2 / 3  # of the budget; the daemons get the rest


def terminate(pid_file: str, timeout: float = 3.0) -> None:
    """SIGTERM the process in pid_file; SIGKILL when it is still there after 80% of `timeout`.

    Returns within `timeout` (plus polling granularity).
    """
    try:
        with open(pid_file, encoding="utf-8") as f:
            pid = int(f.read())
    except (OSError, ValueError):
        return
    if pid <= 1:  # 0 and -1 would signal whole process groups, 1 is tini
        return
    for sig, patience in ((signal.SIGTERM, 0.8 * timeout), (signal.SIGKILL, 0.2 * timeout)):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + max(patience, 0.0)
        while time.monotonic() < deadline:
            if _gone(pid):
                return
            time.sleep(0.05)


def _gone(pid: int) -> bool:
    try:
        return os.waitpid(pid, os.WNOHANG)[0] == pid  # our own child: reap it, or it lingers as a zombie
    except ChildProcessError:
        pass
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


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


def shutdown(supervisor, pid_dir: str = PID_DIR, budget: float = SHUTDOWN_BUDGET) -> None:
    """Disconnect, then stop the daemons; everything finishes within `budget` seconds."""
    end = time.monotonic() + budget
    supervisor.stop(timeout=budget * SUPERVISOR_SHARE)
    for left, name in zip(range(len(DAEMON_PID_FILES), 0, -1), DAEMON_PID_FILES):
        terminate(os.path.join(pid_dir, name), timeout=(end - time.monotonic()) / left)


def main() -> None:
    supervisor = Supervisor(SettingsStore(), interval=reconnect_interval())
    stop_requested = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop_requested.set())
    supervisor.start()
    stop_requested.wait()
    print("[init] stopping", flush=True)
    shutdown(supervisor)
    print("[init] stopped", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
