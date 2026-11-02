"""Container service: supervisor (and, from the WebUI task on, the HTTP server)."""

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


def terminate(pid_file: str, timeout: float = 3.0) -> None:
    """SIGTERM the process in pid_file, wait for it to exit, SIGKILL when it does not."""
    try:
        with open(pid_file, encoding="utf-8") as f:
            pid = int(f.read())
    except (OSError, ValueError):
        return
    if pid <= 1:  # 0 and -1 would signal whole process groups, 1 is tini
        return
    for sig, patience in ((signal.SIGTERM, timeout), (signal.SIGKILL, 1.0)):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + patience
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


def reconnect_interval() -> float:
    raw = os.environ.get("RECONNECT_INTERVAL", "") or "30"
    try:
        value = float(raw)
    except ValueError:
        value = 0
    if value < 1:
        print(f"[init] RECONNECT_INTERVAL must be a number of seconds, at least 1 (got {raw!r})", flush=True)
        sys.exit(1)
    return value


def main() -> None:
    supervisor = Supervisor(SettingsStore(), interval=reconnect_interval())
    shutdown = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: shutdown.set())
    supervisor.start()
    shutdown.wait()
    print("[init] stopping", flush=True)
    supervisor.stop()
    for name in DAEMON_PID_FILES:
        terminate(os.path.join(PID_DIR, name))
    print("[init] stopped", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
