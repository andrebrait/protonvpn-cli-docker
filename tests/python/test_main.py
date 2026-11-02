import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from contextlib import redirect_stdout
from unittest.mock import patch

from protonvpn_container.__main__ import (
    DAEMON_PID_FILES,
    reconnect_interval,
    shutdown,
    start_webui,
    terminate,
    webui_port,
)
from protonvpn_container.config import SettingsStore


def named_child(test, name, ignore_sigterm=False):
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import ctypes, signal, sys; "
            "assert ctypes.CDLL(None).prctl(15, sys.argv[1].encode(), 0, 0, 0) == 0; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN if sys.argv[2] == '1' else signal.SIG_DFL); "
            "print('ready', flush=True); signal.pause()",
            name,
            str(int(ignore_sigterm)),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    test.addCleanup(child.stdout.close)
    test.addCleanup(child.wait)
    test.addCleanup(child.kill)
    test.assertEqual(child.stdout.readline(), "ready\n")
    return child


class TerminateTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.pid_file = os.path.join(tmp.name, "daemon.pid")

    def write_pid(self, pid):
        with open(self.pid_file, "w") as f:
            f.write(f"{pid}\n")

    def test_stops_and_reaps_a_child(self):
        child = named_child(self, "dbus-daemon")
        self.write_pid(child.pid)
        start = time.monotonic()
        terminate(self.pid_file, "dbus-daemon")
        self.assertLess(time.monotonic() - start, 2)
        with self.assertRaises(ProcessLookupError):  # reaped, not a zombie
            os.kill(child.pid, 0)

    def test_kills_a_child_that_ignores_sigterm(self):
        child = named_child(self, "dbus-daemon", ignore_sigterm=True)
        self.write_pid(child.pid)
        terminate(self.pid_file, "dbus-daemon", timeout=0.5)
        with self.assertRaises(ProcessLookupError):
            os.kill(child.pid, 0)

    def test_stale_pid_file_does_not_signal_an_unrelated_live_child(self):
        child = named_child(self, "unrelated")
        self.write_pid(child.pid)
        terminate(self.pid_file, "dbus-daemon", timeout=0.1)
        self.assertIsNone(child.poll())

    def test_exited_pidfd_cannot_signal_a_live_numeric_pid_replacement(self):
        retired = named_child(self, "dbus-daemon")
        replacement = named_child(self, "dbus-daemon")
        self.write_pid(replacement.pid)
        pidfd_open = os.pidfd_open

        def retired_target(pid, flags=0):
            self.assertEqual(pid, replacement.pid)
            fd = pidfd_open(retired.pid, flags)
            retired.kill()
            retired.wait(timeout=2)
            return fd

        # Inject PID reuse at acquisition: procfs sees a live replacement, but the
        # real pidfd still refers to the exited original process.
        with patch("protonvpn_container.__main__.os.pidfd_open", side_effect=retired_target):
            terminate(self.pid_file, "dbus-daemon", timeout=0.1)
        self.assertIsNone(replacement.poll())

    def test_missing_dead_or_bogus_pid_is_ignored(self):
        terminate(self.pid_file, "dbus-daemon")
        self.write_pid("not-a-pid")
        terminate(self.pid_file, "dbus-daemon")
        dead = subprocess.Popen(["true"])
        dead.wait()
        self.write_pid(dead.pid)
        terminate(self.pid_file, "dbus-daemon")

    def test_refuses_pid_1_and_below(self):
        for pid in (0, 1, -1):
            self.write_pid(pid)
            terminate(self.pid_file, "dbus-daemon")  # would kill the test run (or everything) if signalled


class ReconnectIntervalTest(unittest.TestCase):
    def interval(self, environ):
        out = io.StringIO()
        with redirect_stdout(out):
            return reconnect_interval(environ), out.getvalue()

    def test_default_and_valid_values(self):
        self.assertEqual(self.interval({}), (30.0, ""))
        self.assertEqual(self.interval({"RECONNECT_INTERVAL": ""}), (30.0, ""))
        self.assertEqual(self.interval({"RECONNECT_INTERVAL": "45"}), (45.0, ""))
        self.assertEqual(self.interval({"RECONNECT_INTERVAL": "1.5"}), (1.5, ""))

    def test_invalid_values_fall_back_to_30_with_a_message(self):
        for raw in ("nan", "inf", "-inf", "Infinity", "0", "0.5", "-3", "abc"):
            value, out = self.interval({"RECONNECT_INTERVAL": raw})
            self.assertEqual(value, 30.0, raw)
            self.assertIn("[init] RECONNECT_INTERVAL", out, raw)


class ShutdownTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name

    def stubborn_daemons(self):
        children = []
        for name, command in DAEMON_PID_FILES.items():
            child = named_child(self, command, ignore_sigterm=True)
            children.append(child)
            with open(os.path.join(self.dir, name), "w") as f:
                f.write(f"{child.pid}\n")
        return children

    def test_whole_shutdown_fits_the_budget_when_everything_hangs(self):
        class HangingSupervisor:
            def stop(self, timeout):  # a disconnect that uses all the time it is given
                time.sleep(timeout)

        children = self.stubborn_daemons()
        start = time.monotonic()
        shutdown(HangingSupervisor(), self.dir, budget=3.0)
        self.assertLess(time.monotonic() - start, 3.4)
        for child in children:  # SIGKILLed and reaped
            with self.assertRaises(ProcessLookupError):
                os.kill(child.pid, 0)

    def test_stale_daemon_pid_files_leave_unrelated_children_running(self):
        class QuickSupervisor:
            def stop(self, timeout):
                pass

        children = []
        for name in DAEMON_PID_FILES:
            child = named_child(self, "unrelated")
            children.append(child)
            with open(os.path.join(self.dir, name), "w") as f:
                f.write(f"{child.pid}\n")
        shutdown(QuickSupervisor(), self.dir, budget=0.5)
        self.assertTrue(all(child.poll() is None for child in children))

    def test_supervisor_gets_two_thirds_and_daemons_the_rest(self):
        given = []

        class QuickSupervisor:
            def stop(self, timeout):
                given.append(timeout)

        shutdown(QuickSupervisor(), self.dir, budget=9.0)  # no pid files: nothing to stop
        self.assertEqual(given, [6.0])

    def test_webui_is_stopped_before_the_supervisor(self):
        events = []

        class Supervisor:
            def stop(self, timeout):
                events.append("supervisor")

        class Webui:
            def shutdown(self):
                events.append("webui shutdown")

            def server_close(self):
                events.append("webui close")

        shutdown(Supervisor(), self.dir, budget=9.0, webui=Webui())
        self.assertEqual(events, ["webui shutdown", "webui close", "supervisor"])


class WebuiPortTest(unittest.TestCase):
    def port(self, environ):
        out = io.StringIO()
        with redirect_stdout(out):
            return webui_port(environ), out.getvalue()

    def test_default_and_valid_values(self):
        self.assertEqual(self.port({}), (8788, ""))
        self.assertEqual(self.port({"WEBUI_PORT": ""}), (8788, ""))
        self.assertEqual(self.port({"WEBUI_PORT": "9000"}), (9000, ""))
        self.assertEqual(self.port({"WEBUI_PORT": "65535"}), (65535, ""))

    def test_noncanonical_ports_cannot_select_an_unguarded_listener(self):
        for raw in ("0x2328", "02324", "0", "65536", "+8788", "８７８８", "8788 "):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                webui_port({"WEBUI_PORT": raw})


class StubSupervisor:
    def snapshot(self):
        return {"signed_in": False, "tunnel_healthy": False, "health_error": "", "health_checked_ago": None}


class StartWebuiTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = SettingsStore(os.path.join(tmp.name, "settings.json"), environ={})

    def free_port(self):
        with socket.socket() as s:
            s.bind(("0.0.0.0", 0))
            return s.getsockname()[1]

    def test_serves_the_api_on_the_configured_port_and_stops(self):
        port = self.free_port()
        out = io.StringIO()
        with redirect_stdout(out):
            server = start_webui(StubSupervisor(), self.store, {"WEBUI_PORT": str(port), "WEBUI_PASSWORD": ""})
            self.assertIsNotNone(server)
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/state", timeout=5) as resp:
                self.assertTrue(json.load(resp)["banner"])
            server.shutdown()
            server.server_close()
        self.assertIn("[webui] WARNING: WEBUI_PASSWORD is not set", out.getvalue())

    def test_a_busy_port_disables_the_webui_instead_of_crashing(self):
        with socket.socket() as blocker:
            blocker.bind(("0.0.0.0", 0))
            blocker.listen()
            out = io.StringIO()
            with redirect_stdout(out):
                server = start_webui(
                    StubSupervisor(), self.store, {"WEBUI_PORT": str(blocker.getsockname()[1])}
                )
        self.assertIsNone(server)
        self.assertIn("[webui] cannot listen on port", out.getvalue())


if __name__ == "__main__":
    unittest.main()
