import io
import os
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stdout

from protonvpn_container.__main__ import DAEMON_PID_FILES, reconnect_interval, shutdown, terminate


class TerminateTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.pid_file = os.path.join(tmp.name, "daemon.pid")

    def write_pid(self, pid):
        with open(self.pid_file, "w") as f:
            f.write(f"{pid}\n")

    def test_stops_and_reaps_a_child(self):
        child = subprocess.Popen(["sleep", "30"])
        self.addCleanup(child.kill)
        self.write_pid(child.pid)
        start = time.monotonic()
        terminate(self.pid_file)
        self.assertLess(time.monotonic() - start, 2)
        with self.assertRaises(ProcessLookupError):  # reaped, not a zombie
            os.kill(child.pid, 0)

    def test_kills_a_child_that_ignores_sigterm(self):
        child = subprocess.Popen(["sh", "-c", "trap '' TERM; while :; do sleep 1; done"])
        self.addCleanup(child.kill)
        time.sleep(0.3)  # let the trap install
        self.write_pid(child.pid)
        terminate(self.pid_file, timeout=0.5)
        with self.assertRaises(ProcessLookupError):
            os.kill(child.pid, 0)

    def test_missing_dead_or_bogus_pid_is_ignored(self):
        terminate(self.pid_file)
        self.write_pid("not-a-pid")
        terminate(self.pid_file)
        dead = subprocess.Popen(["true"])
        dead.wait()
        self.write_pid(dead.pid)
        terminate(self.pid_file)

    def test_refuses_pid_1_and_below(self):
        for pid in (0, 1, -1):
            self.write_pid(pid)
            terminate(self.pid_file)  # would kill the test run (or everything) if it signalled


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
        for name in DAEMON_PID_FILES:
            child = subprocess.Popen(["sh", "-c", "trap '' TERM; while :; do sleep 1; done"])
            self.addCleanup(child.kill)
            children.append(child)
            with open(os.path.join(self.dir, name), "w") as f:
                f.write(f"{child.pid}\n")
        time.sleep(0.3)  # let the traps install
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

    def test_supervisor_gets_two_thirds_and_daemons_the_rest(self):
        given = []

        class QuickSupervisor:
            def stop(self, timeout):
                given.append(timeout)

        shutdown(QuickSupervisor(), self.dir, budget=9.0)  # no pid files: nothing to stop
        self.assertEqual(given, [6.0])


if __name__ == "__main__":
    unittest.main()
