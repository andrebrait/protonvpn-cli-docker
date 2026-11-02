import os
import subprocess
import tempfile
import time
import unittest

from protonvpn_container.__main__ import terminate


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


if __name__ == "__main__":
    unittest.main()
