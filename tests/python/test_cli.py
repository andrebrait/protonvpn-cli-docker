import os
import unittest
from pathlib import Path

from protonvpn_container import cli

FAKEBIN = str(Path(__file__).resolve().parent / "fakebin")
FAKE_KEYS = ("DEBUG", "FAKE_RC", "FAKE_SLEEP", "FAKE_PRINT", "FAKE_READ")


class RunTest(unittest.TestCase):
    def setUp(self):
        self._saved_env = os.environ.copy()
        os.environ["PATH"] = FAKEBIN + os.pathsep + os.environ["PATH"]
        for key in FAKE_KEYS:
            os.environ.pop(key, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._saved_env)

    def test_run_merges_output_and_rc(self):
        os.environ["FAKE_RC"] = "3"
        result = cli.run("status")
        self.assertEqual(result.rc, 3)
        self.assertIn("status", result.out.splitlines())
        self.assertIn("stderr line", result.out)

    def test_debug_adds_verbose(self):
        os.environ["DEBUG"] = "true"
        result = cli.run("status")
        self.assertEqual(result.out.splitlines()[0], "--verbose")

    def test_timeout_returns_124(self):
        os.environ["FAKE_SLEEP"] = "5"
        os.environ["FAKE_PRINT"] = "partial line"
        result = cli.run("connect", timeout=0.5)
        self.assertEqual(result.rc, 124)
        self.assertIn("partial line", result.out)
        self.assertIn("timed out", result.out)
        self.assertLess(result.out.index("partial line"), result.out.index("timed out"))

    def test_stdin_is_devnull(self):
        # Hold a pipe open on fd 0 that never gets data: an inherited stdin would block `read`.
        os.environ["FAKE_READ"] = "1"
        saved_stdin = os.dup(0)
        read_end, write_end = os.pipe()
        try:
            os.dup2(read_end, 0)
            result = cli.run("login", timeout=1)
        finally:
            os.dup2(saved_stdin, 0)
            for fd in (saved_stdin, read_end, write_end):
                os.close(fd)
        self.assertEqual(result.rc, 0)
        self.assertIn("eof", result.out)

    def test_missing_binary_returns_127(self):
        os.environ["PATH"] = "/nonexistent"
        result = cli.run("status")
        self.assertEqual(result.rc, 127)
        self.assertIn("protonvpn", result.out)


class RunToolTest(unittest.TestCase):
    def test_runs_any_program(self):
        result = cli.run_tool("echo", "hi")
        self.assertEqual((result.rc, result.out), (0, "hi\n"))

    def test_missing_binary_returns_127(self):
        result = cli.run_tool("/nonexistent/tool")
        self.assertEqual(result.rc, 127)
        self.assertIn("/nonexistent/tool", result.out)

    def test_timeout_returns_124(self):
        result = cli.run_tool("sleep", "5", timeout=0.3)
        self.assertEqual(result.rc, 124)
        self.assertIn("sleep timed out", result.out)


if __name__ == "__main__":
    unittest.main()
