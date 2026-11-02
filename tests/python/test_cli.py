import os
import unittest
from pathlib import Path

from protonvpn_container import cli

FAKEBIN = str(Path(__file__).resolve().parent / "fakebin")


class RunTest(unittest.TestCase):
    def setUp(self):
        self._saved_env = os.environ.copy()
        os.environ["PATH"] = FAKEBIN + os.pathsep + os.environ["PATH"]
        for key in ("DEBUG", "FAKE_RC", "FAKE_SLEEP"):
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
        result = cli.run("connect", timeout=0.5)
        self.assertEqual(result.rc, 124)
        self.assertIn("timed out", result.out)

    def test_missing_binary_returns_127(self):
        os.environ["PATH"] = "/nonexistent"
        result = cli.run("status")
        self.assertEqual(result.rc, 127)
        self.assertIn("protonvpn", result.out)


if __name__ == "__main__":
    unittest.main()
