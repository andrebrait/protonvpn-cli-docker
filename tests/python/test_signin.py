import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from protonvpn_container import signin
from protonvpn_container.signin import SigninFlow, Step

FAKE_CLI = str(Path(__file__).resolve().parent / "fakebin" / "protonvpn")


class SigninCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.pid_file = os.path.join(tmp.name, "pid")
        patcher = mock.patch.dict(os.environ, {"FAKE_PIDFILE": self.pid_file})
        patcher.start()
        self.addCleanup(patcher.stop)

    def flow(self, mode, timeout=10):
        os.environ["FAKE_SIGNIN"] = mode
        flow = SigninFlow(argv_prefix=(FAKE_CLI,), timeout=timeout)
        self.addCleanup(self.abandon, flow)
        return flow

    @staticmethod
    def abandon(flow):
        run = flow._run
        if run is not None:
            run.close()

    def pid(self):
        with open(self.pid_file) as f:
            return int(f.read())


class SigninFlowTest(SigninCase):
    def test_signin_no_2fa_done(self):
        step = self.flow("ok").start("me@proton.me", "pw-secret")
        self.assertEqual(step.state, "done")
        self.assertEqual(step.message, "Signed in as me@proton.me")

    def test_signin_2fa_then_done(self):
        flow = self.flow("2fa")
        first = flow.start("me@proton.me", "pw-secret")
        self.assertEqual(first, Step("need_code", ""))
        self.assertEqual(flow.submit_code("123456"), Step("done", "Signed in as me@proton.me"))

    def test_wrong_code_is_an_error_without_the_code_in_it(self):
        flow = self.flow("2fa")
        flow.start("me@proton.me", "pw-secret")
        step = flow.submit_code("654321")
        self.assertEqual(step.state, "error")
        self.assertIn("Invalid 2FA code", step.message)
        self.assertNotIn("654321", step.message)

    def test_wrong_code_asks_again_with_the_cli_message(self):
        flow = self.flow("2fa-retry")
        flow.start("me@proton.me", "pw-secret")
        step = flow.submit_code("654321")
        self.assertEqual(step.state, "need_code")
        self.assertIn("Invalid 2FA code", step.message)
        self.assertNotIn("654321", step.message)  # redacted
        self.assertNotIn("2FA Token", step.message)  # prompts are stripped
        self.assertEqual(flow.start("other@proton.me", "pw").state, "error")  # the flow is still the one in progress
        self.assertEqual(flow.submit_code("123456"), Step("done", "Signed in as me@proton.me"))

    def test_wrong_code_restarts_the_idle_timer(self):
        flow = self.flow("2fa-retry", timeout=1.5)
        flow.start("me@proton.me", "pw-secret")  # timer armed: expires at about 1.8 s
        time.sleep(1.0)
        self.assertEqual(flow.submit_code("654321").state, "need_code")  # rearmed: expires at about 2.8 s
        pid = self.pid()
        time.sleep(0.9)  # past the first deadline
        os.kill(pid, 0)  # still there
        self.assertEqual(flow.submit_code("123456").state, "done")

    def test_abandoned_after_a_wrong_code_is_still_killed(self):
        flow = self.flow("2fa-retry", timeout=1)
        flow.start("me@proton.me", "pw-secret")
        flow.submit_code("654321")
        pid = self.pid()
        time.sleep(1.6)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        self.assertEqual(flow.start("me@proton.me", "pw-secret").state, "need_code")

    def test_code_with_inner_spaces_is_squeezed(self):
        flow = self.flow("2fa")
        flow.start("me@proton.me", "pw-secret")
        self.assertEqual(flow.submit_code(" 123 456\t").state, "done")

    def test_cli_exit_at_the_prompt_leaves_no_prompt_in_the_message(self):
        step = self.flow("quit").start("me@proton.me", "pw-secret")
        self.assertEqual(step, Step("error", "sign-in failed (exit code 1)"))

    def test_signin_bad_password_error_message(self):
        step = self.flow("bad").start("me@proton.me", "pw-secret")
        self.assertEqual(step.state, "error")
        self.assertIn("Invalid credentials for me@proton.me", step.message)
        self.assertNotIn("pw-secret", step.message)  # the fake echoes it back; it must be redacted
        self.assertNotIn("Password:", step.message)  # prompts are stripped

    def test_second_start_rejected(self):
        flow = self.flow("2fa")
        self.assertEqual(flow.start("me@proton.me", "pw-secret").state, "need_code")
        self.assertEqual(flow.start("other@proton.me", "pw"), Step("error", "sign-in already in progress"))
        self.assertEqual(flow.submit_code("123456").state, "done")
        self.assertEqual(flow.start("me@proton.me", "pw-secret").state, "need_code")  # released after the end

    def test_idle_timeout_kills(self):
        flow = self.flow("2fa", timeout=1)
        self.assertEqual(flow.start("me@proton.me", "pw-secret").state, "need_code")
        pid = self.pid()
        time.sleep(1.6)
        with self.assertRaises(ProcessLookupError):  # killed and reaped
            os.kill(pid, 0)
        self.assertEqual(flow.submit_code("123456").state, "error")
        self.assertEqual(flow.start("me@proton.me", "pw-secret").state, "need_code")  # slot free again

    def test_submit_code_without_a_flow_is_an_error(self):
        step = self.flow("2fa").submit_code("123456")
        self.assertEqual(step.state, "error")

    def test_code_submitted_to_a_flow_not_asking_for_one_is_an_error(self):
        flow = self.flow("ok")
        flow.start("me@proton.me", "pw-secret")  # done: nothing waits for a code
        self.assertEqual(flow.submit_code("123456").state, "error")


class SigninFailureTest(SigninCase):
    def test_exception_after_the_password_prompt_kills_the_child_and_frees_the_slot(self):
        flow = self.flow("2fa")
        with mock.patch.object(signin._Run, "send", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                flow.start("me@proton.me", "pw-secret")
        with self.assertRaises(ProcessLookupError):
            os.kill(self.pid(), 0)  # killed and reaped
        self.assertEqual(flow.start("me@proton.me", "pw-secret").state, "need_code")  # slot free again

    def test_exception_while_sending_a_code_kills_the_child_and_frees_the_slot(self):
        flow = self.flow("2fa")
        self.assertEqual(flow.start("me@proton.me", "pw-secret").state, "need_code")
        pid = self.pid()
        with mock.patch.object(signin._Run, "send", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                flow.submit_code("123456")
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        self.assertEqual(flow.submit_code("123456").state, "error")  # nothing is waiting any more
        self.assertEqual(flow.start("me@proton.me", "pw-secret").state, "need_code")

    def test_lone_surrogate_in_the_password_does_not_wedge_the_flow(self):
        flow = self.flow("2fa")
        with self.assertRaises(UnicodeEncodeError):  # the web layer rejects it first; the flow must still clean up
            flow.start("me@proton.me", "a\ud800")
        with self.assertRaises(ProcessLookupError):
            os.kill(self.pid(), 0)
        self.assertEqual(flow.start("me@proton.me", "pw-secret").state, "need_code")


class SigninInputTest(SigninCase):
    def test_option_like_username_is_rejected_before_spawning(self):
        step = self.flow("ok").start("--help", "pw")
        self.assertEqual(step.state, "error")
        self.assertFalse(os.path.exists(self.pid_file))

    def test_empty_username_or_password_is_rejected(self):
        flow = self.flow("ok")
        self.assertEqual(flow.start("", "pw").state, "error")
        self.assertEqual(flow.start("me@proton.me", "").state, "error")
        self.assertFalse(os.path.exists(self.pid_file))

    def test_line_break_in_password_is_rejected(self):
        step = self.flow("2fa").start("me@proton.me", "pw\n123456")  # would answer the 2FA prompt too
        self.assertEqual(step.state, "error")
        self.assertFalse(os.path.exists(self.pid_file))

    def test_empty_code_keeps_the_flow_waiting(self):
        flow = self.flow("2fa")
        flow.start("me@proton.me", "pw-secret")
        self.assertEqual(flow.submit_code("  ").state, "need_code")
        self.assertEqual(flow.submit_code("123456").state, "done")

    def test_missing_cli_is_an_error(self):
        flow = SigninFlow(argv_prefix=("/nonexistent/protonvpn",), timeout=2)
        step = flow.start("me@proton.me", "pw-secret")
        self.assertEqual(step.state, "error")
        self.assertIn("cannot run", step.message)


if __name__ == "__main__":
    unittest.main()
