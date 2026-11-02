"""Sign in through the CLI's interactive prompts, driven over a pseudo-terminal.

`protonvpn signin <user> --totp` asks for the password (and a 2FA code) on a terminal. The flow
waits for each prompt, types the answer and reports what the CLI says. Secrets are only ever
written to the pty; they are redacted from everything returned or logged.
"""

import contextlib
import os
import re
import select
import signal
import subprocess
import termios
import threading
import time
from dataclasses import dataclass

PASSWORD_PROMPT = re.compile(r"password", re.IGNORECASE)
CODE_PROMPT = re.compile(r"2fa|token|code", re.IGNORECASE)
ANY_PROMPT = re.compile(f"{PASSWORD_PROMPT.pattern}|{CODE_PROMPT.pattern}", re.IGNORECASE)
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
SETTLE = 0.2  # a prompt is an unfinished line that stays unfinished this long
EXIT_GRACE = 5  # seconds a child that closed its terminal gets to finish exiting
MAX_FIELD = 256


@dataclass(frozen=True)
class Step:
    state: str  # "need_code" | "done" | "error"
    message: str = ""


def _invalid(value: str, what: str, *, not_option: bool = False) -> str:
    if not value.strip():
        return f"{what} is required"
    if len(value) > MAX_FIELD or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return f"{what} has an invalid character or is too long"
    if not_option and value.startswith("-"):
        return f"{what} must not start with '-'"
    return ""


class _Run:
    """One `protonvpn signin` process on a pty."""

    def __init__(self, argv: list[str]):
        self.master, slave = os.openpty()
        try:
            attrs = termios.tcgetattr(slave)
            attrs[3] &= ~termios.ECHO  # the secrets must not come back as output
            termios.tcsetattr(slave, termios.TCSANOW, attrs)
            self.proc = subprocess.Popen(
                argv, stdin=slave, stdout=slave, stderr=slave, start_new_session=True, close_fds=True
            )
        except BaseException:
            os.close(self.master)
            raise
        finally:
            os.close(slave)  # the child's copies keep it open; ours would stop EOF from ever arriving
        self._poller = select.poll()  # not select(): the fd number may exceed FD_SETSIZE in a busy server
        self._poller.register(self.master, select.POLLIN)
        self.lines: list[str] = []  # finished output lines
        self.partial = ""  # the unfinished last line: the prompt we wait at
        self.secrets: list[str] = []
        self.sent_at = 0  # index in `lines` where the output after the last answer starts
        self.busy = True  # a request thread is working on this run
        self.awaiting_code = False
        self._close_lock = threading.Lock()
        self._closed = False

    def read(self, want: re.Pattern, timeout: float) -> str:
        """Read until `partial` matches `want` ("prompt"), the child ends ("exit") or time is up ("timeout")."""
        end = time.monotonic() + timeout
        while True:
            at_prompt = want.search(self.partial) is not None
            left = end - time.monotonic()
            if left <= 0:
                return "timeout"
            if not self._poller.poll(1000 * (min(left, SETTLE) if at_prompt else left)):
                if at_prompt:
                    return "prompt"
                return "timeout"
            try:
                chunk = os.read(self.master, 4096)
            except OSError:  # EIO: every copy of the slave side is closed
                chunk = b""
            if not chunk:
                return "exit"
            text = ANSI.sub("", chunk.decode(errors="replace")).replace("\r", "")
            *finished, self.partial = (self.partial + text).split("\n")
            self.lines += finished

    def send(self, secret: str) -> None:
        self.secrets.append(secret)
        self.partial = ""  # the prompt it answers
        self.sent_at = len(self.lines)  # what the CLI prints from now on is its answer
        with contextlib.suppress(OSError):  # the CLI already left (EIO); the next read reports how it ended
            os.write(self.master, f"{secret}\n".encode())

    def output(self, *, unfinished: bool) -> str:
        """What the CLI printed since the last answer was sent, redacted, without prompts.

        The unfinished last line is included only when `unfinished` and it is not a prompt.
        """
        tail = [self.partial] if unfinished and not ANY_PROMPT.search(self.partial) else []
        text = "\n".join([*self.lines[self.sent_at :], *tail])
        for secret in self.secrets:
            text = text.replace(secret, "***")
        return "\n".join(line.strip() for line in text.split("\n") if line.strip())

    def close(self, grace: float = 0) -> int:
        """Reap the child, killing it unless it exits within `grace` seconds. Safe to call twice."""
        with self._close_lock:
            if self._closed:
                return self.proc.returncode
            self._closed = True
        try:
            self.proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:  # not reaped yet, so the PID cannot belong to anyone else
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait()
        os.close(self.master)
        return self.proc.returncode


class SigninFlow:
    """Runs at most one sign-in at a time; an abandoned one is killed after `timeout` idle seconds."""

    def __init__(self, argv_prefix: tuple[str, ...] = ("protonvpn",), timeout: float = 300):
        self._argv, self._timeout = tuple(argv_prefix), timeout
        self._mu = threading.Lock()  # guards _run, _timer and the runs' busy/awaiting_code flags
        self._run: _Run | None = None
        self._timer: threading.Timer | None = None

    def start(self, username: str, password: str) -> Step:
        problem = _invalid(username, "username", not_option=True) or _invalid(password, "password")
        if problem:
            return Step("error", problem)
        with self._mu:
            if self._run is not None:
                return Step("error", "sign-in already in progress")
            try:
                run = _Run([*self._argv, "signin", username, "--totp"])
            except OSError as exc:
                return Step("error", f"cannot run {self._argv[0]}: {exc.strerror or exc}")
            self._run = run
        try:  # whatever goes wrong from here on must not leave the child running or the slot taken
            ended = self._until_prompt(run, PASSWORD_PROMPT)
            if ended:
                return ended
            run.send(password)
            ended = self._until_prompt(run, ANY_PROMPT)
            if ended:
                return ended
            if not CODE_PROMPT.search(run.partial):
                return self._end(run, "the CLI asked for the password again, so it was not accepted")
            return self._ask_for_code(run, "")
        except BaseException:
            self._abort(run)
            raise

    def submit_code(self, code: str) -> Step:
        code = "".join(code.split())  # "123 456" is the same code
        with self._mu:
            run = self._run
            if run is None or run.busy or not run.awaiting_code:
                return Step("error", "no sign-in is waiting for a code")
            problem = _invalid(code, "code")
            if problem:
                return Step("need_code", problem)  # still waiting; the idle timer keeps running
            run.busy, run.awaiting_code = True, False
            if self._timer is not None:
                self._timer.cancel()
        try:
            run.send(code)
            ended = self._until_prompt(run, ANY_PROMPT)
            if ended:
                return ended
            if not CODE_PROMPT.search(run.partial):
                return self._end(run, "the CLI asked for the password again, so the code was not accepted")
            # The CLI asks for the code again: tell why, and keep the flow (a new login would cost a new password).
            return self._ask_for_code(run, run.output(unfinished=False) or "the code was not accepted")
        except BaseException:
            self._abort(run)
            raise

    def _ask_for_code(self, run: _Run, message: str) -> Step:
        with self._mu:
            run.busy, run.awaiting_code = False, True
            self._timer = threading.Timer(self._timeout, self._expire, (run,))
            self._timer.daemon = True
            self._timer.start()
        return Step("need_code", message)

    def _abort(self, run: _Run) -> None:
        """End `run` after an unexpected exception: free the slot, stop the timer, kill the child."""
        with self._mu:
            if self._run is run:
                self._run = None
                if self._timer is not None:
                    self._timer.cancel()
        run.close()

    def _until_prompt(self, run: _Run, want: re.Pattern) -> Step | None:
        """None while the CLI waits at a prompt matching `want`; otherwise the final Step."""
        kind = run.read(want, self._timeout)
        if kind == "prompt":
            return None
        return self._end(run, "", exited=True) if kind == "exit" else self._end(run, "the CLI did not answer in time")

    def _end(self, run: _Run, why: str, exited: bool = False) -> Step:
        with self._mu:
            if self._run is run:
                self._run = None
        output = run.output(unfinished=exited)
        rc = run.close(EXIT_GRACE if exited else 0)
        if exited and rc == 0:
            return Step("done", output or "signed in")
        if exited:
            return Step("error", output or f"sign-in failed (exit code {rc})")
        return Step("error", "\n".join(part for part in (output, why) if part))

    def _expire(self, run: _Run) -> None:
        with self._mu:
            if self._run is not run or run.busy:
                return
            self._run = None
        run.close()
