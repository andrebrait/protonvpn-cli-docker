"""Runs the protonvpn CLI and helper tools; never raises for command failures."""

import os
import subprocess
from dataclasses import dataclass

from .config import is_true


@dataclass(frozen=True)
class Result:
    rc: int
    out: str


TIMEOUT = 120


def run(*args: str, timeout: float = TIMEOUT) -> Result:
    if is_true(os.environ.get("DEBUG", "")):
        args = ("--verbose", *args)
    return _exec(["protonvpn", *args], timeout)


def run_tool(*argv: str, timeout: float = 10) -> Result:
    return _exec(list(argv), timeout)


def _exec(argv: list[str], timeout: float) -> Result:
    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        partial = exc.output.decode(errors="replace") if isinstance(exc.output, bytes) else (exc.output or "")
        if partial and not partial.endswith("\n"):
            partial += "\n"
        return Result(124, f"{partial}{argv[0]} timed out after {timeout}s\n")
    except OSError as exc:
        return Result(127, f"cannot run {argv[0]}: {exc}\n")
    return Result(proc.returncode, proc.stdout)
