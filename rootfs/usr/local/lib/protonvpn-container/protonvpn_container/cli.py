"""Runs the protonvpn CLI; never raises for CLI failures."""

import os
import subprocess
from dataclasses import dataclass

from .config import is_true


@dataclass(frozen=True)
class Result:
    rc: int
    out: str


def run(*args: str, timeout: float = 120) -> Result:
    if is_true(os.environ.get("DEBUG", "")):
        args = ("--verbose", *args)
    try:
        proc = subprocess.run(
            ["protonvpn", *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return Result(124, f"protonvpn timed out after {timeout}s\n")
    except OSError as exc:
        return Result(127, f"cannot run protonvpn: {exc}\n")
    return Result(proc.returncode, proc.stdout)
