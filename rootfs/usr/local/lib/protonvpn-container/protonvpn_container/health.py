"""Operational tunnel health: a bounded probe through the WireGuard interface, and the file Docker's healthcheck reads.

Run as `python3 -m protonvpn_container.health`: exit status 0 when the supervisor's file vouches for the tunnel.
"""

import ipaddress
import json
import os
import socket
import sys
import time

TUNNEL = "proton0"
# An IPv4 HTTPS echo, asked only through the tunnel interface. It is not Proton's API: that refuses requests from VPN exits.
PROBE_URL = "https://api.ipify.org"
PROBE_MAX_TIME = 5  # curl's own limit on the whole request
PROBE_TIMEOUT = 6  # the subprocess's: a second more, for curl to report its failure
PROBE_MAX_BYTES = 128
HEALTH_FILE = "/run/protonvpn-container/health.json"
FRESH_FOR = 60  # seconds a successful probe vouches for the tunnel
REASON_MAX = 160


class ProbeError(Exception):
    """A failed probe; the message is a short reason fit for the WebUI."""


def probe(tool, url: str = PROBE_URL) -> str:
    """The public IPv4 address the echo saw through the tunnel; raises ProbeError for anything else."""
    res = tool(
        "curl", "--interface", f"if!{TUNNEL}", "--ipv4", "--max-time", str(PROBE_MAX_TIME),
        "--max-filesize", str(PROBE_MAX_BYTES), "--noproxy", "*", "--fail", "--silent",
        "--show-error", url, timeout=PROBE_TIMEOUT,
    )
    if res.rc != 0:
        reason = (res.out.strip().splitlines() or [""])[-1].partition(" after ")[0]
        raise ProbeError(reason[:REASON_MAX] or f"curl exited with code {res.rc}")
    try:
        ip = ipaddress.IPv4Address(res.out.strip())
    except ValueError:
        ip = None
    # Multicast counts as global for Python, and 0.0.0.0, loopback, link-local, private and shared ranges do not.
    if ip is None or not ip.is_global or ip.is_multicast:
        raise ProbeError("the IP echo did not return a public IPv4 address")
    return str(ip)


def active_handshake(tool) -> tuple[str, int] | None:
    """Exercise the peer without DNS/echo, then read its handshake; unusable evidence is unknown."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(1)
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, f"{TUNNEL}\0".encode())
            if udp.sendto(b"\0", ("10.2.0.1", 9)) != 1:
                return None
    except (OSError, AttributeError):  # SO_BINDTODEVICE is Linux-only
        return None
    res = tool("wg", "show", TUNNEL, "latest-handshakes", timeout=2)
    fields = res.out.split()
    if res.rc != 0 or len(fields) != 2 or len(fields[1]) > 20 or not fields[1].isascii() or not fields[1].isdigit():
        return None  # proton0 has one peer; absent/ambiguous output is not a dead peer
    return fields[0], int(fields[1])


def write_health(path: str, healthy: bool, checked_at: float) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"healthy": healthy, "checked_at": checked_at}, f)
    os.replace(tmp, path)


def is_healthy(path: str = HEALTH_FILE, clock=time.monotonic) -> bool:
    """True iff the file says healthy and was stamped 0 to FRESH_FOR seconds ago; anything doubtful is unhealthy.

    The stamp is on the monotonic clock, so a file left by an earlier boot reads as a time in the future.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        healthy, checked_at = data["healthy"], data["checked_at"]
    except (OSError, ValueError, KeyError, TypeError):
        return False
    if healthy is not True or isinstance(checked_at, bool) or not isinstance(checked_at, (int, float)):
        return False
    return 0 <= clock() - checked_at <= FRESH_FOR


if __name__ == "__main__":
    sys.exit(0 if is_healthy() else 1)
