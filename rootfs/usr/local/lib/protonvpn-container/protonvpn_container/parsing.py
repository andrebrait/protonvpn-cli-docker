"""Parsers for protonvpn CLI, natpmpc and `wg show` output."""

import re
from dataclasses import dataclass

_ACCOUNT = re.compile(r"^Account: '(.*)'\s*$", re.M)
_EXIT_IP = re.compile(r"Your new IP address is (\S+?)\.?\s*$", re.M)
_NATPMP_PORT = re.compile(r"Mapped public port (\d+)")


@dataclass
class Status:
    connected: bool = False
    server: str = ""
    location: str = ""
    load: str = ""
    protocol: str = ""


def parse_status(out: str) -> Status:
    fields: dict[str, str] = {}
    for line in out.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields.setdefault(key.strip(), value.strip())
    server, _, location = fields.get("Server", "").partition(" in ")
    return Status(
        connected=fields.get("Status", "").lower() == "connected",
        server=server,
        location=location,
        load=fields.get("Load", ""),
        protocol=fields.get("Protocol", ""),
    )


def parse_exit_ip(connect_out: str) -> str:
    match = _EXIT_IP.search(connect_out)
    return match.group(1) if match else ""


def parse_natpmp_port(out: str) -> int | None:
    match = _NATPMP_PORT.search(out)
    port = int(match.group(1)) if match else 0
    return port if 1 <= port <= 65535 else None


def parse_wg_transfer(out: str) -> tuple[int, int] | None:
    rx = tx = peers = 0
    for line in out.splitlines():
        fields = line.split("\t")
        if len(fields) == 3 and fields[1].isdecimal() and fields[2].isdecimal():
            rx += int(fields[1])
            tx += int(fields[2])
            peers += 1
    return (rx, tx) if peers else None


def parse_account(info_out: str) -> str:
    """Account name from `protonvpn info`; "" when signed out (the CLI prints 'None' and exits 0)."""
    match = _ACCOUNT.search(info_out)
    return "" if match is None or match.group(1) == "None" else match.group(1)
