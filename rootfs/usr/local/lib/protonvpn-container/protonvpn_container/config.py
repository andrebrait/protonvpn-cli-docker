"""Settings precedence: non-empty env var > /config/settings.json > image default."""

import contextlib
import json
import os
import tempfile
import threading
from collections.abc import Mapping
from dataclasses import dataclass

DEFAULT_PATH = "/config/settings.json"
DEFAULTS = {"KILL_SWITCH": "standard", "ANONYMOUS_CRASH_REPORTS": "off"}
BANNER_KEY = "_banner_dismissed"
TRUE_VALUES = {"true", "1", "yes", "on"}


@dataclass(frozen=True)
class Setting:
    env: str
    cli_key: str | None
    kind: str


SETTINGS = (
    Setting("SERVER", None, "text"),
    Setting("COUNTRY", None, "text"),
    Setting("CITY", None, "text"),
    Setting("P2P", None, "bool"),
    Setting("SECURE_CORE", None, "bool"),
    Setting("TOR", None, "bool"),
    Setting("NETSHIELD", "netshield", "choice"),
    Setting("PORT_FORWARDING", "port-forwarding", "choice"),
    Setting("VPN_ACCELERATOR", "vpn-accelerator", "choice"),
    Setting("MODERATE_NAT", "moderate-nat", "choice"),
    Setting("IPV6", "ipv6", "choice"),
    Setting("CUSTOM_DNS", "custom-dns", "text"),
    Setting("KILL_SWITCH", "kill-switch", "choice"),
    Setting("ANONYMOUS_CRASH_REPORTS", "anonymous-crash-reports", "choice"),
)

ON_OFF = ("off", "on")
# Allowed values of the `choice` settings, from `protonvpn config set <key> --help` (CLI 1.0.5).
CHOICES = {
    "NETSHIELD": ("off", "malware-only", "malware-ads-trackers"),
    "PORT_FORWARDING": ON_OFF,
    "VPN_ACCELERATOR": ON_OFF,
    "MODERATE_NAT": ON_OFF,
    "IPV6": ON_OFF,
    "KILL_SWITCH": ("off", "standard"),
    "ANONYMOUS_CRASH_REPORTS": ON_OFF,
}

FLAG_SETTINGS = (("P2P", "--p2p"), ("SECURE_CORE", "--securecore"), ("TOR", "--tor"))


def is_true(value: str) -> bool:
    return value.strip().lower() in TRUE_VALUES


class SettingsStore:
    def __init__(self, path: str = DEFAULT_PATH, environ: Mapping[str, str] = os.environ):
        self._path = path
        self._environ = environ
        self._lock = threading.Lock()
        self._corrupt_logged = False

    def effective(self, env: str) -> str:
        return self._resolve(env)[0]

    def source(self, env: str) -> str:
        return self._resolve(env)[1]

    def locked(self, env: str) -> bool:
        return bool(self._environ.get(env, ""))

    def save(self, env: str, value: str) -> None:
        if self.locked(env):
            raise PermissionError(f"{env} is set in the environment and cannot be changed")
        self._store(env, value)

    def banner_dismissed(self) -> bool:
        with self._lock:
            return self._load().get(BANNER_KEY) is True

    def dismiss_banner(self) -> None:
        self._store(BANNER_KEY, True)

    def _resolve(self, env: str) -> tuple[str, str]:
        env_value = self._environ.get(env, "")
        if env_value:
            return env_value, "env"
        with self._lock:
            file_value = self._load().get(env)
        if file_value not in (None, ""):
            return str(file_value), "file"
        return DEFAULTS.get(env, ""), "default"

    def _store(self, key: str, value) -> None:
        with self._lock:
            data = self._load()
            if value in (None, ""):
                data.pop(key, None)
            else:
                data[key] = value
            self._write(data)

    def _load(self) -> dict:
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("not a JSON object")
            return data
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            if not self._corrupt_logged:
                self._corrupt_logged = True
                print(f"[webui] {self._path} is unreadable ({exc}); treating it as empty", flush=True)
            return {}

    def _write(self, data: dict) -> None:
        # mkstemp creates the temp file mode 0600; os.replace keeps that mode on the target.
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self._path) or ".", prefix=".settings-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
                f.write("\n")
            os.replace(tmp, self._path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise


def connect_args(store: SettingsStore) -> list[str]:
    server = store.effective("SERVER")
    country = store.effective("COUNTRY")
    city = store.effective("CITY")
    args: list[str] = []
    if server:
        if country or city:
            print("[protonvpn] SERVER is set; ignoring COUNTRY/CITY", flush=True)
        args.append(server)
    else:
        if country:
            args += ["--country", country]
        if city:
            args += ["--city", city]
    args += [flag for env, flag in FLAG_SETTINGS if is_true(store.effective(env))]
    return args


def settings_pairs(store: SettingsStore) -> list[tuple[str, list[str]]]:
    pairs = []
    for setting in SETTINGS:
        words = store.effective(setting.env).split()
        if setting.cli_key is not None and words:
            pairs.append((setting.cli_key, words))
    return pairs
