"""WebUI: the static page and a small JSON API on a ThreadingHTTPServer.

The JSON API lives under `/api/v1/`; ROUTES (end of this module) is the one place listing every route.
Protected routes accept a session cookie or API bearer key while a password is set. POSTs need
`X-Requested-With` unless authenticated by bearer key, and a JSON object body. Log lines carry
the request line and status only: never bodies, passwords, tokens or 2FA codes.
"""

import hmac
import ipaddress
import json
import os
import re
import secrets
import sys
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlsplit

from .config import CHOICES, SETTINGS

OPEN_WARNING = "[webui] WARNING: WEBUI_PASSWORD is not set; the WebUI is open to anyone who can reach it"
CSRF_HEADER, CSRF_VALUE = "X-Requested-With", "protonvpn-webui"
SESSION_COOKIE = "session"
COOKIE_ATTRIBUTES = "HttpOnly; SameSite=Strict; Path=/"
SESSION_TTL = 7 * 24 * 3600
MAX_BODY = 8192
MAX_VALUE = 256
LOGIN_FAILURES, LOGIN_WINDOW, LOGIN_LOCKOUT = 5, 60, 60  # failures per window per client address, lockout seconds
OPTION_RISK = ("SERVER", "COUNTRY", "CITY")  # passed to `protonvpn connect`: a leading '-' would be an option
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".png": "image/png",
}
STATIC_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")  # one plain file name: no '/', '%', leading '.'
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
SETTINGS_BY_ENV = {s.env: s for s in SETTINGS}
# Client-controlled text in log lines is escaped like the stdlib does: no forged lines, no terminal control codes.
LOG_ESCAPES = {c: f"\\x{c:02x}" for c in (*range(0x20), *range(0x7F, 0xA0))} | {ord("\\"): "\\\\"}
CUSTOM_DNS_SYNTAX = "must be off, on, or on --dns <comma-separated IPv4/IPv6 addresses>, e.g. on --dns 1.1.1.1,8.8.8.8"


def custom_dns_ok(value: str) -> bool:
    """The CLI's `config set custom-dns {off|on} [--dns LIST]`; nothing else may reach its command line."""
    words = value.split()
    if words in (["off"], ["on"]):
        return True
    if len(words) != 3 or words[:2] != ["on", "--dns"]:
        return False
    try:
        for address in words[2].split(","):
            ipaddress.ip_address(address)
    except ValueError:
        return False
    return True


def invalid_value(env: str, value: str) -> str:
    """Why `value` is not acceptable for the setting, or "" when it is. The CLI still has the last word."""
    if len(value) > MAX_VALUE or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return "value is too long or has a control character"
    kind = SETTINGS_BY_ENV[env].kind
    if kind == "choice" and value and value not in CHOICES[env]:
        return f"must be one of: {', '.join(CHOICES[env])}"
    if kind == "bool" and value not in ("", "true", "false"):
        return "must be true or false"
    if env in OPTION_RISK and value.lstrip().startswith("-"):
        return "must not start with '-'"
    if env == "CUSTOM_DNS" and value and not custom_dns_ok(value):
        return CUSTOM_DNS_SYNTAX
    return ""


class Ui:
    """State shared by the request threads: sessions, login throttling and the collaborators."""

    def __init__(self, supervisor, store, signin_flow, password: str, api_key: str = ""):
        self.supervisor, self.store, self.signin, self.password = supervisor, store, signin_flow, password
        self.api_key = api_key
        self.clock = time.monotonic
        self._lock = threading.Lock()
        self._sessions: dict[str, float] = {}  # token -> expiry
        self._failures: dict[str, list[float]] = {}  # client address -> failure times within the window
        self._locked_until: dict[str, float] = {}

    def state(self) -> dict:
        state = self.supervisor.snapshot()
        state["settings"] = self.settings()
        state["auth_required"] = bool(self.password)
        state["banner"] = not self.password and not self.store.banner_dismissed()
        return state

    def settings(self) -> list:
        return [
            {
                "env": s.env,
                "value": self.store.effective(s.env),
                "locked": self.store.locked(s.env),
                "source": self.store.source(s.env),
                "kind": s.kind,
                **({"choices": list(CHOICES[s.env])} if s.kind == "choice" else {}),
            }
            for s in SETTINGS
        ]

    def session_valid(self, token: str) -> bool:
        with self._lock:
            expiry = self._sessions.get(token)
            if expiry is not None and expiry <= self.clock():
                del self._sessions[token]
                return False
            return expiry is not None

    def end_session(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)

    def login(self, client: str, password: str) -> tuple[int, str]:
        """(200, session token), (401, "") for a wrong password, or (429, "") while `client` is locked out."""
        now = self.clock()
        with self._lock:
            self._locked_until = {c: t for c, t in self._locked_until.items() if t > now}
            self._failures = {c: f for c, f in self._failures.items() if now - f[-1] < LOGIN_WINDOW}
            if client in self._locked_until:
                return 429, ""
            if hmac.compare_digest(password.encode(), self.password.encode()):
                self._failures.pop(client, None)
                self._sessions = {t: expiry for t, expiry in self._sessions.items() if expiry > now}
                token = secrets.token_urlsafe(32)
                self._sessions[token] = now + SESSION_TTL
                return 200, token
            failures = [t for t in self._failures.get(client, []) if now - t < LOGIN_WINDOW]
            failures.append(now)
            if len(failures) >= LOGIN_FAILURES:
                self._failures.pop(client, None)
                self._locked_until[client] = now + LOGIN_LOCKOUT
            else:
                self._failures[client] = failures
            return 401, ""


class Handler(BaseHTTPRequestHandler):
    server_version = "protonvpn-webui"
    sys_version = ""
    timeout = 30  # a stalled client must not hold a thread for ever

    @property
    def ui(self) -> Ui:
        return self.server.ui

    def log_message(self, format, *args):
        print(f"[webui] {self.client_address[0]} {(format % args).translate(LOG_ESCAPES)}", flush=True)

    def log_request(self, code="-", size="-"):
        if self.command == "GET" and urlsplit(self.path).path == "/api/v1/state" and str(code) == "200":
            return  # the page polls this every 5 s; logging it would drown the container log
        super().log_request(code, size)

    # --- plumbing ---

    def _send(self, status: int, body: bytes, content_type: str, headers: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict, headers: dict | None = None) -> None:
        body = json.dumps(payload).encode()
        self._send(status, body, "application/json", {"Cache-Control": "no-store", **(headers or {})})

    def _guarded(self, handle) -> None:
        try:
            handle()
        except (BrokenPipeError, ConnectionResetError):  # the browser went away
            pass
        except Exception:
            print("[webui] request failed:", flush=True)
            traceback.print_exc(file=sys.stdout)  # code locations only, never request bodies
            sys.stdout.flush()
            self._json(500, {"error": "internal error"})

    def _cookie(self) -> str:
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == SESSION_COOKIE:
                return value
        return ""

    def _bearer_valid(self) -> bool:
        scheme, _, token = self.headers.get("Authorization", "").partition(" ")
        return bool(self.ui.api_key) and scheme.lower() == "bearer" and hmac.compare_digest(
            token.encode(), self.ui.api_key.encode()
        )

    def _authorized(self) -> bool:
        if self.ui.password and not self._bearer_valid() and not self.ui.session_valid(self._cookie()):
            self._json(401, {"error": "login required"})
            return False
        return True

    # --- routing ---

    def do_GET(self) -> None:
        self._guarded(self._get)

    def do_POST(self) -> None:
        self._guarded(lambda: self._api("POST", urlsplit(self.path).path))

    def _get(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            self._static("index.html")
        elif path == "/api":
            self._static("api.html")
        elif path.startswith("/static/"):
            self._static(path[len("/static/") :])
        else:
            self._api("GET", path)

    def _static(self, name: str) -> None:
        content_type = CONTENT_TYPES.get(os.path.splitext(name)[1])
        try:
            if not STATIC_NAME.match(name) or content_type is None:
                raise FileNotFoundError(name)
            body = resources.files(__package__).joinpath("static", name).read_bytes()
        except OSError:
            self._json(404, {"error": "not found"})
            return
        self._send(200, body, content_type, {"Cache-Control": "no-cache"})

    def _api(self, method: str, path: str) -> None:
        route = ROUTE_INDEX.get((method, path))
        if route is None:
            self._json(404, {"error": "not found"})
            return
        if method == "POST" and not self._bearer_valid() and self.headers.get(CSRF_HEADER) != CSRF_VALUE:
            self._json(403, {"error": f"missing {CSRF_HEADER} header"})
            return
        if route.auth and not self._authorized():  # answered 401
            return
        body = self._body() if method == "POST" else {}
        if body is not None:
            route.handler(self, body)

    def _body(self) -> dict | None:
        """The JSON object body, or None after answering 400/413."""
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = -1
        if length > MAX_BODY:
            self._json(413, {"error": "request body too large"})
            return None
        try:
            data = json.loads(self.rfile.read(length)) if length > 0 else None
            if isinstance(data, dict):
                # A lone surrogate ("\ud800") is valid JSON but cannot be encoded: it would fail later, in the pty
                # write or in the CLI call, after the value was accepted. Reject it here, for every route.
                json.dumps(data, ensure_ascii=False).encode("utf-8")
        except ValueError:  # not JSON, or a lone surrogate (UnicodeEncodeError)
            data = None
        if not isinstance(data, dict):
            self._json(400, {"error": "a JSON object body of valid text is required"})
            return None
        return data

    def get_state(self, body: dict) -> None:
        self._json(200, self.ui.state())

    def get_status(self, body: dict) -> None:
        state = self.ui.supervisor.snapshot()
        self._json(200, {key: state[key] for key in (
            "signed_in", "account", "connected", "server", "location", "load", "protocol",
            "exit_ip", "forwarded_port", "last_error",
            "tunnel_healthy", "health_error", "health_checked_ago",
        )})

    def get_port(self, body: dict) -> None:
        port = self.ui.supervisor.snapshot()["forwarded_port"]
        if parse_qs(urlsplit(self.path).query).get("format") == ["text"]:
            self._send(200, str(port).encode() if port is not None else b"", "text/plain", {"Cache-Control": "no-store"})
        else:
            self._json(200, {"port": port})

    def get_traffic(self, body: dict) -> None:
        samples = self.ui.supervisor.snapshot()["traffic"]
        last = samples[-1] if samples else [0, 0, 0]
        self._json(200, {
            "rx_bytes": last[1], "tx_bytes": last[2],
            "samples": [[t - last[0], rx, tx] for t, rx, tx in samples],
        })

    def get_settings(self, body: dict) -> None:
        self._json(200, {"settings": self.ui.settings()})

    def get_openapi(self, body: dict) -> None:
        self._send(200, resources.files(__package__).joinpath("openapi.json").read_bytes(),
                   "application/json", {"Cache-Control": "no-cache"})

    def post_login(self, body: dict) -> None:
        if not self.ui.password:
            self._json(200, {"ok": True})
            return
        password = body.get("password")
        status, token = self.ui.login(self.client_address[0], password if isinstance(password, str) else "")
        if status == 200:
            cookie = f"{SESSION_COOKIE}={token}; {COOKIE_ATTRIBUTES}; Max-Age={SESSION_TTL}"
            self._json(200, {"ok": True}, {"Set-Cookie": cookie})
        elif status == 429:
            message = "too many failed logins; try again in a minute"
            self._json(429, {"error": message}, {"Retry-After": str(LOGIN_LOCKOUT)})
        else:
            self._json(401, {"error": "wrong password"})

    def post_logout(self, body: dict) -> None:
        self.ui.end_session(self._cookie())
        self._json(200, {"ok": True}, {"Set-Cookie": f"{SESSION_COOKIE}=; {COOKIE_ATTRIBUTES}; Max-Age=0"})

    def post_connect(self, body: dict) -> None:
        self.ui.supervisor.request_connect()
        self._json(200, {"ok": True})

    def post_disconnect(self, body: dict) -> None:
        self.ui.supervisor.request_disconnect()
        self._json(200, {"ok": True})

    def post_settings(self, body: dict) -> None:
        env, value = body.get("env"), body.get("value")
        if not isinstance(env, str) or env not in SETTINGS_BY_ENV or not isinstance(value, str):
            self._json(400, {"error": "env must name a setting and value must be a string"})
        elif self.ui.store.locked(env):
            self._json(409, {"error": f"{env} is set by the container config"})
        elif problem := invalid_value(env, value):
            self._json(400, {"error": problem})
        else:
            try:
                ok, message = self.ui.supervisor.apply_setting(env, value)
            except OSError as exc:  # the settings file could not be written
                self._json(500, {"error": f"could not save the setting: {exc.strerror or exc}"})
                return
            self._json(200 if ok else 422, {"ok": True, "message": message} if ok else {"error": message})

    def post_signin(self, body: dict) -> None:
        username, password = body.get("username"), body.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            self._json(400, {"error": "username and password must be strings"})
        else:
            self._step(self.ui.signin.start(username, password))

    def post_signin_code(self, body: dict) -> None:
        code = body.get("code")
        if not isinstance(code, str):
            self._json(400, {"error": "code must be a string"})
        else:
            self._step(self.ui.signin.submit_code(code))

    def _step(self, step) -> None:
        if step.state == "error":
            self._json(400, {"error": step.message})
            return
        if step.state == "done":
            self.ui.supervisor.notify_signed_in()
        self._json(200, asdict(step))

    def post_signout(self, body: dict) -> None:
        ok, message = self.ui.supervisor.sign_out()
        self._json(200 if ok else 500, {"ok": True, "message": message} if ok else {"error": message})

    def post_banner_dismiss(self, body: dict) -> None:
        try:
            self.ui.store.dismiss_banner()
        except OSError as exc:
            self._json(500, {"error": f"could not save the setting: {exc.strerror or exc}"})
        else:
            self._json(200, {"ok": True})


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    handler: Callable  # a Handler method, called as handler(self, body); body is {} for GET
    auth: bool = True  # needs a session or bearer key while a password is set


ROUTES = (
    Route("GET", "/api/v1/state", Handler.get_state),
    Route("GET", "/api/v1/status", Handler.get_status),
    Route("GET", "/api/v1/port", Handler.get_port),
    Route("GET", "/api/v1/traffic", Handler.get_traffic),
    Route("GET", "/api/v1/settings", Handler.get_settings),
    Route("GET", "/api/v1/openapi.json", Handler.get_openapi, auth=False),
    Route("POST", "/api/v1/login", Handler.post_login, auth=False),
    Route("POST", "/api/v1/logout", Handler.post_logout),
    Route("POST", "/api/v1/connect", Handler.post_connect),
    Route("POST", "/api/v1/disconnect", Handler.post_disconnect),
    Route("POST", "/api/v1/settings", Handler.post_settings),
    Route("POST", "/api/v1/signin", Handler.post_signin),
    Route("POST", "/api/v1/signin/code", Handler.post_signin_code),
    Route("POST", "/api/v1/signout", Handler.post_signout),
    Route("POST", "/api/v1/banner/dismiss", Handler.post_banner_dismiss),
)
ROUTE_INDEX = {(route.method, route.path): route for route in ROUTES}


class BoundedHTTPServer(ThreadingHTTPServer):
    """Reject excess connections before allocating a request thread."""

    def __init__(self, server_address, handler):
        self._capacity = threading.BoundedSemaphore(32)
        super().__init__(server_address, handler)

    def process_request(self, request, client_address):
        if not self._capacity.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._capacity.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._capacity.release()


def make_server(port: int, supervisor, store, signin_flow, password: str, api_key: str = "") -> ThreadingHTTPServer:
    """Bind the WebUI on all IPv4 interfaces; the caller runs `serve_forever()`."""
    server = BoundedHTTPServer(("0.0.0.0", port), Handler)
    server.ui = Ui(supervisor, store, signin_flow, password, api_key)
    if not password:
        print(OPEN_WARNING, flush=True)
    print(f"[webui] listening on port {server.server_address[1]}", flush=True)
    return server
