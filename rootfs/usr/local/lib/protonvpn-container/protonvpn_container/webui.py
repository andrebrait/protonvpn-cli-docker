"""WebUI: the static page and a small JSON API on a ThreadingHTTPServer.

Every `/api/*` route except `login` needs a session cookie while a password is set. Every POST needs
the `X-Requested-With` header (a cross-site form cannot send it) and a JSON object body. Log lines
carry the request line and status only: never bodies, passwords or 2FA codes.
"""

import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import traceback
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import urlsplit

from . import cli
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
POST_ROUTES = {
    "/api/login": "login",
    "/api/logout": "logout",
    "/api/connect": "connect",
    "/api/disconnect": "disconnect",
    "/api/settings": "settings",
    "/api/signin": "signin",
    "/api/signin/code": "signin_code",
    "/api/signout": "signout",
    "/api/banner/dismiss": "banner_dismiss",
}
SETTINGS_BY_ENV = {s.env: s for s in SETTINGS}


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
    return ""


class Ui:
    """State shared by the request threads: sessions, login throttling and the collaborators."""

    def __init__(self, supervisor, store, signin_flow, password: str):
        self.supervisor, self.store, self.signin, self.password = supervisor, store, signin_flow, password
        self.clock = time.monotonic
        self._lock = threading.Lock()
        self._sessions: dict[str, float] = {}  # token -> expiry
        self._failures: dict[str, list[float]] = {}  # client address -> failure times within the window
        self._locked_until: dict[str, float] = {}

    def state(self) -> dict:
        state = self.supervisor.snapshot()
        state["settings"] = [
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
        state["auth_required"] = bool(self.password)
        state["banner"] = not self.password and not self.store.banner_dismissed()
        return state

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
        print(f"[webui] {self.client_address[0]} {format % args}", flush=True)

    def log_request(self, code="-", size="-"):
        if self.command == "GET" and urlsplit(self.path).path == "/api/state" and str(code) == "200":
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
            self._json(500, {"ok": False, "message": "internal error"})

    def _cookie(self) -> str:
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == SESSION_COOKIE:
                return value
        return ""

    def _authorized(self) -> bool:
        if self.ui.password and not self.ui.session_valid(self._cookie()):
            self._json(401, {"ok": False, "message": "login required", "auth_required": True})
            return False
        return True

    # --- GET ---

    def do_GET(self) -> None:
        self._guarded(self._get)

    def _get(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            self._static("index.html")
        elif path.startswith("/static/"):
            self._static(path[len("/static/") :])
        elif path == "/api/state":
            if self._authorized():
                self._json(200, self.ui.state())
        else:
            self._json(404, {"ok": False, "message": "not found"})

    def _static(self, name: str) -> None:
        content_type = CONTENT_TYPES.get(os.path.splitext(name)[1])
        try:
            if not STATIC_NAME.match(name) or content_type is None:
                raise FileNotFoundError(name)
            body = resources.files(__package__).joinpath("static", name).read_bytes()
        except OSError:
            self._json(404, {"ok": False, "message": "not found"})
            return
        self._send(200, body, content_type, {"Cache-Control": "no-cache"})

    # --- POST ---

    def do_POST(self) -> None:
        self._guarded(self._post)

    def _post(self) -> None:
        route = POST_ROUTES.get(urlsplit(self.path).path)
        if route is None:
            self._json(404, {"ok": False, "message": "not found"})
        elif self.headers.get(CSRF_HEADER) != CSRF_VALUE:
            self._json(403, {"ok": False, "message": f"missing {CSRF_HEADER} header"})
        elif route == "login" or self._authorized():
            body = self._body()
            if body is not None:
                getattr(self, f"post_{route}")(body)

    def _body(self) -> dict | None:
        """The JSON object body, or None after answering 400/413."""
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = -1
        if length > MAX_BODY:
            self._json(413, {"ok": False, "message": "request body too large"})
            return None
        try:
            data = json.loads(self.rfile.read(length)) if length > 0 else None
        except ValueError:
            data = None
        if not isinstance(data, dict):
            self._json(400, {"ok": False, "message": "a JSON object body is required"})
            return None
        return data

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
            self._json(429, {"ok": False, "message": message}, {"Retry-After": str(LOGIN_LOCKOUT)})
        else:
            self._json(401, {"ok": False, "message": "wrong password"})

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
            self._json(400, {"ok": False, "message": "env must name a setting and value must be a string"})
        elif self.ui.store.locked(env):
            self._json(409, {"ok": False, "message": f"{env} is set by the container config"})
        elif problem := invalid_value(env, value):
            self._json(400, {"ok": False, "message": problem})
        else:
            try:
                ok, message = self.ui.supervisor.apply_setting(env, value)
            except OSError as exc:  # the settings file could not be written
                self._json(500, {"ok": False, "message": f"could not save the setting: {exc.strerror or exc}"})
                return
            self._json(200 if ok else 422, {"ok": ok, "message": message})

    def post_signin(self, body: dict) -> None:
        username, password = body.get("username"), body.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            self._json(400, {"ok": False, "message": "username and password must be strings"})
        else:
            self._step(self.ui.signin.start(username, password))

    def post_signin_code(self, body: dict) -> None:
        code = body.get("code")
        if not isinstance(code, str):
            self._json(400, {"ok": False, "message": "code must be a string"})
        else:
            self._step(self.ui.signin.submit_code(code))

    def _step(self, step) -> None:
        if step.state == "done":
            self.ui.supervisor.notify_signed_in()
        self._json(200, asdict(step))

    def post_signout(self, body: dict) -> None:
        result = cli.run("signout")
        self.ui.supervisor.notify_signed_in()  # the supervisor has no sign-out hook; this forces a state check now
        self._json(200 if result.rc == 0 else 500, {"ok": result.rc == 0, "message": result.out.strip()})

    def post_banner_dismiss(self, body: dict) -> None:
        try:
            self.ui.store.dismiss_banner()
        except OSError as exc:
            self._json(500, {"ok": False, "message": f"could not save the setting: {exc.strerror or exc}"})
        else:
            self._json(200, {"ok": True})


def make_server(port: int, supervisor, store, signin_flow, password: str) -> ThreadingHTTPServer:
    """Bind the WebUI on all IPv4 interfaces; the caller runs `serve_forever()`."""
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.ui = Ui(supervisor, store, signin_flow, password)
    if not password:
        print(OPEN_WARNING, flush=True)
    print(f"[webui] listening on port {server.server_address[1]}", flush=True)
    return server
