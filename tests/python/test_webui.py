import http.client
import io
import json
import os
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from protonvpn_container import webui
from protonvpn_container.config import SettingsStore
from protonvpn_container.signin import SigninFlow, Step

WARNING = "[webui] WARNING: WEBUI_PASSWORD is not set; the WebUI is open to anyone who can reach it"
CSRF = {"X-Requested-With": "protonvpn-webui"}
FAKE_CLI = str(Path(__file__).resolve().parent / "fakebin" / "protonvpn")


class StubSupervisor:
    def __init__(self):
        self.calls = []
        self.apply_result = (True, "saved")
        self.apply_error = None
        self.signout_result = (True, "You have been successfully signed out.")

    def snapshot(self):
        return {
            "signed_in": False,
            "account": "",
            "connected": False,
            "server": "",
            "location": "",
            "load": "",
            "protocol": "",
            "exit_ip": "",
            "forwarded_port": None,
            "traffic": [],
            "last_error": "",
            "settings_errors": {},
            "user_disconnected": False,
        }

    def request_connect(self):
        self.calls.append(("connect",))

    def request_disconnect(self):
        self.calls.append(("disconnect",))

    def notify_signed_in(self):
        self.calls.append(("notify_signed_in",))

    def sign_out(self):
        self.calls.append(("sign_out",))
        return self.signout_result

    def apply_setting(self, env, value):
        self.calls.append(("apply", env, value))
        if self.apply_error:
            raise self.apply_error
        return self.apply_result


class StubSignin:
    def __init__(self):
        self.calls = []
        self.start_step = Step("done", "Signed in")
        self.code_step = Step("done", "Signed in")

    def start(self, username, password):
        self.calls.append(("start", username, password))
        return self.start_step

    def submit_code(self, code):
        self.calls.append(("code", code))
        return self.code_step


class WebuiCase(unittest.TestCase):
    PASSWORD = ""

    def make_signin(self):
        return StubSignin()

    def setUp(self):
        self.out = io.StringIO()
        self.enterContext(redirect_stdout(self.out))  # the server threads print through sys.stdout
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.settings_path = os.path.join(tmp.name, "settings.json")
        self.environ = {}
        self.store = SettingsStore(self.settings_path, environ=self.environ)
        self.sup, self.signin = StubSupervisor(), self.make_signin()
        self.server = webui.make_server(0, self.sup, self.store, self.signin, self.PASSWORD)
        self.port = self.server.server_address[1]
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        self.addCleanup(self.stop_server, thread)

    def stop_server(self, thread):
        self.server.shutdown()
        self.server.server_close()
        thread.join(5)

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body, headers or {})
            resp = conn.getresponse()
            return resp, resp.read()
        finally:
            conn.close()

    def get(self, path, cookie=None):
        resp, data = self.request("GET", path, headers={"Cookie": cookie} if cookie else {})
        return resp.status, resp, data

    def get_json(self, path, cookie=None):
        status, _, data = self.get(path, cookie)
        return status, json.loads(data)

    def post(self, path, body=None, cookie=None, csrf=True, raw=None):
        headers = {"Content-Type": "application/json", **(CSRF if csrf else {})}
        if cookie:
            headers["Cookie"] = cookie
        payload = raw if raw is not None else json.dumps({} if body is None else body)
        resp, data = self.request("POST", path, payload, headers)
        return resp.status, json.loads(data), resp

    def login(self, password="hunter2"):
        status, _, resp = self.post("/api/v1/login", {"password": password})
        self.assertEqual(status, 200)
        return resp.getheader("Set-Cookie").split(";")[0]


class OpenModeTest(WebuiCase):
    def test_open_mode_state_has_banner(self):
        status, state = self.get_json("/api/v1/state")
        self.assertEqual(status, 200)
        self.assertIs(state["banner"], True)
        self.assertIs(state["auth_required"], False)
        self.assertIs(state["signed_in"], False)
        self.assertEqual(state["settings_errors"], {})

    def test_state_lists_every_setting_with_value_lock_source_and_kind(self):
        self.environ["NETSHIELD"] = "malware-only"
        self.store.save("SERVER", "NL#914")
        _, state = self.get_json("/api/v1/state")
        by_env = {s["env"]: s for s in state["settings"]}
        self.assertEqual(
            by_env["NETSHIELD"],
            {
                "env": "NETSHIELD",
                "value": "malware-only",
                "locked": True,
                "source": "env",
                "kind": "choice",
                "choices": ["off", "malware-only", "malware-ads-trackers"],
            },
        )
        self.assertEqual(
            by_env["SERVER"],
            {"env": "SERVER", "value": "NL#914", "locked": False, "source": "file", "kind": "text"},
        )
        self.assertEqual(
            (by_env["KILL_SWITCH"]["value"], by_env["KILL_SWITCH"]["source"]), ("standard", "default")
        )
        self.assertEqual(by_env["P2P"]["kind"], "bool")
        self.assertEqual(len(state["settings"]), 14)

    def test_warning_logged_at_startup(self):
        self.assertIn(WARNING, self.out.getvalue().splitlines())

    def test_banner_dismiss_persists(self):
        status, body, _ = self.post("/api/v1/banner/dismiss")
        self.assertEqual((status, body["ok"]), (200, True))
        self.assertTrue(self.store.banner_dismissed())
        self.assertTrue(SettingsStore(self.settings_path, environ={}).banner_dismissed())  # survives a restart
        _, state = self.get_json("/api/v1/state")
        self.assertIs(state["banner"], False)

    def test_connect_and_disconnect_reach_the_supervisor(self):
        self.assertEqual(self.post("/api/v1/connect")[0], 200)
        self.assertEqual(self.post("/api/v1/disconnect")[0], 200)
        self.assertEqual(self.sup.calls, [("connect",), ("disconnect",)])

    def test_login_in_open_mode_is_a_no_op(self):
        status, body, resp = self.post("/api/v1/login", {"password": "anything"})
        self.assertEqual((status, body["ok"]), (200, True))
        self.assertIsNone(resp.getheader("Set-Cookie"))


class PasswordModeTest(WebuiCase):
    PASSWORD = "hunter2"

    def test_no_warning_and_no_banner_with_a_password(self):
        self.assertNotIn("WARNING", self.out.getvalue())
        cookie = self.login()
        _, state = self.get_json("/api/v1/state", cookie)
        self.assertEqual((state["banner"], state["auth_required"]), (False, True))

    def test_password_mode_requires_login(self):
        status, body = self.get_json("/api/v1/state")
        self.assertEqual(status, 401)
        self.assertIs(body["auth_required"], True)
        self.assertEqual(self.post("/api/v1/connect")[0], 401)
        self.assertEqual(self.sup.calls, [])
        cookie = self.login()
        self.assertEqual(self.get_json("/api/v1/state", cookie)[0], 200)

    def test_session_cookie_attributes(self):
        _, _, resp = self.post("/api/v1/login", {"password": "hunter2"})
        cookie = resp.getheader("Set-Cookie")
        self.assertRegex(cookie, r"^session=[A-Za-z0-9_-]{43};")
        for attribute in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(attribute, cookie)

    def test_wrong_password_and_forged_cookie_are_rejected(self):
        status, body, resp = self.post("/api/v1/login", {"password": "nope"})
        self.assertEqual((status, body["ok"]), (401, False))
        self.assertIsNone(resp.getheader("Set-Cookie"))
        self.assertEqual(self.get_json("/api/v1/state", "session=forged")[0], 401)
        self.assertEqual(self.post("/api/v1/login", {})[0], 401)
        self.assertEqual(self.post("/api/v1/login", {"password": 12345})[0], 401)

    def test_login_rate_limit(self):
        for _ in range(5):
            self.assertEqual(self.post("/api/v1/login", {"password": "bad"})[0], 401)
        status, body, resp = self.post("/api/v1/login", {"password": "bad"})
        self.assertEqual(status, 429)
        self.assertEqual(resp.getheader("Retry-After"), "60")
        self.assertEqual(self.post("/api/v1/login", {"password": "hunter2"})[0], 429)  # even the right one is refused

    def test_login_lockout_ends_after_60s(self):
        now = [1000.0]
        self.server.ui.clock = lambda: now[0]
        for _ in range(6):
            self.post("/api/v1/login", {"password": "bad"})
        self.assertEqual(self.post("/api/v1/login", {"password": "hunter2"})[0], 429)
        now[0] = 1061.0
        self.assertEqual(self.post("/api/v1/login", {"password": "hunter2"})[0], 200)

    def test_failures_older_than_a_minute_do_not_count(self):
        now = [1000.0]
        self.server.ui.clock = lambda: now[0]
        for _ in range(4):
            self.post("/api/v1/login", {"password": "bad"})
        now[0] = 1061.0
        self.assertEqual(self.post("/api/v1/login", {"password": "bad"})[0], 401)  # 1 of 5 again, not the 5th
        self.assertEqual(self.post("/api/v1/login", {"password": "hunter2"})[0], 200)

    def test_sessions_expire(self):
        now = [1000.0]
        self.server.ui.clock = lambda: now[0]
        cookie = self.login()
        self.assertEqual(self.get_json("/api/v1/state", cookie)[0], 200)
        now[0] += webui.SESSION_TTL + 1
        self.assertEqual(self.get_json("/api/v1/state", cookie)[0], 401)

    def test_logout_ends_the_session(self):
        cookie = self.login()
        status, _, resp = self.post("/api/v1/logout", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", resp.getheader("Set-Cookie"))
        self.assertEqual(self.get_json("/api/v1/state", cookie)[0], 401)

    def test_static_files_need_no_login(self):
        self.assertEqual(self.get("/")[0], 200)  # the page has to load to show the login form

    def test_login_never_logs_the_password(self):
        self.post("/api/v1/login", {"password": "hunter2"})
        self.post("/api/v1/login", {"password": "wrong-guess"})
        logged = self.out.getvalue()
        self.assertIn("[webui]", logged)
        self.assertNotIn("hunter2", logged)
        self.assertNotIn("wrong-guess", logged)


class RequestRulesTest(WebuiCase):
    def test_post_requires_header(self):
        status, body, _ = self.post("/api/v1/connect", csrf=False)
        self.assertEqual(status, 403)
        self.assertEqual(self.sup.calls, [])

    def test_post_requires_a_json_object_body(self):
        for raw in ("", "not json", "[1]", '"text"'):
            status, _, _ = self.post("/api/v1/connect", raw=raw)
            self.assertEqual(status, 400, raw)
        self.assertEqual(self.sup.calls, [])

    def test_oversized_body_is_refused_before_reading_it(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.putrequest("POST", "/api/v1/connect")
        for name, value in {**CSRF, "Content-Type": "application/json", "Content-Length": "20000"}.items():
            conn.putheader(name, value)
        conn.endheaders()  # no body follows: the server must answer from the header alone
        self.assertEqual(conn.getresponse().status, 413)
        conn.close()
        self.assertEqual(self.sup.calls, [])

    def test_unknown_post_and_get_routes_are_404(self):
        self.assertEqual(self.post("/api/v1/nope")[0], 404)
        self.assertEqual(self.get("/api/v1/nope")[0], 404)
        self.assertEqual(self.get("/nope")[0], 404)

    def test_unversioned_api_paths_are_gone(self):
        self.assertEqual(self.get("/api/state")[0], 404)
        self.assertEqual(self.post("/api/connect")[0], 404)
        self.assertEqual(self.sup.calls, [])

    def test_route_table_is_the_single_list_of_api_routes(self):
        keys = [(r.method, r.path) for r in webui.ROUTES]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertTrue(all(path.startswith("/api/v1/") for _, path in keys))
        self.assertEqual([r.path for r in webui.ROUTES if not r.auth], ["/api/v1/login"])
        handlers = {n for n in dir(webui.Handler) if n.startswith(("get_", "post_"))}
        self.assertEqual(handlers, {r.handler.__name__ for r in webui.ROUTES})  # no handler outside the table
        self.assertEqual({r.method for r in webui.ROUTES}, {"GET", "POST"})

    def test_successful_state_polls_are_not_logged_but_other_requests_are(self):
        self.get("/api/v1/state")  # the page polls this every 5 s: it would drown the container log
        self.get("/nope")
        self.post("/api/v1/connect")
        logged = self.out.getvalue()
        self.assertNotIn("GET /api/v1/state", logged)
        self.assertIn('[webui] 127.0.0.1 "GET /nope HTTP/1.1" 404', logged)
        self.assertIn('"POST /api/v1/connect HTTP/1.1" 200', logged)

    def test_state_is_not_cacheable(self):
        _, resp, _ = self.get("/api/v1/state")
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        self.assertEqual(resp.getheader("Content-Type"), "application/json")

    def test_handler_errors_return_500_without_a_body_leak(self):
        self.sup.snapshot = mock.Mock(side_effect=RuntimeError("secret detail"))
        status, resp, data = self.get("/api/v1/state")
        self.assertEqual(status, 500)
        self.assertNotIn(b"secret detail", data)


class StaticTest(WebuiCase):
    def test_page_and_assets_have_content_types(self):
        for path, ctype in (
            ("/", "text/html; charset=utf-8"),
            ("/static/app.js", "text/javascript; charset=utf-8"),
            ("/static/style.css", "text/css; charset=utf-8"),
            ("/static/logo.png", "image/png"),
            ("/static/favicon-32.png", "image/png"),
            ("/static/favicon-16.png", "image/png"),
        ):
            status, resp, data = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertEqual(resp.getheader("Content-Type"), ctype, path)
            self.assertTrue(data, path)

    def test_page_sets_a_restrictive_csp(self):
        _, resp, _ = self.get("/")
        csp = resp.getheader("Content-Security-Policy")
        self.assertIn("default-src 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")

    def test_static_traversal_404(self):
        for path in (
            "/static/../webui.py",
            "/static/%2e%2e/webui.py",
            "/static/..%2fwebui.py",
            "/static/./app.js",
            "/static//app.js",
            "/static/",
            "/static",
            "/static/.hidden",
            "/static/missing.css",
        ):
            self.assertEqual(self.get(path)[0], 404, path)

    def test_package_modules_are_not_served(self):
        self.assertEqual(self.get("/static/index.html")[0], 200)
        self.assertEqual(self.get("/webui.py")[0], 404)
        self.assertEqual(self.get("/static/__init__.py")[0], 404)

    def test_static_payload_is_small_and_loads_nothing_from_outside(self):
        static = Path(webui.__file__).parent / "static"
        code = [p for p in static.iterdir() if p.suffix in (".html", ".js", ".css")]
        self.assertLess(sum(p.stat().st_size for p in code), 60 * 1024)  # images excluded
        for path in code:
            text = path.read_text(encoding="utf-8")
            for needle in ("http://", "https://", "@import"):
                self.assertNotIn(needle, text, f"{path.name}: {needle}")


class SettingsTest(WebuiCase):
    def test_setting_goes_through_the_supervisor(self):
        status, body, _ = self.post("/api/v1/settings", {"env": "NETSHIELD", "value": "off"})
        self.assertEqual((status, body), (200, {"ok": True, "message": "saved"}))
        self.assertEqual(self.sup.calls, [("apply", "NETSHIELD", "off")])

    def test_rejected_value_is_422_with_the_cli_message(self):
        self.sup.apply_result = (False, "Error: invalid choice")
        status, body, _ = self.post("/api/v1/settings", {"env": "NETSHIELD", "value": "off"})
        self.assertEqual((status, body), (422, {"ok": False, "message": "Error: invalid choice"}))

    def test_locked_setting_409(self):
        self.environ["KILL_SWITCH"] = "off"
        status, body, _ = self.post("/api/v1/settings", {"env": "KILL_SWITCH", "value": "standard"})
        self.assertEqual(status, 409)
        self.assertFalse(body["ok"])
        self.assertIn("KILL_SWITCH", body["message"])
        self.assertEqual(self.sup.calls, [])

    def test_unsaveable_store_is_500(self):
        self.sup.apply_error = PermissionError("read-only file system")
        status, body, _ = self.post("/api/v1/settings", {"env": "NETSHIELD", "value": "off"})
        self.assertEqual((status, body["ok"]), (500, False))
        self.assertIn("read-only file system", body["message"])

    def test_invalid_values_are_400_and_never_reach_the_supervisor(self):
        bad = (
            {"env": "SERVER", "value": "-h"},  # would parse as a CLI option
            {"env": "SERVER", "value": "--help"},
            {"env": "COUNTRY", "value": "--random"},
            {"env": "CITY", "value": " -x"},
            {"env": "CITY", "value": "line\nbreak"},
            {"env": "NETSHIELD", "value": "bogus"},
            {"env": "KILL_SWITCH", "value": "on"},
            {"env": "P2P", "value": "maybe"},
            {"env": "NOPE", "value": "x"},
            {"env": "SERVER", "value": 5},
            {"env": "SERVER"},
            {"value": "x"},
            {"env": ["SERVER"], "value": "x"},
            {"env": "SERVER", "value": "x" * 300},
        )
        for body in bad:
            status, reply, _ = self.post("/api/v1/settings", body)
            self.assertEqual(status, 400, body)
            self.assertFalse(reply["ok"], body)
            self.assertTrue(reply["message"], body)
        self.assertEqual(self.sup.calls, [])

    def test_custom_dns_must_be_the_cli_syntax(self):
        bad = (
            "--help",
            "-h",
            "on --help",
            "off --help",
            "on --dns",
            "on --dns --help",
            "on --dns 1.1.1.1 --help",
            "off --dns 1.1.1.1",
            "on 1.1.1.1",
            "1.1.1.1",
            "on --dns notanip",
            "on --dns 1.1.1.1,",
            "on --dns 1.1.1.1, 8.8.8.8",
            "on --dns=1.1.1.1",
            "ON",
        )
        for value in bad:
            status, reply, _ = self.post("/api/v1/settings", {"env": "CUSTOM_DNS", "value": value})
            self.assertEqual(status, 400, value)
            self.assertIn("--dns", reply["message"], value)
        self.assertEqual(self.sup.calls, [])

    def test_custom_dns_accepts_off_on_and_a_server_list(self):
        for value in ("", "off", "on", "on --dns 1.1.1.1", "on --dns 1.1.1.1,8.8.8.8", "on  --dns  2606:4700:4700::1111"):
            self.assertEqual(self.post("/api/v1/settings", {"env": "CUSTOM_DNS", "value": value})[0], 200, value)

    def test_valid_values_pass(self):
        for env, value in (
            ("SERVER", "NL#914"),
            ("COUNTRY", "United States"),
            ("CITY", ""),  # clears the saved value
            ("P2P", "true"),
            ("TOR", "false"),
            ("NETSHIELD", "malware-ads-trackers"),
            ("IPV6", ""),
            ("CUSTOM_DNS", "on --dns 1.1.1.1,8.8.8.8"),
        ):
            self.assertEqual(self.post("/api/v1/settings", {"env": env, "value": value})[0], 200, (env, value))


class SigninRouteTest(WebuiCase):
    def test_signin_done_notifies_supervisor(self):
        status, body, _ = self.post("/api/v1/signin", {"username": "me@proton.me", "password": "pw"})
        self.assertEqual((status, body), (200, {"state": "done", "message": "Signed in"}))
        self.assertEqual(self.signin.calls, [("start", "me@proton.me", "pw")])
        self.assertEqual(self.sup.calls, [("notify_signed_in",)])

    def test_signin_with_2fa_notifies_only_when_the_code_is_accepted(self):
        self.signin.start_step = Step("need_code", "")
        _, body, _ = self.post("/api/v1/signin", {"username": "me@proton.me", "password": "pw"})
        self.assertEqual(body["state"], "need_code")
        self.assertEqual(self.sup.calls, [])
        status, body, _ = self.post("/api/v1/signin/code", {"code": "123456"})
        self.assertEqual((status, body["state"]), (200, "done"))
        self.assertEqual(self.signin.calls[-1], ("code", "123456"))
        self.assertEqual(self.sup.calls, [("notify_signed_in",)])

    def test_signin_error_does_not_notify(self):
        self.signin.start_step = Step("error", "Invalid credentials")
        status, body, _ = self.post("/api/v1/signin", {"username": "me@proton.me", "password": "pw"})
        self.assertEqual((status, body), (200, {"state": "error", "message": "Invalid credentials"}))
        self.assertEqual(self.sup.calls, [])

    def test_signin_needs_string_fields(self):
        for body in ({}, {"username": "me"}, {"username": 1, "password": "pw"}, {"username": "me", "password": None}):
            self.assertEqual(self.post("/api/v1/signin", body)[0], 400, body)
        self.assertEqual(self.post("/api/v1/signin/code", {"code": 123456})[0], 400)
        self.assertEqual(self.signin.calls, [])

    def test_signin_secrets_are_not_logged(self):
        self.post("/api/v1/signin", {"username": "me@proton.me", "password": "pw-never-logged"})
        self.post("/api/v1/signin/code", {"code": "987654"})
        logged = self.out.getvalue()
        self.assertNotIn("pw-never-logged", logged)
        self.assertNotIn("987654", logged)

    def test_signout_goes_through_the_supervisor(self):
        self.sup.signout_result = (True, "You have been successfully signed out.")
        status, body, _ = self.post("/api/v1/signout")
        self.assertEqual((status, body), (200, {"ok": True, "message": "You have been successfully signed out."}))
        self.assertEqual(self.sup.calls, [("sign_out",)])

    def test_failed_signout_reports_the_cli_message(self):
        self.sup.signout_result = (False, "Error: not signed in")
        status, body, _ = self.post("/api/v1/signout")
        self.assertEqual((status, body), (500, {"ok": False, "message": "Error: not signed in"}))


class LoneSurrogateTest(WebuiCase):
    PASSWORD = "hunter2"

    def test_every_post_route_refuses_a_lone_surrogate_anywhere_in_the_body(self):
        cookie = self.login()
        bodies = (
            '{"password": "a\\ud800"}',
            '{"value": ["x", {"k": "\\udc00"}]}',
            '{"\\ud800": 1}',
        )
        for route in (r for r in webui.ROUTES if r.method == "POST"):
            for raw in bodies:
                status, reply, _ = self.post(route.path, cookie=cookie, raw=raw)
                self.assertEqual(status, 400, (route.path, raw))
                self.assertFalse(reply["ok"])
        self.assertEqual((self.sup.calls, self.signin.calls), ([], []))

    def test_a_surrogate_pair_is_one_valid_character(self):
        cookie = self.login()
        body = {"username": "me@proton.me", "password": "pw\U0001f600"}  # json.dumps escapes it as a pair
        self.assertEqual(self.post("/api/v1/signin", body, cookie=cookie)[0], 200)
        self.assertEqual(self.signin.calls, [("start", "me@proton.me", "pw\U0001f600")])

    def test_a_poisonous_setting_is_not_saved(self):
        cookie = self.login()
        status, _, _ = self.post("/api/v1/settings", raw='{"env": "SERVER", "value": "\\ud800x"}', cookie=cookie)
        self.assertEqual(status, 400)
        self.assertEqual(self.sup.calls, [])


class RealSigninFlowTest(WebuiCase):
    """The real SigninFlow behind the real server, with the fake CLI on the pty."""

    def make_signin(self):
        patcher = mock.patch.dict(os.environ, {"FAKE_SIGNIN": "2fa"})
        patcher.start()
        self.addCleanup(patcher.stop)
        flow = SigninFlow(argv_prefix=(FAKE_CLI,), timeout=3)
        self.addCleanup(lambda: flow._run and flow._run.close())
        return flow

    def test_lone_surrogate_password_is_400_and_a_later_signin_still_works(self):
        raw = '{"username": "me@proton.me", "password": "a\\ud800"}'
        self.assertEqual(self.post("/api/v1/signin", raw=raw)[0], 400)
        status, body, _ = self.post("/api/v1/signin", {"username": "me@proton.me", "password": "pw"})
        self.assertEqual((status, body["state"]), (200, "need_code"))  # not "sign-in already in progress"
        status, body, _ = self.post("/api/v1/signin/code", {"code": "123456"})
        self.assertEqual((status, body["state"]), (200, "done"))
        self.assertEqual(self.sup.calls, [("notify_signed_in",)])


class LogHygieneTest(WebuiCase):
    def test_control_characters_in_the_request_line_are_escaped_in_the_log(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as conn:
            conn.sendall(b"GET /\x1b[2K\x1b[1G[webui]fake\x9b\x07 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            while conn.recv(4096):
                pass
        logged = self.out.getvalue()
        for char in ("\x1b", "\x9b", "\x07"):
            self.assertNotIn(char, logged)
        self.assertIn(r'"GET /\x1b[2K\x1b[1G[webui]fake\x9b\x07 HTTP/1.1" 404', logged)
        self.assertTrue(all(line.startswith("[webui] ") for line in logged.splitlines()))


if __name__ == "__main__":
    unittest.main()
