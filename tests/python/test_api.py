"""HTTP contracts: authorization, focused reads, errors, and the shipped document."""
import json
import unittest
from unittest import mock

from protonvpn_container import __main__ as main, webui
from protonvpn_container.cli import Result
from protonvpn_container.supervisor import Supervisor
from tests.python.test_supervisor import TCP, UDP, Clock, FakeCli, FakeTimers, FakeTool, mapped
from tests.python.test_webui import CSRF, WebuiCase

try:
    from jsonschema import Draft202012Validator
except ImportError:  # the image has no jsonschema; CI runs the contract check where it is installed
    Draft202012Validator = None


class ApiTest(WebuiCase):
    PASSWORD = "hunter2"
    API_KEY = "test-only-random-looking-key-" + "x" * 40

    def api(self, method, path, body=None, token=None, headers=None):
        headers = {"Authorization": "Bearer " + (self.API_KEY if token is None else token), **(headers or {})}
        payload = json.dumps(body) if body is not None else None
        if payload is not None:
            headers["Content-Type"] = "application/json"
        resp, raw = self.request(method, path, payload, headers)
        return resp, json.loads(raw) if resp.getheader("Content-Type") == "application/json" else raw

    def test_key_and_cookie_are_independent_alternatives(self):
        self.assertEqual(self.api("GET", "/api/v1/status")[0].status, 200)
        for token in ("wrong", self.PASSWORD, "", "é" , self.API_KEY + "x"):
            self.assertEqual(self.api("GET", "/api/v1/status", token=token)[0].status, 401)
        self.assertEqual(self.get_json("/api/v1/status")[0], 401)
        self.assertEqual(self.get_json("/api/v1/status", self.login())[0], 200)

    def test_only_valid_bearer_bypasses_write_header(self):
        self.assertEqual(self.api("POST", "/api/v1/connect", {})[0].status, 200)
        self.assertEqual(self.sup.calls, [("connect",)])
        cookie = self.login()
        self.assertEqual(self.post("/api/v1/connect", cookie=cookie, csrf=False)[0], 403)
        self.assertEqual(self.api("POST", "/api/v1/connect", {}, token="wrong")[0].status, 403)
        self.assertEqual(self.api("POST", "/api/v1/connect", {}, token="wrong", headers=CSRF)[0].status, 401)

    def test_missing_key_disables_bearer_not_cookie_or_open_mode(self):
        self.server.ui.api_key = ""
        self.assertEqual(self.api("GET", "/api/v1/status")[0].status, 401)
        self.assertEqual(self.get_json("/api/v1/status", self.login())[0], 200)
        self.server.ui.password = ""
        self.assertEqual(self.api("GET", "/api/v1/status")[0].status, 200)
        self.assertEqual(self.api("POST", "/api/v1/connect", {})[0].status, 403)
        self.assertEqual(self.api("POST", "/api/v1/connect", {}, headers=CSRF)[0].status, 200)
        self.server.ui.api_key = self.API_KEY
        self.assertEqual(self.api("POST", "/api/v1/connect", {}, token="wrong")[0].status, 403)
        self.assertEqual(self.api("POST", "/api/v1/connect", {})[0].status, 200)

    def test_malformed_authorization_never_grants_bypass(self):
        for authorization in (self.API_KEY, "Basic " + self.API_KEY, "Bearer  " + self.API_KEY):
            resp, raw = self.request("GET", "/api/v1/status", headers={"Authorization": authorization})
            self.assertEqual((resp.status, json.loads(raw)), (401, {"error": "login required"}))
            self.server.ui.password = ""
            resp, _ = self.request("POST", "/api/v1/connect", "{}", {"Authorization": authorization})
            self.assertEqual(resp.status, 403)
            self.server.ui.password = self.PASSWORD

    def test_reads_expose_contract_not_secrets(self):
        snapshot = self.sup.snapshot()
        snapshot.update(forwarded_port=41404, traffic=[[100, 10, 20], [105, 30, 50]])
        self.sup.snapshot = lambda: snapshot.copy()
        _, status = self.api("GET", "/api/v1/status")
        self.assertEqual(status, {key: snapshot[key] for key in (
            "signed_in", "account", "connected", "server", "location", "load", "protocol", "exit_ip", "forwarded_port",
            "last_error", "tunnel_healthy", "health_error", "health_checked_ago")})
        self.assertEqual(self.api("GET", "/api/v1/port")[1], {"port": 41404})
        resp, raw = self.api("GET", "/api/v1/port?format=text")
        self.assertEqual((raw, resp.getheader("Content-Type")), (b"41404", "text/plain"))
        self.assertEqual(self.api("GET", "/api/v1/traffic")[1], {
            "rx_bytes": 30, "tx_bytes": 50, "samples": [[-5, 10, 20], [0, 30, 50]]})
        self.environ["NETSHIELD"] = "off"
        settings = self.api("GET", "/api/v1/settings")[1]["settings"]
        self.assertEqual(next(s for s in settings if s["env"] == "NETSHIELD"), {
            "env": "NETSHIELD", "value": "off", "locked": True, "source": "env", "kind": "choice",
            "choices": ["off", "malware-only", "malware-ads-trackers"]})
        for path in ("state", "status", "settings", "openapi.json"):
            _, data = self.api("GET", "/api/v1/" + path)
            self.assertNotIn(self.API_KEY, json.dumps(data))
            self.assertNotIn(self.PASSWORD, json.dumps(data))
        self.assertNotIn(self.API_KEY, self.out.getvalue())

    def test_no_port_or_traffic_has_stable_empty_values(self):
        self.assertEqual(self.api("GET", "/api/v1/port")[1], {"port": None})
        self.assertEqual(self.api("GET", "/api/v1/port?format=text")[1], b"")
        self.assertEqual(self.api("GET", "/api/v1/traffic")[1], {"rx_bytes": 0, "tx_bytes": 0, "samples": []})

    def test_error_shape_at_http_boundary(self):
        self.environ["NETSHIELD"] = "off"
        cases = [
            ("GET", "/api/v1/status", None, "wrong", 401),
            ("GET", "/api/v1/missing", None, None, 404),
            ("POST", "/api/v1/settings", {}, None, 400),
            ("POST", "/api/v1/settings", {"env": "NETSHIELD", "value": "malware-only"}, None, 409),
        ]
        for method, path, payload, token, expected in cases:
            resp, data = self.api(method, path, payload, token=token)
            self.assertEqual(resp.status, expected)
            self.assertEqual(set(data), {"error"})
            self.assertIsInstance(data["error"], str)
            self.assertTrue(data["error"])

    def test_remaining_http_errors_use_only_error(self):
        self.sup.apply_result = (False, "rejected")
        self.sup.signout_result = (False, "signout failed")
        for path, body, expected in (
            ("/api/v1/settings", {"env": "NETSHIELD", "value": "off"}, 422),
            ("/api/v1/signout", {}, 500),
            ("/api/v1/connect", {"padding": "x" * 8192}, 413),
        ):
            resp, data = self.api("POST", path, body)
            self.assertEqual(resp.status, expected)
            self.assertEqual(set(data), {"error"})
        for _ in range(6):
            status, data, _ = self.post("/api/v1/login", {"password": "wrong"})
        self.assertEqual(status, 429)
        self.assertEqual(set(data), {"error"})
        resp, data = self.api("POST", "/api/v1/connect", {}, token="wrong")
        self.assertEqual(resp.status, 403)
        self.assertEqual(set(data), {"error"})

    def test_silent_cli_failures_return_nonempty_http_errors(self):
        for output in ("", " \n"):
            with self.subTest(output=output):
                clock = Clock()
                cli = FakeCli(clock)
                supervisor = Supervisor(
                    self.store, run=cli, tool=FakeTool(), clock=clock,
                    port_file=self.settings_path + ".port",
                    health_file=self.settings_path + ".health",
                    native_settings=self.settings_path + ".native",
                )
                supervisor.tick()
                self.server.ui.supervisor = supervisor
                cli.responses[("signout",)] = Result(7, output)
                cli.responses[("config", "set", "netshield", "off")] = Result(9, output)
                resp, data = self.api("POST", "/api/v1/signout", {})
                self.assertEqual(resp.status, 500)
                self.assertEqual(data, {"error": "signout failed (exit code 7)"})
                self.assertTrue(supervisor.snapshot()["signed_in"])
                resp, data = self.api("POST", "/api/v1/settings", {"env": "NETSHIELD", "value": "off"})
                self.assertEqual(resp.status, 422)
                self.assertEqual(data, {"error": "config set netshield failed (exit code 9)"})
                self.assertEqual(self.store.effective("NETSHIELD"), "")
                cli.responses[("connect", "--country", "XX")] = Result(7, output)  # a target change that reconnects silently
                resp, data = self.api("POST", "/api/v1/settings", {"env": "COUNTRY", "value": "XX"})
                self.assertEqual(resp.status, 422)
                self.assertEqual(data, {"error": "connect failed (exit code 7)"})
                self.assertEqual(self.store.effective("COUNTRY"), "")

    def test_documented_login_error_matches_http_response(self):
        _, document = self.get_json("/api/v1/openapi.json")
        status, data, _ = self.post("/api/v1/login", {"password": "wrong"})
        self.assertEqual(status, 401)
        example = document["paths"]["/login"]["post"]["responses"]["401"]["content"]["application/json"]["example"]
        self.assertEqual(data, example)

    def test_public_docs_and_document(self):
        for path in ("/api", "/api/v1/openapi.json", "/static/api.js"):
            self.assertEqual(self.get(path)[0], 200)
        _, document = self.get_json("/api/v1/openapi.json")
        self.assertEqual(document["openapi"], "3.1.0")
        self.assertEqual(document["jsonSchemaDialect"], "https://json-schema.org/draft/2020-12/schema")
        schemes = document["components"]["securitySchemes"]
        self.assertEqual(schemes["bearerAuth"], {"type": "http", "scheme": "bearer"})
        self.assertEqual(schemes["cookieAuth"], {"type": "apiKey", "in": "cookie", "name": "session"})

    @unittest.skipIf(Draft202012Validator is None, "needs jsonschema: runs in CI, outside the image")
    def test_documented_operations_return_their_actual_contract(self):
        _, document = self.get_json("/api/v1/openapi.json")
        operation_ids = set()
        for path, methods in document["paths"].items():
            for method, operation in methods.items():
                with self.subTest(method=method, path=path):
                    self.assertTrue(operation["summary"])
                    self.assertNotIn(operation["operationId"], operation_ids)
                    operation_ids.add(operation["operationId"])
                    request = operation.get("requestBody", {}).get("content", {}).get("application/json", {})
                    body = {"password": self.PASSWORD} if path == "/login" else request.get("example")
                    resp, data = self.api(method.upper(), "/api/v1" + path, body)
                    self.assertEqual(resp.status, 200, data)
                    content = operation["responses"]["200"]["content"]["application/json"]
                    # The components travel with the schema so that its #/components/... references resolve.
                    schema = {**content["schema"], "components": document["components"]}
                    self.assertEqual(list(Draft202012Validator(schema).iter_errors(data)), [])
        self.assertEqual(len(operation_ids), 15)

    def live_supervisor(self):
        """A real supervisor behind the server, with a connection and a forwarded port."""
        self.environ["PORT_FORWARDING"] = "on"
        self.clock = Clock()
        self.cli, tool = FakeCli(self.clock), FakeTool()
        tool.responses[UDP] = tool.responses[TCP] = mapped(41404)
        self.port_file = self.settings_path + ".port"
        supervisor = Supervisor(
            self.store, run=self.cli, tool=tool, clock=self.clock, port_file=self.port_file, timer=FakeTimers(),
            health_file=self.settings_path + ".health",
            native_settings=self.settings_path + ".native",
        )
        self.server.ui.supervisor = supervisor
        supervisor.tick()
        return supervisor

    def consumer_view(self):
        _, status = self.api("GET", "/api/v1/status")
        _, port = self.api("GET", "/api/v1/port")
        with open(self.port_file) as f:
            return status["signed_in"], status["connected"], status["forwarded_port"], port["port"], f.read()

    def test_signout_leaves_no_connection_or_port_for_consumers(self):
        supervisor = self.live_supervisor()
        self.assertEqual(self.consumer_view(), (True, True, 41404, 41404, "41404\n"))
        self.assertEqual(self.api("POST", "/api/v1/signout", {})[0].status, 200)
        self.assertEqual(self.consumer_view(), (False, False, None, None, ""))
        self.cli.responses[("info",)] = Result(124, "protonvpn timed out after 120s\n")  # the next check fails
        self.clock.now += 1
        supervisor.tick()
        self.assertEqual(self.consumer_view(), (False, False, None, None, ""))

    def test_failed_state_check_is_not_hidden_behind_the_last_good_state(self):
        supervisor = self.live_supervisor()
        self.cli.responses[("info",)] = Result(124, "protonvpn timed out after 120s\n")
        self.clock.now += 30
        supervisor.tick()
        self.assertEqual(self.consumer_view(), (True, False, None, None, ""))  # one error is not a signout
        self.assertEqual(self.api("GET", "/api/v1/port?format=text")[1], b"")
        self.assertIn("state check failed (rc 124)", self.api("GET", "/api/v1/status")[1]["last_error"])

    def test_status_carries_the_traffic_check_fields(self):
        self.sup.overrides = {
            "connected": True, "tunnel_healthy": False,
            "health_error": "IPv4 HTTPS probe timed out", "health_checked_ago": 12.5,
        }
        _, status = self.api("GET", "/api/v1/status")
        self.assertEqual(
            {field: status[field] for field in ("connected", "tunnel_healthy", "health_error", "health_checked_ago")},
            self.sup.overrides,
        )

    @unittest.skipIf(Draft202012Validator is None, "needs jsonschema: runs in CI, outside the image")
    def test_traffic_check_states_match_the_status_schema(self):
        _, document = self.get_json("/api/v1/openapi.json")
        schema = {**document["components"]["schemas"]["Status"], "components": document["components"]}
        states = (
            {"connected": False, "tunnel_healthy": False, "health_error": "", "health_checked_ago": None},
            {"connected": True, "tunnel_healthy": None, "health_error": "", "health_checked_ago": None},
            {"connected": True, "tunnel_healthy": True, "health_error": "", "health_checked_ago": 4.5},
            {
                "connected": True,
                "tunnel_healthy": False,
                "health_error": "IPv4 HTTPS probe timed out",
                "health_checked_ago": 75.0,
            },
        )
        for overrides in states:
            with self.subTest(**overrides):
                self.sup.overrides = overrides
                _, status = self.api("GET", "/api/v1/status")
                self.assertEqual(list(Draft202012Validator(schema).iter_errors(status)), [])

    @unittest.skipIf(Draft202012Validator is None, "needs jsonschema: runs in CI, outside the image")
    def test_documented_status_examples_match_the_status_schema(self):
        _, document = self.get_json("/api/v1/openapi.json")
        schema = {**document["components"]["schemas"]["Status"], "components": document["components"]}
        examples = document["paths"]["/status"]["get"]["responses"]["200"]["content"]["application/json"]["examples"]
        for name, example in examples.items():
            with self.subTest(example=name):
                self.assertEqual(list(Draft202012Validator(schema).iter_errors(example["value"])), [])

    def test_short_key_warning_only_at_start(self):
        for key, count in (("k" * 16, 1), ("k" * 64, 0), ("", 0)):
            with self.subTest(length=len(key)):
                self.out.truncate(0)
                self.out.seek(0)
                with mock.patch.object(main, "webui_port", return_value=0):
                    server = main.start_webui(self.sup, self.store, {"WEBUI_PASSWORD": "pw", "API_KEY": key})
                try:
                    self.assertEqual(server.ui.api_key, key)
                    self.assertEqual(self.out.getvalue().count("API_KEY is shorter than 32 characters"), count)
                    if key:
                        self.assertNotIn(key, self.out.getvalue())
                finally:
                    server.shutdown()
                    server.server_close()
