import http.server
import os
import tempfile
import threading
import unittest

from protonvpn_container import health
from protonvpn_container.cli import Result, run_tool
from protonvpn_container.health import ProbeError, is_healthy, probe, write_health



def answering(rc, out):

    def tool(*argv, timeout):
        return Result(rc, out)

    return tool


class ProbeTest(unittest.TestCase):
    def test_a_public_ipv4_literal_is_the_answer(self):
        tool = answering(0, "205.147.16.74\n")
        self.assertEqual(probe(tool), "205.147.16.74")

    def test_anything_but_a_public_ipv4_literal_is_rejected_without_echoing_it(self):
        for body in (
            "", "<html>502</html>", "node-nl-307.protonvpn.net", "205.147.16.74/24", '{"IP":"205.147.16.74"}',
            "2a02:6ea0:c041:6653::23", "205.147.16.74%eth0", "205.147.16.74\n205.147.16.75", "01.2.3.4",
            "0.0.0.0", "127.0.0.1", "10.2.0.2", "100.64.0.1", "169.254.1.1", "192.168.1.1", "224.0.0.1", "255.255.255.255",
        ):
            with self.subTest(body=body), self.assertRaises(ProbeError) as raised:
                probe(answering(0, body))
            self.assertIn("public IPv4", str(raised.exception))
            self.assertNotIn(body.strip() or "\0", str(raised.exception))

    def test_a_curl_failure_is_reported_in_its_own_words(self):
        for rc, out, reason in (
            (45, "curl: (45) Couldn't bind to interface 'proton0' with errno 19: No such device\n",
             "curl: (45) Couldn't bind to interface 'proton0' with errno 19: No such device"),
            (28, "curl: (28) Connection timed out after 5001 milliseconds\n", "curl: (28) Connection timed out after 5001 milliseconds"),
            (22, "curl: (22) The requested URL returned error: 503\n", "curl: (22) The requested URL returned error: 503"),
            (124, "curl timed out after 6s\n", "curl timed out after 6s"),
            (127, "cannot run curl: [Errno 2] No such file or directory: 'curl'\n", "cannot run curl: [Errno 2] No such file or directory: 'curl'"),
            (7, "", "curl exited with code 7"),
        ):
            with self.subTest(rc=rc), self.assertRaises(ProbeError) as raised:
                probe(answering(rc, out))
            self.assertEqual(str(raised.exception), reason)

    def test_a_long_failure_is_cut_to_a_short_reason(self):
        with self.assertRaises(ProbeError) as raised:
            probe(answering(1, "curl: (1) " + "x" * 5000))
        self.assertLessEqual(len(str(raised.exception)), health.REASON_MAX)


class Echo(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"205.147.16.74\n")

    def log_message(self, *args):
        pass


class RealCurlTest(unittest.TestCase):
    """The real transport, on a machine with no proton0: it must fail although the echo is reachable by the host's route."""

    def setUp(self):
        if os.path.exists(f"/sys/class/net/{health.TUNNEL}"):
            self.skipTest(f"{health.TUNNEL} exists here: this checks the no-tunnel case")
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.url = f"http://127.0.0.1:{server.server_port}/"

    def test_the_echo_is_reachable_by_the_host_route_yet_the_probe_without_proton0_fails(self):
        reached = run_tool("curl", "--noproxy", "*", "--max-time", "5", "--fail", "--silent", "--show-error", self.url)
        self.assertEqual((reached.rc, reached.out), (0, "205.147.16.74\n"), "curl must be in the image, and the echo reachable")
        with self.assertRaises(ProbeError) as raised:
            probe(run_tool, self.url)
        self.assertIn(health.TUNNEL, str(raised.exception))  # curl's own refusal to bind, not a missing binary or a timeout


class HealthFileTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = os.path.join(tmp.name, "health.json")

    def put(self, text):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(text)

    def test_a_fresh_pass_is_healthy_for_60_seconds_and_no_longer(self):
        write_health(self.path, True, 100.0)
        for now, expected in ((100.0, True), (160.0, True), (160.5, False), (1e6, False)):
            self.assertIs(is_healthy(self.path, lambda: now), expected, now)

    def test_a_failing_verdict_is_never_healthy(self):
        write_health(self.path, False, 100.0)
        self.assertFalse(is_healthy(self.path, lambda: 100.0))

    def test_a_stamp_from_the_future_is_not_fresh(self):  # a file left by an earlier boot, whose monotonic clock ran higher
        write_health(self.path, True, 5000.0)
        self.assertFalse(is_healthy(self.path, lambda: 40.0))

    def test_a_missing_or_doubtful_file_is_unhealthy(self):
        self.assertFalse(is_healthy(self.path, lambda: 100.0))
        for text in (
            "", "not json", "[]", "null", '"healthy"', "{}", '{"healthy": true}', '{"checked_at": 100}',
            '{"healthy": "true", "checked_at": 100}', '{"healthy": 1, "checked_at": 100}',
            '{"healthy": true, "checked_at": "100"}', '{"healthy": true, "checked_at": true}',
            '{"healthy": true, "checked_at": null}', '{"healthy": true, "checked_at": NaN}',
            '{"healthy": true, "checked_at": Infinity}', '{"healthy": true, "checked_at": -Infinity}',
        ):
            with self.subTest(text=text):
                self.put(text)
                self.assertFalse(is_healthy(self.path, lambda: 100.0))
        with open(self.path, "wb") as f:
            f.write(b"\xff\xfe")
        self.assertFalse(is_healthy(self.path, lambda: 100.0))



if __name__ == "__main__":
    unittest.main()
