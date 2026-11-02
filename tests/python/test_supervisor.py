import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout

from protonvpn_container.cli import Result
from protonvpn_container.config import SettingsStore
from protonvpn_container.supervisor import HINT, Supervisor, decide

STATUS_UP = "Status: Connected\nServer: NL#914 in Amsterdam, Netherlands\nLoad: 31%\nProtocol: wireguard\n"
CONNECT_OUT = "Connected to NL#914 in Amsterdam, Netherlands. \nYour new IP address is 205.147.16.78.\n"
UDP = ("natpmpc", "-a", "1", "0", "udp", "60", "-g", "10.2.0.1")
TCP = ("natpmpc", "-a", "1", "0", "tcp", "60", "-g", "10.2.0.1")
WG = ("wg", "show", "proton0", "transfer")


def mapped(port):
    return Result(0, f"Mapped public port {port} protocol UDP to local port 0 lifetime 60\n")


NATPMP_FAILED = Result(1, "readnatpmpresponseorretry() failed : the gateway does not support nat-pmp\n")


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class FakeCli:
    """Stateful `protonvpn`; `responses[argv]` (a Result, or a list consumed in order) overrides the reply."""

    def __init__(self, clock):
        self.clock = clock
        self.calls = []
        self.timeouts = []
        self.responses = {}
        self.signed_in = True
        self.connected = False
        self.connect_rc = 0
        self.connect_duration = 0

    def __call__(self, *args, timeout=120):
        self.calls.append((self.clock.now, args))
        self.timeouts.append((args, timeout))
        reply = self.responses.get(args)
        if isinstance(reply, list):
            reply = reply.pop(0) if len(reply) > 1 else reply[0]
        if reply is not None:
            return reply
        if args == ("info",):
            return Result(0, f"Account: '{'me@proton.me' if self.signed_in else 'None'}'\n")
        if args == ("status",):
            return Result(0, STATUS_UP if self.connected else "Status: Disconnected\n")
        if args[:3] == ("config", "set", "kill-switch") and self.connected:
            return Result(2, "Error: Disconnect before changing Kill Switch. Run 'protonvpn disconnect' first.\n")
        if args[0] == "connect":
            self.clock.now += self.connect_duration
            if self.connect_rc:
                return Result(self.connect_rc, "Error: Connection failed.\n")
            self.connected = True
            return Result(0, CONNECT_OUT)
        if args == ("disconnect",):
            self.connected = False
            return Result(0, "Disconnected.\n")
        return Result(0, "")

    def times(self, verb):
        return [t for t, args in self.calls if args[0] == verb]

    def argvs(self, verb):
        return [args for _, args in self.calls if args[0] == verb]


class FakeTool:
    """`natpmpc`/`wg`: responses[argv] is a Result, a list consumed in order (last repeats) or fn(n)."""

    def __init__(self):
        self.responses = {}
        self.calls = []

    def __call__(self, *argv, timeout=10):
        n = sum(1 for a in self.calls if a == argv)
        self.calls.append(argv)
        reply = self.responses.get(argv, Result(1, "not scripted\n"))
        if callable(reply):
            return reply(n)
        if isinstance(reply, list):
            return reply[min(n, len(reply) - 1)]
        return reply


class SupervisorCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.port_file = os.path.join(self.dir, "forwarded_port")
        self.clock = Clock()
        self.cli = FakeCli(self.clock)
        self.tool = FakeTool()
        self.exits = []
        self.out = io.StringIO()

    def make(self, environ=None, file=None):
        path = os.path.join(self.dir, "settings.json")
        if file is not None:
            with open(path, "w") as f:
                json.dump(file, f)
        self.store = SettingsStore(path, environ or {})
        self.sup = Supervisor(
            self.store,
            run=self.cli,
            tool=self.tool,
            clock=self.clock,
            interval=30,
            port_file=self.port_file,
            exit_fn=self.exits.append,
        )
        return self.sup

    def tick(self, advance=0):
        self.clock.now += advance
        with redirect_stdout(self.out):
            self.sup.tick()

    def next_connect(self, limit=400):
        """Tick once a second until the next `connect` call; returns its clock time."""
        seen = len(self.cli.times("connect"))
        for _ in range(limit):
            self.tick(1)
            if len(self.cli.times("connect")) > seen:
                return self.cli.times("connect")[-1]
        self.fail("no connect attempt")

    def apply(self, env, value):
        with redirect_stdout(self.out):
            return self.sup.apply_setting(env, value)

    def read_port_file(self):
        with open(self.port_file) as f:
            return f.read()


class DecideTest(unittest.TestCase):
    def test_decide_table(self):
        self.assertEqual(decide(False, True, False), "wait_signin")  # session revoked, connection lingers
        self.assertEqual(decide(False, False, False), "wait_signin")
        self.assertEqual(decide(True, True, False), "connected")
        self.assertEqual(decide(True, False, True), "idle")
        self.assertEqual(decide(True, False, False), "connect")


class SigninTest(SupervisorCase):
    def test_hint_logged_at_most_every_60s(self):
        self.cli.signed_in = False
        self.make()
        self.tick()
        self.tick(30)
        self.assertEqual(self.out.getvalue().count(HINT), 1)
        self.tick(30)
        self.assertEqual(self.out.getvalue().count(HINT), 2)
        self.assertFalse(self.sup.snapshot()["signed_in"])
        self.assertEqual(self.cli.argvs("connect"), [])
        self.assertEqual(
            HINT,
            "Not signed in. Sign in from the WebUI or run: docker exec -it <name> protonvpn signin <username>",
        )

    def test_signed_in_connects_and_reports(self):
        self.make()
        self.tick()
        snap = self.sup.snapshot()
        self.assertEqual(
            (snap["signed_in"], snap["account"], snap["connected"], snap["server"]),
            (True, "me@proton.me", True, "NL#914"),
        )
        self.assertEqual(
            (snap["location"], snap["load"], snap["protocol"], snap["exit_ip"]),
            ("Amsterdam, Netherlands", "31%", "wireguard", "205.147.16.78"),
        )
        self.assertEqual(snap["last_error"], "")

    def test_cli_failure_skips_cycle(self):
        self.make()
        self.cli.responses[("status",)] = Result(124, "protonvpn timed out after 120s\n")
        self.tick()
        self.assertEqual(self.cli.argvs("connect"), [])
        self.assertIn("timed out", self.out.getvalue())


class ConnectTest(SupervisorCase):
    def test_backoff_sequence(self):
        self.make()
        self.cli.connect_rc = 1
        times = [self.next_connect()]
        for _ in range(3):  # four failing connects
            times.append(self.next_connect())
        self.assertEqual(self.sup.snapshot()["last_error"], "Error: Connection failed.")
        self.cli.connect_rc = 0
        times.append(self.next_connect())  # the fifth attempt succeeds
        self.assertEqual([b - a for a, b in zip(times, times[1:])], [30, 60, 120, 300])
        self.assertTrue(self.sup.snapshot()["connected"])
        self.assertEqual(self.sup.snapshot()["last_error"], "")
        # After a success the sequence starts over at 30 s.
        self.cli.connected = False
        self.cli.connect_rc = 1
        failed = self.next_connect()
        self.assertEqual(self.next_connect() - failed, 30)

    def test_backoff_counts_from_end_of_attempt(self):
        self.make()
        self.cli.connect_rc = 1
        self.cli.connect_duration = 40
        starts = [self.next_connect() for _ in range(4)]
        self.assertEqual([b - a for a, b in zip(starts, starts[1:])], [70, 100, 160])  # 40 s + 30, 60, 120

    def test_target_change_while_backing_off_connects_at_once(self):
        self.make()
        self.cli.connect_rc = 1
        self.next_connect()
        self.next_connect()  # now waiting out 60 s
        self.assertEqual(self.apply("COUNTRY", "NL"), (True, "saved; connecting"))
        self.cli.connect_rc = 0
        self.tick(1)
        self.assertEqual(self.cli.argvs("connect")[-1], ("connect", "--country", "NL"))
        self.assertTrue(self.sup.snapshot()["connected"])
        self.assertEqual(len(self.cli.argvs("disconnect")), 0)

    def test_bool_target_change_in_spelling_only_is_unchanged(self):
        self.make()
        self.tick()
        self.assertEqual(self.apply("P2P", "false"), (True, "unchanged"))
        self.assertEqual(self.apply("P2P", "true"), (True, "reconnected"))
        self.assertEqual(self.apply("P2P", "on"), (True, "unchanged"))
        self.assertEqual(len(self.cli.argvs("connect")), 2)

    def test_connect_rc0_but_not_connected_counts_as_failure(self):
        self.make()
        self.cli.responses[("connect",)] = Result(0, "free plan limitation\n")
        first = self.next_connect()
        self.assertEqual(self.next_connect() - first, 30)
        self.assertEqual(self.next_connect() - first, 90)

    def test_connect_uses_target_args(self):
        self.make(environ={"COUNTRY": "NL", "P2P": "true"})
        self.tick()
        self.assertEqual(self.cli.argvs("connect"), [("connect", "--country", "NL", "--p2p")])

    def test_user_disconnect_suspends_reconnect(self):
        self.make()
        self.tick()
        self.assertTrue(self.cli.connected)
        self.sup.request_disconnect()
        self.tick(1)
        self.assertEqual(self.cli.argvs("disconnect"), [("disconnect",)])
        self.assertFalse(self.sup.snapshot()["connected"])
        for _ in range(5):
            self.tick(30)
        self.assertEqual(len(self.cli.argvs("connect")), 1)
        self.sup.request_connect()
        self.tick(1)
        self.assertEqual(len(self.cli.argvs("connect")), 2)
        self.assertTrue(self.sup.snapshot()["connected"])

    def test_console_connect_after_webui_disconnect_is_left_alone(self):
        self.make()
        self.tick()
        self.sup.request_disconnect()
        self.tick(1)
        self.cli.connected = True  # user runs `protonvpn connect` by hand
        self.tick(30)
        self.assertEqual(len(self.cli.argvs("disconnect")), 1)


class ApplySettingsTest(SupervisorCase):
    def test_applied_once_per_session(self):
        self.make(environ={"NETSHIELD": "malware"})
        self.tick()
        applied = self.cli.argvs("config")
        self.assertIn(("config", "set", "netshield", "malware"), applied)
        self.assertIn(("config", "set", "kill-switch", "standard"), applied)
        self.tick(30)
        self.assertEqual(self.cli.argvs("config"), applied)
        self.sup.notify_signed_in()
        self.tick(1)
        again = self.cli.argvs("config")[len(applied) :]
        # Connected now, so the kill switch (refused by the CLI while a connection is up) waits.
        self.assertEqual(again, [a for a in applied if a[2] != "kill-switch"])

    def test_reapplied_after_signout_and_signin(self):
        self.make()
        self.tick()
        count = len(self.cli.argvs("config"))
        self.cli.signed_in, self.cli.connected = False, False  # signout ends the connection too
        self.tick(30)
        self.cli.signed_in = True
        self.tick(30)
        self.assertEqual(len(self.cli.argvs("config")), 2 * count)

    def test_env_kill_switch_while_connected_does_not_exit(self):
        self.make(environ={"KILL_SWITCH": "off"})
        self.cli.connected = True  # a connection lingers into the first signed-in tick
        self.tick()
        self.assertEqual(self.exits, [])
        calls = [a for _, a in self.cli.calls]
        self.assertNotIn(("config", "set", "kill-switch", "off"), calls)
        self.assertIn(("config", "set", "anonymous-crash-reports", "off"), calls)
        self.assertEqual(self.sup.snapshot()["settings_errors"], {})
        # Applied once the connection is gone, before the next connect.
        self.cli.connected = False
        self.tick(30)
        calls = [a for _, a in self.cli.calls]
        self.assertEqual(self.exits, [])
        self.assertLess(calls.index(("config", "set", "kill-switch", "off")), calls.index(("connect",)))

    def test_transient_cli_failure_is_retried(self):
        self.make(environ={"NETSHIELD": "malware"})
        key = ("config", "set", "netshield", "malware")
        self.cli.responses[key] = [Result(124, "protonvpn timed out after 120s\n"), Result(0, "ok\n")]
        self.tick()
        self.assertEqual(self.exits, [])  # not a rejection, although the value comes from the environment
        self.assertEqual(self.sup.snapshot()["settings_errors"], {})
        self.assertEqual(self.cli.argvs("connect"), [])  # nothing connects with settings half applied
        self.tick(30)
        self.assertEqual([a for a in self.cli.argvs("config") if a == key], [key, key])
        self.assertEqual(self.exits, [])
        self.assertTrue(self.sup.snapshot()["connected"])
        self.tick(30)
        self.assertEqual([a for a in self.cli.argvs("config") if a == key], [key, key])  # applied: not again

    def test_missing_cli_binary_is_transient_too(self):
        self.make(environ={"NETSHIELD": "malware"})
        self.cli.responses[("config", "set", "netshield", "malware")] = Result(127, "cannot run protonvpn\n")
        self.tick()
        self.assertEqual(self.exits, [])

    def test_hung_setting_does_not_block_connect_forever(self):
        self.make(environ={"NETSHIELD": "malware"})
        key = ("config", "set", "netshield", "malware")
        self.cli.responses[key] = Result(124, "protonvpn timed out after 120s\n")

        def calls(argv):
            return [a for a in self.cli.argvs("config") if a == argv]

        self.tick()  # check 1
        self.tick(30)  # check 2
        self.assertEqual(self.cli.argvs("connect"), [])
        self.assertIn("holding the connect, check 2 of 3", self.out.getvalue())
        self.tick(30)  # check 3
        self.assertEqual(len(self.cli.argvs("connect")), 1)
        self.assertTrue(self.sup.snapshot()["connected"])
        self.assertIn("[protonvpn] connecting without netshield (will keep retrying)", self.out.getvalue())
        # The other settings were applied once, although netshield (earlier in the list) kept failing.
        self.assertEqual(len(calls(("config", "set", "kill-switch", "standard"))), 1)
        self.assertEqual(len(calls(("config", "set", "anonymous-crash-reports", "off"))), 1)
        # Still retried at every later check, now while connected, until it works.
        self.tick(30)
        self.assertEqual(len(calls(key)), 4)
        self.cli.responses[key] = Result(0, "NetShield has been set to malware\n")
        self.tick(30)
        self.assertEqual(len(calls(key)), 5)
        self.tick(30)
        self.assertEqual(len(calls(key)), 5)
        self.assertEqual(self.exits, [])

    def test_hung_kill_switch_waits_for_a_disconnected_moment(self):
        self.make()
        ks = ("config", "set", "kill-switch", "standard")
        self.cli.responses[ks] = Result(124, "protonvpn timed out after 120s\n")
        for _ in range(3):
            self.tick(30)
        self.assertEqual(len(self.cli.argvs("connect")), 1)
        self.tick(30)  # connected: the CLI would refuse kill-switch, so it is not tried
        self.assertEqual(self.cli.argvs("config").count(ks), 3)
        self.cli.connected = False  # the tunnel drops
        self.tick(30)
        self.assertEqual(self.cli.argvs("config").count(ks), 4)
        self.assertEqual(len(self.cli.argvs("connect")), 2)  # no second hold

    def test_env_setting_rejected_exits(self):
        self.make(environ={"NETSHIELD": "bogus"})
        self.cli.responses[("config", "set", "netshield", "bogus")] = Result(2, "Error: invalid choice\n")
        self.tick()
        self.assertEqual(self.exits, [1])
        self.assertIn("NETSHIELD", self.out.getvalue())

    def test_file_setting_rejected_continues(self):
        self.make(file={"NETSHIELD": "bogus"})
        self.cli.responses[("config", "set", "netshield", "bogus")] = Result(2, "Error: invalid choice\n")
        self.tick()
        self.assertEqual(self.exits, [])
        self.assertEqual(self.sup.snapshot()["settings_errors"], {"NETSHIELD": "Error: invalid choice"})
        self.assertTrue(self.sup.snapshot()["connected"])

    def test_apply_setting_signed_out_saves(self):
        self.make()
        ok, message = self.apply("COUNTRY", "NL")
        self.assertTrue(ok)
        self.assertIn("applied at sign in", message)
        self.assertEqual(self.store.effective("COUNTRY"), "NL")
        self.assertEqual(self.cli.calls, [])

    def test_apply_setting_signed_in_saves_on_success(self):
        self.make()
        self.tick()
        self.cli.responses[("config", "set", "netshield", "malware")] = Result(0, "NetShield has been set to malware\n")
        self.assertEqual(self.apply("NETSHIELD", "malware"), (True, "NetShield has been set to malware"))
        self.assertEqual(self.store.effective("NETSHIELD"), "malware")

    def test_apply_setting_rejected_is_not_saved(self):
        self.make()
        self.tick()
        self.cli.responses[("config", "set", "netshield", "bogus")] = Result(2, "Error: invalid choice\n")
        self.assertEqual(self.apply("NETSHIELD", "bogus"), (False, "Error: invalid choice"))
        self.assertEqual(self.store.effective("NETSHIELD"), "")

    def test_apply_setting_locked_refused(self):
        self.make(environ={"NETSHIELD": "off"})
        self.tick()
        ok, message = self.apply("NETSHIELD", "malware")
        self.assertFalse(ok)
        self.assertIn("environment", message)
        self.assertEqual(self.store.effective("NETSHIELD"), "off")

    def test_apply_target_setting_reconnects(self):
        self.make()
        self.tick()
        self.assertEqual(self.apply("COUNTRY", "CH"), (True, "reconnected"))
        self.assertEqual(self.cli.argvs("connect")[-1], ("connect", "--country", "CH"))
        self.assertEqual(len(self.cli.argvs("disconnect")), 1)
        self.assertEqual(self.store.effective("COUNTRY"), "CH")
        self.assertEqual(self.apply("COUNTRY", "CH"), (True, "unchanged"))
        self.assertEqual(len(self.cli.argvs("connect")), 2)

    def test_apply_target_setting_failure_restores(self):
        self.make(file={"COUNTRY": "NL"})
        self.tick()
        self.cli.connect_rc = 2
        ok, message = self.apply("COUNTRY", "XX")
        self.assertFalse(ok)
        self.assertIn("Connection failed", message)
        self.assertEqual(self.store.effective("COUNTRY"), "NL")

    def test_apply_target_setting_while_disconnected_only_saves(self):
        self.make()
        self.tick()
        self.sup.request_disconnect()
        self.tick(1)
        ok, message = self.apply("COUNTRY", "CH")
        self.assertTrue(ok)
        self.assertIn("next connect", message)
        self.assertEqual(len(self.cli.argvs("connect")), 1)


class NatpmpTest(SupervisorCase):
    def setUp(self):
        super().setUp()
        self.tool.responses[UDP] = [mapped(41404), mapped(41404), mapped(41405), NATPMP_FAILED]
        self.tool.responses[TCP] = [mapped(41404), mapped(41404), mapped(41405), NATPMP_FAILED]

    def test_natpmp_port_change_written(self):
        self.make(environ={"PORT_FORWARDING": "on"})
        self.tick()
        self.assertEqual(self.read_port_file(), "41404\n")
        self.assertEqual(stat.S_IMODE(os.stat(self.port_file).st_mode), 0o644)
        self.assertEqual(self.sup.snapshot()["forwarded_port"], 41404)
        self.tick(30)  # not due yet
        self.assertEqual(self.tool.calls.count(UDP), 1)
        self.tick(15)  # same port: no rewrite, no new log line
        self.assertEqual(self.tool.calls.count(UDP), 2)
        self.assertEqual(self.out.getvalue().count("[natpmp] forwarded port"), 1)
        self.tick(45)
        self.assertEqual(self.read_port_file(), "41405\n")
        self.assertEqual(self.out.getvalue().count("[natpmp] forwarded port"), 2)
        self.assertIn("[natpmp] forwarded port 41405", self.out.getvalue())
        self.tick(45)  # refresh fails
        self.assertEqual(self.read_port_file(), "")
        self.assertIsNone(self.sup.snapshot()["forwarded_port"])
        self.assertIn("[natpmp] refresh failed", self.out.getvalue())
        self.assertEqual(self.tool.calls.count(TCP), 3)  # the failing udp call ended the refresh

    def test_udp_failure_skips_tcp(self):
        self.tool.responses[UDP] = NATPMP_FAILED
        self.make(environ={"PORT_FORWARDING": "on"})
        self.tick()
        self.assertEqual(self.tool.calls.count(UDP), 1)
        self.assertNotIn(TCP, self.tool.calls)
        self.assertEqual(self.read_port_file(), "")

    def test_port_forwarding_switched_off_clears_file_at_once(self):
        self.make(file={"PORT_FORWARDING": "on"})
        self.tick()
        self.assertEqual(self.read_port_file(), "41404\n")
        self.assertEqual(self.apply("PORT_FORWARDING", "off")[0], True)
        self.tick(1)  # the refresh is not due for another 44 s
        self.assertEqual(self.read_port_file(), "")
        self.assertIsNone(self.sup.snapshot()["forwarded_port"])
        self.assertEqual(self.tool.calls.count(UDP), 1)

    def test_natpmp_idle_when_port_forwarding_off(self):
        self.make()
        self.tick()
        self.tick(45)
        self.assertNotIn(UDP, self.tool.calls)
        self.assertEqual(self.read_port_file(), "")

    def test_port_file_truncated_at_start_and_on_disconnect(self):
        with open(self.port_file, "w") as f:
            f.write("12345\n")
        self.make(environ={"PORT_FORWARDING": "on"})
        self.cli.connect_rc = 1
        self.tick()
        self.assertEqual(self.read_port_file(), "")
        self.cli.connect_rc = 0
        self.tick(30)
        self.assertEqual(self.read_port_file(), "41404\n")
        self.sup.request_disconnect()
        self.tick(1)
        self.assertEqual(self.read_port_file(), "")
        self.assertIsNone(self.sup.snapshot()["forwarded_port"])


class TrafficTest(SupervisorCase):
    def test_traffic_ring_buffer(self):
        self.make()
        self.tool.responses[WG] = lambda n: Result(0, f"KEY\t{(n + 1) * 100}\t{(n + 1) * 10}\n")
        self.tick()
        for _ in range(199):
            self.tick(5)
        traffic = self.sup.snapshot()["traffic"]
        self.assertEqual(len(traffic), 180)
        self.assertEqual(traffic[-1], [self.clock.now, 20000, 2000])
        self.assertEqual(traffic[1][0] - traffic[0][0], 5)
        # A new connection starts a fresh series.
        self.cli.connected = False
        self.tick(30)
        traffic = self.sup.snapshot()["traffic"]
        self.assertEqual(len(traffic), 1)
        self.assertEqual(traffic[0], [self.clock.now, 20100, 2010])

    def test_no_sample_when_wg_fails(self):
        self.make()
        self.tool.responses[WG] = Result(1, "Unable to access interface: No such device\n")
        self.tick()
        self.assertEqual(self.sup.snapshot()["traffic"], [])


class StopTest(SupervisorCase):
    def test_stop_disconnects_and_joins(self):
        self.make()
        self.tick()
        self.sup.start()
        with redirect_stdout(self.out):
            self.sup.stop()
        self.assertIn(("disconnect",), self.cli.argvs("disconnect"))
        self.assertFalse(self.sup._thread.is_alive())

    def test_stop_respects_the_time_it_is_given(self):
        self.make()
        self.sup.stop(timeout=2)
        self.assertEqual(self.cli.timeouts[-1], (("disconnect",), 2))
        self.sup.stop()
        self.assertEqual(self.cli.timeouts[-1], (("disconnect",), 5))


if __name__ == "__main__":
    unittest.main()
