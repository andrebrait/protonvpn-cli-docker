import io
import json
import os
import stat
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

from protonvpn_container.cli import Result, run_tool
from protonvpn_container.config import SettingsStore
from protonvpn_container.health import is_healthy, write_health
from protonvpn_container.supervisor import HINT, Supervisor, decide

STATUS_UP = "Status: Connected\nServer: NL#914 in Amsterdam, Netherlands\nLoad: 31%\nProtocol: wireguard\n"
CONNECT_OUT = "Connected to NL#914 in Amsterdam, Netherlands. \nYour new IP address is 205.147.16.78.\n"
UDP = ("natpmpc", "-a", "1", "0", "udp", "60", "-g", "10.2.0.1")
TCP = ("natpmpc", "-a", "1", "0", "tcp", "60", "-g", "10.2.0.1")
WG = ("wg", "show", "proton0", "transfer")
HANDSHAKE = ("wg", "show", "proton0", "latest-handshakes")
SUPERVISOR = "protonvpn_container.supervisor"
PROBE = ("curl",)
ECHO_IP = "205.147.16.74"
PROBE_OK = Result(0, f"{ECHO_IP}\n")
BIND_FAILED = Result(45, "curl: (45) Couldn't bind to interface 'proton0' with errno 19: No such device\n")
TIMED_OUT = Result(28, "curl: (28) Connection timed out after 5001 milliseconds\n")


def mapped(port, lifetime=60):
    return Result(0, f"Mapped public port {port} protocol UDP to local port 0 lifetime {lifetime}\n")


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
        self.slow = {}  # argv -> seconds the call takes; a call given a shorter timeout is cut off at it, as the real one is
        self.during = {}  # argv -> fn(), run while that call is blocked: time passes, timers fire
        self.protocol = "wireguard"
        self.native_settings = None  # when set, a connect uses the protocol saved there, as Proton's does

    def __call__(self, *args, timeout=120):
        self.calls.append((self.clock.now, args))
        self.timeouts.append((args, timeout))
        duration = self.slow.get(args, 0)
        if duration > timeout:
            self.clock.now += timeout
            return Result(124, f"protonvpn timed out after {timeout}s\n")
        self.clock.now += duration
        if args in self.during:
            self.during[args]()
        reply = self.responses.get(args)
        if isinstance(reply, list):
            reply = reply.pop(0) if len(reply) > 1 else reply[0]
        if reply is not None:
            return reply
        if args == ("info",):
            return Result(0, f"Account: '{'me@proton.me' if self.signed_in else 'None'}'\n")
        if args == ("status",):
            return Result(0, STATUS_UP.replace("wireguard", self.protocol) if self.connected else "Status: Disconnected\n")
        if args[:3] == ("config", "set", "kill-switch") and self.connected:
            return Result(2, "Error: Disconnect before changing Kill Switch. Run 'protonvpn disconnect' first.\n")
        if args[0] == "connect":
            self.clock.now += self.connect_duration
            if self.native_settings:
                try:
                    with open(self.native_settings) as f:
                        self.protocol = json.load(f).get("protocol", "protun-smart")
                except FileNotFoundError:
                    self.protocol = "protun-smart"  # Proton's free-tier default when nothing is saved
            if self.connect_rc:
                return Result(self.connect_rc, "Error: Connection failed.\n")
            self.connected = True
            return Result(0, CONNECT_OUT)
        if args == ("disconnect",):
            self.connected = False
            return Result(0, "Disconnected.\n")
        if args == ("signout",):  # signing out ends the connection too
            self.signed_in = self.connected = False
            return Result(0, "You have been successfully signed out.\n")
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
        argv = PROBE if argv and argv[0] == "curl" else argv
        n = sum(1 for a in self.calls if a == argv)
        self.calls.append(argv)
        reply = self.responses.get(argv, Result(1, "not scripted\n"))
        if callable(reply):
            return reply(n)
        if isinstance(reply, list):
            return reply[min(n, len(reply) - 1)]
        return reply


class FakeTimers:
    """threading.Timer stand-in: nothing fires by itself; a test fires the callbacks the real clock would have."""

    class Timer:
        def __init__(self, interval, function, args):
            self.interval, self.function, self.args = interval, function, args
            self.daemon = self.started = self.cancelled = self.fired = False

        def start(self):
            self.started = True

        def cancel(self):
            self.cancelled = True

        def fire(self):
            self.fired = True
            self.function(*self.args)

    def __init__(self):
        self.created = []

    def __call__(self, interval, function, args):
        self.created.append(self.Timer(interval, function, args))
        return self.created[-1]

    def fire_live(self):
        for timer in self.created:
            if timer.started and not (timer.cancelled or timer.fired):
                timer.fire()


class Gate:
    """A probe reply that waits until the test lets it through; `timed_out` shows it was kept waiting for nothing."""

    def __init__(self, result):
        self.result = result
        self.started, self.release, self.timed_out = threading.Event(), threading.Event(), False

    def __call__(self, n):
        self.started.set()
        self.timed_out = not self.release.wait(10)
        return self.result


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
        self.timers = FakeTimers()
        self.health_file = os.path.join(self.dir, "health.json")
        self.tool.responses[PROBE] = PROBE_OK

    def make(self, environ=None, file=None):
        self.native_settings = os.path.join(self.dir, "Proton", "VPN", "settings.json")
        self.cli.native_settings = self.native_settings
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
            timer=self.timers,
            health_file=self.health_file,
            native_settings=self.native_settings,
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

    def test_a_signin_notice_after_the_tick_saw_the_signin_changes_nothing(self):
        # The CLI saves the account before `protonvpn signin` exits: the tick applies the settings and connects, then
        # the WebUI's notice arrives. A second `config set` on the live connection fails, as it did for real.
        self.cli.signed_in = False
        self.tool.responses[UDP] = self.tool.responses[TCP] = mapped(41404)
        self.make(environ={"PORT_FORWARDING": "on"})
        port_forwarding = ("config", "set", "port-forwarding", "on")
        self.cli.responses[port_forwarding] = [Result(0, "ok\n"), Result(1, "An unexpected error occurred.\n")]
        self.tick()  # signed out
        self.cli.signed_in = True
        self.tick(30)
        applied = self.cli.argvs("config")
        self.assertEqual(applied.count(port_forwarding), 1)
        self.assertEqual((self.sup.snapshot()["connected"], self.read_port_file()), (True, "41404\n"))
        self.sup.notify_signed_in()
        snap = self.sup.snapshot()  # before any tick
        self.assertEqual((snap["connected"], snap["forwarded_port"], self.read_port_file()), (True, 41404, "41404\n"))
        self.tick(1)  # the notice brought the check forward
        self.tick(30)
        self.assertEqual(self.cli.argvs("config"), applied)
        self.assertEqual((self.exits, len(self.cli.argvs("connect")), self.cli.argvs("disconnect")), ([], 1, []))
        snap = self.sup.snapshot()
        self.assertEqual((snap["connected"], snap["forwarded_port"], snap["settings_errors"]), (True, 41404, {}))
        self.assertEqual(self.read_port_file(), "41404\n")


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

    def test_snapshot_reports_a_user_disconnect_until_connect_is_requested(self):
        self.make()
        self.tick()
        self.assertIs(self.sup.snapshot()["user_disconnected"], False)
        self.sup.request_disconnect()
        self.assertIs(self.sup.snapshot()["user_disconnected"], True)
        self.tick(1)
        self.assertIs(self.sup.snapshot()["user_disconnected"], True)
        self.sup.request_connect()
        self.assertIs(self.sup.snapshot()["user_disconnected"], False)

    def test_console_connect_after_webui_disconnect_is_left_alone(self):
        self.make()
        self.tick()
        self.sup.request_disconnect()
        self.tick(1)
        self.cli.connected = True  # user runs `protonvpn connect` by hand
        self.tick(30)
        self.assertEqual(len(self.cli.argvs("disconnect")), 1)

    def test_connect_supersedes_a_queued_disconnect_and_restores_the_port(self):
        self.tool.responses[UDP] = self.tool.responses[TCP] = mapped(41404)
        self.make(environ={"PORT_FORWARDING": "on"})
        self.tick()
        self.sup.request_disconnect()
        self.sup.request_connect()
        self.tick(1)
        snap = self.sup.snapshot()
        self.assertEqual((snap["connected"], snap["user_disconnected"], snap["forwarded_port"]),
                         (True, False, 41404))
        self.assertEqual(self.read_port_file(), "41404\n")
        self.assertEqual(self.cli.argvs("disconnect"), [])
        self.assertEqual(len(self.cli.argvs("connect")), 1)  # adopt the still-live tunnel

    def test_connect_during_a_state_check_supersedes_the_old_disconnect_intent(self):
        self.make()
        self.tick()
        self.sup.request_disconnect()
        self.cli.during[("status",)] = self.sup.request_connect
        self.tick(1)
        self.assertTrue(self.sup.snapshot()["connected"])
        self.assertFalse(self.sup.snapshot()["user_disconnected"])
        self.assertEqual(self.cli.argvs("disconnect"), [])

    def test_failed_disconnect_retries_without_readvertising_the_port(self):
        self.tool.responses[UDP] = self.tool.responses[TCP] = mapped(41404)
        self.make(environ={"PORT_FORWARDING": "on"})
        self.tick()
        self.cli.responses[("disconnect",)] = Result(1, "Error: temporary agent failure\n")
        self.sup.request_disconnect()
        self.tick(1)
        snap = self.sup.snapshot()
        self.assertEqual((snap["connected"], snap["user_disconnected"], snap["forwarded_port"]),
                         (True, True, None))  # truthful native status, but no usable port while leaving
        self.assertEqual(self.read_port_file(), "")
        del self.cli.responses[("disconnect",)]
        self.tick(30)
        self.assertEqual(len(self.cli.argvs("disconnect")), 2)
        self.assertFalse(self.cli.connected)
        self.assertFalse(self.sup.snapshot()["connected"])
        self.assertEqual(len(self.cli.argvs("connect")), 1)

    def test_failed_disconnect_with_an_unreadable_followup_status_remains_pending(self):
        self.make()
        self.tick()
        self.cli.responses[("disconnect",)] = Result(1, "Error: temporary agent failure\n")
        self.cli.responses[("status",)] = [Result(0, STATUS_UP), Result(1, "status unavailable\n")]
        self.sup.request_disconnect()
        self.tick(1)
        self.assertTrue(self.cli.connected)
        del self.cli.responses[("disconnect",)]
        del self.cli.responses[("status",)]
        self.tick(30)
        self.assertFalse(self.cli.connected)
        self.assertFalse(self.sup.snapshot()["connected"])
        self.assertEqual(len(self.cli.argvs("disconnect")), 2)

    def test_connect_during_a_failed_disconnect_cancels_the_retry(self):
        self.tool.responses[UDP] = self.tool.responses[TCP] = mapped(41404)
        self.make(environ={"PORT_FORWARDING": "on"})
        self.tick()
        self.cli.responses[("disconnect",)] = Result(1, "Error: temporary agent failure\n")
        self.cli.during[("disconnect",)] = self.sup.request_connect
        self.sup.request_disconnect()
        self.tick(1)
        self.tick(30)
        snap = self.sup.snapshot()
        self.assertEqual((snap["connected"], snap["user_disconnected"], snap["forwarded_port"]),
                         (True, False, 41404))
        self.assertEqual(len(self.cli.argvs("disconnect")), 1)

    def test_connect_during_a_successful_disconnect_reconnects_without_another_request(self):
        self.make()
        self.tick()
        self.cli.during[("disconnect",)] = self.sup.request_connect
        self.sup.request_disconnect()
        self.tick(1)
        self.assertTrue(self.sup.snapshot()["connected"])
        self.assertFalse(self.sup.snapshot()["user_disconnected"])
        self.assertEqual(len(self.cli.argvs("connect")), 2)

    def test_disconnect_during_connect_withdraws_the_late_tunnel_without_backoff(self):
        self.enterContext(redirect_stdout(self.out))
        self.tool.responses[UDP] = self.tool.responses[TCP] = mapped(41404)
        self.make(environ={"PORT_FORWARDING": "on"})
        started, release = threading.Event(), threading.Event()

        def hold_connect():
            started.set()
            release.wait(5)

        self.cli.during[("connect",)] = hold_connect
        worker = threading.Thread(target=self.sup.tick)
        self.addCleanup(worker.join, 5)
        self.addCleanup(release.set)
        worker.start()
        self.assertTrue(started.wait(5))
        self.sup.request_disconnect()
        release.set()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertFalse(self.cli.connected)
        snap = self.sup.snapshot()
        self.assertEqual((snap["connected"], snap["tunnel_healthy"], snap["forwarded_port"], snap["last_error"]),
                         (False, False, None, ""))
        self.assertEqual(self.read_port_file(), "")
        self.assertNotIn(UDP, self.tool.calls)
        self.assertNotIn("connect failed; retrying", self.out.getvalue())
        self.assertEqual(len(self.cli.argvs("status")), 1)  # compensate before another potentially slow CLI call
        del self.cli.during[("connect",)]
        self.cli.connect_rc = 1
        self.sup.request_connect()
        first = self.next_connect()
        self.assertEqual(self.next_connect() - first, 30)

    def test_connect_supersedes_disconnect_while_late_connect_is_being_compensated(self):
        self.make()
        self.cli.during[("connect",)] = self.sup.request_disconnect
        self.cli.during[("disconnect",)] = self.sup.request_connect
        self.tick()
        self.assertFalse(self.cli.connected)
        self.assertFalse(self.sup.snapshot()["user_disconnected"])
        del self.cli.during[("connect",)]
        self.tick(1)
        self.assertTrue(self.cli.connected)
        self.assertTrue(self.sup.snapshot()["connected"])
        self.assertEqual(len(self.cli.argvs("connect")), 2)
        self.assertEqual(len(self.cli.argvs("disconnect")), 1)
        self.assertNotIn("connect failed; retrying", self.out.getvalue())

    def test_disconnect_during_connect_status_does_not_publish_the_late_tunnel(self):
        self.make()
        statuses = []

        def disconnect_after_connect():
            statuses.append(self.cli.connected)
            if self.cli.connected:
                self.sup.request_disconnect()

        self.cli.during[("status",)] = disconnect_after_connect
        self.tick()
        self.assertEqual(statuses, [False, True])
        self.assertFalse(self.cli.connected)
        self.assertFalse(self.sup.snapshot()["connected"])
        self.assertEqual(self.sup.snapshot()["last_error"], "")

    def test_connect_supersedes_late_disconnect_before_compensation_starts(self):
        self.make()

        def newest_intent():
            self.sup.request_disconnect()
            self.sup.request_connect()

        self.cli.during[("connect",)] = newest_intent
        self.tick()
        self.assertTrue(self.cli.connected)
        self.assertTrue(self.sup.snapshot()["connected"])
        self.assertEqual(self.cli.argvs("disconnect"), [])
        self.assertEqual(self.sup.snapshot()["last_error"], "")


class SignoutTest(SupervisorCase):
    def test_signout_excludes_a_setting_change_while_it_runs(self):
        self.enterContext(redirect_stdout(self.out))  # two threads print: one redirect for the whole test
        self.make()
        self.tick()
        started, release, results = threading.Event(), threading.Event(), {}

        def slow_signout():
            started.set()
            release.wait(5)

        self.cli.during[("signout",)] = slow_signout
        signout = threading.Thread(target=lambda: results.update(signout=self.sup.sign_out()))
        change = threading.Thread(target=lambda: results.update(change=self.sup.apply_setting("NETSHIELD", "malware-only")))
        signout.start()
        self.assertTrue(started.wait(5))
        change.start()
        change.join(0.3)
        self.assertTrue(change.is_alive())  # it waits for the signout instead of running `config set` beside it
        release.set()
        signout.join(5)
        change.join(5)
        self.assertEqual(results["signout"], (True, "You have been successfully signed out."))
        self.assertEqual(results["change"], (True, "saved; applied at sign in"))  # signed out by then: saved only
        self.assertEqual([a for a in self.cli.argvs("config") if a[2] == "netshield"], [])

    def test_signout_resets_the_session_state_at_once(self):
        self.make(file={"NETSHIELD": "bogus"})
        self.cli.responses[("config", "set", "netshield", "bogus")] = Result(2, "Error: invalid choice\n")
        self.tick()
        self.assertEqual(self.sup.snapshot()["settings_errors"], {"NETSHIELD": "Error: invalid choice"})
        self.assertTrue(self.sup.sign_out()[0])
        snap = self.sup.snapshot()  # before any tick
        self.assertEqual((snap["signed_in"], snap["account"], snap["settings_errors"]), (False, "", {}))

    def test_signout_forces_a_state_check_and_settings_apply_again_at_the_next_signin(self):
        self.make()
        self.tick()
        count = len(self.cli.argvs("config"))
        infos = len(self.cli.argvs("info"))
        self.assertTrue(self.sup.sign_out()[0])
        self.tick(1)  # far sooner than the 30 s check interval
        self.assertEqual(len(self.cli.argvs("info")), infos + 1)
        self.assertEqual(len(self.cli.argvs("connect")), 1)  # signed out: nothing reconnects
        self.cli.signed_in = True  # signs in again from the console
        self.tick(30)
        self.assertEqual(len(self.cli.argvs("config")), 2 * count)

    def test_a_webui_signin_after_a_signout_applies_the_settings_and_connects_at_once(self):
        self.make()
        self.tick()
        count = len(self.cli.argvs("config"))
        self.assertTrue(self.sup.sign_out()[0])
        self.tick(1)
        self.assertEqual(len(self.cli.argvs("connect")), 1)  # signed out: nothing reconnects
        self.cli.signed_in = True  # the CLI saved the account; the WebUI says so
        self.sup.notify_signed_in()
        self.tick(1)  # far sooner than the 30 s check interval
        self.assertEqual(len(self.cli.argvs("config")), 2 * count)
        self.assertEqual(len(self.cli.argvs("connect")), 2)
        self.assertTrue(self.sup.snapshot()["connected"])

    def test_failed_signout_changes_nothing(self):
        self.make()
        self.tick()
        self.cli.responses[("signout",)] = Result(1, "Error: boom\n")
        self.assertEqual(self.sup.sign_out(), (False, "Error: boom"))
        snap = self.sup.snapshot()
        self.assertEqual((snap["signed_in"], snap["account"]), (True, "me@proton.me"))


class ConnectionStateTest(SupervisorCase):
    """What the WebUI and the port file show is never a connection that is ending or that the CLI cannot vouch for."""

    def setUp(self):
        super().setUp()
        self.tool.responses[UDP] = self.tool.responses[TCP] = mapped(41404)
        self.make(environ={"PORT_FORWARDING": "on"})
        self.tick()
        self.assertEqual(self.consumer(), (True, 41404, "41404\n"))

    def consumer(self):
        snap = self.sup.snapshot()
        return snap["connected"], snap["forwarded_port"], self.read_port_file()

    def fail_next_check(self):
        self.cli.responses[("info",)] = Result(124, "protonvpn timed out after 120s\n")

    def test_successful_signout(self):
        self.assertTrue(self.sup.sign_out()[0])
        self.assertEqual(self.consumer(), (False, None, ""))
        self.assertEqual(self.sup.snapshot()["exit_ip"], "")
        self.fail_next_check()
        self.tick(1)
        self.assertEqual(self.consumer(), (False, None, ""))

    def test_disconnect_request(self):
        self.sup.request_disconnect()
        self.assertEqual(self.consumer(), (False, None, ""))  # before the loop did anything
        self.fail_next_check()
        self.tick(1)
        self.assertEqual(self.consumer(), (False, None, ""))

    def test_detected_drop_clears_port_before_reconnect(self):
        self.cli.connected = False
        seen = []
        self.cli.during[("connect",)] = lambda: seen.append(self.consumer())
        self.tick(30)
        self.assertEqual(seen, [(False, None, "")])

    def test_reconnect_for_a_new_target(self):
        seen = []
        self.cli.during[("connect", "--country", "CH")] = lambda: seen.append(self.consumer())
        self.assertEqual(self.apply("COUNTRY", "CH"), (True, "reconnected"))
        self.assertEqual(seen, [(False, None, "")])  # while the new connection was being made
        self.assertEqual(self.consumer(), (True, None, ""))  # the new connection's port is requested by the next tick
        self.tick(1)
        self.assertEqual(self.consumer(), (True, 41404, "41404\n"))

    def test_failed_state_check_is_visible_and_recovers(self):
        self.cli.responses[("status",)] = Result(124, "protonvpn timed out after 120s\n")
        self.tick(30)
        snap = self.sup.snapshot()
        self.assertEqual(self.consumer(), (False, None, ""))
        self.assertIn("state check failed (rc 124)", snap["last_error"])
        self.assertEqual((snap["signed_in"], snap["account"]), (True, "me@proton.me"))  # one error is not a signout
        self.assertEqual(snap["exit_ip"], "205.147.16.78")
        del self.cli.responses[("status",)]
        self.tick(30)
        self.assertEqual(self.consumer(), (True, 41404, "41404\n"))
        self.assertEqual(self.sup.snapshot()["last_error"], "")


class ApplySettingsTest(SupervisorCase):
    def test_applied_once_per_session(self):
        self.make(environ={"NETSHIELD": "malware"})
        self.tick()
        applied = self.cli.argvs("config")
        self.assertIn(("config", "set", "netshield", "malware"), applied)
        self.assertIn(("config", "set", "kill-switch", "standard"), applied)
        self.tick(30)
        self.assertEqual(self.cli.argvs("config"), applied)

    def test_reapplied_after_signout_and_signin(self):
        self.make()
        self.tick()
        count = len(self.cli.argvs("config"))
        self.cli.signed_in, self.cli.connected = False, False  # signout ends the connection too
        self.tick(30)
        self.cli.signed_in = True
        self.tick(30)
        self.assertEqual(len(self.cli.argvs("config")), 2 * count)

    def test_kill_switch_is_always_standard_and_waits_while_a_connection_lingers(self):
        self.make()
        self.cli.connected = True  # a connection lingers into the first signed-in tick
        self.tick()
        self.assertEqual(self.exits, [])
        ks = ("config", "set", "kill-switch", "standard")
        calls = [a for _, a in self.cli.calls]
        self.assertNotIn(ks, calls)  # the CLI refuses it while connected
        self.assertIn(("config", "set", "anonymous-crash-reports", "off"), calls)
        self.assertEqual(self.sup.snapshot()["settings_errors"], {})
        # Applied once the connection is gone, before the next connect.
        self.cli.connected = False
        self.tick(30)
        calls = [a for _, a in self.cli.calls]
        self.assertEqual(self.exits, [])
        self.assertLess(calls.index(ks), calls.index(("connect",)))
        self.tick(30)
        self.assertEqual(self.cli.argvs("config").count(ks), 1)  # once per session

    def test_a_kill_switch_value_in_the_environment_is_ignored(self):
        self.make(environ={"KILL_SWITCH": "off"})
        self.tick()
        self.assertEqual(
            [a for a in self.cli.argvs("config") if a[2] == "kill-switch"], [("config", "set", "kill-switch", "standard")]
        )
        self.assertEqual(self.exits, [])

    def test_a_failing_kill_switch_is_logged_retried_and_never_fatal(self):
        ks = ("config", "set", "kill-switch", "standard")
        # rc 2 is the CLI refusing it while connected: the value is fixed and valid, so no rc means "invalid".
        for rc in (1, 2):
            with self.subTest(rc=rc):
                self.cli, self.out, self.exits = FakeCli(self.clock), io.StringIO(), []
                self.make()
                self.cli.responses[ks] = Result(rc, "Error: it failed\n")
                self.tick()
                self.assertEqual(self.exits, [])
                self.assertIn(f"setting kill-switch not applied (rc {rc})", self.out.getvalue())
                self.assertEqual(self.sup.snapshot()["settings_errors"], {})  # not a public setting
                self.assertEqual(self.cli.argvs("connect"), [])  # the same bounded hold as any setting
                self.tick(30)
                self.tick(30)
                self.assertEqual(len(self.cli.argvs("connect")), 1)
                self.assertIn("connecting without kill-switch", self.out.getvalue())
                self.assertEqual(self.cli.argvs("config").count(ks), 3)
                self.assertEqual(self.exits, [])
                self.assertTrue(self.sup.snapshot()["connected"])

    def test_transient_cli_failure_is_retried(self):
        self.make(environ={"NETSHIELD": "malware"})
        key = ("config", "set", "netshield", "malware")
        self.cli.responses[key] = [Result(124, "protonvpn timed out after 120s\n"), Result(0, "ok\n")]
        self.tick()
        self.assertEqual(self.exits, [])  # not a rejection, although the value comes from the environment
        self.assertEqual(self.sup.snapshot()["settings_errors"], {"NETSHIELD": "protonvpn timed out after 120s"})
        self.assertEqual(self.cli.argvs("connect"), [])  # nothing connects with settings half applied
        self.tick(30)
        self.assertEqual([a for a in self.cli.argvs("config") if a == key], [key, key])
        self.assertEqual(self.exits, [])
        self.assertTrue(self.sup.snapshot()["connected"])
        self.assertEqual(self.sup.snapshot()["settings_errors"], {})  # the retry worked: nothing left to show
        self.tick(30)
        self.assertEqual([a for a in self.cli.argvs("config") if a == key], [key, key])  # applied: not again

    def test_env_setting_failing_with_rc1_is_transient_not_fatal(self):
        # rc 1 is any runtime failure of the CLI (here the local agent timing out), not proof that the value is invalid.
        self.make(environ={"PORT_FORWARDING": "on"})
        key = ("config", "set", "port-forwarding", "on")
        failure = "An unexpected error occurred. Please try again later."
        self.cli.responses[key] = Result(1, failure + "\n")
        self.tick()
        self.assertEqual(self.exits, [])
        self.assertEqual(self.sup.snapshot()["settings_errors"], {"PORT_FORWARDING": failure})  # visible in the WebUI
        self.assertEqual(self.cli.argvs("connect"), [])  # the same bounded hold as any transient failure
        self.tick(30)
        self.tick(30)
        self.assertEqual(len(self.cli.argvs("connect")), 1)
        self.assertIn("connecting without port-forwarding", self.out.getvalue())
        self.assertEqual(self.exits, [])
        self.cli.responses[key] = Result(0, "Port forwarding has been enabled\n")
        self.tick(30)  # still retried while connected, until it works
        self.assertEqual(self.sup.snapshot()["settings_errors"], {})
        self.assertEqual(self.exits, [])

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

    def test_save_racing_a_signin_check_still_reaches_the_cli(self):
        self.enterContext(redirect_stdout(self.out))
        self.make(file={"NETSHIELD": "off"})
        paused, resume, saved, original = threading.Event(), threading.Event(), [], self.store.save

        def slow_save(env, value):
            paused.set()
            resume.wait(5)
            original(env, value)

        self.store.save = slow_save
        change = threading.Thread(target=lambda: saved.append(self.sup.apply_setting("NETSHIELD", "malware-only")))
        change.start()
        self.assertTrue(paused.wait(5))  # mid-save, while the supervisor still believes it is signed out
        tick = threading.Thread(target=self.sup.tick)
        tick.start()
        tick.join(0.3)
        self.assertTrue(tick.is_alive())  # the tick signs in only once the save is done
        resume.set()
        change.join(5)
        tick.join(5)
        self.assertEqual(saved, [(True, "saved; applied at sign in")])
        self.assertEqual(
            [a for a in self.cli.argvs("config") if a[2] == "netshield"], [("config", "set", "netshield", "malware-only")]
        )

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

    def test_target_change_canceled_by_disconnect_is_saved_without_a_failure(self):
        self.make(file={"COUNTRY": "NL"})
        self.tick()
        self.cli.during[("connect", "--country", "CH")] = self.sup.request_disconnect
        self.assertEqual(self.apply("COUNTRY", "CH"), (True, "saved; applies at next connect"))
        self.assertEqual(self.store.effective("COUNTRY"), "CH")
        self.assertFalse(self.cli.connected)
        self.assertFalse(self.sup.snapshot()["connected"])
        self.assertEqual(self.sup.snapshot()["last_error"], "")
        self.sup.request_connect()
        del self.cli.during[("connect", "--country", "CH")]
        self.tick(1)
        self.assertTrue(self.cli.connected)
        self.assertEqual(self.cli.argvs("connect")[-1], ("connect", "--country", "CH"))

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

    def test_mismatched_udp_and_tcp_ports_publish_nothing(self):
        self.tool.responses[UDP] = [mapped(41404), mapped(41404)]
        self.tool.responses[TCP] = [mapped(41404), mapped(50000)]
        self.make(environ={"PORT_FORWARDING": "on"})
        self.tick()
        self.assertEqual(self.read_port_file(), "41404\n")
        self.tick(45)  # the renewal maps tcp elsewhere
        self.assertEqual(self.read_port_file(), "")
        self.assertIsNone(self.sup.snapshot()["forwarded_port"])
        self.assertIn("mapped udp to 41404 but tcp to 50000", self.out.getvalue())

    def test_a_failed_natpmpc_call_publishes_nothing_even_with_a_mapping_line(self):
        line = "Mapped public port 41404 protocol UDP to local port 0 lifetime 60\n"
        for failing, other in ((UDP, TCP), (TCP, UDP)):
            with self.subTest(failing=failing[4]):
                self.tool.responses[failing] = Result(1, line)
                self.tool.responses[other] = mapped(41404)
                self.make(environ={"PORT_FORWARDING": "on"})
                self.tick()
                self.assertIsNone(self.sup.snapshot()["forwarded_port"])
                self.assertEqual(self.read_port_file(), "")
                self.assertIn("[natpmp] refresh failed (rc 1)", self.out.getvalue())
                self.tool.calls.clear()

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

    def test_failed_clear_unlinks_the_old_port_and_retries_the_write(self):
        self.make(environ={"PORT_FORWARDING": "on"})
        self.tick()
        with redirect_stdout(self.out), mock.patch(f"{SUPERVISOR}.os.replace", side_effect=OSError("replace denied")):
            self.sup.request_disconnect()
        self.assertIsNone(self.sup.snapshot()["forwarded_port"])
        self.assertFalse(os.path.exists(self.port_file))
        self.assertIn("[natpmp] cannot write", self.out.getvalue())
        self.tick(1)
        self.assertEqual(self.read_port_file(), "")  # a later check retries the failed clear

    def test_failed_changed_port_write_unlinks_old_publication_and_retries(self):
        self.make(environ={"PORT_FORWARDING": "on"})
        self.tick()
        self.assertEqual(self.read_port_file(), "41404\n")
        self.tool.responses[UDP] = self.tool.responses[TCP] = mapped(41405)
        with mock.patch(f"{SUPERVISOR}.os.replace", side_effect=OSError("replace denied")):
            self.tick(45)
        self.assertEqual(self.sup.snapshot()["forwarded_port"], 41405)
        self.assertFalse(os.path.exists(self.port_file))
        self.tick(45)
        self.assertEqual(self.read_port_file(), "41405\n")
        self.assertEqual(self.sup.snapshot()["forwarded_port"], 41405)

    def test_failed_clear_when_unlink_is_denied_still_revokes_the_api_and_retries(self):
        self.make(environ={"PORT_FORWARDING": "on"})
        self.tick()
        with mock.patch(f"{SUPERVISOR}.os.replace", side_effect=OSError("read only")), \
                mock.patch(f"{SUPERVISOR}.os.unlink", side_effect=OSError("read only")):
            self.sup.request_disconnect()
        self.assertIsNone(self.sup.snapshot()["forwarded_port"])
        self.assertEqual(self.read_port_file(), "41404\n")  # no writable-storage guarantee is possible
        self.tick(1)
        self.assertEqual(self.read_port_file(), "")

    def native_natpmp(self, delete_action=""):
        """An executable gateway model: source identity/protocol state changes, not an argv echo."""
        path = os.path.join(self.dir, "natpmpc")
        state = path + ".json"
        with open(state, "w") as f:
            json.dump({"own": {}, "other": {"udp": 50000, "tcp": 50000}, "deletes": []}, f)
        with open(path, "w") as f:
            f.write(
                "#!/usr/bin/env python3\n"
                "import json, os, sys, time\n"
                "path = __file__ + '.json'\n"
                "with open(path) as f: state = json.load(f)\n"
                "if os.path.exists(__file__ + '.disabled'): sys.exit('public-address query: connection refused')\n"
                "args = sys.argv[1:]\n"
                "assert len(args) == 7 and args[0] == '-a' and args[5:] == ['-g', '10.2.0.1'], args\n"
                "public, private, proto, lifetime = args[1:5]\n"
                "assert private == '0' and proto in ('udp', 'tcp'), args\n"
                "if lifetime == '0':\n"
                "    assert public == '0', args\n"
                "    state['deletes'].append(proto)\n"
                "    with open(path, 'w') as f: json.dump(state, f)\n"
                f"    {delete_action or 'pass'}\n"
                "    state['own'].pop(proto, None)\n"
                "    port = 0\n"
                "else:\n"
                "    assert public == '1' and lifetime == '60', args\n"
                "    port = 41404\n"
                "    state['own'][proto] = port\n"
                "with open(path, 'w') as f: json.dump(state, f)\n"
                "print(f'Mapped public port {port} protocol {proto.upper()} to local port 0 lifetime {lifetime}')\n"
            )
        os.chmod(path, 0o755)

        def tool(*argv, timeout=10):
            if argv[0] == "natpmpc":
                return run_tool(path, *argv[1:], timeout=timeout)
            return self.tool(*argv, timeout=timeout)

        self.sup._tool = tool
        return state

    def native_forwarding_config(self, off_rc=0):
        """Native config OFF removes the gateway endpoint before returning, as Proton does."""
        path = os.path.join(self.dir, "protonvpn")
        disabled = os.path.join(self.dir, "natpmpc.disabled")
        with open(path, "w") as f:
            f.write(
                "#!/usr/bin/env python3\n"
                "import os, sys\n"
                "assert sys.argv[1:4] == ['config', 'set', 'port-forwarding'], sys.argv\n"
                f"disabled = {disabled!r}\n"
                "if sys.argv[4] == 'off':\n"
                f"    if {off_rc}: sys.exit({off_rc})\n"
                "    with open(disabled, 'w'): pass\n"
                "else:\n"
                "    assert sys.argv[4] == 'on', sys.argv\n"
                "    if os.path.exists(disabled): os.unlink(disabled)\n"
                "print('Port forwarding setting applied')\n"
            )
        os.chmod(path, 0o755)
        original = self.sup._run

        def run(*argv, timeout=120):
            if argv[:3] == ("config", "set", "port-forwarding"):
                return run_tool(path, *argv, timeout=timeout)
            return original(*argv, timeout=timeout)

        self.sup._run = run
        return disabled

    def test_unsupported_tunnel_rejection_withdraws_live_leases_even_if_disconnect_fails(self):
        for requested in (False, True):
            with self.subTest(user_disconnect=requested):
                self.cli.connected, self.cli.protocol = False, "wireguard"
                self.cli.responses.pop(("disconnect",), None)
                self.make(file={"PORT_FORWARDING": "on"})
                state = self.native_natpmp()
                self.tick()
                self.sup.health_tick()
                self.cli.protocol = "openvpn-tcp"
                self.cli.responses[("disconnect",)] = Result(1, "disconnect failed")
                if requested:
                    self.sup.request_disconnect()
                self.tick(30)
                self.tick(1)
                self.assertTrue(self.cli.connected)
                snap = self.sup.snapshot()
                self.assertEqual((snap["connected"], snap["tunnel_healthy"], snap["forwarded_port"]), (False, False, None))
                with open(state) as f:
                    remote = json.load(f)
                self.assertEqual((remote["own"], remote["deletes"]), ({}, ["udp", "tcp"]))
                self.assertEqual(remote["other"], {"udp": 50000, "tcp": 50000})
                self.assertEqual(self.read_port_file(), "")

    def test_successful_disconnect_deletes_leases_before_the_gateway_disappears(self):
        self.make(file={"PORT_FORWARDING": "on"})
        state = self.native_natpmp()
        self.tick()

        def disconnect():
            with open(os.path.join(self.dir, "natpmpc.disabled"), "w"):
                pass

        self.cli.during[("disconnect",)] = disconnect
        self.sup.request_disconnect()
        self.tick(1)
        with open(state) as f:
            remote = json.load(f)
        self.assertEqual((remote["own"], remote["deletes"]), ({}, ["udp", "tcp"]))
        self.assertEqual(remote["other"], {"udp": 50000, "tcp": 50000})
        self.assertFalse(self.cli.connected)
        self.assertEqual((self.sup.snapshot()["connected"], self.read_port_file()), (False, ""))

    def test_failed_disconnect_deletes_the_mappings_of_the_tunnel_left_up(self):
        self.make(file={"PORT_FORWARDING": "on"})
        state = self.native_natpmp()
        self.tick()
        self.cli.responses[("disconnect",)] = Result(1, "Error: disconnect failed\n")
        self.sup.request_disconnect()
        self.tick(1)
        self.tick(1)
        self.assertTrue(self.cli.connected)
        with open(state) as f:
            remote = json.load(f)
        self.assertEqual((remote["own"], remote["deletes"]), ({}, ["udp", "tcp"]))
        self.assertEqual((self.sup.snapshot()["forwarded_port"], self.read_port_file()), (None, ""))
        self.tick(1)
        with open(state) as f:
            self.assertEqual(json.load(f), remote)  # one deletion, and no new mapping while leaving

    def test_target_change_deletes_old_mappings_before_disconnect(self):
        self.make(file={"PORT_FORWARDING": "on"})
        state = self.native_natpmp()
        self.tick()
        self.assertEqual(self.sup.snapshot()["forwarded_port"], 41404)
        disabled = os.path.join(self.dir, "natpmpc.disabled")

        def disconnect():
            with open(state) as f:
                remote = json.load(f)
            self.assertEqual(remote["own"], {})
            self.assertEqual(remote["other"], {"udp": 50000, "tcp": 50000})
            self.assertEqual((self.sup.snapshot()["forwarded_port"], self.read_port_file()), (None, ""))
            with open(disabled, "w"):
                pass

        self.cli.during[("disconnect",)] = disconnect
        self.cli.during[("connect", "--country", "CH")] = lambda: os.unlink(disabled)
        self.assertEqual(self.apply("COUNTRY", "CH"), (True, "reconnected"))
        self.tick(1)
        with open(state) as f:
            remote = json.load(f)
        self.assertEqual(remote["deletes"], ["udp", "tcp"])
        self.assertEqual(remote["own"], {"udp": 41404, "tcp": 41404})
        self.assertEqual((self.sup.snapshot()["forwarded_port"], self.read_port_file()), (41404, "41404\n"))

    def test_off_deletes_only_this_source_protocols_once_and_on_reacquires(self):
        self.make(file={"PORT_FORWARDING": "on"})
        state = self.native_natpmp()
        disabled = self.native_forwarding_config()
        self.tick()
        self.assertEqual(self.read_port_file(), "41404\n")
        self.assertTrue(self.apply("PORT_FORWARDING", "off")[0])
        self.assertTrue(os.path.exists(disabled))
        self.assertIsNone(self.sup.snapshot()["forwarded_port"])
        self.assertEqual(self.read_port_file(), "")
        self.tick(1)
        self.tick(1)
        with open(state) as f:
            remote = json.load(f)
        self.assertEqual(remote, {"own": {}, "other": {"udp": 50000, "tcp": 50000}, "deletes": ["udp", "tcp"]})
        self.assertTrue(self.cli.connected)
        self.assertTrue(self.apply("PORT_FORWARDING", "on")[0])
        self.tick(1)
        self.assertEqual((self.sup.snapshot()["forwarded_port"], self.read_port_file()), (41404, "41404\n"))

    def test_failed_native_off_keeps_on_saved_and_renews_after_withdrawal(self):
        self.make(file={"PORT_FORWARDING": "on"})
        state = self.native_natpmp()
        disabled = self.native_forwarding_config(off_rc=1)
        self.tick()
        self.assertFalse(self.apply("PORT_FORWARDING", "off")[0])
        self.assertEqual(self.store.effective("PORT_FORWARDING"), "on")
        self.assertFalse(os.path.exists(disabled))
        self.assertEqual((self.sup.snapshot()["forwarded_port"], self.read_port_file()), (None, ""))
        with open(state) as f:
            remote = json.load(f)
        self.assertEqual(remote["own"], {})
        self.assertEqual(remote["deletes"], ["udp", "tcp"])
        self.tick(1)
        self.assertEqual((self.sup.snapshot()["forwarded_port"], self.read_port_file()), (41404, "41404\n"))
        with open(state) as f:
            remote = json.load(f)
        self.assertEqual(remote["own"], {"udp": 41404, "tcp": 41404})
        self.assertEqual(remote["deletes"], ["udp", "tcp"])

    def test_default_forwarding_withdraws_and_deletes_without_forcing_a_native_setting(self):
        self.make(file={"PORT_FORWARDING": "on"})
        state = self.native_natpmp()
        disabled = self.native_forwarding_config()
        self.tick()
        self.assertTrue(self.apply("PORT_FORWARDING", "")[0])
        self.assertEqual(self.store.effective("PORT_FORWARDING"), "")
        self.assertFalse(os.path.exists(disabled))
        self.assertEqual((self.sup.snapshot()["forwarded_port"], self.read_port_file()), (None, ""))
        with open(state) as f:
            remote = json.load(f)
        self.assertEqual(remote["own"], {})
        self.assertEqual(remote["deletes"], ["udp", "tcp"])

    def test_off_rejected_deletions_do_not_restore_publication_or_repeat(self):
        self.make(file={"PORT_FORWARDING": "on"})
        state = self.native_natpmp("sys.exit('gateway refuses deletion')")
        self.tick()
        self.assertTrue(self.apply("PORT_FORWARDING", "off")[0])
        self.assertEqual((self.sup.snapshot()["forwarded_port"], self.read_port_file()), (None, ""))
        self.tick(1)
        with open(state) as f:
            remote = json.load(f)
        self.assertEqual(remote["own"], {"udp": 41404, "tcp": 41404})
        self.assertEqual(remote["deletes"], ["udp", "tcp"])
        self.assertIn("[natpmp] udp deletion failed", self.out.getvalue())
        self.assertIn("[natpmp] tcp deletion failed", self.out.getvalue())

    def test_off_hung_deletions_are_bounded_and_not_retried(self):
        self.make(file={"PORT_FORWARDING": "on"})
        state = self.native_natpmp("time.sleep(20)")
        self.tick()
        begin = time.monotonic()
        self.assertTrue(self.apply("PORT_FORWARDING", "off")[0])
        self.assertLess(time.monotonic() - begin, 6)
        self.assertEqual((self.sup.snapshot()["forwarded_port"], self.read_port_file()), (None, ""))
        self.tick(1)
        with open(state) as f:
            remote = json.load(f)
        self.assertEqual(remote["own"], {"udp": 41404, "tcp": 41404})
        self.assertEqual(remote["deletes"], ["udp", "tcp"])
        self.assertIn("udp deletion failed (rc 124)", self.out.getvalue())
        self.assertIn("tcp deletion failed (rc 124)", self.out.getvalue())

    def test_off_withdraws_before_bounded_deletions_without_holding_state_or_port_locks(self):
        self.enterContext(redirect_stdout(self.out))
        self.make(file={"PORT_FORWARDING": "on"})
        self.tick()
        gate = Gate(Result(0, ""))
        original, timeouts = self.tool, []

        def tool(*argv, timeout=10):
            if argv[:4] == ("natpmpc", "-a", "0", "0"):
                timeouts.append(timeout)
                return gate(0)
            return original(*argv, timeout=timeout)

        self.sup._tool = tool
        results = []
        worker = threading.Thread(target=lambda: results.append(self.sup.apply_setting("PORT_FORWARDING", "off")))
        self.addCleanup(worker.join, 5)
        self.addCleanup(gate.release.set)
        worker.start()
        try:
            self.assertTrue(gate.started.wait(1))
            self.assertEqual((self.sup.snapshot()["forwarded_port"], self.read_port_file()), (None, ""))
            self.sup.request_disconnect()
        finally:
            gate.release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertTrue(results[0][0])
        self.assertEqual(timeouts, [2, 2])
        self.assertFalse(gate.timed_out)

    def test_off_deletes_partial_mapping_after_failed_refresh_and_status_withdrawal(self):
        self.tool.responses[UDP], self.tool.responses[TCP] = mapped(41404), NATPMP_FAILED
        self.make(file={"PORT_FORWARDING": "on"})
        self.tick()
        self.assertEqual((self.sup.snapshot()["forwarded_port"], self.read_port_file()), (None, ""))
        self.cli.responses[("status",)] = Result(1, "unavailable")
        self.tick(30)
        self.assertTrue(self.apply("PORT_FORWARDING", "off")[0])
        deletes = [argv for argv in self.tool.calls if argv[:4] == ("natpmpc", "-a", "0", "0")]
        self.assertEqual(deletes, [("natpmpc", "-a", "0", "0", "udp", "0", "-g", "10.2.0.1")])

    def test_off_does_not_delete_an_expired_mapping(self):
        self.make(file={"PORT_FORWARDING": "on"})
        self.tick()
        self.clock.now += 61
        self.assertTrue(self.apply("PORT_FORWARDING", "off")[0])
        self.assertFalse(any(argv[:4] == ("natpmpc", "-a", "0", "0") for argv in self.tool.calls))

    def test_off_deletes_a_known_remote_lease_after_publication_has_expired(self):
        self.tool.responses[UDP] = self.tool.responses[TCP] = mapped(41404, 120)
        self.make(file={"PORT_FORWARDING": "on"})
        self.tick()
        self.clock.now += 61
        self.timers.fire_live()
        self.assertEqual((self.sup.snapshot()["forwarded_port"], self.read_port_file()), (None, ""))
        self.assertTrue(self.apply("PORT_FORWARDING", "off")[0])
        deletes = [argv for argv in self.tool.calls if argv[:4] == ("natpmpc", "-a", "0", "0")]
        self.assertEqual(deletes, [
            ("natpmpc", "-a", "0", "0", "udp", "0", "-g", "10.2.0.1"),
            ("natpmpc", "-a", "0", "0", "tcp", "0", "-g", "10.2.0.1"),
        ])


class LeaseTest(SupervisorCase):
    """A forwarded port is advertised only while its 60 s mapping lease can still be alive."""

    def setUp(self):
        super().setUp()
        self.tool.responses[UDP] = self.tool.responses[TCP] = mapped(41404)
        self.tool.responses[WG] = Result(0, "KEY\t100\t10\n")
        self.make(environ={"PORT_FORWARDING": "on"})

    def consumer(self):
        return self.sup.snapshot()["forwarded_port"], self.read_port_file()

    def test_a_blocked_cli_does_not_keep_an_expired_lease_advertised(self):
        self.tick()  # the lease runs 1000 to 1060
        self.assertEqual(self.consumer(), (41404, "41404\n"))
        self.assertEqual(self.timers.created[-1].interval, 60)
        seen = []

        def blocked_for_two_minutes():  # a CLI call that ignores the limit it was given
            self.clock.now += 120
            self.timers.fire_live()  # the timer thread, at 1060
            seen.append(self.consumer())

        self.cli.during[("info",)] = blocked_for_two_minutes
        self.tick(30)
        self.assertEqual(seen, [(None, "")])
        self.assertIn("lease ran out", self.out.getvalue())
        self.assertEqual(self.consumer(), (41404, "41404\n"))  # renewed once the loop came back
        self.assertEqual(self.timers.created[-1].interval, 60)

    def test_a_healthy_cli_call_slower_than_a_second_late_in_the_lease_is_no_failure(self):
        self.tick()  # the lease runs 1000 to 1060
        self.cli.slow[("info",)] = self.cli.slow[("status",)] = 1.1
        self.tick(39)  # a state check at lease age 39 s
        snap = self.sup.snapshot()
        self.assertEqual((snap["connected"], snap["last_error"]), (True, ""))
        self.assertEqual(self.consumer(), (41404, "41404\n"))

    def test_a_settings_save_late_in_the_lease_succeeds_and_persists(self):
        self.tick()
        key = ("config", "set", "netshield", "malware")
        self.cli.slow[key] = 1.1
        self.cli.responses[key] = Result(0, "NetShield has been set to malware\n")
        self.clock.now += 39  # lease age 39 s
        self.assertEqual(self.apply("NETSHIELD", "malware"), (True, "NetShield has been set to malware"))
        self.assertEqual(self.store.effective("NETSHIELD"), "malware")
        self.assertEqual(self.consumer(), (41404, "41404\n"))

    def test_a_renewal_comes_before_a_due_state_check(self):
        self.tick()
        self.sup.request_connect()  # makes a check due as well
        renewals = []
        self.cli.during[("info",)] = lambda: renewals.append(self.tool.calls.count(UDP))
        self.tick(46)
        self.assertEqual(renewals, [2])  # the second udp request had already been made when the check began

    def test_the_old_lease_timer_cannot_clear_a_renewed_lease(self):
        self.tick()
        old = self.timers.created[-1]
        self.tick(46)
        self.assertTrue(old.cancelled)
        old.fire()  # it was already running when the renewal cancelled it
        self.assertEqual(self.consumer(), (41404, "41404\n"))
        self.timers.created[-1].fire()  # the current lease runs out without another renewal
        self.assertEqual(self.consumer(), (None, ""))

    def test_time_is_read_again_after_a_slow_connect(self):
        self.cli.connect_duration = 40
        self.tick()
        self.assertEqual(self.timers.created[-1].interval, 60)  # counted from the request at 1040
        self.assertEqual(self.sup.snapshot()["traffic"], [[1040.0, 100, 10]])

    def test_the_shortest_granted_lifetime_expires_for_both_consumers(self):
        for udp, tcp, duration in ((10, 60, 10), (60, 12, 12), (120, 120, 60)):
            with self.subTest(udp=udp, tcp=tcp):
                self.tool.responses[UDP], self.tool.responses[TCP] = mapped(41404, udp), mapped(41404, tcp)
                self.make(environ={"PORT_FORWARDING": "on"})
                self.tick()
                self.assertEqual(self.consumer(), (41404, "41404\n"))
                timer = self.timers.created[-1]
                self.assertEqual(timer.interval, duration)
                self.clock.now += duration
                timer.fire()  # the main loop remains blocked until after this observation
                self.assertEqual(self.consumer(), (None, ""))

    def test_missing_or_zero_granted_lifetime_revokes_an_existing_port(self):
        for response in (Result(0, "Mapped public port 41404 protocol UDP to local port 0\n"), mapped(41404, 0)):
            for failing in (UDP, TCP):
                with self.subTest(output=response.out, protocol=failing[4]):
                    self.tool.responses[UDP] = self.tool.responses[TCP] = mapped(41404)
                    self.make(environ={"PORT_FORWARDING": "on"})
                    self.tick()
                    self.tool.responses[failing] = response
                    self.tick(45)
                    self.assertEqual(self.consumer(), (None, ""))

    def test_a_mapping_already_expired_before_tcp_returns_is_never_published(self):
        self.tool.responses[UDP] = mapped(41404, 1)

        def slow_tcp(n):
            self.clock.now += 2
            return mapped(41404)

        self.tool.responses[TCP] = slow_tcp
        self.tick()
        self.assertEqual(self.consumer(), (None, ""))
        self.assertNotIn("[natpmp] forwarded port", self.out.getvalue())


class HealthCase(SupervisorCase):
    """Operational health runs on its own worker: these tests step `health_tick()` as the others step `tick()`."""

    def setUp(self):
        super().setUp()
        self.socket = self.enterContext(mock.patch("socket.socket"))
        self.socket.return_value.__enter__.return_value.sendto.return_value = 1

    def probe_now(self, advance=0):
        self.clock.now += advance
        with redirect_stdout(self.out):
            self.sup.health_tick()

    def health(self):
        snap = self.sup.snapshot()
        return snap["tunnel_healthy"], snap["health_error"], snap["health_checked_ago"]

    def docker_says_healthy(self):
        return is_healthy(self.health_file, clock=self.clock)

    def health_lines(self):
        return [line for line in self.out.getvalue().splitlines() if line.startswith("[health]")]

    def worker(self, gate):
        """A health worker held inside its probe by `gate`."""
        self.tool.responses[PROBE] = gate
        thread = threading.Thread(target=self.sup.health_tick)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(gate.release.set)  # runs first: a failed test must not leave the thread waiting
        self.assertTrue(gate.started.wait(5))
        return thread

    def finish(self, gate, worker):
        with redirect_stdout(self.out):
            gate.release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())


class HealthTest(HealthCase):
    def test_a_connection_is_unchecked_until_the_first_probe_which_follows_at_once(self):
        self.make()
        self.assertEqual(self.health(), (False, "", None))  # nothing connected
        self.tick()
        self.assertEqual((self.sup.snapshot()["connected"], self.health()), (True, (None, "", None)))
        self.assertFalse(self.docker_says_healthy())
        self.assertNotIn(PROBE, self.tool.calls)  # the loop's state check never waits for the network
        self.probe_now()
        self.assertEqual((self.health(), self.docker_says_healthy()), ((True, "", 0.0), True))

    def test_probes_repeat_every_30_seconds_counted_from_the_end_of_the_last(self):
        self.make()
        self.tick()
        for advance, calls in ((0, 1), (29, 1), (1, 2), (29, 2), (1, 3)):
            self.probe_now(advance)
            self.assertEqual(self.tool.calls.count(PROBE), calls)

    def test_nothing_is_probed_while_not_connected(self):
        self.cli.signed_in = False
        self.make()
        self.tick()
        self.probe_now()
        self.assertEqual((PROBE in self.tool.calls, self.health()), (False, (False, "", None)))

    def test_failed_echo_with_live_handshake_leaves_connection_port_and_native_error_alone(self):
        self.tool.responses[UDP] = self.tool.responses[TCP] = mapped(41404)
        self.make(environ={"PORT_FORWARDING": "on"})
        self.tick()
        self.tool.responses[PROBE] = BIND_FAILED
        self.tool.responses[HANDSHAKE] = lambda n: Result(0, f"peer\t{100 + n}\n")
        self.probe_now()
        snap = self.sup.snapshot()
        reason = snap["health_error"]
        self.assertEqual((snap["connected"], snap["tunnel_healthy"]), (True, False))
        self.assertTrue(reason)
        self.assertEqual((snap["last_error"], snap["forwarded_port"], self.read_port_file()), ("", 41404, "41404\n"))
        self.assertFalse(self.docker_says_healthy())
        self.tick(30)  # the state check still reads Connected and keeps the verdict: no reconnect is asked for
        self.assertEqual((self.sup.snapshot()["connected"], self.health()), (True, (False, reason, 30.0)))
        for _ in range(7):
            self.probe_now(30)
            self.tick()
        self.tool.responses[PROBE] = PROBE_OK
        self.probe_now(30)
        self.assertEqual((self.health(), self.docker_says_healthy()), ((True, "", 0.0), True))
        self.assertEqual((len(self.cli.argvs("connect")), self.cli.argvs("disconnect")), (1, []))
        self.assertEqual(len(self.health_lines()), 2)  # failure and recovery only

    def test_timeout_timing_does_not_turn_one_outage_into_repeated_log_events(self):
        self.make()
        self.tick()
        first = Result(28, "curl: (28) Resolving timed out after 5000 milliseconds\n")
        second = Result(28, "curl: (28) Resolving timed out after 5001 milliseconds\n")
        self.tool.responses[PROBE] = [first, second, first, BIND_FAILED, BIND_FAILED, PROBE_OK, PROBE_OK]
        for _ in range(7):
            self.probe_now(30)
        self.assertEqual(len(self.health_lines()), 3)  # timeout, changed cause, recovery
        self.assertTrue(self.sup.snapshot()["tunnel_healthy"])
        self.assertTrue(self.docker_says_healthy())

    def test_invalid_tool_bytes_become_a_visible_failed_probe_not_an_unhandled_decoder_error(self):
        self.make()
        self.tick()
        fake_curl = os.path.join(self.dir, "curl")
        with open(fake_curl, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\n" + r"printf '\377'" + "\n")
        os.chmod(fake_curl, 0o755)
        raw_result = run_tool(fake_curl)
        self.assertEqual(raw_result.rc, 0)
        self.assertIsInstance(raw_result.out, str)
        self.sup._tool = run_tool
        with mock.patch.dict(os.environ, {"PATH": self.dir + os.pathsep + os.environ["PATH"]}):
            self.probe_now()
        snap = self.sup.snapshot()
        self.assertEqual((snap["connected"], snap["tunnel_healthy"], snap["last_error"]), (True, False, ""))
        self.assertTrue(snap["health_error"])
        self.assertFalse(self.docker_says_healthy())

    def test_a_pass_vouches_for_60_seconds_only(self):
        self.make()
        self.tick()
        self.probe_now()
        self.clock.now += 60
        self.assertEqual((self.health(), self.docker_says_healthy()), ((True, "", 60.0), True))
        self.clock.now += 1
        healthy, error, ago = self.health()
        self.assertEqual((healthy, ago, self.sup.snapshot()["connected"], self.docker_says_healthy()), (False, 61.0, True, False))
        self.assertTrue(error)

    def test_a_disconnect_request_revokes_a_fresh_pass_before_the_loop_does_anything(self):
        self.make()
        self.tick()
        self.probe_now()
        self.assertTrue(self.docker_says_healthy())
        self.sup.request_disconnect()
        self.assertEqual((self.health(), self.docker_says_healthy()), ((False, "", None), False))

    def test_an_unreadable_or_ended_connection_supersedes_a_fresh_pass_and_is_checked_anew(self):
        self.make()
        self.tick()
        self.probe_now()
        self.cli.responses[("info",)] = Result(124, "protonvpn timed out after 120s\n")  # the CLI cannot vouch for it
        self.tick(30)
        self.assertEqual((self.health(), self.docker_says_healthy()), ((False, "", None), False))
        del self.cli.responses[("info",)]
        self.tick(30)
        self.assertEqual(self.health(), (None, "", None))  # connected again, not yet checked
        self.probe_now()
        self.assertEqual((self.health(), self.docker_says_healthy()), ((True, "", 0.0), True))
        self.cli.connected, self.cli.connect_rc = False, 1  # the tunnel drops and the reconnect fails
        self.tick(30)
        self.assertEqual((self.health(), self.docker_says_healthy()), ((False, "", None), False))
        self.assertEqual(len(self.cli.argvs("connect")), 2)  # the one failed attempt is the loop's, not a probe's

    def test_a_late_result_after_a_disconnect_restores_neither_health_nor_the_exit_ip(self):
        self.cli.connected = True  # adopted: with no connect output the probe would supply the exit IP
        self.make()
        self.tick()
        gate = Gate(PROBE_OK)
        worker = self.worker(gate)
        self.sup.request_disconnect()
        self.cli.connected = False
        self.tick(30)
        self.finish(gate, worker)
        snap = self.sup.snapshot()
        self.assertEqual((snap["connected"], snap["tunnel_healthy"], snap["exit_ip"]), (False, False, ""))
        self.assertFalse(self.docker_says_healthy())
        self.assertEqual(self.health_lines(), [])

    def test_a_late_result_of_the_old_connection_is_not_the_new_connections(self):
        self.make()
        self.tick()
        gate = Gate(PROBE_OK)
        worker = self.worker(gate)
        self.cli.connected = False  # the tunnel drops; the loop reconnects while the probe is still out
        self.tick(30)
        self.assertEqual(len(self.cli.argvs("connect")), 2)
        self.finish(gate, worker)
        self.assertEqual((self.health(), self.docker_says_healthy()), ((None, "", None), False))
        self.probe_now()  # the new connection is probed on its own
        self.assertEqual((self.health(), self.docker_says_healthy()), ((True, "", 0.0), True))

    def test_a_slow_probe_delays_neither_the_loop_nor_the_port_lease(self):
        self.tool.responses[UDP] = self.tool.responses[TCP] = mapped(41404)
        self.make(environ={"PORT_FORWARDING": "on"})
        self.tick()
        gate = Gate(PROBE_OK)
        worker = self.worker(gate)
        self.tick(45)  # the renewal falls due while the probe waits for the network
        snap = self.sup.snapshot()
        self.assertEqual(self.tool.calls.count(UDP), 2)
        self.assertEqual((snap["connected"], snap["tunnel_healthy"], snap["forwarded_port"]), (True, None, 41404))
        self.finish(gate, worker)
        self.assertFalse(gate.timed_out)  # nothing the loop did had to wait for the probe
        self.assertEqual(self.health(), (True, "", 0.0))

    def test_a_verdict_written_late_cannot_overwrite_a_revocation(self):
        self.make()
        self.tick()
        written, entered, proceed, write = [], threading.Event(), threading.Event(), write_health

        def slow_first_write(path, healthy, stamp):
            written.append(healthy)
            if len(written) == 1:  # the worker's pass: it is still being written when the disconnect revokes it
                entered.set()
                proceed.wait(5)
            write(path, healthy, stamp)

        with redirect_stdout(self.out), mock.patch(f"{SUPERVISOR}.write_health", side_effect=slow_first_write):
            worker = threading.Thread(target=self.sup.health_tick)
            worker.start()
            self.assertTrue(entered.wait(5))
            revoke = threading.Thread(target=self.sup.request_disconnect)
            revoke.start()
            for _ in range(500):  # the revocation has changed the state, and waits for the file
                if not self.sup.snapshot()["connected"]:
                    break
                time.sleep(0.01)
            proceed.set()
            worker.join(5)
            revoke.join(5)
        self.assertEqual(written, [True, False])
        self.assertFalse(self.docker_says_healthy())

    def test_an_unwritable_health_file_is_logged_once_and_changes_nothing_else(self):
        self.health_file = os.path.join(self.dir, "missing", "health.json")
        self.make()
        self.tick()
        self.probe_now()
        self.probe_now(30)
        self.assertEqual(self.health(), (True, "", 0.0))
        self.assertEqual(self.out.getvalue().count("[health] cannot write"), 1)
        self.assertFalse(self.docker_says_healthy())


class RecoveryTest(HealthCase):
    def stuck(self, handshake=0, environ=None):
        self.make(environ=environ)
        self.tick()
        self.tool.responses[PROBE] = TIMED_OUT
        self.tool.responses[HANDSHAKE] = Result(0, f"peer\t{handshake}\n")
        self.probe_now()

    def queue_recovery(self):
        for _ in range(6):
            self.probe_now(30)

    def test_stale_or_zero_handshake_queues_once_after_180_seconds_and_keeps_credentials_and_target(self):
        for handshake in (0, 123):
            with self.subTest(handshake=handshake):
                self.setUp()
                self.stuck(handshake, {"COUNTRY": "Netherlands"})
                original = self.cli.argvs("connect")[0]
                self.probe_now(150)
                self.probe_now(29)
                self.tick()
                self.assertEqual(len(self.cli.argvs("connect")), 1)
                self.probe_now(1)
                self.assertEqual(self.cli.argvs("disconnect"), [])  # worker only queues
                self.tick()
                self.assertEqual(self.cli.argvs("connect"), [original, original])
                self.assertEqual(self.cli.argvs("disconnect"), [("disconnect",)])
                self.assertEqual(self.cli.argvs("signin") + self.cli.argvs("signout"), [])
                self.assertTrue(self.sup.snapshot()["connected"])
                self.assertEqual(self.store.effective("COUNTRY"), "Netherlands")
                self.tick()
                self.assertEqual(len(self.cli.argvs("connect")), 2)

    def test_ipify_dns_outage_with_advancing_handshake_never_reconnects(self):
        self.stuck(123)
        self.tool.responses[HANDSHAKE] = lambda n: Result(0, f"peer\t{123 + n}\n")
        for _ in range(10):
            self.probe_now(30)
            self.tick()
        self.assertEqual((len(self.cli.argvs("connect")), self.cli.argvs("disconnect")), (1, []))
        self.assertFalse(self.sup.snapshot()["tunnel_healthy"])

    def test_successful_echo_or_advancing_handshake_cancels_queued_recovery(self):
        for live_echo in (True, False):
            with self.subTest(live_echo=live_echo):
                self.setUp()
                self.stuck()
                self.queue_recovery()
                if live_echo:
                    self.tool.responses[PROBE] = PROBE_OK
                else:
                    self.tool.responses[HANDSHAKE] = Result(0, "peer\t1\n")
                self.probe_now(30)
                self.tick()
                self.assertEqual((len(self.cli.argvs("connect")), self.cli.argvs("disconnect")), (1, []))

    def test_unknown_wireguard_or_failed_stimulus_does_not_accumulate_dead_evidence(self):
        for result, stimulus_ok in ((Result(124, "timeout"), True), (Result(0, ""), True),
                                     (Result(0, "malformed"), True), (Result(0, "peer\t0\n"), False)):
            with self.subTest(result=result, stimulus_ok=stimulus_ok):
                self.setUp()
                self.stuck()
                self.tool.responses[HANDSHAKE] = result
                self.socket.return_value.__enter__.return_value.sendto.side_effect = None if stimulus_ok else OSError("no route")
                self.probe_now(180)
                self.tick()
                self.assertEqual(self.cli.argvs("disconnect"), [])
                self.tool.responses[HANDSHAKE] = Result(0, "peer\t0\n")
                self.socket.return_value.__enter__.return_value.sendto.side_effect = None
                self.probe_now(30)
                self.tick()
                self.assertEqual(self.cli.argvs("disconnect"), [])

    def test_new_generation_and_successful_echo_restart_the_evidence_grace(self):
        for new_connection in (True, False):
            with self.subTest(new_connection=new_connection):
                self.setUp()
                self.stuck()
                self.probe_now(150)
                if new_connection:
                    self.cli.connected = False
                    self.tick()
                else:
                    self.tool.responses[PROBE] = PROBE_OK
                    self.probe_now(30)
                    self.tool.responses[PROBE] = TIMED_OUT
                expected = len(self.cli.argvs("connect"))
                self.probe_now(30)
                self.probe_now(150)
                self.tick()
                self.assertEqual(len(self.cli.argvs("connect")), expected)

    def test_intent_changes_cancel_queued_recovery(self):
        for intent in ("disconnect", "signout", "stop"):
            with self.subTest(intent=intent):
                self.setUp()
                self.stuck()
                self.queue_recovery()
                with redirect_stdout(self.out):
                    if intent == "disconnect":
                        self.sup.request_disconnect()
                    elif intent == "signout":
                        self.sup.sign_out()
                    else:
                        self.sup.stop()
                before = len(self.cli.argvs("disconnect"))
                self.tick()
                self.assertEqual(len(self.cli.argvs("connect")), 1)
                self.assertLessEqual(len(self.cli.argvs("disconnect")), before + (intent == "disconnect"))

    def test_failed_recovery_backoff_survives_native_connected_and_further_probes(self):
        for disconnect_fails in (True, False):
            with self.subTest(disconnect_fails=disconnect_fails):
                self.setUp()
                self.stuck()
                self.queue_recovery()
                if disconnect_fails:
                    self.cli.responses[("disconnect",)] = Result(124, "disconnect timed out")
                    self.cli.slow[("disconnect",)] = 9
                else:
                    self.cli.connect_rc = 1
                    self.cli.connect_duration = 7
                for delay in (30, 60, 120, 300):
                    self.tick()
                    completed = self.clock.now
                    attempts = len(self.cli.argvs("disconnect"))
                    self.assertFalse(self.sup.snapshot()["connected"])
                    self.cli.connected = True  # native Error retains a connection object
                    self.sup.notify_signed_in()  # unrelated wake-up cannot defeat the recovery deadline
                    self.probe_now(delay - 1)
                    self.tick()
                    self.assertEqual(len(self.cli.argvs("disconnect")), attempts)
                    self.tick(1)
                    self.assertEqual(self.cli.times("disconnect")[-1], completed + delay)
                    if disconnect_fails:
                        self.assertEqual(len(self.cli.argvs("connect")), 1)
                self.assertTrue(all(timeout == 5 for args, timeout in self.cli.timeouts if args == ("disconnect",)))

    def test_invalid_native_settings_are_preserved_and_block_recovery_with_backoff(self):
        for raw in ('{"protocol": "openvpn-tcp",', '["openvpn-tcp"]', '\ud800'):
            with self.subTest(raw=raw):
                self.setUp()
                self.cli.connected = True
                self.stuck()  # adopt the connection, leaving the kill-switch deferred
                applied = self.cli.argvs("config")
                ks = ("config", "set", "kill-switch", "standard")
                self.assertNotIn(ks, applied)
                os.makedirs(os.path.dirname(self.native_settings), exist_ok=True)
                original = raw.encode("utf-8", errors="surrogatepass")
                with open(self.native_settings, "wb") as f:
                    f.write(original)

                def overwrite_native():
                    with open(self.native_settings, "w") as f:
                        json.dump({}, f)

                self.cli.during[ks] = overwrite_native  # native setters can replace malformed JSON with defaults
                self.queue_recovery()
                started = self.clock.now
                for advance, attempts in ((0, 1), (29, 1), (1, 2)):
                    self.tick(advance)
                    self.assertEqual(len(self.cli.argvs("disconnect")), attempts)
                    self.assertEqual(self.cli.argvs("config"), applied)
                    self.assertEqual(self.cli.argvs("connect"), [])
                    snap = self.sup.snapshot()
                    self.assertFalse(snap["connected"])
                    self.assertIn("cannot set the wireguard protocol", snap["last_error"])
                    with open(self.native_settings, "rb") as f:
                        self.assertEqual(f.read(), original)
                self.assertEqual(self.cli.times("disconnect"), [started, started + 30])

    def test_recovery_revokes_publication_before_disconnect_and_preserves_late_connect_compensation(self):
        self.tool.responses[UDP] = self.tool.responses[TCP] = mapped(41404)
        self.stuck(environ={"PORT_FORWARDING": "on"})
        self.queue_recovery()

        def during_disconnect():
            snap = self.sup.snapshot()
            self.assertEqual((snap["connected"], snap["forwarded_port"], snap["tunnel_healthy"]), (False, None, False))
            self.assertEqual(self.read_port_file(), "")
            self.assertFalse(self.docker_says_healthy())

        self.cli.during[("disconnect",)] = during_disconnect
        original = self.cli.argvs("connect")[0]
        self.cli.during[original] = self.sup.request_disconnect
        self.tick()
        self.assertFalse(self.sup.snapshot()["connected"])
        self.assertEqual(len(self.cli.argvs("disconnect")), 2)

    def test_late_handshake_result_cannot_recover_a_replacement_connection(self):
        self.stuck()
        self.probe_now(150)
        gate = Gate(Result(0, "peer\t0\n"))
        self.tool.responses[HANDSHAKE] = gate
        self.clock.now += 30
        worker = threading.Thread(target=self.sup.health_tick)
        worker.start()
        self.addCleanup(worker.join, 5)
        self.addCleanup(gate.release.set)
        self.assertTrue(gate.started.wait(5))
        self.cli.connected = False
        self.tick()
        self.finish(gate, worker)
        self.tick()
        self.assertEqual((len(self.cli.argvs("connect")), self.cli.argvs("disconnect")), (2, []))

    def test_slow_handshake_observation_blocks_neither_cli_nor_port_renewal(self):
        self.tool.responses[UDP] = self.tool.responses[TCP] = mapped(41404)
        self.stuck(environ={"PORT_FORWARDING": "on"})
        gate = Gate(Result(0, "peer\t0\n"))
        self.tool.responses[HANDSHAKE] = gate
        self.clock.now += 30
        worker = threading.Thread(target=self.sup.health_tick)
        worker.start()
        self.addCleanup(worker.join, 5)
        self.addCleanup(gate.release.set)
        self.assertTrue(gate.started.wait(5))
        self.tick(15)
        self.assertEqual(self.tool.calls.count(UDP), 2)
        self.assertEqual(self.sup.snapshot()["forwarded_port"], 41404)
        self.finish(gate, worker)
        self.assertFalse(gate.timed_out)


class ExitIpTest(HealthCase):
    """A connection whose connect output we never saw (adopted at start, or made by hand) gets its exit IP from the probe."""

    IP = ECHO_IP

    def adopt(self):
        self.cli.connected = True
        self.make()

    def exit_ip(self):
        return self.sup.snapshot()["exit_ip"]

    def test_an_adopted_connection_gets_its_exit_ip_from_the_probe(self):
        self.adopt()
        self.tick()
        self.assertEqual((self.exit_ip(), self.cli.argvs("connect"), PROBE in self.tool.calls), ("", [], False))
        self.probe_now()
        self.assertEqual(self.exit_ip(), self.IP)
        self.assertIn(f"exit IP {self.IP}", self.out.getvalue())

    def test_the_connect_output_stays_the_primary_source(self):
        self.make()
        self.tick()
        self.probe_now()
        self.probe_now(30)
        self.assertEqual(self.exit_ip(), "205.147.16.78")

    def test_a_failed_probe_finds_no_exit_ip_and_a_later_one_does(self):
        self.adopt()
        self.tick()
        self.tool.responses[PROBE] = [BIND_FAILED, TIMED_OUT, PROBE_OK]
        for expected in ("", "", self.IP):
            self.probe_now(30)
            snap = self.sup.snapshot()
            self.assertEqual((snap["connected"], snap["last_error"], snap["exit_ip"]), (True, "", expected))

    def test_an_exit_ip_is_forgotten_with_its_connection_and_found_again(self):
        self.adopt()
        self.tick()
        self.probe_now()
        self.assertEqual(self.exit_ip(), self.IP)
        self.cli.connected, self.cli.connect_rc = False, 1  # the tunnel drops and our reconnect fails
        self.tick(30)
        snap = self.sup.snapshot()
        self.assertEqual((snap["connected"], snap["exit_ip"]), (False, ""))
        self.cli.connected = True  # one made by hand while we back off
        self.tick(30)
        self.assertEqual(self.exit_ip(), "")
        self.tool.responses[PROBE] = Result(0, "205.147.16.99\n")
        self.probe_now()
        self.assertEqual(self.exit_ip(), "205.147.16.99")


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

    def test_failed_check_breaks_traffic_continuity_even_if_the_replacement_counters_are_larger(self):
        self.make()
        self.tool.responses[WG] = [Result(0, "OLD\t100\t10\n"), Result(0, "NEW\t10000\t1000\n")]
        self.tick()
        self.assertEqual(self.sup.snapshot()["traffic"], [[1000.0, 100, 10]])
        self.cli.responses[("status",)] = Result(1, "agent unavailable\n")
        self.tick(30)
        self.assertEqual(self.sup.snapshot()["traffic"], [])
        self.assertEqual(self.sup.snapshot()["account"], "me@proton.me")
        del self.cli.responses[("status",)]
        self.tick(30)
        self.assertEqual(self.sup.snapshot()["traffic"], [[1060.0, 10000, 1000]])


class StopTest(SupervisorCase):
    def test_stop_disconnects_and_joins(self):
        self.make()
        self.tick()
        with redirect_stdout(self.out):
            self.sup.start()
            self.sup.stop()
        self.assertIn(("disconnect",), self.cli.argvs("disconnect"))
        self.assertFalse(self.sup._thread.is_alive())
        self.assertFalse(self.sup._health_thread.is_alive())

    def test_stop_respects_the_time_it_is_given(self):
        self.make()
        self.sup.stop(timeout=2)
        self.assertEqual(self.cli.timeouts[-1], (("disconnect",), 2))
        self.sup.stop()
        self.assertEqual(self.cli.timeouts[-1], (("disconnect",), 5))

    def test_stop_during_connect_is_bounded_and_a_late_success_is_disconnected(self):
        self.enterContext(redirect_stdout(self.out))
        self.tool.responses[UDP] = self.tool.responses[TCP] = mapped(41404)
        self.make(environ={"PORT_FORWARDING": "on"})
        started, release = threading.Event(), threading.Event()

        def hold_connect():
            started.set()
            release.wait(10)

        self.cli.during[("connect",)] = hold_connect
        worker = threading.Thread(target=self.sup.tick)
        self.sup._thread = worker
        self.addCleanup(worker.join, 5)
        self.addCleanup(release.set)
        worker.start()
        self.assertTrue(started.wait(5))
        begin = time.monotonic()
        self.sup.stop(timeout=0.1)
        self.assertLess(time.monotonic() - begin, 1)
        self.assertTrue(worker.is_alive())  # stop did not wait for the CLI mutation lock
        release.set()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertFalse(self.cli.connected)  # the late connect must not outlive shutdown
        snap = self.sup.snapshot()
        self.assertEqual((snap["connected"], snap["tunnel_healthy"], snap["forwarded_port"]), (False, False, None))
        self.assertEqual(self.read_port_file(), "")
        self.assertEqual(self.tool.calls.count(UDP), 0)
        self.assertEqual(len(self.cli.argvs("disconnect")), 2)


class HealthStopTest(HealthCase):
    def test_stop_revokes_a_fresh_pass(self):
        self.make()
        self.tick()
        self.probe_now()
        self.assertTrue(self.docker_says_healthy())
        with redirect_stdout(self.out):
            self.sup.stop()
        self.assertEqual((self.health(), self.docker_says_healthy()), ((False, "", None), False))

    def test_start_revokes_what_an_earlier_run_left_in_the_file(self):
        self.cli.signed_in = False  # nothing to connect: the loop stays quiet
        self.make()
        write_health(self.health_file, True, self.clock.now)
        self.assertTrue(self.docker_says_healthy())
        with redirect_stdout(self.out):
            self.sup.start()
            self.assertFalse(self.docker_says_healthy())
            self.sup.stop()

    def test_stop_stays_within_its_budget_while_a_probe_hangs_and_the_late_pass_is_dropped(self):
        self.make()
        self.tick()
        gate = Gate(PROBE_OK)
        self.tool.responses[PROBE] = gate
        self.addCleanup(gate.release.set)
        with redirect_stdout(self.out):
            self.sup.start()
            self.assertTrue(gate.started.wait(5))
            begin = time.monotonic()
            self.sup.stop(timeout=0.5)
            self.assertLess(time.monotonic() - begin, 3)
            self.assertEqual((self.health(), self.docker_says_healthy()), ((False, "", None), False))
            gate.release.set()
            self.sup._health_thread.join(5)
        self.assertFalse(self.sup._health_thread.is_alive())
        self.assertEqual((self.health(), self.docker_says_healthy(), self.health_lines()), ((False, "", None), False, []))


class ProtocolTest(SupervisorCase):
    """Only WireGuard: Proton's saved protocol picks the backend of every connect, and the CLI has no command for it."""

    def save_native(self, data):
        os.makedirs(os.path.dirname(self.native_settings), exist_ok=True)
        with open(self.native_settings, "w") as f:
            json.dump(data, f)

    def test_connect_saves_wireguard_and_keeps_the_other_native_settings(self):
        self.make()
        self.save_native({"protocol": "openvpn-tcp", "killswitch": 1})
        self.tick()
        self.assertEqual(self.cli.protocol, "wireguard")
        with open(self.native_settings) as f:
            self.assertEqual(json.load(f), {"protocol": "wireguard", "killswitch": 1})
        self.assertEqual(stat.S_IMODE(os.stat(self.native_settings).st_mode), 0o600)
        self.assertEqual(self.sup.snapshot()["protocol"], "wireguard")

    def test_nothing_saved_connects_over_wireguard_not_the_tier_default(self):
        self.make()
        self.tick()
        self.assertEqual((self.cli.protocol, self.sup.snapshot()["connected"]), ("wireguard", True))

    def test_an_adopted_openvpn_tunnel_is_replaced_by_wireguard(self):
        self.cli.connected, self.cli.protocol = True, "openvpn-udp"
        self.make()
        self.tick()
        self.assertEqual(len(self.cli.argvs("disconnect")), 1)
        self.assertFalse(self.sup.snapshot()["connected"])
        self.tick(30)
        self.assertEqual(self.cli.protocol, "wireguard")
        snap = self.sup.snapshot()
        self.assertEqual((snap["connected"], snap["protocol"], snap["last_error"]), (True, "wireguard", ""))

    def test_an_unsupported_tunnel_that_will_not_disconnect_is_never_vouched_for(self):
        self.cli.connected, self.cli.protocol = True, "openvpn-tcp"
        self.cli.responses[("disconnect",)] = Result(1, "Error: disconnect failed\n")
        self.make(file={"PORT_FORWARDING": "on"})
        self.tick()
        self.tick(1)
        snap = self.sup.snapshot()
        self.assertEqual((snap["connected"], snap["forwarded_port"]), (False, None))
        self.assertIn("openvpn-tcp", snap["last_error"])
        self.assertEqual((self.cli.argvs("connect"), [a for a in self.tool.calls if a[0] == "natpmpc"]), ([], []))
        self.tick(30)
        self.assertEqual(len(self.cli.argvs("disconnect")), 2)  # tried again at the next check

    def test_a_protocol_that_cannot_be_saved_stops_the_connect(self):
        self.make()
        os.makedirs(self.native_settings)  # unreadable as a file
        self.tick()
        self.assertEqual(self.cli.argvs("connect"), [])
        self.assertIn("cannot set the wireguard protocol", self.sup.snapshot()["last_error"])

    def test_unsupported_adoption_is_not_published_during_disconnect(self):
        self.make()
        self.cli.connected, self.cli.protocol = True, "openvpn-tcp"
        seen = []
        self.cli.during[("disconnect",)] = lambda: seen.append(self.sup.snapshot())
        self.tick()
        self.assertTrue(seen)
        self.assertFalse(seen[0]["connected"])
        self.assertIsNone(seen[0]["forwarded_port"])

    def test_connect_rejects_a_non_wireguard_result_even_after_pinning(self):
        self.make(file={"PORT_FORWARDING": "on"})
        # Simulate native code ignoring the saved preference, or a console writer racing it.
        self.cli.responses[("status",)] = [
            Result(0, "Status: Disconnected\n"),
            Result(0, STATUS_UP.replace("wireguard", "openvpn-tcp")),
        ]
        self.tick()
        self.assertFalse(self.sup.snapshot()["connected"])
        self.assertIsNone(self.sup.snapshot()["forwarded_port"])
        self.assertEqual(len(self.cli.argvs("disconnect")), 1)
        self.assertIn("openvpn-tcp", self.sup.snapshot()["last_error"])

    def test_invalid_native_settings_are_preserved_and_block_connect(self):
        for raw in ('{"protocol": "openvpn-tcp",', '["openvpn-tcp"]', '\ud800'):
            with self.subTest(raw=raw):
                self.make()
                os.makedirs(os.path.dirname(self.native_settings), exist_ok=True)
                original = raw.encode("utf-8", errors="surrogatepass")
                with open(self.native_settings, "wb") as f:
                    f.write(original)
                # Native config set ignores malformed JSON and can persist defaults; it must not run first.
                self.cli.during[("config", "set", "anonymous-crash-reports", "off")] = lambda: self.save_native({})
                self.tick()
                self.assertEqual(self.cli.argvs("connect"), [])
                with open(self.native_settings, "rb") as f:
                    self.assertEqual(f.read(), original)

    def test_protocol_rejection_replaces_the_previous_check_failure(self):
        self.make()
        self.tick()
        self.cli.responses[("status",)] = Result(124, "state query timed out")
        self.tick(30)
        self.assertIn("state query timed out", self.sup.snapshot()["last_error"])
        del self.cli.responses[("status",)]
        self.cli.protocol = "openvpn-tcp"
        self.tick(30)
        self.assertIn("openvpn-tcp", self.sup.snapshot()["last_error"])
        self.assertFalse(self.sup.snapshot()["connected"])

    def test_cancellation_during_protocol_verification_keeps_the_selected_target(self):
        for phase in ("status", "rejection"):
            with self.subTest(cancel_during=phase):
                self.cli.responses.clear()
                self.cli.during.clear()
                self.cli.connected = False
                self.make(file={"COUNTRY": "NL"})
                self.tick()
                self.cli.responses[("status",)] = Result(0, STATUS_UP.replace("wireguard", "openvpn-tcp"))

                def status():
                    if phase == "status":
                        self.sup.request_disconnect()
                    else:
                        self.cli.during[("disconnect",)] = self.sup.request_disconnect

                self.cli.during[("status",)] = status
                ok, _ = self.apply("COUNTRY", "CH")
                self.assertTrue(ok)
                self.assertEqual(self.store.effective("COUNTRY"), "CH")
                self.assertFalse(self.sup.snapshot()["connected"])
                self.assertIsNone(self.sup.snapshot()["forwarded_port"])
                self.cli.responses.clear()
                self.cli.during.clear()
                self.sup.request_connect()
                self.tick(1)
                self.assertEqual(self.cli.argvs("connect")[-1], ("connect", "--country", "CH"))
                self.assertTrue(self.sup.snapshot()["connected"])



if __name__ == "__main__":
    unittest.main()


class CountersTest(HealthCase):
    def counters(self):
        return self.sup.snapshot()["counters"]

    def test_connect_attempts_count_failures_and_successes(self):
        self.make()
        self.cli.connect_rc = 1
        self.next_connect()
        self.next_connect()
        self.cli.connect_rc = 0
        self.next_connect()
        self.assertEqual(
            (self.counters()["connect_attempts_total"], self.counters()["connect_failures_total"]), (3, 2)
        )

    def test_a_wanted_tunnel_that_is_down_counts_as_failed_checks_every_30_seconds(self):
        def checks():
            return self.counters()["health_checks_total"], self.counters()["health_check_failures_total"]

        self.make()
        self.tick()
        self.probe_now()
        self.assertEqual(checks(), (1, 0))
        self.tool.responses[PROBE] = TIMED_OUT
        self.probe_now(30)
        self.assertEqual(checks(), (2, 1))
        self.cli.connected = False
        self.cli.connect_rc = 1
        self.tick(30)  # the reconnect fails: no tunnel, so no probe
        calls = self.tool.calls.count(PROBE)
        for advance, expected in ((0, (3, 2)), (10, (3, 2)), (20, (4, 3))):
            self.probe_now(advance)
            self.assertEqual(checks(), expected)
        self.assertEqual(self.tool.calls.count(PROBE), calls)
        self.sup.request_disconnect()  # an intentional disconnect is not downtime
        self.probe_now(30)
        self.assertEqual(checks(), (4, 3))

    def test_nothing_is_counted_while_signed_out(self):
        self.cli.signed_in = False
        self.make()
        self.tick()
        self.probe_now()
        self.probe_now(30)
        self.assertEqual((self.counters()["health_checks_total"], self.counters()["health_check_failures_total"]), (0, 0))

    def test_each_stalled_tunnel_recovery_is_counted(self):
        self.make()
        self.tick()
        self.tool.responses[PROBE] = TIMED_OUT
        self.tool.responses[HANDSHAKE] = Result(0, "peer\t0\n")
        self.probe_now()
        self.probe_now(150)
        self.probe_now(30)
        self.assertEqual(self.counters()["recovery_attempts_total"], 0)
        self.tick()
        self.assertEqual(self.counters()["recovery_attempts_total"], 1)
        self.assertEqual(len(self.cli.argvs("connect")), 2)
