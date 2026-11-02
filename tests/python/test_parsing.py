import unittest

from protonvpn_container.parsing import (
    Status,
    parse_account,
    parse_exit_ip,
    parse_natpmp_port,
    parse_status,
    parse_wg_transfer,
)

STATUS_CONNECTED = "Status: Connected\nServer: NL#914 in Amsterdam, Netherlands\nLoad: 31%\nProtocol: wireguard\n"
CONNECT_OUT = "Connected to NL#810 in Amsterdam, Netherlands. \nYour new IP address is 205.147.16.78.\n"


class ParseStatusTest(unittest.TestCase):
    def test_connected(self):
        self.assertEqual(
            parse_status(STATUS_CONNECTED),
            Status(
                connected=True,
                server="NL#914",
                location="Amsterdam, Netherlands",
                load="31%",
                protocol="wireguard",
            ),
        )

    def test_disconnected(self):
        self.assertEqual(parse_status("Status: Disconnected\n"), Status())


class ParseExitIpTest(unittest.TestCase):
    def test_exit_ip(self):
        self.assertEqual(parse_exit_ip(CONNECT_OUT), "205.147.16.78")

    def test_missing(self):
        self.assertEqual(parse_exit_ip("Connecting...\n"), "")


class ParseNatpmpPortTest(unittest.TestCase):
    def test_mapped(self):
        out = "Mapped public port 41404 protocol TCP to local port 0 lifetime 60\n"
        self.assertEqual(parse_natpmp_port(out), 41404)

    def test_failure(self):
        out = "readnatpmpresponseorretry() failed : the gateway does not support nat-pmp\n"
        self.assertIsNone(parse_natpmp_port(out))


class ParseWgTransferTest(unittest.TestCase):
    def test_one_peer(self):
        self.assertEqual(parse_wg_transfer("KEY\t1000\t2000\n"), (1000, 2000))

    def test_sums_peers(self):
        self.assertEqual(parse_wg_transfer("A\t1\t2\nB\t10\t20\n"), (11, 22))

    def test_empty(self):
        self.assertIsNone(parse_wg_transfer(""))


class ParseAccountTest(unittest.TestCase):
    def test_signed_in(self):
        self.assertEqual(parse_account("Account: 'me@proton.me'\n"), "me@proton.me")

    def test_signed_out_prints_none(self):
        self.assertEqual(parse_account("Account: 'None'\n"), "")

    def test_unexpected_output(self):
        self.assertEqual(parse_account("Traceback ...\n"), "")


if __name__ == "__main__":
    unittest.main()
