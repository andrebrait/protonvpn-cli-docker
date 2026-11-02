import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout

from protonvpn_container.config import SettingsStore, connect_args, is_true, settings_pairs


class SettingsStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "settings.json")

    def tearDown(self):
        self.tmp.cleanup()

    def write_file(self, data):
        with open(self.path, "w") as f:
            json.dump(data, f)

    def test_env_wins_and_locks(self):
        self.write_file({"COUNTRY": "CH"})
        store = SettingsStore(self.path, {"COUNTRY": "NL"})
        self.assertEqual(store.effective("COUNTRY"), "NL")
        self.assertTrue(store.locked("COUNTRY"))
        self.assertEqual(store.source("COUNTRY"), "env")

    def test_file_then_default(self):
        store = SettingsStore(self.path, {})
        self.write_file({"COUNTRY": "CH", "KILL_SWITCH": "off"})  # read per call, not cached
        self.assertEqual(store.effective("COUNTRY"), "CH")
        self.assertEqual(store.source("COUNTRY"), "file")
        self.assertFalse(store.locked("COUNTRY"))
        self.assertEqual(store.effective("KILL_SWITCH"), "off")
        self.write_file({"COUNTRY": "CH"})
        self.assertEqual(store.effective("KILL_SWITCH"), "standard")
        self.assertEqual(store.source("KILL_SWITCH"), "default")
        self.assertEqual(store.effective("NETSHIELD"), "")

    def test_save_locked_raises(self):
        store = SettingsStore(self.path, {"COUNTRY": "NL"})
        with self.assertRaises(PermissionError):
            store.save("COUNTRY", "CH")
        self.assertFalse(os.path.exists(self.path))

    def test_save_atomic_mode(self):
        self.write_file({})
        os.chmod(self.path, 0o644)
        store = SettingsStore(self.path, {})
        store.save("COUNTRY", "CH")
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(store.effective("COUNTRY"), "CH")
        self.assertEqual(os.listdir(self.tmp.name), ["settings.json"])
        store.save("COUNTRY", "")
        with open(self.path) as f:
            self.assertNotIn("COUNTRY", json.load(f))

    def test_corrupt_file_is_empty(self):
        with open(self.path, "w") as f:
            f.write("{not json")
        store = SettingsStore(self.path, {})
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(store.effective("COUNTRY"), "")
            self.assertEqual(store.effective("KILL_SWITCH"), "standard")
            self.assertFalse(store.banner_dismissed())
        self.assertEqual(out.getvalue().count("[webui]"), 1)
        with open(self.path) as f:
            self.assertEqual(f.read(), "{not json")
        store.save("COUNTRY", "CH")
        self.assertEqual(store.effective("COUNTRY"), "CH")

    def test_banner_flag_roundtrip(self):
        store = SettingsStore(self.path, {})
        self.assertFalse(store.banner_dismissed())
        store.save("COUNTRY", "CH")
        store.dismiss_banner()
        self.assertTrue(store.banner_dismissed())
        self.assertTrue(SettingsStore(self.path, {}).banner_dismissed())
        self.assertEqual(store.effective("COUNTRY"), "CH")

    def test_connect_args_server(self):
        store = SettingsStore(self.path, {"SERVER": "NL#914", "COUNTRY": "NL", "P2P": "true"})
        out = io.StringIO()
        with redirect_stdout(out):
            args = connect_args(store)
        self.assertEqual(args, ["NL#914", "--p2p"])
        self.assertIn("[protonvpn] SERVER is set; ignoring COUNTRY/CITY", out.getvalue())

    def test_connect_args_city_spaces(self):
        store = SettingsStore(self.path, {"COUNTRY": "US", "CITY": "New York"})
        self.assertEqual(connect_args(store), ["--country", "US", "--city", "New York"])

    def test_connect_args_empty(self):
        self.assertEqual(connect_args(SettingsStore(self.path, {})), [])

    def test_connect_args_flags(self):
        store = SettingsStore(self.path, {"SECURE_CORE": "Yes", "TOR": "0"})
        self.assertEqual(connect_args(store), ["--securecore"])

    def test_settings_pairs_order(self):
        store = SettingsStore(self.path, {})
        self.assertEqual(
            settings_pairs(store),
            [("kill-switch", ["standard"]), ("anonymous-crash-reports", ["off"])],
        )

    def test_settings_pairs_custom_dns(self):
        store = SettingsStore(self.path, {"CUSTOM_DNS": "on 1.1.1.1"})
        self.assertEqual(
            settings_pairs(store),
            [
                ("custom-dns", ["on", "1.1.1.1"]),
                ("kill-switch", ["standard"]),
                ("anonymous-crash-reports", ["off"]),
            ],
        )

    def test_is_true_values(self):
        for value in ("true", "1", "yes", "on", "TRUE", "Yes"):
            self.assertTrue(is_true(value), value)
        for value in ("", "0", "false", "no", "off", "maybe"):
            self.assertFalse(is_true(value), value)


if __name__ == "__main__":
    unittest.main()
