import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/check_updates.py"


class DependencyUpdateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("check_updates", SCRIPT)
        cls.updates = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.updates)

    def test_latest_package_uses_debian_order_not_repository_order(self):
        index = "\n\n".join(
            f"Package: protonvpn-stable-release\nArchitecture: all\nVersion: {version}\nSHA256: {'a' * 64}\n"
            for version in ("1.0.10", "1.0.3-2", "1.0.9")
        )
        self.assertEqual(self.updates.latest_package(index, "protonvpn-stable-release")["Version"], "1.0.10")

    def test_no_downgrade_when_repository_lags_current_pin(self):
        self.assertEqual(self.updates.newer_version("6.1.0", "6.1.1"), False)
        self.assertEqual(self.updates.newer_version("6.1.1", "6.1.1"), False)
        self.assertEqual(self.updates.newer_version("6.1.2", "6.1.1"), True)
    def test_bootstrap_update_keeps_version_and_checksum_together(self):
        dockerfile = (
            "ARG PROTON_RELEASE_VERSION=1.0.9\n"
            f"ARG PROTON_RELEASE_SHA256={'b' * 64}\n"
            "ARG PROTON_CLI_VERSION=1.1.0\n"
            "ARG PROTON_API_CORE_VERSION=6.1.1\n"
        )
        index = "\n\n".join(
            f"Package: {name}\nArchitecture: all\nVersion: {version}\nSHA256: {'a' * 64}\n"
            for name, version in (
                ("protonvpn-stable-release", "1.0.10"),
                ("proton-vpn-cli", "1.1.0"),
                ("python3-proton-vpn-api-core", "6.1.0"),
            )
        )
        updated, changes = self.updates.update_proton(dockerfile, index)
        self.assertEqual(updated, dockerfile.replace("1.0.9", "1.0.10").replace("b" * 64, "a" * 64))
        self.assertEqual(changes, ["- protonvpn-stable-release: 1.0.9 → 1.0.10"])


    def test_missing_package_fails_instead_of_silently_skipping(self):
        with self.assertRaises(ValueError):
            self.updates.latest_package("Package: other\nVersion: 1.0\n", "proton-vpn-cli")

    def test_bootstrap_checksum_must_be_valid(self):
        for checksum in ("", "a" * 63, "z" * 64, "a" * 64 + "\nARG INJECTED=yes"):
            with self.subTest(checksum=checksum):
                with self.assertRaises(ValueError):
                    self.updates.validate_package({"Version": "1.0.11", "SHA256": checksum})

    def test_upstream_version_cannot_inject_dockerfile_instructions(self):
        with self.assertRaises(ValueError):
            self.updates.validate_package({"Version": "1.0.11\nRUN malicious", "SHA256": "a" * 64})


if __name__ == "__main__":
    unittest.main()
