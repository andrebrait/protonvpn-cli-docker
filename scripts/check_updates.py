"""Propose reviewed Proton and ShellCheck pins; never install upstream updates."""

import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
PROTON_INDEX = "https://repo.protonvpn.com/debian/dists/stable/main/binary-all/Packages"
PACKAGES = {
    "PROTON_RELEASE_VERSION": "protonvpn-stable-release",
    "PROTON_CLI_VERSION": "proton-vpn-cli",
    "PROTON_API_CORE_VERSION": "python3-proton-vpn-api-core",
}


def fetch(url):
    headers = {"User-Agent": "protonvpn-cli-docker-update-check"}
    if url.startswith("https://api.github.com/") and os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise ValueError("Upstream metadata exceeds 8 MiB")
    return data.decode("utf-8")


def newer_version(candidate, current):
    result = subprocess.run(["dpkg", "--compare-versions", candidate, "gt", current], check=False)
    if result.returncode not in (0, 1):
        raise ValueError("Invalid Debian version comparison")
    return result.returncode == 0


def validate_package(package):
    if not re.fullmatch(r"[0-9][0-9A-Za-z.+:~\-]*", package.get("Version", "")):
        raise ValueError("Invalid upstream package version")
    if not re.fullmatch(r"[0-9a-f]{64}", package.get("SHA256", "")):
        raise ValueError("Invalid upstream package SHA256")


def latest_package(index, name):
    latest = None
    for paragraph in index.split("\n\n"):
        fields = dict(line.split(": ", 1) for line in paragraph.splitlines() if ": " in line and not line.startswith(" "))
        if fields.get("Package") != name or fields.get("Architecture") not in ("all", "amd64"):
            continue
        validate_package(fields)
        if latest is None or newer_version(fields["Version"], latest["Version"]):
            latest = fields
    if latest is None:
        raise ValueError(f"Package missing from Proton stable repository: {name}")
    return latest


def pin(text, name):
    matches = re.findall(rf"^ARG {name}=(\S+)$", text, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one Dockerfile pin: {name}")
    return matches[0]


def update_proton(dockerfile, index):
    changes = []
    for name, package in PACKAGES.items():
        latest = latest_package(index, package)
        current = pin(dockerfile, name)
        if not newer_version(latest["Version"], current):
            continue
        dockerfile = dockerfile.replace(f"ARG {name}={current}\n", f"ARG {name}={latest['Version']}\n")
        if name == "PROTON_RELEASE_VERSION":
            checksum = pin(dockerfile, "PROTON_RELEASE_SHA256")
            dockerfile = dockerfile.replace(f"ARG PROTON_RELEASE_SHA256={checksum}\n", f"ARG PROTON_RELEASE_SHA256={latest['SHA256']}\n")
        changes.append(f"- {package}: {current} → {latest['Version']}")
    return dockerfile, changes


def main():
    dockerfile = (ROOT / "Dockerfile").read_text()
    dockerfile, changes = update_proton(dockerfile, fetch(PROTON_INDEX))
    lint_path = ROOT / "tests/lint.sh"
    lint = lint_path.read_text()
    current = re.search(r"koalaman/shellcheck:v([0-9.]+)", lint).group(1)
    release = json.loads(fetch("https://api.github.com/repos/koalaman/shellcheck/releases/latest"))
    latest = release["tag_name"].removeprefix("v")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", latest) or release["prerelease"] or release["draft"]:
        raise ValueError("Expected a stable ShellCheck release")
    if newer_version(latest, current):
        lint = lint.replace(f"koalaman/shellcheck:v{current}", f"koalaman/shellcheck:v{latest}")
        changes.append(f"- ShellCheck: {current} → {latest}")
    # Fetch and validate every source before modifying tracked files.
    if changes:
        readme_path = ROOT / "README.md"
        readme = readme_path.read_text()
        for label, name in (("CLI", "PROTON_CLI_VERSION"), ("API core", "PROTON_API_CORE_VERSION")):
            readme, count = re.subn(rf"\*\*{label} [^*]+\*\*", f"**{label} {pin(dockerfile, name)}**", readme, count=1)
            if count != 1:
                raise ValueError(f"Missing README version: {label}")
        (ROOT / "Dockerfile").write_text(dockerfile)
        lint_path.write_text(lint)
        readme_path.write_text(readme)
    print("\n".join(changes) if changes else "All checked pins are current; no downgrade proposed.")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write("\n".join(changes) + "\n" if changes else "No pin updates found.\n")


if __name__ == "__main__":
    main()
