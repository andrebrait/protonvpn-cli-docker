#!/bin/sh
# Prints the Proton packages installed in <image> and fails unless they are the versions the Dockerfile pins.
# Usage: tests/versions.sh <image> [platform, e.g. linux/arm64]
set -eu
cd "$(dirname "$0")/.."
pin() { sed -n "s/^ARG $1=//p" Dockerfile; }

installed=$(docker run --rm --platform "${2:-}" --entrypoint dpkg-query "$1" \
  -W -f '${Package} ${Version}\n' proton-vpn-cli python3-proton-vpn-api-core)
printf '%s\n' "$installed"
want="proton-vpn-cli $(pin PROTON_CLI_VERSION)
python3-proton-vpn-api-core $(pin PROTON_API_CORE_VERSION)"
[ "$installed" = "$want" ] || { echo "expected:"; echo "$want"; exit 1; }
