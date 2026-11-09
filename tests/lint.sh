#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
git grep -Il '^#!/bin/sh' -- rootfs tests | xargs docker run --rm -v "$PWD:/mnt" -w /mnt koalaman/shellcheck:v0.11.0 -s sh
