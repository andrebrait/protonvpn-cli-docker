#!/bin/sh
# Unit tests for firewall.sh (pure functions only; nothing is loaded into the kernel).
# shellcheck disable=SC2329  # helpers are invoked indirectly through check
cd "$(dirname "$0")/.." || exit 1
FAILED=0
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# shellcheck source=/dev/null
. rootfs/usr/local/lib/protonvpn-container/firewall.sh

# check <description> <command...>
check() {
  desc=$1; shift
  if "$@"; then echo "ok   $desc"; else echo "FAIL $desc"; FAILED=1; fi
}

cg() { printf '%s\n' "$1" > "$TMP/cg"; own_cgroup "$TMP/cg"; }
eq() { [ "$1" = "$2" ]; }
has() { printf '%s\n' "$RULES" | grep -qxF -- "$1"; }
lacks() { ! printf '%s\n' "$RULES" | grep -qF -- "$1"; }
# line number of an exact rule line
ln_of() { printf '%s\n' "$RULES" | grep -nxF -- "$1" | cut -d: -f1; }

check "own_cgroup private ns" eq "$(cg '0::/')" /
check "own_cgroup host ns" eq "$(cg '0::/system.slice/docker-abc.scope')" /system.slice/docker-abc.scope
check "own_cgroup v1 only fails" test "$(cg '12:cpu:/docker/abc' >/dev/null 2>&1; echo $?)" = 1
check "own_cgroup missing file fails" test "$(own_cgroup "$TMP/none" >/dev/null 2>&1; echo $?)" = 1

LAN_NETWORKS='10.0.0.0/8, fd00::/8' WEBUI_PORT=8788
export LAN_NETWORKS WEBUI_PORT
RULES=$(firewall_rules 4 / 192.168.65.7 fd00::53)
check "v4 document" eq "$(printf '%s\n' "$RULES" | sed -n '1p;$p' | tr '\n' ' ')" '*filter COMMIT '
check "v4 policies drop" has ':INPUT DROP [0:0]'
check "v4 forward drop" has ':FORWARD DROP [0:0]'
check "v4 LAN out" has '-A OUTPUT -o eth0 -d 10.0.0.0/8 -j ACCEPT'
check "v4 LAN in" has '-A INPUT -i eth0 -s 10.0.0.0/8 -j ACCEPT'
check "v4 omits v6 LAN" lacks 'fd00::/8'
check "v4 omits v6 resolver" lacks 'fd00::53'
check "v4 webui port" has '-A INPUT -i eth0 -p tcp --dport 8788 -j ACCEPT'
check "v4 tunnel and fwmark" has '-A OUTPUT -m mark --mark 0xea13b2c -j ACCEPT'
check "v4 own 443" has '-A OUTPUT -o eth0 -m cgroup --path / -p tcp --dport 443 -j ACCEPT'
check "v4 own dns udp" has '-A OUTPUT -o eth0 -m cgroup --path / -p udp --dport 53 -d 192.168.65.7 -j ACCEPT'
check "v4 own dns tcp" has '-A OUTPUT -o eth0 -m cgroup --path / -p tcp --dport 53 -d 192.168.65.7 -j ACCEPT'
accept=$(ln_of '-A OUTPUT -o lo -d 127.0.0.11 -m cgroup --path / -j ACCEPT')
drop=$(ln_of '-A OUTPUT -o lo -d 127.0.0.11 -j DROP')
lo=$(ln_of '-A OUTPUT -o lo -j ACCEPT')
check "v4 embedded dns: accept < drop < lo" test "${accept:-9}" -lt "${drop:-8}" -a "${drop:-9}" -lt "${lo:-0}"

RULES=$(firewall_rules 6 /system.slice/docker-abc.scope 192.168.65.7 fd00::53)
check "v6 LAN" has '-A OUTPUT -o eth0 -d fd00::/8 -j ACCEPT'
check "v6 omits v4 LAN" lacks '10.0.0.0/8'
check "v6 no embedded dns" lacks '127.0.0.11'
check "v6 resolver" has '-A OUTPUT -o eth0 -m cgroup --path /system.slice/docker-abc.scope -p udp --dport 53 -d fd00::53 -j ACCEPT'
check "v6 omits v4 resolver" lacks '192.168.65.7'

unset WEBUI_PORT
RULES=$(firewall_rules 4 /)
check "webui port defaults to 8788" has '-A INPUT -i eth0 -p tcp --dport 8788 -j ACCEPT'

[ "$FAILED" -eq 0 ] && echo "all ok"
exit "$FAILED"
