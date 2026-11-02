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

LAN_NETWORKS='10.0.0.0/8, fd00::/8' WEBUI_PORT=8788 WEBUI_ALLOWED_NETWORKS=
export LAN_NETWORKS WEBUI_PORT WEBUI_ALLOWED_NETWORKS
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
check "v4 no icmpv6" lacks ipv6-icmp
check "v4 OUTPUT established is own-cgroup eth0 only" has '-A OUTPUT -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -m cgroup --path / -j ACCEPT'
check "v4 every OUTPUT established rule has cgroup or webui sport" eq "$(printf '%s\n' "$RULES" | grep 'OUTPUT.*ESTABLISHED' | grep -vc -e '-m cgroup --path' -e '-p tcp --sport 8788 ')" 0
check "v4 webui replies by sport" has '-A OUTPUT -o eth0 -p tcp --sport 8788 -m conntrack --ctstate ESTABLISHED -j ACCEPT'
check "v4 embedded dns: accept < drop < lo" test "${accept:-9}" -lt "${drop:-8}" -a "${drop:-9}" -lt "${lo:-0}"

RULES=$(firewall_rules 6 /system.slice/docker-abc.scope 192.168.65.7 fd00::53)
check "v6 LAN" has '-A OUTPUT -o eth0 -d fd00::/8 -j ACCEPT'
check "v6 omits v4 LAN" lacks '10.0.0.0/8'
check "v6 no embedded dns" lacks '127.0.0.11'
check "v6 resolver" has '-A OUTPUT -o eth0 -m cgroup --path /system.slice/docker-abc.scope -p udp --dport 53 -d fd00::53 -j ACCEPT'
check "v6 omits v4 resolver" lacks '192.168.65.7'
for t in neighbour-solicitation neighbour-advertisement; do
  check "v6 ND $t out" has "-A OUTPUT -o eth0 -p ipv6-icmp --icmpv6-type $t -j ACCEPT"
  check "v6 ND $t in" has "-A INPUT -i eth0 -p ipv6-icmp --icmpv6-type $t -j ACCEPT"
done
check "v6 every OUTPUT established rule has cgroup or webui sport" eq "$(printf '%s\n' "$RULES" | grep 'OUTPUT.*ESTABLISHED' | grep -vc -e '-m cgroup --path' -e '-p tcp --sport 8788 ')" 0

RULES=$(firewall_rules 6 / 'fe80::1%eth0' bad/addr '*' 10.0.0.1)
check "v6 resolver zone id stripped" has '-A OUTPUT -o eth0 -m cgroup --path / -p udp --dport 53 -d fe80::1 -j ACCEPT'
check "invalid resolver skipped" lacks 'bad/addr'
check "glob resolver skipped" lacks ' -d * '
check "v4 resolver skipped for v6" lacks '10.0.0.1'

unset WEBUI_PORT
RULES=$(firewall_rules 4 /)
check "webui port defaults to 8788" has '-A INPUT -i eth0 -p tcp --dport 8788 -j ACCEPT'

# WEBUI_ALLOWED_NETWORKS: the WebUI port's source policy is the first thing INPUT does. Runtime proof is in smoke.sh; this pins the order.
# rules_with <list> <4|6>: the rules for that family with that list. chain: the WebUI chain's rules, in order, '|'-separated.
rules_with() { RULES=$(WEBUI_ALLOWED_NETWORKS=$1; firewall_rules "$2" /); }
chain() { printf '%s\n' "$RULES" | grep '^-A WEBUI_HTTP ' | tr '\n' '|'; }
nets() { ( WEBUI_ALLOWED_NETWORKS=$1; webui_networks | tr '\n' ' ' ); }
PROTON_DROP='-A WEBUI_HTTP -i proton0 -j DROP|'

rules_with '' 4
check "no list: chain declared" has ':WEBUI_HTTP - [0:0]'
check "no list: the jump is the first INPUT rule" eq "$(printf '%s\n' "$RULES" | grep -m1 '^-A INPUT ')" '-A INPUT -p tcp --dport 8788 -j WEBUI_HTTP'
check "no list: the chain only drops proton0" eq "$(chain)" "$PROTON_DROP"
check "no list: LAN and port accepts kept" has '-A INPUT -i eth0 -s 10.0.0.0/8 -j ACCEPT'
jump=$(ln_of '-A INPUT -p tcp --dport 8788 -j WEBUI_HTTP')
for later in '-A INPUT -i lo -j ACCEPT' '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' '-A INPUT -i proton0 -j ACCEPT' \
  '-A INPUT -i eth0 -s 10.0.0.0/8 -j ACCEPT' '-A INPUT -i eth0 -p tcp --dport 8788 -j ACCEPT'; do
  check "webui jump precedes: $later" test "${jump:-9}" -lt "$(ln_of "$later")"
done
rules_with '' 6
check "no list v6: the chain only drops proton0" eq "$(chain)" "$PROTON_DROP"

rules_with ' 10.1.2.3 , 192.168.1.5/24,fd00::/8, 2001:DB8::1 ' 4
check "list v4: proton0 drop, normalized sources, then drop" eq "$(chain)" "${PROTON_DROP}-A WEBUI_HTTP -s 10.1.2.3/32 -j RETURN|-A WEBUI_HTTP -s 192.168.1.0/24 -j RETURN|-A WEBUI_HTTP -j DROP|"
check "list v4: no loopback bypass" lacks '-A WEBUI_HTTP -i lo'
rules_with ' 10.1.2.3 , 192.168.1.5/24,fd00::/8, 2001:DB8::1 ' 6
check "list v6: proton0 drop, normalized sources, then drop" eq "$(chain)" "${PROTON_DROP}-A WEBUI_HTTP -s fd00::/8 -j RETURN|-A WEBUI_HTTP -s 2001:db8::1/128 -j RETURN|-A WEBUI_HTTP -j DROP|"
rules_with 10.0.0.0/8 6
check "list without a v6 entry denies v6" eq "$(chain)" "${PROTON_DROP}-A WEBUI_HTTP -j DROP|"
rules_with '0.0.0.0/0, ::/0' 4
check "allow-all v4 still drops proton0 first" eq "$(chain)" "${PROTON_DROP}-A WEBUI_HTTP -s 0.0.0.0/0 -j RETURN|-A WEBUI_HTTP -j DROP|"
rules_with '0.0.0.0/0, ::/0' 6
check "allow-all v6 still drops proton0 first" eq "$(chain)" "${PROTON_DROP}-A WEBUI_HTTP -s ::/0 -j RETURN|-A WEBUI_HTTP -j DROP|"
RULES=$(WEBUI_PORT=9000; firewall_rules 4 /)
check "webui chain follows WEBUI_PORT" has '-A INPUT -p tcp --dport 9000 -j WEBUI_HTTP'
check "webui chain follows WEBUI_PORT: no old port" lacks 8788

check "networks normalized" eq "$(nets ' 10.1.2.3 , 192.168.1.5/24,fd00::/8, 2001:DB8::1 ')" '10.1.2.3/32 192.168.1.0/24 fd00::/8 2001:db8::1/128 '
check "networks: empty prints nothing" eq "$(nets '')" ''
check "networks: duplicates are harmless" eq "$(nets '10.0.0.1,10.0.0.1')" '10.0.0.1/32 10.0.0.1/32 '
# bad_networks <list> <4|6>: no document, status 1, an error that names the variable.
bad_networks() {
  ( WEBUI_ALLOWED_NETWORKS=$1; firewall_rules "$2" / ) > "$TMP/out" 2> "$TMP/err"
  [ $? -eq 1 ] && [ ! -s "$TMP/out" ] && grep -q WEBUI_ALLOWED_NETWORKS "$TMP/err"
}
for bad in example.com '*' '10.0.0.*' 10.0.0.0/33 fd00::/129 ',' ' ' '10.0.0.1,' '10.0.0.1,,10.0.0.2' '10.0.0.1 10.0.0.2' \
  10.0.0.0/255.0.0.0 10.0.0.0/0.0.0.0 fe80::1%eth0 '10.0.0.0/8;reboot' '-j ACCEPT' 010.0.0.1; do
  for f in 4 6; do check "invalid list '$bad' fails closed (v$f)" bad_networks "$bad" "$f"; done
done

# Restart recovery: resolv.conf and NM's file as the previous run left them.
kdr() { # kdr <resolv content> <nm content, or - for none> <saved content, or - for none>; prints resolv|saved|nm
  rm -f "$TMP/resolv" "$TMP/nm" "$TMP/saved"
  printf '%s\n' "$1" > "$TMP/resolv"
  [ "$2" = - ] || printf '%s\n' "$2" > "$TMP/nm"
  [ "$3" = - ] || printf '%s\n' "$3" > "$TMP/saved"
  keep_docker_resolver "$TMP/resolv" "$TMP/nm" "$TMP/saved"
  printf '%s|%s|%s' "$(cat "$TMP/resolv")" "$(cat "$TMP/saved")" "$([ -e "$TMP/nm" ] && echo kept || echo removed)"
}
check "first boot saves Docker's resolver" eq "$(kdr 'nameserver 127.0.0.11' - -)" 'nameserver 127.0.0.11|nameserver 127.0.0.11|removed'
check "restart with the tunnel DNS left in place restores Docker's" eq "$(kdr 'nameserver 10.2.0.1' 'nameserver 10.2.0.1' 'nameserver 127.0.0.11')" 'nameserver 127.0.0.11|nameserver 127.0.0.11|removed'
check "restart keeps a regenerated Docker resolver and drops NM's stale file" eq "$(kdr 'nameserver 192.168.1.1' 'nameserver 10.2.0.1' 'nameserver 127.0.0.11')" 'nameserver 192.168.1.1|nameserver 192.168.1.1|removed'
check "no saved original: the file is saved as it is" eq "$(kdr 'nameserver 10.2.0.1' 'nameserver 10.2.0.1' -)" 'nameserver 10.2.0.1|nameserver 10.2.0.1|removed'

[ "$FAILED" -eq 0 ] && echo "all ok"
exit "$FAILED"
