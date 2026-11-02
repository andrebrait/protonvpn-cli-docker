#!/bin/sh
# shellcheck disable=SC2329  # helpers are invoked indirectly through assert
# Smoke tests: runs $IMAGE (builds nothing) with the required flags and a temp /config.
IMAGE=${IMAGE:-protonvpn-cli:test}
FAILED=0
TMP=$(mktemp -d)
CONTAINERS=""
NETWORKS=""

cleanup() {
  # shellcheck disable=SC2086  # intentional word splitting of the name lists
  [ -z "$CONTAINERS" ] || docker rm -f $CONTAINERS >/dev/null 2>&1
  # shellcheck disable=SC2086
  [ -z "$NETWORKS" ] || docker network rm $NETWORKS >/dev/null 2>&1
  # The containers write /config as root: empty it the same way, then remove the directory as the invoking user.
  docker run --rm -v "$TMP:/t" --entrypoint find "$IMAGE" /t -mindepth 1 -delete >/dev/null 2>&1
  rm -rf "$TMP"
}
trap cleanup EXIT

# start_container <name> [extra docker args...]: start detached.
start_container() {
  name=$1; shift
  CONTAINERS="$CONTAINERS $name"
  docker run -d --name "$name" --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv4.conf.all.src_valid_mark=1 -v "$TMP:/config" "$@" "$IMAGE" >/dev/null
}

# run_container <name> [extra docker args...]: start detached and wait until the boot finished.
run_container() {
  start_container "$@" && wait_ready "$1"
}

# attach <name> <container>: idle container sharing <container>'s network namespace.
attach() {
  CONTAINERS="$CONTAINERS $1"
  docker run -d --name "$1" --network "container:$2" --entrypoint sleep "$IMAGE" infinity >/dev/null
}

wait_ready() {
  i=0
  while [ "$i" -lt 30 ]; do
    docker exec "$1" test -f /run/session-bus.env 2>/dev/null && return 0
    [ "$(docker inspect -f '{{.State.Running}}' "$1")" = true ] || break
    i=$((i + 1)); sleep 1
  done
  docker logs "$1" 2>&1 | tail -n 20
  return 1
}

# assert <description> <command...>
assert() {
  desc=$1; shift
  if "$@" >/dev/null 2>&1; then echo "ok   $desc"; else echo "FAIL $desc"; FAILED=1; fi
}

nm_running() { [ "$(docker exec "$C" nmcli -t -f RUNNING general)" = running ]; }
cli_disconnected() { [ "$(docker exec "$C" protonvpn status | head -n 1)" = "Status: Disconnected" ]; }
mode_is() { [ "$(docker exec "$C" stat -c %a "$1")" = "$2" ]; }
link_is() { [ "$(docker exec "$C" readlink "$1")" = "$2" ]; }

# Device state reads "connected"; the connection state is the one that reads "activated".
user_root_profile_activates() {
  docker exec "$C" nmcli con add type dummy ifname smoke0 con-name smoke \
    connection.permissions user:root ipv4.method manual ipv4.addresses 10.250.0.1/32 \
    ipv6.method disabled || return 1
  i=0; ok=1
  while [ "$i" -lt 10 ]; do
    if docker exec "$C" nmcli -t -f GENERAL.STATE connection show smoke | grep -q activated; then ok=0; break; fi
    i=$((i + 1)); sleep 1
  done
  docker exec "$C" nmcli con delete smoke >/dev/null 2>&1
  return "$ok"
}

# reboot <container> restart|kill: the previous boot's session-bus.env would satisfy wait_ready before the new boot removes it.
reboot() {
  docker exec "$1" rm -f /run/session-bus.env || return 1
  if [ "$2" = kill ]; then
    docker kill "$1" >/dev/null && docker start "$1" >/dev/null || return 1
  else
    docker restart "$1" >/dev/null || return 1
  fi
  wait_ready "$1"
}

# resolver_is <container> <nameserver lines>: what resolv.conf, the file the resolver reads, currently names.
resolver_is() { [ "$(docker exec "$1" grep '^nameserver' /etc/resolv.conf)" = "$2" ]; }
# What a connection leaves behind: NM's resolver file with the tunnel's DNS, copied over resolv.conf by NM's real dispatcher
# (D-Bus activated, no systemd). The profile never autoconnects, so a restarted NM does not bring it back.
tunnel_dns_populated() {
  docker exec "$C" nmcli con add type dummy ifname smoketun0 con-name smoketun connection.autoconnect no \
    ipv4.method manual ipv4.addresses 10.250.3.1/32 ipv4.dns 10.2.0.1 ipv6.method disabled >/dev/null || return 1
  docker exec "$C" nmcli con up smoketun >/dev/null || return 1
  eventually 10 resolver_is "$C" "nameserver 10.2.0.1"
}
# A managed connection's DNS reaches resolv.conf through NM's real dispatcher, and Docker's resolver returns when it goes down.
managed_dns_follows_connection() {
  orig=$(docker exec "$C" grep '^nameserver' /run/protonvpn-container/resolv.conf.docker) || return 1
  [ -n "$orig" ] || return 1
  docker exec "$C" nmcli con add type dummy ifname smokedns0 con-name smokedns connection.permissions user:root \
    ipv4.method manual ipv4.addresses 10.250.2.1/32 ipv4.dns 10.99.0.53 ipv6.method disabled >/dev/null || return 1
  ok=0
  eventually 10 resolver_is "$C" "nameserver 10.99.0.53" || ok=1
  docker exec "$C" nmcli con down smokedns >/dev/null || ok=1
  eventually 10 resolver_is "$C" "$orig" || ok=1
  docker exec "$C" nmcli con delete smokedns >/dev/null 2>&1
  return "$ok"
}
docker_resolver_restored() {
  saved=$(docker exec "$C" grep '^nameserver' /run/protonvpn-container/resolv.conf.docker) || return 1
  [ -n "$saved" ] && [ "$saved" != "nameserver 10.2.0.1" ] &&
    [ "$(docker exec "$C" grep '^nameserver' /etc/resolv.conf)" = "$saved" ]
}

is_running() { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }
# tcp_from <container> <host> <port>: connect succeeds.
tcp_from() { docker exec "$1" timeout 5 bash -c "</dev/tcp/$2/$3"; }
# blocked_from <container> <host> <port>: container is up and the connect times out (exit 124).
# Anything else (refused, exec failure, missing bash) is not proof of a drop.
blocked_from() {
  is_running "$1" || return 1
  docker exec "$1" timeout 5 bash -c "</dev/tcp/$2/$3" >/dev/null 2>&1
  [ $? -eq 124 ]
}
# reachable_from <container> <host> <port>: connect succeeds or the peer refuses it; a timeout or
# an exec failure fails.
reachable_from() {
  is_running "$1" || return 1
  out=$(docker exec "$1" timeout 5 bash -c "</dev/tcp/$2/$3" 2>&1); rc=$?
  [ "$rc" -eq 0 ] && return 0
  [ "$rc" -eq 1 ] && case $out in *refused*) return 0 ;; esac
  return 1
}
dns_from() { docker exec "$1" timeout 5 getent hosts example.com; }
# dns_blocked_from <container>: lookup fails with "not found" (2) or times out (124), not an exec error.
dns_blocked_from() {
  is_running "$1" || return 1
  docker exec "$1" timeout 5 getent hosts example.com >/dev/null 2>&1
  rc=$?; [ "$rc" -eq 2 ] || [ "$rc" -eq 124 ]
}
# Docker's original resolv.conf survives NM bringing a connection up and down.
resolv_survives_nm() {
  want=$(docker exec "$C" grep '^nameserver' /run/protonvpn-container/resolv.conf.docker) || return 1
  [ -n "$want" ] || return 1
  docker exec "$C" nmcli con add type dummy ifname smoke1 con-name smoke1 ipv4.method manual \
    ipv4.addresses 10.250.1.1/32 ipv6.method disabled >/dev/null || return 1
  sleep 2
  docker exec "$C" nmcli con delete smoke1 >/dev/null || return 1
  sleep 2
  [ "$(docker exec "$C" grep '^nameserver' /etc/resolv.conf)" = "$want" ]
}
bridge_field() { docker network inspect bridge -f "{{(index .IPAM.Config 0).$1}}"; }
# fails_closed <name> <env assignment> <log text>: the container stops with a non-zero status and logs <log text>.
fails_closed() {
  start_container "$1" -e "$2" || return 1
  i=0
  while [ "$i" -lt 10 ]; do
    [ "$(docker inspect -f '{{.State.Running}}' "$1")" = false ] && break
    i=$((i + 1)); sleep 1
  done
  [ "$(docker inspect -f '{{.State.Running}}' "$1")" = false ] || return 1
  [ "$(docker inspect -f '{{.State.ExitCode}}' "$1")" -ne 0 ] || return 1
  docker logs "$1" 2>&1 | grep -qF "$3"
}

# Connected tunnel helpers. NM's WireGuard policy sends every flow without the tunnel's fwmark into the tunnel,
# the WebUI's replies and LAN_NETWORKS flows included.
# wg_up <container>: a real NM WireGuard profile (dummy endpoint, no handshake needed) installs the same policy rules as Proton's.
# Named wgsim0, so the filter's "-o proton0" accept does not cover it.
wg_up() {
  docker exec -i "$1" sh -s <<'EOF'
key=$(wg genkey); pub=$(echo "$key" | wg pubkey)
f=/run/NetworkManager/system-connections/wgsim.nmconnection
cat > "$f" <<KF
[connection]
id=wgsim
uuid=0c3d1b8e-6f0a-4a4e-9d2f-5b7f6a1c2e11
type=wireguard
interface-name=wgsim0
autoconnect=false

[wireguard]
private-key=$key

[wireguard-peer.$pub]
endpoint=192.0.2.1:51820
allowed-ips=0.0.0.0/0;::/0;

[ipv4]
method=manual
address1=10.99.1.2/32

[ipv6]
method=manual
address1=fd99::2/128
KF
chmod 600 "$f" && nmcli con load "$f" && nmcli con up wgsim
EOF
}
# tunnel_policy_setup: $GW becomes the default gateway of $HOLD's namespace and owns 10.55.0.9, 10.56.0.9, fd55::9 and fd56::9 (on lo):
# reachable only through that default route, which the policy suppresses while the tunnel is up. $POL's LAN_NETWORKS are 10.55.0.0/24 and fd55::/64.
tunnel_policy_setup() {
  gw4=$(docker inspect -f "{{(index .NetworkSettings.Networks \"t5b-$$-v6\").IPAddress}}" "$GW") &&
    gw6=$(docker inspect -f "{{(index .NetworkSettings.Networks \"t5b-$$-v6\").GlobalIPv6Address}}" "$GW") &&
    docker exec "$GW" sh -c 'ip addr add 10.55.0.9/32 dev lo && ip addr add 10.56.0.9/32 dev lo &&
      ip -6 addr add fd55::9/128 dev lo && ip -6 addr add fd56::9/128 dev lo' &&
    docker exec "$HOLD" sh -c "ip route replace default via $gw4 dev eth0 && ip -6 route replace default via $gw6 dev eth0 metric 1024"
}
# ks_up <container>: a stand-in for Proton's kill-switch interface, which NM keeps up with its own default routes in the main table
# (live: IPv6 metric 95, against Docker's 1024 on eth0), so a lookup in the main table picks it over eth0.
ks_up() {
  docker exec "$1" nmcli con add type dummy ifname pvpnksintrf0 con-name pvpn-ks \
    ipv4.method manual ipv4.addresses 100.85.0.1/24 ipv4.gateway 100.85.0.2 ipv4.route-metric 98 \
    ipv6.method manual ipv6.addresses fdeb:446c:912d:8da::2/64 ipv6.gateway fdeb:446c:912d:8da::1 ipv6.route-metric 95 >/dev/null
}
# ks_defaults_in_main <container>: both families' main tables carry the kill-switch default, so the scenario really is the live one.
ks_defaults_in_main() {
  docker exec "$1" ip -4 route show default | grep -q pvpnksintrf0 && docker exec "$1" ip -6 route show default | grep -q pvpnksintrf0
}
# route_dev <container> <dev> <ip args...>: the kernel's route for that flow ("<dst> [via <gw>] dev <dev> ...") leaves through <dev>.
route_dev() {
  c=$1 dev=$2; shift 2
  [ "$(docker exec "$c" ip "$@" | sed -n '1s/.* dev \([^ ]*\).*/\1/p')" = "$dev" ]
}
# tcp_from_addr <container> <source address> <host> <port>: connect as a client behind the gateway.
tcp_from_addr() {
  docker exec "$1" python3 -c 'import socket, sys
s = socket.socket(socket.AF_INET); s.bind((sys.argv[1], 0)); s.settimeout(5); s.connect((sys.argv[2], int(sys.argv[3])))' "$2" "$3" "$4"
}
# policy_rules_once <container>: the WebUI and LAN_NETWORKS rules exist exactly once per family.
policy_rules_once() {
  r4=$(docker exec "$1" ip -4 rule show) && r6=$(docker exec "$1" ip -6 rule show) || return 1
  [ "$(echo "$r4" | grep -c 'sport 8788 lookup [0-9]')" = 1 ] && [ "$(echo "$r4" | grep -c 'to 10.55.0.0/24 lookup [0-9]')" = 1 ] &&
    [ "$(echo "$r6" | grep -c 'sport 8788 lookup [0-9]')" = 1 ] && [ "$(echo "$r6" | grep -c 'to fd55::/64 lookup [0-9]')" = 1 ]
}
# egress_table_eth0_only <container>: the table the WebUI rule selects, per family, has a default route and routes through eth0 only:
# no kill-switch or tunnel route, even when an earlier run left them in the main table.
egress_table_eth0_only() {
  for f in 4 6; do
    t=$(docker exec "$1" ip -"$f" rule show | sed -n 's/.*sport 8788 lookup \([0-9][0-9]*\).*/\1/p') && [ -n "$t" ] || return 1
    routes=$(docker exec "$1" ip -"$f" route show table "$t") || return 1
    echo "$routes" | grep -q '^default' || return 1
    ! echo "$routes" | grep -Ev '^throw 10\.2\.0\.1(/32)?( |$)' | grep -qv ' dev eth0\( \|$\)' || return 1
  done
}

# Task 4 helpers: supervisor, health, shutdown.
# eventually <seconds> <command...>: retry once a second until it succeeds.
eventually() {
  n=$1; shift
  i=0
  while [ "$i" -lt "$n" ]; do
    "$@" && return 0
    i=$((i + 1)); sleep 1
  done
  return 1
}
SIGNIN_HINT='Not signed in. Sign in from the WebUI or run: docker exec -it <name> protonvpn signin <username>'
hint_logged() { docker logs "$1" 2>&1 | grep -qF "$SIGNIN_HINT"; }
# Exit 1 is the health command's own "not connected"; an exec failure (126/127) must not pass.
unhealthy_when_signed_out() {
  is_running "$1" || return 1
  docker exec "$1" /usr/local/bin/healthcheck.sh >/dev/null 2>&1
  [ $? -eq 1 ]
}
port_file_empty_644() {
  [ "$(docker exec "$1" stat -c '%a %s' /config/forwarded_port)" = "644 0" ]
}
# The PIDs recorded for shutdown name the real daemons (NM, not the log prefixer).
pid_file_is() { [ "$(docker exec "$1" sh -c "cat /proc/\$(cat /run/protonvpn-container/$2)/comm")" = "$3" ]; }
graceful_stop() {
  start=$(date +%s)
  docker stop -t 15 "$1" >/dev/null || return 1
  [ $(($(date +%s) - start)) -lt 10 ] || return 1
  [ "$(docker inspect -f '{{.State.ExitCode}}' "$1")" = 0 ] || return 1
  docker logs "$1" 2>&1 | grep -qF '[init] stopped'
}

# Task 5 helpers: WebUI.
# webui_get <container> <path>: prints the status on the first line, then the body; a 4xx still reports its status.
webui_get() {
  docker exec "$1" python3 -c '
import sys, urllib.error, urllib.request
try:
    resp = urllib.request.urlopen("http://127.0.0.1:8788" + sys.argv[1], timeout=5)
except urllib.error.HTTPError as err:
    resp = err
print(resp.status)
print(resp.read().decode())
' "$2"
}
# webui_says <container> <path> <grep pattern>
webui_says() { webui_get "$1" "$2" | grep -q -e "$3"; }
webui_state_signed_out_with_banner() {
  out=$(webui_get "$1" /api/v1/state) || return 1
  case $out in "200"*'"signed_in": false'*'"banner": true'*) return 0 ;; esac
  return 1
}
WEBUI_WARNING='[webui] WARNING: WEBUI_PASSWORD is not set; the WebUI is open to anyone who can reach it'
logged() { docker logs "$1" 2>&1 | grep -qF "$2"; }
not_logged() { ! logged "$@"; }

bearer_smoke() {
  docker exec "$1" python3 -c '
import json, sys, urllib.error, urllib.request
base = "http://127.0.0.1:8788"
def request(path, key=None, data=None):
    headers = {"Authorization": "Bearer " + key} if key else {}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as err:
        resp = err
    return resp.status, json.load(resp)
key = sys.argv[1]
status, state = request("/api/v1/status", key)
assert status == 200 and state["signed_in"] is False and state["tunnel_healthy"] is False
assert request("/api/v1/status")[0] == 401
assert request("/api/v1/status", "wrong")[0] == 401
assert request("/api/v1/openapi.json")[1]["openapi"] == "3.1.0"
assert request("/api/v1/disconnect", key, b"{}")[0] == 200
assert request("/api/v1/connect", "wrong", b"{}")[0] == 403
print("bearer status 200; absent/wrong 401; public OpenAPI 200; bearer write 200; invalid write 403")
' "$2"
}

# WebUI source policy helpers.
# ip_of / ip6_of <container> [network]: its IPv4 / global IPv6 address on the network (default bridge).
ip_of() { docker inspect -f "{{(index .NetworkSettings.Networks \"${2:-bridge}\").IPAddress}}" "$1"; }
ip6_of() { docker inspect -f "{{(index .NetworkSettings.Networks \"${2:-bridge}\").GlobalIPv6Address}}" "$1"; }
# http_from <client> <url> [header...]: GET from <client>; prints the status, "timeout" when nothing answers within 5 seconds (a dropped
# SYN), "error" for anything else (a refusal included).
http_from() {
  hc=$1; shift
  docker exec "$hc" python3 -c '
import sys, urllib.error, urllib.request
req = urllib.request.Request(sys.argv[1], headers=dict(h.split(": ", 1) for h in sys.argv[2:]))
try:
    print(urllib.request.urlopen(req, timeout=5).status)
except urllib.error.HTTPError as err:
    print(err.code)
except (TimeoutError, urllib.error.URLError) as err:
    print("timeout" if isinstance(getattr(err, "reason", err), TimeoutError) else "error")
' "$@"
}
# http_is <status|timeout> <client> <url> [header...]
http_is() { want=$1; shift; [ "$(http_from "$@")" = "$want" ]; }
# v6_listener <container>: the stand-in for an IPv6 WebUI (the real one binds IPv4 only): a listener on the WebUI port, IPv6 only.
v6_listener() {
  docker exec -d "$1" python3 -c 'import socket, time
s = socket.socket(socket.AF_INET6); s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
s.bind(("::", 8788)); s.listen(); time.sleep(600)'
}
listening6() { docker exec "$1" ss -ltn 'sport = :8788' | grep -q '\[::\]'; }
# proton0_data <product> <client>: the same tunnel client that cannot reach the control port exchanges TCP and UDP application data.
proton0_data() {
  docker exec -d "$1" python3 -c '
import selectors, socket
sel = selectors.DefaultSelector()
for family, addr in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        s = socket.socket(family, kind)
        if family == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind((addr, 51413))
        if kind == socket.SOCK_STREAM:
            s.listen()
        sel.register(s, selectors.EVENT_READ, kind)
while True:
    for key, _ in sel.select():
        if key.data == socket.SOCK_DGRAM:
            data, addr = key.fileobj.recvfrom(1024)
            key.fileobj.sendto(data, addr)
        else:
            conn, _ = key.fileobj.accept()
            with conn:
                conn.settimeout(5)
                conn.sendall(conn.recv(16, socket.MSG_WAITALL))
' || return 1
  eventually 10 docker exec "$2" python3 -c '
import socket
for family, addr in ((socket.AF_INET, "10.77.0.1"), (socket.AF_INET6, "fd77::1")):
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        with socket.socket(family, kind) as s:
            s.settimeout(5)
            s.connect((addr, 51413))
            s.sendall(b"application-data")
            assert s.recv(16, socket.MSG_WAITALL if kind == socket.SOCK_STREAM else 0) == b"application-data", (addr, kind)
'
}
wg_handshaken() { [ "$(docker exec "$1" wg show wgq latest-handshakes | cut -f2)" -gt 0 ]; }
# proton0_pair <product container> <client container>: proton0 (the interface name the filter treats as the tunnel) in the product is a
# WireGuard link to wgq in the client. The product opens it, with the tunnel fwmark, so its UDP leaves the kill switch and the answers
# are ESTABLISHED. The client reaches the product at 10.77.0.1 / fd77::1 through it, and the egress table that rule 100 selects for the
# WebUI's replies routes them back into it (without that route the handshake could not complete, drop or no drop).
proton0_pair() {
  pk=$(docker exec "$1" wg genkey) && qk=$(docker exec "$2" wg genkey) || return 1
  ppub=$(echo "$pk" | docker exec -i "$1" wg pubkey) && qpub=$(echo "$qk" | docker exec -i "$2" wg pubkey) || return 1
  docker exec -i "$2" sh -es "$qk" "$ppub" <<'EOF' || return 1
ip link add wgq type wireguard
echo "$1" | wg set wgq private-key /dev/stdin listen-port 51820 peer "$2" allowed-ips 10.77.0.1/32,fd77::1/128
ip addr add 10.77.0.2/32 dev wgq; ip -6 addr add fd77::2/128 dev wgq; ip link set wgq up
ip route add 10.77.0.1/32 dev wgq; ip -6 route add fd77::1/128 dev wgq
EOF
  docker exec -i "$1" sh -es "$pk" "$qpub" "$(ip_of "$2")" <<'EOF' || return 1
egress_table() { ip -"$1" rule show | sed -n "s/.*sport 8788 lookup \([0-9][0-9]*\).*/\1/p"; }
ip link add proton0 type wireguard
echo "$1" | wg set proton0 private-key /dev/stdin listen-port 51821 fwmark 0xea13b2c peer "$2" endpoint "$3:51820" allowed-ips 10.77.0.2/32,fd77::2/128 persistent-keepalive 1
ip addr add 10.77.0.1/32 dev proton0; ip -6 addr add fd77::1/128 dev proton0; ip link set proton0 up
ip route add 10.77.0.2/32 dev proton0; ip -6 route add fd77::2/128 dev proton0
ip route add 10.77.0.2/32 dev proton0 table "$(egress_table 4)"; ip -6 route add fd77::2/128 dev proton0 table "$(egress_table 6)"
EOF
  eventually 15 wg_handshaken "$2"
}
# proton0_drop_only <product container> <client container>: with the WebUI up (IPv4) and a stand-in listening (IPv6), the client cannot
# connect through proton0; with the drop rules taken out the same connections complete, and put back they are dropped again.
proton0_drop_only() {
  eventually 20 webui_says "$1" /api/v1/state '^200$' || return 1
  v6_listener "$1" && eventually 5 listening6 "$1" || return 1
  blocked_from "$2" 10.77.0.1 8788 && blocked_from "$2" fd77::1 8788 || return 1
  docker exec "$1" iptables -D WEBUI_HTTP -i proton0 -j DROP && docker exec "$1" ip6tables -D WEBUI_HTTP -i proton0 -j DROP || return 1
  tcp_from "$2" 10.77.0.1 8788 && tcp_from "$2" fd77::1 8788; open=$?
  docker exec "$1" iptables -I WEBUI_HTTP 1 -i proton0 -j DROP && docker exec "$1" ip6tables -I WEBUI_HTTP 1 -i proton0 -j DROP || return 1
  [ "$open" -eq 0 ] && blocked_from "$2" 10.77.0.1 8788 && blocked_from "$2" fd77::1 8788
}

# A live attached app holds the namespace after the product exits during firewall installation.
# Both directions exchange payloads first, so a missing listener or broken IPv6 route cannot look like containment.
failure_listener() {
  docker exec -d "$1" python3 -c '
import selectors, socket
sel = selectors.DefaultSelector()
for family, addr in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
    s = socket.socket(family)
    if family == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, 4444)); s.listen()
    sel.register(s, selectors.EVENT_READ, True)
while True:
    for key, _ in sel.select():
        if key.data:
            conn, _ = key.fileobj.accept()
            sel.register(conn, selectors.EVENT_READ, False)
            continue
        conn = key.fileobj
        try:
            data = conn.recv(1024)
            if data:
                conn.sendall(data)
                continue
        except ConnectionError:
            pass
        sel.unregister(conn)
        conn.close()
'
}
# failure_exchange <open|drop|down|hold> <client> <address> [address6]: only timeouts prove a filter drop.
# With disabled interfaces, explicit network/host-unreachable errors are also valid; refusals and exec errors never are.
# hold acknowledges both live sockets, then waits for restore_failure to trigger another payload on those same sockets.
failure_exchange() {
  fe_detach=
  [ "$1" = hold ] && fe_detach=-d
  docker exec ${fe_detach:+"$fe_detach"} "$2" python3 -c '
import errno, socket, sys, time
from pathlib import Path
mode, addr, addr6 = sys.argv[1:]
held = mode == "hold"

def exchange(s, expected, payload, address=None):
    try:
        if address is not None:
            s.connect((address, 4444))
        s.sendall(payload)
        assert s.recv(5, socket.MSG_WAITALL) == payload, "EOF or incorrect echo is not containment"
    except TimeoutError:
        assert expected in ("drop", "down")
    except OSError as err:
        assert expected == "down" and err.errno in (errno.ENETDOWN, errno.ENETUNREACH, errno.EHOSTUNREACH), err
    else:
        assert expected == "open", "application payload escaped the failed firewall install"

sockets = []
try:
    for address in (addr, addr6) if held else (addr,):
        s = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET)
        sockets.append(s)
        s.settimeout(3)
        exchange(s, "open" if held else mode, b"probe", address)
    if held:
        Path("/tmp/failure-held-ready").touch()
        mode_file = Path("/tmp/failure-held-mode")
        deadline = time.monotonic() + 60
        while not mode_file.exists():
            assert time.monotonic() < deadline, "held-flow trigger was not delivered"
            time.sleep(.05)
        mode = mode_file.read_text()
        for s in sockets:
            exchange(s, mode, b"after")
        Path("/tmp/failure-held-result").write_text("ok")
except Exception:
    if held:
        Path("/tmp/failure-held-result").write_text("failed")
    raise
finally:
    for s in sockets:
        s.close()
' "$1" "$3" "${4:-}"
}
# restore_failure <4|6> <full|baseline> <peer> <network>: inject only at the chosen restore boundary.
restore_failure() {
  rf_family=$1 rf_stage=$2 rf_peer=$3 rf_net=$4
  rf_hold=t5b-$$-failure-$1-$2-hold rf_app=t5b-$$-failure-$1-$2-app rf_product=t5b-$$-failure-$1-$2
  rf_bin=$TMP/failure-$1-$2
  mkdir -p "$rf_bin"
  rf_cmd=iptables-restore
  [ "$rf_family" = 6 ] && rf_cmd=ip6tables-restore
  cat > "$rf_bin/$rf_cmd" <<'EOF'
#!/bin/sh
rules=$(cat)
if [ "$FAIL_RESTORE_STAGE" = baseline ] || printf '%s\n' "$rules" | grep -q '^:WEBUI_HTTP '; then
  echo "injected $FAIL_RESTORE_STAGE restore failure" >&2
  exit 1
fi
printf '%s\n' "$rules" | "/usr/sbin/${0##*/}"
EOF
  chmod 755 "$rf_bin/$rf_cmd"
  CONTAINERS="$CONTAINERS $rf_hold $rf_product"
  docker run -d --name "$rf_hold" --network "$rf_net" --cap-add NET_ADMIN --entrypoint sleep "$IMAGE" infinity >/dev/null || return 1
  attach "$rf_app" "$rf_hold" && failure_listener "$rf_app" || return 1
  rf_hold4=$(ip_of "$rf_hold" "$rf_net") rf_hold6=$(ip6_of "$rf_hold" "$rf_net")
  rf_peer4=$(ip_of "$rf_peer" "$rf_net") rf_peer6=$(ip6_of "$rf_peer" "$rf_net")
  eventually 10 failure_exchange open "$rf_app" "$rf_peer4" &&
    eventually 10 failure_exchange open "$rf_app" "$rf_peer6" &&
    eventually 10 failure_exchange open "$rf_peer" "$rf_hold4" &&
    eventually 10 failure_exchange open "$rf_peer" "$rf_hold6" || return 1
  failure_exchange hold "$rf_app" "$rf_peer4" "$rf_peer6" &&
    eventually 10 docker exec "$rf_app" test -f /tmp/failure-held-ready &&
    failure_exchange open "$rf_app" "$rf_peer4" || return 1
  # No test firewall or entrypoint replaces the product: only its selected restore executable is wrapped.
  docker run -d --name "$rf_product" --network "container:$rf_hold" --cap-add NET_ADMIN --device /dev/net/tun \
    -v "$TMP:/config" -v "$rf_bin:/test-firewall-bin:ro" -e FAIL_RESTORE_STAGE="$rf_stage" \
    -e PATH=/test-firewall-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin "$IMAGE" >/dev/null || return 1
  timeout 20 docker wait "$rf_product" >/dev/null || return 1
  [ "$(docker inspect -f '{{.State.ExitCode}}' "$rf_product")" -ne 0 ] &&
    logged "$rf_product" "injected $rf_stage restore failure" &&
    is_running "$rf_hold" && is_running "$rf_app" || return 1
  rf_expect=drop
  if [ "$rf_stage" = baseline ]; then
    rf_expect=down
    logged "$rf_product" 'non-loopback interfaces disabled' || return 1
    docker exec "$rf_hold" sh -c '[ -z "$(ip -o link show up | grep -v " lo:")" ]' || return 1
  fi
  docker exec "$rf_app" sh -c 'printf "%s" "$1" > /tmp/failure-held-mode' sh "$rf_expect" &&
    eventually 10 docker exec "$rf_app" test -f /tmp/failure-held-result &&
    docker exec "$rf_app" grep -qx ok /tmp/failure-held-result &&
    failure_exchange "$rf_expect" "$rf_app" "$rf_peer4" &&
    failure_exchange "$rf_expect" "$rf_app" "$rf_peer6" &&
    failure_exchange "$rf_expect" "$rf_peer" "$rf_hold4" &&
    failure_exchange "$rf_expect" "$rf_peer" "$rf_hold6"
}

C=t5b-$$-smoke
mkdir -p "$TMP/Proton"
echo '{}' > "$TMP/Proton/stale.json"
chmod 644 "$TMP/Proton/stale.json"
run_container "$C" || { echo "FAIL container boot"; exit 1; }

assert "nm running" nm_running
assert "cli disconnected" cli_disconnected
assert "user:root profile activates" user_root_profile_activates
assert "config modes: /config/Proton 700" mode_is /config/Proton 700
assert "config modes: /config/cache 700" mode_is /config/cache 700
assert "config modes: stale.json 600" mode_is /config/Proton/stale.json 600
assert "symlinks: /etc/Proton" link_is /etc/Proton /config/Proton
assert "symlinks: /var/cache/Proton" link_is /var/cache/Proton /config/cache
assert "restart boots" reboot "$C" restart
assert "restart boots: nm running" nm_running
assert "restart boots: cli disconnected" cli_disconnected

# NM's real dispatcher carries a managed connection's DNS to resolv.conf and Docker's resolver back.
assert "managed connection dns reaches resolv.conf, Docker's returns" managed_dns_follows_connection

# A connection left tunnel DNS populated, then the container is killed and started: lookups work again before any signin.
assert "dns works before" dns_from "$C"
assert "tunnel dns populated" tunnel_dns_populated
assert "populated tunnel dns does not resolve" dns_blocked_from "$C"
assert "kill and start boots" reboot "$C" kill
assert "dns recovers after kill/start" eventually 10 dns_from "$C"
assert "resolv.conf is Docker's again" docker_resolver_restored

# Task 3: kill switch. $C sits on the default bridge, attached containers share its namespace.
assert "resolv.conf survives nm up/down" resolv_survives_nm
attach "t5b-$$-att" "$C" || { echo "FAIL attach"; exit 1; }
assert "own 443 allowed" tcp_from "$C" 1.1.1.1 443
assert "own 80 blocked" blocked_from "$C" 1.1.1.1 80
assert "own dns allowed" dns_from "$C"
assert "attached 443 blocked" blocked_from "t5b-$$-att" 1.1.1.1 443
assert "attached dns blocked" dns_blocked_from "t5b-$$-att"

NETWORKS="$NETWORKS t5b-$$-net"
docker network create "t5b-$$-net" >/dev/null
run_container "t5b-$$-emb" --network "t5b-$$-net" || { echo "FAIL embedded boot"; exit 1; }
attach "t5b-$$-emb-att" "t5b-$$-emb" || { echo "FAIL attach"; exit 1; }
assert "own embedded dns allowed" dns_from "t5b-$$-emb"
assert "attached embedded dns blocked" dns_blocked_from "t5b-$$-emb-att"

GW=$(bridge_field Gateway)
run_container "t5b-$$-lan" -e LAN_NETWORKS="$(bridge_field Subnet)" || { echo "FAIL lan boot"; exit 1; }
attach "t5b-$$-lan-att" "t5b-$$-lan" || { echo "FAIL attach"; exit 1; }
assert "lan allowed" reachable_from "t5b-$$-lan-att" "$GW" 9
assert "lan blocked without LAN_NETWORKS" blocked_from "t5b-$$-att" "$GW" 9

# WebUI port: the WebUI (a listener in $C's own cgroup) must complete the handshake with an outside peer.
CIP=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' "$C")
CONTAINERS="$CONTAINERS t5b-$$-peer"
docker run -d --name "t5b-$$-peer" --entrypoint sleep "$IMAGE" infinity >/dev/null
assert "webui port open inbound" eventually 20 tcp_from "t5b-$$-peer" "$CIP" 8788
assert "other inbound port blocked" blocked_from "t5b-$$-peer" "$CIP" 8789

# IPv6 LAN: neighbour discovery must work for LAN_NETWORKS on an IPv6 network.
NETWORKS="$NETWORKS t5b-$$-v6"
docker network create --ipv6 --subnet fd00:3:3:3::/64 "t5b-$$-v6" >/dev/null
CONTAINERS="$CONTAINERS t5b-$$-v6peer"
docker run -d --name "t5b-$$-v6peer" --network "t5b-$$-v6" --entrypoint sleep "$IMAGE" infinity >/dev/null
V6PEER=$(docker inspect -f "{{(index .NetworkSettings.Networks \"t5b-$$-v6\").GlobalIPv6Address}}" "t5b-$$-v6peer")
run_container "t5b-$$-v6" --network "t5b-$$-v6" -e LAN_NETWORKS=fd00:3:3:3::/64 || { echo "FAIL v6 boot"; exit 1; }
attach "t5b-$$-v6-att" "t5b-$$-v6" || { echo "FAIL attach"; exit 1; }
assert "ipv6 lan allowed" reachable_from "t5b-$$-v6-att" "$V6PEER" 9
run_container "t5b-$$-v6n" --network "t5b-$$-v6" || { echo "FAIL v6n boot"; exit 1; }
attach "t5b-$$-v6n-att" "t5b-$$-v6n" || { echo "FAIL attach"; exit 1; }
assert "ipv6 lan blocked without LAN_NETWORKS" blocked_from "t5b-$$-v6n-att" "$V6PEER" 9
assert "bad LAN fails closed" fails_closed "t5b-$$-bad" LAN_NETWORKS=192.0.2.0/33 '[firewall]'
for port in 0 0x2328 02324; do
  assert "ambiguous WEBUI_PORT '$port' fails closed" fails_closed "t5b-$$-badport$port" "WEBUI_PORT=$port" WEBUI_PORT
done

# Full rules may fail on matches unavailable in the kernel even though the deny-only baseline is supported.
# An unavailable IPv6 filter has a different, disruptive fallback: every non-loopback interface is disabled.
failure_listener "t5b-$$-v6peer" || { echo "FAIL firewall failure peer listener"; exit 1; }
assert "IPv4 full-restore failure contains a surviving attached app in both families" restore_failure 4 full "t5b-$$-v6peer" "t5b-$$-v6"
assert "IPv6 full-restore failure contains a surviving attached app in both families" restore_failure 6 full "t5b-$$-v6peer" "t5b-$$-v6"
assert "IPv6 baseline failure disables shared interfaces rather than leaving IPv6 open" restore_failure 6 baseline "t5b-$$-v6peer" "t5b-$$-v6"

# WEBUI_ALLOWED_NETWORKS, judged on real TCP between containers: a client's address is the one the WebUI container sees.
# The list is the container's environment, so each case is its own container.
n=0
for bad in example.com '10.0.0.*' 10.0.0.0/33 ',,' '10.0.0.0/8,fd00::/129'; do
  n=$((n + 1))
  assert "invalid WEBUI_ALLOWED_NETWORKS '$bad' fails closed" fails_closed "t5b-$$-badnet$n" "WEBUI_ALLOWED_NETWORKS=$bad" WEBUI_ALLOWED_NETWORKS
done

CONTAINERS="$CONTAINERS t5b-$$-peer2"
docker run -d --name "t5b-$$-peer2" --entrypoint sleep "$IMAGE" infinity >/dev/null
PEER1=$(ip_of "t5b-$$-peer") ACL_KEY=$(openssl rand -hex 32)
# LAN_NETWORKS covers both peers: it admits them to other ports, but must not admit the unlisted one to the WebUI.
ACL=t5b-$$-acl
run_container "$ACL" -e WEBUI_ALLOWED_NETWORKS="$PEER1" -e LAN_NETWORKS="$(bridge_field Subnet)" -e WEBUI_PASSWORD=x -e API_KEY="$ACL_KEY" \
  || { echo "FAIL allowlist boot"; exit 1; }
ACLIP=$(ip_of "$ACL")
assert "allowlist: a listed client is served the API with its key" eventually 20 http_is 200 "t5b-$$-peer" "http://$ACLIP:8788/api/v1/status" "Authorization: Bearer $ACL_KEY"
assert "allowlist: a listed client is served the page" http_is 200 "t5b-$$-peer" "http://$ACLIP:8788/"
assert "allowlist: an unlisted LAN client never completes the handshake" blocked_from "t5b-$$-peer2" "$ACLIP" 8788
assert "allowlist: forged forwarding headers and a valid key do not help" http_is timeout "t5b-$$-peer2" "http://$ACLIP:8788/api/v1/status" \
  "Authorization: Bearer $ACL_KEY" "X-Forwarded-For: $PEER1" "X-Real-IP: $PEER1" "Forwarded: for=$PEER1"
assert "allowlist: the public API docs are behind the same policy" http_is timeout "t5b-$$-peer2" "http://$ACLIP:8788/api/v1/openapi.json"
assert "allowlist: other ports still follow LAN_NETWORKS" reachable_from "t5b-$$-peer2" "$ACLIP" 9
assert "allowlist: loopback is not implicitly allowed" blocked_from "$ACL" 127.0.0.1 8788
assert "allowlist: the container's own address is not implicitly allowed" blocked_from "$ACL" "$ACLIP" 8788
assert "allowlist: healthcheck does not need HTTP" unhealthy_when_signed_out "$ACL"
ACLO=t5b-$$-aclo
run_container "$ACLO" -e WEBUI_ALLOWED_NETWORKS=127.0.0.1 -e LAN_NETWORKS="$(bridge_field Subnet)" || { echo "FAIL loopback allowlist boot"; exit 1; }
assert "allowlist: loopback listed, the WebUI answers in the container" eventually 20 webui_says "$ACLO" /api/v1/state '^200$'
assert "allowlist: loopback listed, a client in LAN_NETWORKS is still dropped" blocked_from "t5b-$$-peer" "$(ip_of "$ACLO")" 8788

# IPv6 has its own list: the WebUI listens on IPv4 only, so a stand-in listener on the same port takes its place for IPv6.
CONTAINERS="$CONTAINERS t5b-$$-v6peer2"
docker run -d --name "t5b-$$-v6peer2" --network "t5b-$$-v6" --entrypoint sleep "$IMAGE" infinity >/dev/null
ACL6=t5b-$$-acl6
run_container "$ACL6" --network "t5b-$$-v6" -e WEBUI_ALLOWED_NETWORKS="$V6PEER" || { echo "FAIL ipv6 allowlist boot"; exit 1; }
ACL6IP=$(ip6_of "$ACL6" "t5b-$$-v6")
v6_listener "$ACL6" || { echo "FAIL ipv6 stand-in listener"; exit 1; }
assert "ipv6 allowlist: stand-in is listening" eventually 10 listening6 "$ACL6"
assert "ipv6 allowlist: a listed client connects" tcp_from "t5b-$$-v6peer" "$ACL6IP" 8788
assert "ipv6 allowlist: an unlisted client never completes the handshake" blocked_from "t5b-$$-v6peer2" "$ACL6IP" 8788
assert "ipv6 allowlist: no IPv4 entry, so no IPv4 client" blocked_from "t5b-$$-v6peer" "$(ip_of "$ACL6" "t5b-$$-v6")" 8788

# Packets that really arrive on proton0: a WireGuard pair in which the container opens the tunnel, so that the kill switch lets the
# UDP out and takes the answers as ESTABLISHED. With no list and with allow-all, the tunnel's clients never reach the WebUI, and the drop
# is the only thing that stops them: without it the same connections complete.
for mode in open all local; do
  CONTAINERS="$CONTAINERS t5b-$$-q0$mode"
  docker run -d --name "t5b-$$-q0$mode" --cap-add NET_ADMIN --entrypoint sleep "$IMAGE" infinity >/dev/null
done
run_container "t5b-$$-p0open" || { echo "FAIL proton0 boot"; exit 1; }
run_container "t5b-$$-p0all" -e WEBUI_ALLOWED_NETWORKS=0.0.0.0/0,::/0 || { echo "FAIL proton0 boot"; exit 1; }
run_container "t5b-$$-p0local" -e WEBUI_ALLOWED_NETWORKS=127.0.0.1 || { echo "FAIL proton0 boot"; exit 1; }
for mode in open all local; do
  assert "proton0 ($mode): the tunnel is up" proton0_pair "t5b-$$-p0$mode" "t5b-$$-q0$mode"
  if [ "$mode" = local ]; then
    assert "proton0 ($mode): an unlisted eth0 client is dropped" blocked_from "t5b-$$-peer" "$(ip_of "t5b-$$-p0$mode")" 8788
  else
    assert "proton0 ($mode): an eth0 client is served" eventually 20 tcp_from "t5b-$$-peer" "$(ip_of "t5b-$$-p0$mode")" 8788
  fi
  assert "proton0 ($mode): the same peer exchanges TCP and UDP application data" proton0_data "t5b-$$-p0$mode" "t5b-$$-q0$mode"
  if [ "$mode" = local ]; then
    assert "proton0 ($mode): the same unlisted peer cannot reach the control port" blocked_from "t5b-$$-q0$mode" 10.77.0.1 8788
  else
    assert "proton0 ($mode): tunnel clients never reach the WebUI, and only the drop stops them" proton0_drop_only "t5b-$$-p0$mode" "t5b-$$-q0$mode"
  fi
done

# Connected tunnel (needs the IPv6 network above): the WebUI answers and LAN_NETWORKS stay reachable, all else goes into the tunnel,
# with the kill-switch interface's default routes in the main table. $HOLD owns the namespace, so it outlives $POL's restarts.
GW=t5b-$$-gw HOLD=t5b-$$-hold POL=t5b-$$-pol
CONTAINERS="$CONTAINERS $GW $HOLD $POL"
docker run -d --name "$GW" --network "t5b-$$-v6" --cap-add NET_ADMIN --entrypoint sleep "$IMAGE" infinity >/dev/null
docker run -d --name "$HOLD" --network "t5b-$$-v6" --cap-add NET_ADMIN --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  --entrypoint sleep "$IMAGE" infinity >/dev/null
docker run -d --name "$POL" --network "container:$HOLD" --cap-add NET_ADMIN --device /dev/net/tun -v "$TMP:/config" \
  -e LAN_NETWORKS=10.55.0.0/24,fd55::/64 "$IMAGE" >/dev/null || { echo "FAIL tunnel policy start"; exit 1; }
wait_ready "$POL" || { echo "FAIL tunnel policy boot"; exit 1; }
tunnel_policy_setup || { echo "FAIL tunnel policy setup"; exit 1; }
ks_up "$POL" || { echo "FAIL kill-switch stand-in"; exit 1; }
# The restart takes the snapshot of eth0's routes (the gateway above) with the kill-switch routes already in the main table.
reboot "$POL" restart || { echo "FAIL tunnel policy restart"; exit 1; }
assert "kill switch defaults are in the main table" eventually 10 ks_defaults_in_main "$POL"
assert "kill switch present: egress table holds eth0 routes only" egress_table_eth0_only "$POL"
assert "kill switch present: WebUI replies select eth0" route_dev "$POL" eth0 -6 route get fd56::9 ipproto tcp sport 8788 dport 54321
assert "kill switch present: IPv6 LAN_NETWORKS select eth0" route_dev "$POL" eth0 -6 route get fd55::9
assert "tunnel down: LAN reachable through the gateway" reachable_from "$POL" 10.55.0.9 9
assert "tunnel down: IPv6 LAN reachable through the gateway" reachable_from "$POL" fd55::9 9
wg_up "$POL" >/dev/null || { echo "FAIL tunnel up"; exit 1; }
POLIP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"t5b-$$-v6\").IPAddress}}" "$HOLD")
assert "tunnel up: ordinary traffic selects the tunnel" route_dev "$POL" wgsim0 route get 1.1.1.1
assert "tunnel up: IPv6 ordinary traffic selects the tunnel" route_dev "$POL" wgsim0 -6 route get 2001:db8::1
assert "tunnel up: unconfigured network selects the tunnel" route_dev "$POL" wgsim0 route get 10.56.0.9
assert "tunnel up: unconfigured network is blocked" blocked_from "$POL" 10.56.0.9 9
assert "tunnel up: unconfigured IPv6 network is blocked" blocked_from "$POL" fd56::9 9
assert "tunnel up: LAN_NETWORKS select eth0" route_dev "$POL" eth0 route get 10.55.0.9
assert "tunnel up: IPv6 LAN_NETWORKS select eth0" route_dev "$POL" eth0 -6 route get fd55::9
assert "tunnel up: LAN reachable" reachable_from "$POL" 10.55.0.9 9
assert "tunnel up: IPv6 LAN reachable" reachable_from "$POL" fd55::9 9
assert "tunnel up: WebUI replies select eth0" route_dev "$POL" eth0 route get 10.56.0.9 ipproto tcp sport 8788 dport 54321
assert "tunnel up: IPv6 WebUI replies select eth0" route_dev "$POL" eth0 -6 route get fd56::9 ipproto tcp sport 8788 dport 54321
assert "tunnel up: other source ports still select the tunnel" route_dev "$POL" wgsim0 route get 10.56.0.9 ipproto tcp sport 8789 dport 54321
assert "tunnel up: WebUI answers a client outside LAN_NETWORKS" eventually 20 tcp_from_addr "$GW" 10.56.0.9 "$POLIP" 8788

# The namespace outlives the container and still holds the kill switch and tunnel: a restart must not stack the rules,
# and the leftovers must stay out of the egress table.
assert "namespace restarts" reboot "$POL" restart
assert "restart: policy rules once" policy_rules_once "$POL"
assert "restart: egress table holds eth0 routes only" egress_table_eth0_only "$POL"
assert "restart: WebUI replies select eth0" route_dev "$POL" eth0 -6 route get fd56::9 ipproto tcp sport 8788 dport 54321
assert "restart: IPv6 LAN_NETWORKS select eth0" route_dev "$POL" eth0 -6 route get fd55::9

# A broad LAN CIDR must not steal the tunnel's DNS/NAT-PMP destination.
assert "broad LAN policy reloads" docker exec -e LAN_NETWORKS=10.0.0.0/8,fd55::/64 "$POL" sh -c '. /usr/local/lib/protonvpn-container/firewall.sh; firewall_routes 4'
assert "broad LAN keeps Proton gateway in tunnel" route_dev "$POL" wgsim0 route get 10.2.0.1
assert "broad LAN still reaches other LAN addresses" route_dev "$POL" eth0 route get 10.55.0.9

# Kernel route dumps spell RA lifetimes as 'expires Nsec', which route replace cannot parse.
assert "RA-style routes installed" docker exec "$POL" sh -c "ip -6 route replace default via $gw6 dev eth0 proto ra metric 1024 expires 1800 && ip -6 route add fd88:2:2:2::/64 dev eth0 proto ra expires 1800"
assert "RA-style routes survive startup copy" reboot "$POL" restart
assert "RA-style routes keep IPv6 WebUI reachable" route_dev "$POL" eth0 -6 route get fd56::9 ipproto tcp sport 8788 dport 54321
assert "RA-style routes keep IPv6 LAN reachable" route_dev "$POL" eth0 -6 route get fd55::9

# Task 4: supervisor while signed out.
run_container "t5b-$$-main" || { echo "FAIL supervisor boot"; exit 1; }
assert "signin hint logged" eventually 20 hint_logged "t5b-$$-main"
assert "unhealthy when signed out" unhealthy_when_signed_out "t5b-$$-main"
assert "signed out: traffic check not passed" eventually 20 webui_says "t5b-$$-main" /api/v1/status '"tunnel_healthy": false'
assert "forwarded_port is empty, mode 644" eventually 5 port_file_empty_644 "t5b-$$-main"
assert "pid file: NetworkManager" pid_file_is "t5b-$$-main" nm.pid NetworkManager
assert "pid file: system bus" pid_file_is "t5b-$$-main" dbus-system.pid dbus-daemon
assert "pid file: session bus" pid_file_is "t5b-$$-main" dbus-session.pid dbus-daemon
assert "graceful stop" graceful_stop "t5b-$$-main"

# Task 5: WebUI, open (default) and with a password.
run_container "t5b-$$-open" || { echo "FAIL webui boot"; exit 1; }
assert "webui open: state is signed out with the banner" eventually 20 webui_state_signed_out_with_banner "t5b-$$-open"
assert "webui open: warning logged" logged "t5b-$$-open" "$WEBUI_WARNING"
assert "webui open: page served" webui_says "t5b-$$-open" / '<title>Proton VPN</title>'
assert "webui open: script served" webui_says "t5b-$$-open" /static/app.js '^200$'
assert "webui open: traversal refused" webui_says "t5b-$$-open" /static/../webui.py '^404$'
API_KEY=$(openssl rand -hex 32)
run_container "t5b-$$-pw" -e WEBUI_PASSWORD=x -e API_KEY="$API_KEY" || { echo "FAIL webui password boot"; exit 1; }
assert "webui password: state is 401" eventually 20 webui_says "t5b-$$-pw" /api/v1/state '^401$'
assert "webui password: page still loads" webui_says "t5b-$$-pw" / '<title>Proton VPN</title>'
assert "webui password: no open warning" not_logged "t5b-$$-pw" "$WEBUI_WARNING"
assert "public api: real bearer HTTP contract" bearer_smoke "t5b-$$-pw" "$API_KEY"
assert "webui stops within the shutdown budget" graceful_stop "t5b-$$-open"

[ "$FAILED" -eq 0 ] && echo "all ok"
exit "$FAILED"
