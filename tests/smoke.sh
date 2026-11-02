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

no_runtime_installs() {
  [ -z "$(docker exec "$C" sh -c 'ls /var/lib/apt/lists | grep -v -e lock -e partial')" ]
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
bad_lan_fails_closed() {
  start_container t3-bad -e LAN_NETWORKS=not-a-cidr || return 1
  i=0
  while [ "$i" -lt 10 ]; do
    [ "$(docker inspect -f '{{.State.Running}}' t3-bad)" = false ] && break
    i=$((i + 1)); sleep 1
  done
  [ "$(docker inspect -f '{{.State.Running}}' t3-bad)" = false ] || return 1
  [ "$(docker inspect -f '{{.State.ExitCode}}' t3-bad)" -ne 0 ] || return 1
  docker logs t3-bad 2>&1 | grep -qF '[firewall]'
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
  out=$(webui_get "$1" /api/state) || return 1
  case $out in "200"*'"signed_in": false'*'"banner": true'*) return 0 ;; esac
  return 1
}
WEBUI_WARNING='[webui] WARNING: WEBUI_PASSWORD is not set; the WebUI is open to anyone who can reach it'
logged() { docker logs "$1" 2>&1 | grep -qF "$2"; }
not_logged() { ! logged "$@"; }

C=t1-smoke
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
# The previous boot's session-bus.env would satisfy wait_ready before the new boot removes it.
docker exec "$C" rm -f /run/session-bus.env
docker restart "$C" >/dev/null && wait_ready "$C"
assert "restart boots: nm running" nm_running
assert "restart boots: cli disconnected" cli_disconnected
assert "no runtime installs" no_runtime_installs

# Task 3: kill switch. $C sits on the default bridge, attached containers share its namespace.
assert "resolv.conf survives nm up/down" resolv_survives_nm
attach t3-att "$C" || { echo "FAIL attach"; exit 1; }
assert "own 443 allowed" tcp_from "$C" 1.1.1.1 443
assert "own 80 blocked" blocked_from "$C" 1.1.1.1 80
assert "own dns allowed" dns_from "$C"
assert "attached 443 blocked" blocked_from t3-att 1.1.1.1 443
assert "attached dns blocked" dns_blocked_from t3-att

NETWORKS="$NETWORKS t3-net"
docker network create t3-net >/dev/null
run_container t3-emb --network t3-net || { echo "FAIL embedded boot"; exit 1; }
attach t3-emb-att t3-emb || { echo "FAIL attach"; exit 1; }
assert "own embedded dns allowed" dns_from t3-emb
assert "attached embedded dns blocked" dns_blocked_from t3-emb-att

GW=$(bridge_field Gateway)
run_container t3-lan -e LAN_NETWORKS="$(bridge_field Subnet)" || { echo "FAIL lan boot"; exit 1; }
attach t3-lan-att t3-lan || { echo "FAIL attach"; exit 1; }
assert "lan allowed" reachable_from t3-lan-att "$GW" 9
assert "lan blocked without LAN_NETWORKS" blocked_from t3-att "$GW" 9

# WebUI port: the WebUI (a listener in $C's own cgroup) must complete the handshake with an outside peer.
CIP=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' "$C")
CONTAINERS="$CONTAINERS t3-peer"
docker run -d --name t3-peer --entrypoint sleep "$IMAGE" infinity >/dev/null
assert "webui port open inbound" eventually 20 tcp_from t3-peer "$CIP" 8788
assert "other inbound port blocked" blocked_from t3-peer "$CIP" 8789

# IPv6 LAN: neighbour discovery must work for LAN_NETWORKS on an IPv6 network.
NETWORKS="$NETWORKS t3-v6"
docker network create --ipv6 --subnet fd00:3:3:3::/64 t3-v6 >/dev/null
CONTAINERS="$CONTAINERS t3-v6peer"
docker run -d --name t3-v6peer --network t3-v6 --entrypoint sleep "$IMAGE" infinity >/dev/null
V6PEER=$(docker inspect -f '{{(index .NetworkSettings.Networks "t3-v6").GlobalIPv6Address}}' t3-v6peer)
run_container t3-v6 --network t3-v6 -e LAN_NETWORKS=fd00:3:3:3::/64 || { echo "FAIL v6 boot"; exit 1; }
attach t3-v6-att t3-v6 || { echo "FAIL attach"; exit 1; }
assert "ipv6 lan allowed" reachable_from t3-v6-att "$V6PEER" 9
run_container t3-v6n --network t3-v6 || { echo "FAIL v6n boot"; exit 1; }
attach t3-v6n-att t3-v6n || { echo "FAIL attach"; exit 1; }
assert "ipv6 lan blocked without LAN_NETWORKS" blocked_from t3-v6n-att "$V6PEER" 9
assert "bad LAN fails closed" bad_lan_fails_closed

# Task 4: supervisor while signed out.
run_container t4-main || { echo "FAIL supervisor boot"; exit 1; }
assert "signin hint logged" eventually 20 hint_logged t4-main
assert "unhealthy when signed out" unhealthy_when_signed_out t4-main
assert "forwarded_port is empty, mode 644" eventually 5 port_file_empty_644 t4-main
assert "pid file: NetworkManager" pid_file_is t4-main nm.pid NetworkManager
assert "pid file: system bus" pid_file_is t4-main dbus-system.pid dbus-daemon
assert "pid file: session bus" pid_file_is t4-main dbus-session.pid dbus-daemon
assert "graceful stop" graceful_stop t4-main

# Task 5: WebUI, open (default) and with a password.
run_container t5-open || { echo "FAIL webui boot"; exit 1; }
assert "webui open: state is signed out with the banner" eventually 20 webui_state_signed_out_with_banner t5-open
assert "webui open: warning logged" logged t5-open "$WEBUI_WARNING"
assert "webui open: page served" webui_says t5-open / '<title>Proton VPN</title>'
assert "webui open: script served" webui_says t5-open /static/app.js '^200$'
assert "webui open: traversal refused" webui_says t5-open /static/../webui.py '^404$'
run_container t5-pw -e WEBUI_PASSWORD=x || { echo "FAIL webui password boot"; exit 1; }
assert "webui password: state is 401" eventually 20 webui_says t5-pw /api/state '^401$'
assert "webui password: page still loads" webui_says t5-pw / '<title>Proton VPN</title>'
assert "webui password: no open warning" not_logged t5-pw "$WEBUI_WARNING"
assert "webui stops within the shutdown budget" graceful_stop t5-open

[ "$FAILED" -eq 0 ] && echo "all ok"
exit "$FAILED"
