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

not() { ! "$@"; }
# tcp_from <container> <host> <port>: connect succeeds.
tcp_from() { docker exec "$1" timeout 5 bash -c "</dev/tcp/$2/$3"; }
# reachable_from <container> <host> <port>: connect succeeds or is refused; only a timeout (exit 124) fails.
reachable_from() { docker exec "$1" timeout 5 bash -c "</dev/tcp/$2/$3" 2>/dev/null; [ $? -ne 124 ]; }
dns_from() { docker exec "$1" timeout 5 getent hosts example.com; }
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
docker restart "$C" >/dev/null && wait_ready "$C"
assert "restart boots: nm running" nm_running
assert "restart boots: cli disconnected" cli_disconnected
assert "no runtime installs" no_runtime_installs

# Task 3: kill switch. $C sits on the default bridge, attached containers share its namespace.
attach t3-att "$C" || { echo "FAIL attach"; exit 1; }
assert "own 443 allowed" tcp_from "$C" 1.1.1.1 443
assert "own 80 blocked" not tcp_from "$C" 1.1.1.1 80
assert "own dns allowed" dns_from "$C"
assert "attached 443 blocked" not tcp_from t3-att 1.1.1.1 443
assert "attached dns blocked" not dns_from t3-att

NETWORKS="$NETWORKS t3-net"
docker network create t3-net >/dev/null
run_container t3-emb --network t3-net || { echo "FAIL embedded boot"; exit 1; }
attach t3-emb-att t3-emb || { echo "FAIL attach"; exit 1; }
assert "own embedded dns allowed" dns_from t3-emb
assert "attached embedded dns blocked" not dns_from t3-emb-att

GW=$(bridge_field Gateway)
run_container t3-lan -e LAN_NETWORKS="$(bridge_field Subnet)" || { echo "FAIL lan boot"; exit 1; }
attach t3-lan-att t3-lan || { echo "FAIL attach"; exit 1; }
assert "lan allowed" reachable_from t3-lan-att "$GW" 9
assert "lan blocked without LAN_NETWORKS" not reachable_from t3-att "$GW" 9

CIP=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' "$C")
CONTAINERS="$CONTAINERS t3-peer"
docker run -d --name t3-peer --entrypoint sleep "$IMAGE" infinity >/dev/null
assert "webui port open inbound" reachable_from t3-peer "$CIP" 8788
assert "bad LAN fails closed" bad_lan_fails_closed

[ "$FAILED" -eq 0 ] && echo "all ok"
exit "$FAILED"
