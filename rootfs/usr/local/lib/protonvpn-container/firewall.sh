#!/bin/sh
# Fail-closed kill switch. Sourced by entrypoint.sh; see "Kill switch" in the design spec.

fw_log() { echo "[firewall] $*"; }

# own_cgroup [file]: print the cgroup v2 path from /proc/self/cgroup; exit 1 without a 0:: line.
own_cgroup() {
  while IFS= read -r line; do
    case $line in 0::*) printf '%s\n' "${line#0::}"; return 0 ;; esac
  done < "${1:-/proc/self/cgroup}"
  return 1
}

# firewall_rules <4|6> <own_cgroup> [resolvers...]: print an iptables-restore *filter document.
# Reads LAN_NETWORKS (comma-separated CIDRs) and WEBUI_PORT (default 8788) from the environment.
firewall_rules() {
  fam=$1 cg=$2; shift 2
  set -f  # CIDR and resolver lists are expanded unquoted: no globbing
  echo '*filter'
  echo ':INPUT DROP [0:0]'
  echo ':OUTPUT DROP [0:0]'
  echo ':FORWARD DROP [0:0]'
  if [ "$fam" = 4 ]; then
    # Docker's embedded DNS answers on lo but forwards outside the tunnel: own cgroup only.
    echo "-A OUTPUT -o lo -d 127.0.0.11 -m cgroup --path $cg -j ACCEPT"
    echo '-A OUTPUT -o lo -d 127.0.0.11 -j DROP'
  fi
  echo '-A OUTPUT -o lo -j ACCEPT'
  echo '-A INPUT -i lo -j ACCEPT'
  echo '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
  # Replies leave eth0 only from this container's own sockets; attached flows get nothing here.
  echo "-A OUTPUT -o eth0 -m conntrack --ctstate ESTABLISHED,RELATED -m cgroup --path $cg -j ACCEPT"
  echo '-A OUTPUT -o proton0 -j ACCEPT'
  echo '-A INPUT -i proton0 -j ACCEPT'
  echo '-A OUTPUT -m mark --mark 0xea13b2c -j ACCEPT'
  for net in $(echo "${LAN_NETWORKS:-}" | tr ',' ' '); do
    case $net in *:*) [ "$fam" = 6 ] || continue ;; *) [ "$fam" = 4 ] || continue ;; esac
    echo "-A OUTPUT -o eth0 -d $net -j ACCEPT"
    echo "-A INPUT -i eth0 -s $net -j ACCEPT"
  done
  if [ "$fam" = 6 ]; then
    # Neighbour discovery, or no IPv6 peer on the LAN is reachable (kernel-originated, no cgroup).
    for t in neighbour-solicitation neighbour-advertisement; do
      echo "-A OUTPUT -o eth0 -p ipv6-icmp --icmpv6-type $t -j ACCEPT"
      echo "-A INPUT -i eth0 -p ipv6-icmp --icmpv6-type $t -j ACCEPT"
    done
  fi
  echo "-A INPUT -i eth0 -p tcp --dport ${WEBUI_PORT:-8788} -j ACCEPT"
  # The SYN-ACK of a listener carries no matchable cgroup, so WebUI replies are matched by port;
  # ESTABLISHED limits this to flows that were opened inbound to the WebUI port.
  echo "-A OUTPUT -o eth0 -p tcp --sport ${WEBUI_PORT:-8788} -m conntrack --ctstate ESTABLISHED -j ACCEPT"
  echo "-A OUTPUT -o eth0 -m cgroup --path $cg -p tcp --dport 443 -j ACCEPT"
  for r in "$@"; do
    r=${r%%%*}  # drop an IPv6 zone id
    case $r in
      '') continue ;;
      *[!0-9a-fA-F:.]*) continue ;;
      *:*) [ "$fam" = 6 ] || continue ;;
      *) [ "$fam" = 4 ] || continue ;;
    esac
    echo "-A OUTPUT -o eth0 -m cgroup --path $cg -p udp --dport 53 -d $r -j ACCEPT"
    echo "-A OUTPUT -o eth0 -m cgroup --path $cg -p tcp --dport 53 -d $r -j ACCEPT"
  done
  echo 'COMMIT'
  set +f
}

# keep_docker_resolver <resolv.conf> <NM resolv.conf> <saved>: keep Docker's resolv.conf at <saved> for the NM dispatcher.
# /run and /etc/resolv.conf can outlive a container restart. Nothing runs yet, so NM's file is the previous run's, and a
# resolv.conf identical to it is the tunnel DNS the dispatcher left behind, not Docker's: put the saved one back and
# never overwrite the saved one with it. NM's stale file goes before NM starts.
keep_docker_resolver() {
  if [ -s "$3" ] && [ -s "$2" ] && cmp -s "$1" "$2"; then
    cat "$3" > "$1"  # in place: it is a bind mount
  else
    cp "$1" "$3"
  fi
  chmod 644 "$3"
  rm -f "$2"
}

# Docker's own routes (every route through eth0) live in this table, private to the container's namespace; see firewall_routes.
FW_EGRESS_TABLE=7788

# firewall_routes <4|6>: NetworkManager's WireGuard policy ("lookup main suppress_prefixlength 0", then "not fwmark <tunnel> lookup <tunnel table>",
# priorities ~31000) sends every flow without the tunnel's fwmark into the tunnel, including the WebUI's replies and the LAN_NETWORKS flows
# the filter lets out of eth0. Those flows must leave through eth0, but the main table cannot be trusted to pick it: Proton's kill-switch
# interface puts its own default there (IPv6 metric 95, against Docker's 1024 on eth0), so "lookup main" would send them into the kill switch.
# So eth0's routes are snapshotted into FW_EGRESS_TABLE (taken before NetworkManager runs, and "dev eth0" leaves out any
# kill-switch or tunnel route an earlier run left in the main table), and two rules ahead of the tunnel policy send exactly those flows
# there; all other traffic still follows the tunnel. Rebuilt from scratch, so a namespace that outlives a restart gets no duplicates.
# Reads LAN_NETWORKS and WEBUI_PORT like firewall_rules.
firewall_routes() {
  fam=$1
  for prio in 100 101; do
    while ip -"$fam" rule del priority "$prio" 2>/dev/null; do :; done
  done
  # A table that holds nothing does not exist: showing it prints an error, flushing it fails.
  [ -z "$(ip -"$fam" route show table "$FW_EGRESS_TABLE" 2>/dev/null)" ] || ip -"$fam" route flush table "$FW_EGRESS_TABLE" || return 1
  # No eth0 (--network none) means no routes to keep. "show dev" leaves the device out of each line.
  routes=$(ip -"$fam" route show dev eth0 2>/dev/null)
  if [ -n "$routes" ]; then
    printf '%s\n' "$routes" | sed "s/\$/ dev eth0/; s/^/route replace table $FW_EGRESS_TABLE /" | ip -"$fam" -batch - || return 1
  fi
  ip -"$fam" rule add priority 100 ipproto tcp sport "${WEBUI_PORT:-8788}" lookup "$FW_EGRESS_TABLE" || return 1
  for net in $(echo "${LAN_NETWORKS:-}" | tr ',' ' '); do
    case $net in *:*) [ "$fam" = 6 ] || continue ;; *) [ "$fam" = 4 ] || continue ;; esac
    ip -"$fam" rule add priority 101 to "$net" lookup "$FW_EGRESS_TABLE" || return 1
  done
}

# firewall_init: load both families before anything else touches the network; exit on any failure.
# iptables-restore without --noflush replaces only the filter table, so Docker's nat rules survive.
firewall_init() {
  [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" = cgroup2fs ] || { fw_log "cgroup v2 required: /sys/fs/cgroup is not cgroup2fs"; exit 1; }
  cg=$(own_cgroup) || { fw_log "cgroup v2 required: no 0:: line in /proc/self/cgroup"; exit 1; }
  mkdir -p /run/protonvpn-container
  keep_docker_resolver /etc/resolv.conf /run/NetworkManager/resolv.conf /run/protonvpn-container/resolv.conf.docker
  resolvers=$(sed -n 's/^nameserver[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' /etc/resolv.conf)
  set -f
  for fam in 4 6; do
    cmd=iptables-restore
    [ "$fam" = 6 ] && cmd=ip6tables-restore
    # shellcheck disable=SC2086  # intentional word splitting of the resolver list
    rules=$(firewall_rules "$fam" "$cg" $resolvers)
    out=$(printf '%s\n' "$rules" | "$cmd" 2>&1) || { fw_log "$cmd failed: $out"; exit 1; }
    firewall_routes "$fam" || { fw_log "ip -$fam rule failed: WebUI and LAN_NETWORKS replies would be lost while the VPN is up"; exit 1; }
  done
  set +f
  fw_log "kill switch loaded (cgroup $cg)"
}
