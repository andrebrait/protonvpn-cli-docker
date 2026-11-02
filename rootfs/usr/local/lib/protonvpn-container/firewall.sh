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

# firewall_init: load both families before anything else touches the network; exit on any failure.
# iptables-restore without --noflush replaces only the filter table, so Docker's nat rules survive.
firewall_init() {
  [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" = cgroup2fs ] || { fw_log "cgroup v2 required: /sys/fs/cgroup is not cgroup2fs"; exit 1; }
  cg=$(own_cgroup) || { fw_log "cgroup v2 required: no 0:: line in /proc/self/cgroup"; exit 1; }
  # Keep Docker's resolv.conf: the NM dispatcher restores it when NM has no nameserver to offer.
  mkdir -p /run/protonvpn-container
  cp /etc/resolv.conf /run/protonvpn-container/resolv.conf.docker
  chmod 644 /run/protonvpn-container/resolv.conf.docker
  resolvers=$(sed -n 's/^nameserver[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' /etc/resolv.conf)
  set -f
  for fam in 4 6; do
    cmd=iptables-restore
    [ "$fam" = 6 ] && cmd=ip6tables-restore
    # shellcheck disable=SC2086  # intentional word splitting of the resolver list
    rules=$(firewall_rules "$fam" "$cg" $resolvers)
    out=$(printf '%s\n' "$rules" | "$cmd" 2>&1) || { fw_log "$cmd failed: $out"; exit 1; }
  done
  set +f
  fw_log "kill switch loaded (cgroup $cg)"
}
