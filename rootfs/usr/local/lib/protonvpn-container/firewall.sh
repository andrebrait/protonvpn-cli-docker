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
  echo '-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
  echo '-A OUTPUT -o proton0 -j ACCEPT'
  echo '-A INPUT -i proton0 -j ACCEPT'
  echo '-A OUTPUT -m mark --mark 0xea13b2c -j ACCEPT'
  for net in $(echo "${LAN_NETWORKS:-}" | tr ',' ' '); do
    case $net in *:*) [ "$fam" = 6 ] || continue ;; *) [ "$fam" = 4 ] || continue ;; esac
    echo "-A OUTPUT -o eth0 -d $net -j ACCEPT"
    echo "-A INPUT -i eth0 -s $net -j ACCEPT"
  done
  echo "-A INPUT -i eth0 -p tcp --dport ${WEBUI_PORT:-8788} -j ACCEPT"
  echo "-A OUTPUT -o eth0 -m cgroup --path $cg -p tcp --dport 443 -j ACCEPT"
  for r in "$@"; do
    case $r in *:*) [ "$fam" = 6 ] || continue ;; *) [ "$fam" = 4 ] || continue ;; esac
    echo "-A OUTPUT -o eth0 -m cgroup --path $cg -p udp --dport 53 -d $r -j ACCEPT"
    echo "-A OUTPUT -o eth0 -m cgroup --path $cg -p tcp --dport 53 -d $r -j ACCEPT"
  done
  echo 'COMMIT'
}

# firewall_init: load both families before anything else touches the network; exit on any failure.
# iptables-restore without --noflush replaces only the filter table, so Docker's nat rules survive.
firewall_init() {
  cg=$(own_cgroup) || { fw_log "cgroup v2 required: no 0:: line in /proc/self/cgroup"; exit 1; }
  resolvers=$(sed -n 's/^nameserver[[:space:]]*//p' /etc/resolv.conf)
  for fam in 4 6; do
    cmd=iptables-restore
    [ "$fam" = 6 ] && cmd=ip6tables-restore
    # shellcheck disable=SC2086  # intentional word splitting of the resolver list
    rules=$(firewall_rules "$fam" "$cg" $resolvers)
    out=$(printf '%s\n' "$rules" | "$cmd" 2>&1) || { fw_log "$cmd failed: $out"; exit 1; }
  done
  fw_log "kill switch loaded (cgroup $cg)"
}
