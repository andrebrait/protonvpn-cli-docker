#!/bin/sh
set -eu
umask 077

log() { echo "[init] $*"; }

# Load the kill switch first, before anything can touch the network; it is never removed.
# shellcheck source=/dev/null
. /usr/local/lib/protonvpn-container/firewall.sh
firewall_init

# The Python service reads the daemons' PIDs from here at shutdown.
pids=/run/protonvpn-container
mkdir -p "$pids"
rm -f /run/session-bus.env "$pids"/*.pid "$pids/nm.log" "$pids"/health.json*  # no healthy verdict survives a restart

# Proton hard-codes /etc/Proton and /var/cache/Proton when running as root; persist both under /config.
mkdir -p /config/Proton /config/cache
rm -rf /etc/Proton /var/cache/Proton
ln -s /config/Proton /etc/Proton
ln -s /config/cache /var/cache/Proton
chmod 700 /config/Proton /config/cache
find /config/Proton -type f -exec chmod 600 {} +

mkdir -p /run/dbus
chmod 755 /run/dbus
rm -f /run/dbus/pid
log "starting system bus"
dbus-daemon --system --fork --print-pid=3 3> "$pids/dbus-system.pid"

# Proton's NM profiles carry permissions=user:root; NM only activates those for a user with a
# logind session. No logind in a container, so publish the sd-login records NM reads.
# Must be world-readable: dbus-daemon reads them after dropping privileges (umask is 077).
mkdir -p /run/systemd/seats /run/systemd/users
chmod 755 /run/systemd /run/systemd/seats /run/systemd/users
printf 'STATE=active\nSESSIONS=c1\nACTIVE_SESSIONS=c1\nONLINE_SESSIONS=c1\n' > /run/systemd/users/0
chmod 644 /run/systemd/users/0

nm_args=--no-daemon
[ "${DEBUG:-false}" = true ] && nm_args="--no-daemon --debug"
log "starting NetworkManager"
# A FIFO instead of a pipe, so $! is NetworkManager and not the log prefixer.
mkfifo "$pids/nm.log"
sed -u 's/^/[nm] /' < "$pids/nm.log" &
# shellcheck disable=SC2086
NetworkManager $nm_args > "$pids/nm.log" 2>&1 &
echo $! > "$pids/nm.pid"

i=0
until [ "$(nmcli -t -f RUNNING general 2>/dev/null)" = running ]; do
  i=$((i + 1))
  if [ "$i" -gt 15 ]; then log "NetworkManager did not start within 15s"; exit 1; fi
  sleep 1
done

DBUS_SESSION_BUS_ADDRESS=$(dbus-daemon --session --fork --print-address --print-pid=3 3> "$pids/dbus-session.pid")
echo "export DBUS_SESSION_BUS_ADDRESS='$DBUS_SESSION_BUS_ADDRESS'" > /run/session-bus.env
log "ready"
exec python3 -m protonvpn_container
