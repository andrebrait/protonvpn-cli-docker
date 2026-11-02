#!/bin/sh
set -eu
umask 077

log() { echo "[init] $*"; }

rm -f /run/session-bus.env

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
dbus-daemon --system --fork

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
# shellcheck disable=SC2086
NetworkManager $nm_args 2>&1 | sed -u 's/^/[nm] /' &

i=0
until [ "$(nmcli -t -f RUNNING general 2>/dev/null)" = running ]; do
  i=$((i + 1))
  if [ "$i" -gt 15 ]; then log "NetworkManager did not start within 15s"; exit 1; fi
  sleep 1
done

DBUS_SESSION_BUS_ADDRESS=$(dbus-daemon --session --fork --print-address)
echo "export DBUS_SESSION_BUS_ADDRESS='$DBUS_SESSION_BUS_ADDRESS'" > /run/session-bus.env
log "ready"
exec sleep infinity
