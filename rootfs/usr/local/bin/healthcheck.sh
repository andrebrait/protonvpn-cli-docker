#!/bin/sh
# Healthy iff the supervisor's last tunnel probe passed less than a minute ago while the CLI reports a live connection
# (any other state revokes the file). Port forwarding does not matter here. Docker passes no arguments.
exec python3 -m protonvpn_container.health
