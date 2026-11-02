#!/bin/sh
# Healthy iff the CLI reports a live connection; port forwarding does not matter here.
[ "$(/usr/local/bin/protonvpn status 2>/dev/null | head -n 1)" = "Status: Connected" ]
