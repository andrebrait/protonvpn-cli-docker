# Manual release checks

Run this checklist on a disposable test deployment on the target Unraid/Linux host **before each release**, after automated checks. It requires the operator's Proton credentials and can interrupt connectivity. Do not use production attached applications for fault injection. Never record passwords, TOTP codes, bearer keys, or session tokens in results.

This is a checklist, not a record of successful tests. Leave unexercised items unchecked and state why. Real arm64 VPN operation and FIDO2 sign-in are unverified until separately exercised and recorded.

## Record the environment

- [ ] Record date, image tag/digest, architecture, Unraid/OS version, kernel (`uname -r`), Docker version, and cgroup mode (`docker info`). Identify the host and container iptables backends separately; they do not need to match.
- [ ] Confirm cgroup v2, host `xt_cgroup` and `wireguard` support, `/dev/net/tun`, and the documented run flags. Check startup logs show the firewall loaded before NetworkManager starts.
- [ ] Use a fresh test `/config` volume. Set `WEBUI_PASSWORD` and a distinct random `API_KEY` (for example, `openssl rand -hex 32`). Restrict published ports to a trusted network and configure the actual LAN CIDRs.
- [ ] Start only the VPN container first. Confirm no runtime package installation, the signed-out hint in `docker logs protonvpn-cli`, an accessible WebUI, and unhealthy Docker status while signed out.
- [ ] Record whether IPv6 internet and IPv6 LAN probes have a working baseline. Mark unavailable IPv6 checks as not exercised, not passed.

## Authentication and persistence

- [ ] Unlock the WebUI; sign in to Proton with username/password and TOTP. Confirm the account is detected, settings apply, and a connection starts without restarting the container.
- [ ] Try an invalid Proton password and invalid TOTP. Confirm useful errors, no successful authentication, and no credentials/codes in `docker logs` or CLI logs. Confirm abandoned sign-in expires after five minutes and a new flow can start.
- [ ] Sign out; use `docker exec -it protonvpn-cli protonvpn signin YOUR_USERNAME --totp` (or Unraid Console). Confirm console TOTP sign-in also leads to automatic connection.
- [ ] Recreate the VPN container with the same `/config` volume. Confirm the Proton session and saved WebUI settings survive and settings are reapplied. Recreate attached containers too if any exist.
- [ ] Check `/config/Proton` and `/config/cache` are mode 700, Proton token/settings files are mode 600, `/config/settings.json` is mode 600, and `/config/forwarded_port` is mode 644 when created. Protect backups as credentials.

### Optional, separately recorded coverage

- [ ] If a FIDO2 account and usable security-key access are available, test CLI interactive sign-in from Console without `--totp`. Record the device/access method and outcome; otherwise record **FIDO2 unverified**. Do not imply WebUI FIDO2 support.
- [ ] If real arm64 hardware is available, repeat credentialed VPN, DNS, forwarding and leak checks there. An arm64 build/import check alone is not a real VPN test.

## Connection, settings and port forwarding

- [ ] Connect by `COUNTRY`, by exact `SERVER`, and with `P2P=true`. Verify status/server/location and confirm `SERVER` takes precedence over `COUNTRY`/`CITY` with a warning.
- [ ] With no setting environment overrides, confirm the WebUI fields remain editable, including the Python startup defaults `KILL_SWITCH=standard` and `ANONYMOUS_CRASH_REPORTS=off`.
- [ ] Change a CLI setting and connection target in the WebUI while signed in. Confirm the CLI setting applies immediately, target changes reconnect, and accepted values persist in `/config/settings.json`. Reject an invalid value without saving it.
- [ ] Change a setting while signed out, then sign in. Confirm it is applied; a rejected upstream value is visible rather than silently ignored.
- [ ] Recreate with a non-empty setting environment variable. Confirm its value applies, the WebUI field is locked, and API writes to it return 409. Remove/empty the override and recreate; confirm the saved value or Python default returns and the field unlocks. `docker restart` alone cannot change container environment.
- [ ] Confirm `/etc/resolv.conf` uses the VPN-provided DNS after connection (unless deliberately using custom DNS). Check DNS and the public exit IP from an attached application; compare the exit IP with VPN status rather than the host's normal route.
- [ ] On an eligible P2P server/plan, enable port forwarding. Confirm a valid matching port in the WebUI, `/config/forwarded_port`, JSON `/api/v1/port`, and text `/api/v1/port?format=text`. Observe multiple renewals at roughly 45-second intervals.
- [ ] Configure the torrent listener to that port and confirm inbound reachability using a suitable external peer/probe. This project does not automatically update qBittorrent. Do not mistake a Docker host port publication for VPN forwarding.
- [ ] Exercise a NAT-PMP refresh failure. Confirm a warning and cleared forwarded port; a connected VPN remains healthy. Restore the path and confirm the port returns.
- [ ] Generate traffic in the attached application. Confirm the traffic graph changes, API RX/TX totals increase, `/traffic` samples have newest relative time 0, and totals/samples reset on a new connection.

## Attached applications and namespace lifecycle

After the VPN is healthy, start a disposable diagnostic container. This image supplies the probe tools; it is not added to the VPN image:

```bash
docker run -d --name vpn-probe \
  --network=container:protonvpn-cli \
  --cap-drop=NET_RAW \
  nicolaka/netshoot sleep infinity
```

- [ ] Confirm the probe has no `NET_ADMIN` and has `NET_RAW` dropped. Check Compose's `service_healthy` dependency gates startup of attached applications.
- [ ] While connected, record successful public HTTPS, HTTP, and DNS baselines from the probe. Example commands: `docker exec vpn-probe curl --fail --max-time 8 https://1.1.1.1` and `docker exec vpn-probe dig +time=2 +tries=1 @1.1.1.1 example.com`. Establish IPv6 baselines separately if supported.
- [ ] Publish an attached application's UI port on the VPN container. Confirm trusted LAN access with `LAN_NETWORKS` set, and no port collision with 8788. Check an explicitly allowed IPv6 LAN CIDR too if available.
- [ ] Recreate the VPN container in the test stack. Recreate the attached application and probe so they join the replacement namespace; confirm connectivity again. Do not assume an already-running attachment follows a container name or that `depends_on` repairs it.

## Kill-switch fault matrix

Use the probe only after the healthy baseline above. Keep probe attempts running during each disruption, not only after reconnection. Capture timestamps/results and check both IPv4 and available IPv6. The threat model is accidental application leakage, not malicious packet marking or firewall modification.

Perform **each row**, observing the three expectation groups below:

| Fault | Procedure / recovery |
| --- | --- |
| CLI killed | Kill an active `/usr/bin/protonvpn` CLI child in the test container (the spec's fault injection is `pkill -f /usr/bin/protonvpn`); observe supervisor recovery. Ensure an actual CLI process was killed and record whether the tunnel stayed up or dropped. If it stayed up, also exercise a tunnel-down case; an intact tunnel is not evidence of disconnected isolation. |
| Explicit disconnect | Run `docker exec protonvpn-cli protonvpn disconnect`; observe the down interval before the supervisor reconnects. Also check the WebUI Disconnect action holds the tunnel down until Connect is selected. |
| Signed out | Sign out through the WebUI, verify unhealthy state, then sign back in to recover. |

- [ ] **For every row:** attached probe traffic to non-LAN addresses fails whenever the tunnel is down. Check public TCP 80 and 443, UDP and TCP DNS 53, and another port such as 853 against established baselines. Check direct DNS and Docker embedded DNS (`dig @127.0.0.11 example.com`, when present); neither may fall back outside the tunnel. Record any IPv6 coverage gaps explicitly.
- [ ] **For every row:** the VPN container's own processes retain only the intended non-LAN direct exceptions: TCP 443 and UDP/TCP 53 to startup resolvers, not arbitrary DNS servers or other ports. Use `docker exec` probes (Python sockets or installed `wget`); attached-container sockets must not inherit these cgroup exceptions. Check IPv4 and available IPv6.
- [ ] **For every row:** loopback and configured LAN access remain usable; no non-LAN bypass is observed. The firewall rules remain installed even when the CLI is absent or signed out.
- [ ] Observe no continued direct `eth0` traffic from a pre-existing attached flow after the tunnel drops. Use packet capture on the test host/namespace if needed to distinguish encrypted WireGuard traffic from application leaks.

## Recovery and health

- [ ] In the disposable deployment, record the selected WireGuard endpoint (`docker exec protonvpn-cli wg show proton0 endpoints`). Block only that endpoint's traffic for five minutes using a reversible test-host rule; record the exact rule and its removal command before applying it. Do not block management access or all host traffic. Observe leak probes throughout, then remove the rule and confirm recovery and retry backoff (up to 300 seconds).
- [ ] Confirm Docker health follows `protonvpn status`: startup grace 60 seconds, interval 30 seconds, timeout 10 seconds, three retries. A missing forwarded port alone must not fail health.
- [ ] Confirm an unhealthy container is not assumed to restart from health status. The supervisor handles connection recovery; the Docker restart policy only handles process exits.
- [ ] Stop the container normally. Confirm disconnect and daemon shutdown complete, no secrets in logs, and no unexpected attached-application direct route during shutdown.

## WebUI and public API

Use `VPN_URL=http://YOUR_TEST_HOST:8788` and a locally exported `API_KEY`; do not paste real keys into evidence.

- [ ] With `WEBUI_PASSWORD` set, unauthenticated protected GETs return 401 with `{"error":"message"}`. A valid WebUI session or `Authorization: Bearer $API_KEY` succeeds; a wrong token does not. Confirm the WebUI password is not implicitly accepted as a bearer key.
- [ ] Check `/api/v1/status`, `/api/v1/port`, `/api/v1/traffic`, `/api/v1/settings`, and aggregate `/api/v1/state`. Compare reported values with CLI/WebUI state. Text port output is a bare number or empty body; JSON port output is a number or null.
- [ ] Open `/api` and GET `/api/v1/openapi.json` without auth. Confirm the docs render offline with no external CDN dependency and show the bearer-key generation and request examples.
- [ ] Exercise connect/disconnect, settings, sign-in/code/sign-out, login/logout, and banner dismissal using the documented POST bodies. Confirm non-bearer POSTs need `X-Requested-With: protonvpn-webui`; valid bearer requests do not. Validate errors use `{"error":"message"}` with non-success status, including invalid sign-in and locked settings.
- [ ] Make five incorrect WebUI login attempts within 60 seconds from one client IP. Confirm a 60-second lockout and recovery. Behind a shared-IP proxy/rootless/Desktop path, record that other clients sharing the observed IP are locked out too.
- [ ] In a separate disposable open-mode configuration, leave `WEBUI_PASSWORD` empty with `API_KEY` set. Confirm the log warning and dismissible banner, and that unauthenticated API access still works. An API key alone must not be described as protection. Restore password protection afterward.

## Finish and record

- [ ] Remove temporary endpoint-block rules, probes, and the disposable deployment/volumes when no longer needed. Never remove production containers or data as part of this checklist.
- [ ] Record each checked result with date, host, image digest, observations, failures, and unexercised cases. Review `/config/cache/VPN/logs/vpn-cli.log` and `docker logs`; redact sensitive details before sharing. Do not mark the release credentialed checks complete from automated smoke results alone.
