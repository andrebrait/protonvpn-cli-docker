# Manual release checks

Run this checklist on a disposable test deployment on the target Unraid/Linux host **before each release**, after automated checks. It requires the operator's Proton credentials and can interrupt connectivity. Do not use production attached applications for fault injection. Never record passwords, TOTP codes, bearer keys, or session tokens in results.

This is a checklist, not a record of successful tests. Leave unexercised items unchecked and state why. Real arm64 VPN operation and FIDO2 sign-in are unverified until separately exercised and recorded.

## Record the environment

- [ ] Record date, image tag/digest, architecture, Unraid/OS version, kernel (`uname -r`), Docker version, and cgroup mode (`docker info`). Identify the host and container iptables backends separately; they do not need to match.
- [ ] Confirm cgroup v2, host `xt_cgroup` and `wireguard` support, `/dev/net/tun`, and the documented run flags. Check startup logs show the firewall loaded before NetworkManager starts.
- [ ] Use a fresh test `/config` volume. Set `WEBUI_PASSWORD` and a distinct random `API_KEY` (for example, `openssl rand -hex 32`). Restrict published ports to a trusted network and configure the actual LAN CIDRs.
- [ ] Start only the VPN container first. Confirm no runtime package installation, the signed-out hint in `docker logs protonvpn-cli`, an accessible WebUI, and unhealthy Docker status while signed out.
- [ ] Record the installed Proton packages: `sh tests/versions.sh IMAGE` (from a checkout of the same revision) must pass and list CLI 1.1.0 / api-core 6.1.1 for the first release.
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
- [ ] With no setting environment overrides, confirm the WebUI fields remain editable, including the Python startup default `ANONYMOUS_CRASH_REPORTS=off`. Confirm there is no kill-switch field or API override: Standard is the fixed Proton target and the container firewall remains enforced. An adopted connected tunnel may retain its prior Proton setting until a disconnected opportunity, as documented.
- [ ] In a disposable stopped deployment, set the saved native `protocol` to `openvpn-tcp` without changing other values. Start it and confirm the supervisor saves `wireguard` before connecting, native status reports WireGuard, and traffic health/forwarding recover. A corrupt or unwritable native settings file must block connect without overwriting it. An already-connected unsupported protocol must never be published as connected while its bounded disconnect is in progress or failing.
- [ ] Change a CLI setting and connection target in the WebUI while signed in. Confirm the CLI setting applies immediately, target changes reconnect, and accepted values persist in `/config/settings.json`. Reject an invalid value without saving it.
- [ ] Change a setting while signed out, then sign in. Confirm it is applied; a rejected upstream value is visible rather than silently ignored.
- [ ] Recreate with a non-empty setting environment variable. Confirm its value applies, the WebUI field is locked, and API writes to it return 409. Remove/empty the override and recreate; confirm the saved value or Python default returns and the field unlocks. `docker restart` alone cannot change container environment.
- [ ] Confirm `/etc/resolv.conf` uses the VPN-provided DNS after connection (unless deliberately using custom DNS). Check DNS and the public exit IP from an attached application; compare the exit IP with VPN status rather than the host's normal route.
- [ ] Allow `LAN_NETWORKS=10.0.0.0/8` and confirm ordinary LAN traffic is direct but `10.2.0.1` still routes through the VPN, so Proton DNS and NAT-PMP work.
- [ ] On an IPv6 network with router-advertisement routes, confirm startup succeeds with route lifetimes present and WebUI/LAN replies remain direct.
- [ ] Restart with a connected tunnel and confirm Exit IP recovers without a new sign-in. The same traffic-check probe fills it. An echo failure with independently advancing WireGuard handshakes must leave `connected` true (CLI-derived), mark `tunnel_healthy` false, and never reconnect the VPN.
- [ ] While connected (VPN DNS in `/etc/resolv.conf`), `docker kill` and `docker start` the VPN container. Before signing in or reconnecting, confirm `docker exec protonvpn-cli getent hosts example.com` works and `/etc/resolv.conf` is Docker's resolver again, not the VPN's `10.2.0.1`; then confirm the session reconnects and DNS follows the tunnel.
- [ ] On an eligible P2P server/plan, enable port forwarding. Confirm a valid matching port in the WebUI, `/config/forwarded_port`, JSON `/api/v1/port`, and text `/api/v1/port?format=text`. Observe multiple renewals at roughly 45-second intervals.
- [ ] Turn forwarding Off through the unlocked WebUI/API. Confirm API/file withdrawal precedes bounded deletion attempts, the native tunnel stays connected, and deletion acknowledgment, rejection or timeout is recorded honestly. Remember deletion covers this tunnel source identity's protocol mappings, including attached applications. Turn On again and confirm a current matching port returns. Do not count absent advertisement as proof of remote revocation.
- [ ] Request Disconnect while forwarding. Confirm the advertised port is withdrawn immediately and bounded deletion attempts happen before the native disconnect, on both success and failure. A failed disconnect must neither renew nor repeatedly delete those known mappings while the request remains pending.
- [ ] Configure the torrent listener to that port and confirm inbound reachability using a suitable external peer/probe. This project does not automatically update qBittorrent. Do not mistake a Docker host port publication for VPN forwarding.
- [ ] Exercise a NAT-PMP refresh failure. Confirm a warning and cleared forwarded port; a connected VPN remains healthy. Restore the path and confirm the port returns.
- [ ] Confirm the published port is a single number that is reachable over both TCP and UDP. Then stop the gateway answering NAT-PMP (or block UDP 5351 to `10.2.0.1` from the container), and confirm the port clears from the WebUI, `/api/v1/port` and `/config/forwarded_port` within about a minute and returns after restoring the path. Freeze a running CLI call (`kill -STOP`) for over a minute while connected: an expired port must not stay advertised.
- [ ] While forwarding, Sign out, Disconnect, and change `COUNTRY` in the WebUI. Confirm the connected state, exit IP and port disappear immediately, not at the next check. Make `protonvpn status` fail (for example `kill -STOP` it for its 120-second timeout) and confirm the WebUI shows a state-check error rather than the last good connection.
- [ ] In a disposable controlled scenario, request Disconnect while native Connect is still pending. Confirm the late tunnel is disconnected before publication and cancellation does not count as a failed network attempt or roll back a saved target. A newer Connect must still supersede the canceled intent promptly.
- [ ] Generate traffic in the attached application. Confirm the traffic graph changes, API RX/TX totals increase, `/traffic` samples have newest relative time 0, and totals/samples reset on a new connection.
- [ ] In a disposable setup, fail one CLI state check and recover on the same or a replaced tunnel. Confirm traffic history is cleared rather than calculating a rate across the unverified interval.

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
- [ ] **For every row:** the VPN container's own processes retain only the intended non-LAN direct exceptions: TCP 443 and UDP/TCP 53 to startup resolvers, not arbitrary DNS servers or other ports. Use `docker exec` probes (Python sockets); attached-container sockets must not inherit these cgroup exceptions. Check IPv4 and available IPv6.
- [ ] **For every row:** loopback and configured LAN access remain usable; no non-LAN bypass is observed. The firewall rules remain installed even when the CLI is absent or signed out.
- [ ] Observe no continued direct `eth0` traffic from a pre-existing attached flow after the tunnel drops. Use packet capture on the test host/namespace if needed to distinguish encrypted WireGuard traffic from application leaks.

## Recovery and health

- [ ] In the disposable deployment, record the selected WireGuard endpoint (`docker exec protonvpn-cli wg show proton0 endpoints`). Block only that endpoint's traffic for five minutes using a reversible test-host rule; record the exact rule and its removal command before applying it. Do not block management access or all host traffic. Observe leak probes throughout, then remove the rule and confirm recovery and retry backoff (up to 300 seconds).
- [ ] Confirm Docker health requires both the CLI reporting `Status: Connected` and a passing traffic check (`tunnel_healthy` true in `/api/v1/status`, last check within 60 seconds). Startup grace 60 seconds, interval 30 seconds, timeout 10 seconds, three retries. A missing forwarded port alone must not fail health.
- [ ] While the CLI reports `Connected`, block the tunnel's UDP path with the reversible endpoint rule above. Confirm `/api/v1/status` initially keeps `connected: true` but shows `tunnel_healthy: false` with a short `health_error`; Docker becomes unhealthy and the WebUI shows a failed traffic check, never an all-healthy green state. After at least 180 seconds of valid unchanged/zero handshake evidence with successful independent UDP stimulus, confirm the supervisor withdraws connection/port/health publication before a bounded disconnect and reconnect. A failed disconnect must not connect over the old tunnel. Record retry delays of 30/60/120/300 seconds from failed-attempt completion, despite native status continuing to report `Connected`. No signout/signin or target/settings change is allowed. Record whether the CLI itself dropped instead and which path recovered.
- [ ] Remove the endpoint rule. Confirm the traffic check returns to **Passed** and Docker returns to healthy, without signing in again or pressing Connect.
- [ ] Third-party probe outage: while the tunnel is healthy, block HTTPS to `api.ipify.org` from the container with a reversible host rule (record the rule and its removal command first). Repeat with an ipify-only DNS failure. Observe for over 180 seconds: the traffic check fails and Docker goes unhealthy, but independent interface-bound UDP stimulus advances `wg show proton0 latest-handshakes`; native status remains `Connected`, logs show no reconnect/disconnect, and forwarding stays advertised while its lease renews. Restore the path and confirm the check passes without signing in.
- [ ] Confirm an unhealthy container is not assumed to restart from health status. The supervisor handles connection recovery; the Docker restart policy only handles process exits.
- [ ] Stop the container normally. Confirm disconnect and daemon shutdown complete, no secrets in logs, and no unexpected attached-application direct route during shutdown.

## WebUI and public API

Use `VPN_URL=http://YOUR_TEST_HOST:8788` and a locally exported `API_KEY`; do not paste real keys into evidence.

- [ ] With `WEBUI_PASSWORD` set, unauthenticated protected GETs return 401 with `{"error":"message"}`. A valid WebUI session or `Authorization: Bearer $API_KEY` succeeds; a wrong token does not. Confirm the WebUI password is not implicitly accepted as a bearer key.
- [ ] Check `/api/v1/status`, `/api/v1/port`, `/api/v1/traffic`, `/api/v1/settings`, and aggregate `/api/v1/state`. Compare reported values with CLI/WebUI state. Text port output is a bare number or empty body; JSON port output is a number or null. Confirm `tunnel_healthy`, `health_error` and `health_checked_ago` agree with the WebUI traffic check.
- [ ] Open `/api` and GET `/api/v1/openapi.json` without auth. Confirm the docs render offline with no external CDN dependency and show the bearer-key generation and request examples.
- [ ] Exercise connect/disconnect, settings, sign-in/code/sign-out, login/logout, and banner dismissal using the documented POST bodies. Confirm non-bearer POSTs need `X-Requested-With: protonvpn-webui`; valid bearer requests do not. Validate errors use `{"error":"message"}` with non-success status, including invalid sign-in and locked settings.
- [ ] Save a preference while signed out, then make applying it fail after sign-in. Confirm its current error replaces the earlier save-success message. During a delayed save, edit the same field again; the newer edit must remain pending after the response and next poll. A failed banner-dismiss request must retain both the banner and its inline error after subsequent polls.
- [ ] With multiple dirty preferences, reject one settings request at the transport layer. Confirm a per-field error and accurate batch count, the remaining fields are attempted, failed values stay pending and Save is immediately retryable. Include reverting to the prior value while the POST is held and a state poll sees the submitted value; the input must survive that poll. A concurrent poll-401 or logout must invalidate the old batch, even if its response arrives after a new settings view is built.
- [ ] Make five incorrect WebUI login attempts within 60 seconds from one client IP. Confirm a 60-second lockout and recovery. Behind a shared-IP proxy/rootless/Desktop path, record that other clients sharing the observed IP are locked out too.
- [ ] In a separate disposable open-mode configuration, leave `WEBUI_PASSWORD` empty with `API_KEY` set. Confirm the log warning and dismissible banner, and that unauthenticated API access still works. An API key alone must not be described as protection. Restore password protection afterward.

## WebUI network allowlist

Use a disposable deployment with at least two clients: one whose address is listed in `WEBUI_ALLOWED_NETWORKS`, and one whose address is not. Recreate the container after each change; `docker restart` keeps the old environment. Record the exact list, each client's address, and the source address the container observed for each attempt.

- [ ] Set `WEBUI_ALLOWED_NETWORKS` to the allowed client's address with `/32` (for example `192.0.2.10/32`) and recreate. Confirm the listed client loads `/`, `/api`, and `/api/v1/openapi.json`, and that the WebUI password or `API_KEY` still applies where configured.
- [ ] From the unlisted client, confirm the TCP connection to the published port fails with no HTTP response. Repeat with `X-Forwarded-For` set to the allowed address and with a valid bearer key or session cookie. None of these attempts may succeed.
- [ ] Set the list to `127.0.0.1/32` only, recreate, and run `docker exec protonvpn-cli curl --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}' 'http://127.0.0.1:8788/api/v1/openapi.json'`. Expect `200`. Replace the list with a nonempty LAN CIDR that excludes loopback, recreate, and confirm the same command times out without an HTTP response: loopback is not implicitly allowed. The OpenAPI route is used because it needs no credentials.
- [ ] Set the list to an IPv4 range only (for example `0.0.0.0/0`). Confirm an IPv4 client is allowed and an IPv6 client is denied. Then use an IPv6 entry only and confirm the IPv4 client is denied. If the HTTP service listens only on IPv4, use a controlled IPv6 listener on the same port in an isolated test namespace to exercise the IPv6 filter; a missing listener is not evidence of filtering.
- [ ] With a controlled WireGuard peer sending real packets into `proton0`, confirm TCP connections to `WEBUI_PORT` fail for an empty list, a list matching the peer, and `0.0.0.0/0,::/0`. For each case, confirm a non-VPN client reaches HTTP and that the same peer can reach separate TCP and UDP application/data ports through the tunnel. The HTTP drop must not block those ports. Confirm `iptables-save` and `ip6tables-save` show the HTTP drop before generic accepts as secondary evidence. Use an isolated test deployment and record tunnel checks as not exercised if no controlled peer is available; do not count rule inspection alone as runtime proof.
- [ ] Set `LAN_NETWORKS` to the denied client's network while `WEBUI_ALLOWED_NETWORKS` excludes that client. Confirm the WebUI still refuses it: `LAN_NETWORKS` does not admit WebUI clients.
- [ ] Unset `WEBUI_ALLOWED_NETWORKS` (or leave it empty) and recreate. Confirm a LAN client reaches the WebUI as before, and that authentication behaves unchanged.
- [ ] Startup validation: in separate disposable deployments, set `WEBUI_ALLOWED_NETWORKS` to `example.com`, `10.0.0.0/33`, `*`, and `,`. For each, confirm the container fails startup with a `WEBUI_ALLOWED_NETWORKS` error in `docker logs` and never serves HTTP. Record any value that starts successfully as a failure.
- [ ] In disposable deployments, set `WEBUI_PORT` to `0x2328`, `02324`, and `0`. Each must fail startup before serving HTTP; the firewall, routing rules and listener must never interpret the same port differently. Confirm a valid decimal port such as `9000` serves HTTP on that port with the same source and tunnel restrictions.
- [ ] Confirm Docker health is unaffected by the list: with a restrictive list that excludes the Docker host, `docker inspect --format '{{.State.Health.Status}}' protonvpn-cli` still reflects the CLI and traffic check.
- [ ] With an isolated partial-install failure while another container retains the namespace, confirm attached IPv4/IPv6 payloads remain blocked after startup exits. If baseline filtering itself fails, confirm external interfaces are disabled; recreate the shared namespace before retrying. Do not run fault injection in a production namespace.
- [ ] If a reverse proxy fronts the WebUI, confirm the container sees the proxy's address rather than the client's. Confirm clients that must be blocked are blocked at the proxy, since the container cannot tell them apart.
- [ ] Lockout recovery: with a denied client, change `WEBUI_ALLOWED_NETWORKS` in the Unraid template (or Compose or `docker run`), recreate the VPN container and its attached containers, and confirm the intended client regains access. Confirm `docker exec protonvpn-cli protonvpn status` works during the lockout.

## Finish and record

- [ ] Remove temporary endpoint-block rules, probes, and the disposable deployment/volumes when no longer needed. Never remove production containers or data as part of this checklist.
- [ ] Record each checked result with date, host, image digest, observations, failures, and unexercised cases. Review `/config/cache/VPN/logs/vpn-cli.log` and `docker logs`; redact sensitive details before sharing. Do not mark the release credentialed checks complete from automated smoke results alone.
