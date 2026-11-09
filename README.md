<p align="center"><img src="images/icon-256.png" alt="Proton VPN" width="160"></p>

# protonvpn-cli-docker

Run the official Proton VPN CLI in Docker, with a WebUI and a shared VPN network for other containers.

The image uses Debian 13 slim and includes the CLI, NetworkManager, WireGuard tools, firewall tools, and all runtime dependencies at build time. It does not install packages on startup. A supervisor manages connections and NAT-PMP port forwarding; the WebUI handles sign-in, settings, status, and traffic.

Every build installs exactly one reviewed Proton release: **CLI 1.1.0** with **API core 6.1.1**, pinned in the [`Dockerfile`](Dockerfile) and printed in the build output. A new Proton release is adopted by changing those pins after it is tested, never by merely rebuilding. Published tags are `latest` and, for each release, `X.Y.Z` and `X.Y` (currently `0.1.0` and `0.1`). The Debian 13 slim base is refreshed at every build.

**Proton does not officially support headless use.** This project supplies the container integration; an upstream CLI change can break it. It is not affiliated with Proton AG. The icon is Proton AG's trademark, used to identify the Proton VPN service.

## Dependency update proposals

The **Dependency updates** GitHub Actions workflow checks Proton's stable repository and ShellCheck daily at 05:17 UTC, or on manual dispatch. It opens or updates one review PR with newer pins, keeps the Proton repository bootstrap version and SHA256 together, and updates the README's Proton versions. It never proposes downgrades or merges an update automatically.

Dependabot checks GitHub Actions versions and the Debian base image tag weekly. Unpinned Debian packages and the current base image tag continue to receive available updates through the existing weekly rebuild.

The scheduled workflow needs **Settings → Actions → General → Workflow permissions → Allow GitHub Actions to create and approve pull requests** enabled. It uses the repository's `GITHUB_TOKEN`; no personal token is required. It explicitly dispatches CI on the update branch because token-created PRs do not trigger normal PR workflows. Review the CI run and upstream release notes before approving or merging.

## Requirements and compatibility

- Linux Docker host with cgroup v2, the `xt_cgroup` iptables match, WireGuard kernel support (`wireguard`), `/dev/net/tun`, Linux pidfd support and readable procfs for identity-safe daemon shutdown.
- The VPN container needs `NET_ADMIN`, the TUN device, and `net.ipv4.conf.all.src_valid_mark=1`. Do not use privileged mode or host networking.
- A Proton VPN account; some features, including port forwarding, depend on your plan and selected server.

Measured Unraid compatibility is **Unraid 7.3.4, kernel 6.18.58, Docker 29.8.2, cgroup v2, and `xt_cgroup`**. The host and container can use different iptables backends: host legacy versus container nft is not itself a compatibility problem. This is not a claim of support for all Unraid or Docker versions. The arm64 image build and Python imports have been verified; a real arm64 VPN connection has not.

## Quick start

### Docker run

Choose a strong WebUI password. Replace `192.168.1.10` with the Docker host's trusted LAN address and change the LAN CIDR to your own network. Leave `LAN_NETWORKS` empty if no direct LAN access is needed. Binding a LAN address does not replace source filtering or authentication.

```bash
export WEBUI_PASSWORD='replace-this-with-a-strong-password'
docker run -d --name protonvpn-cli \
  --restart unless-stopped \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  -p 192.168.1.10:8788:8788 \
  -v protonvpn-config:/config \
  -e WEBUI_PASSWORD \
  -e LAN_NETWORKS=192.168.1.0/24 \
  ghcr.io/andrebrait/protonvpn-cli-docker:latest
```

Open `http://YOUR_DOCKER_HOST:8788/`, unlock the WebUI, and sign in to Proton. Until the VPN is connected and the traffic check passes, the container remains running but unhealthy. Keep the published port on a trusted network, and set `WEBUI_ALLOWED_NETWORKS` to limit which clients may connect; the built-in server uses HTTP, not TLS. Use a trusted HTTPS reverse proxy for remote access, rather than exposing it directly to the internet.

For HTTPS access, let the reverse proxy terminate TLS, redirect plain HTTP to HTTPS, and add `Secure` to the `session` cookie. Restrict direct access to the backend HTTP port to trusted clients or the proxy with `WEBUI_ALLOWED_NETWORKS`; do not trust forwarded headers for access control. The backend intentionally omits `Secure` because direct LAN HTTP is supported. For example, an Nginx HTTPS proxy can set [`proxy_cookie_flags session secure;`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cookie_flags) in its proxy location. Use the equivalent response-cookie option on other proxies, and enable HSTS on a dedicated HTTPS hostname once HTTPS-only access works.

To build locally instead of pulling a published image:

```bash
docker build -t ghcr.io/andrebrait/protonvpn-cli-docker:latest .
```

### Docker Compose with an attached application

Save this as `compose.yaml`. Replace `192.168.1.10` with the Docker host's trusted LAN address, replace the LAN CIDR, set `WEBUI_PASSWORD` as above, and run `docker compose up -d`. qBittorrent starts only after the VPN reports healthy. On first use, sign in to Proton through port 8788 while Compose waits for that health check; if the dependency times out, run `docker compose up -d` again after connecting.

```yaml
services:
  protonvpn-cli:
    image: ghcr.io/andrebrait/protonvpn-cli-docker:latest
    container_name: protonvpn-cli
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    sysctls:
      net.ipv4.conf.all.src_valid_mark: "1"
    ports:
      - "192.168.1.10:8788:8788"
      - "192.168.1.10:8080:8080" # qBittorrent WebUI, published on the VPN container
    environment:
      WEBUI_PASSWORD: ${WEBUI_PASSWORD:?Set WEBUI_PASSWORD first}
      LAN_NETWORKS: 192.168.1.0/24
    volumes:
      - protonvpn-config:/config

  qbittorrent:
    image: lscr.io/linuxserver/qbittorrent:latest
    network_mode: service:protonvpn-cli
    depends_on:
      protonvpn-cli:
        condition: service_healthy
    cap_drop:
      - NET_RAW
    restart: unless-stopped
    environment:
      WEBUI_PORT: "8080"
    volumes:
      - qbittorrent-config:/config
      - ./downloads:/downloads

volumes:
  protonvpn-config:
  qbittorrent-config:
```

The qBittorrent service has its own authentication and storage configuration; consult its image documentation. `depends_on` gates startup, not ongoing health or namespace recovery.

## Sign-in and settings

Use the WebUI to sign in with your Proton username and password, including a TOTP code when enabled. Alternatively, use the Unraid **Console** button or:

```bash
docker exec -it protonvpn-cli protonvpn signin YOUR_USERNAME --totp
```

FIDO2 security-key sign-in is console-only and **unverified** in this container. Use the CLI's interactive sign-in without `--totp` for that flow. Proton passwords and TOTP codes are not stored by the service; session tokens are persisted in `/config/Proton/`. Treat the entire `/config` volume and its backups as sensitive.

The supervisor detects sign-in, applies settings, and connects without a restart. Sign-out resets upstream CLI settings; the service reapplies effective settings on the next sign-in.

Settings resolve in this order:

1. A **non-empty environment variable** wins and locks that field in the WebUI.
2. Otherwise, the value saved by the WebUI in `/config/settings.json` wins.
3. Otherwise, Python's `ANONYMOUS_CRASH_REPORTS=off` startup default applies; other configurable settings are left to the CLI.

That startup default is **not a Docker `ENV` value** and does not lock the field. Leave setting variables empty to configure them in the WebUI. Accepted changes apply live while signed in; signed-out changes are saved for the next sign-in. To change environment variables, recreate the container with the new configuration; `docker restart` does not change its environment.

### Environment variables

Connection settings default to empty (automatic selection, with optional filters).

| Variable | Value / purpose |
| --- | --- |
| `SERVER` | Server name, such as `NL#914`; overrides `COUNTRY` and `CITY` with a warning. |
| `COUNTRY` | Country code or full name. |
| `CITY` | City filter. |
| `P2P` | `true` / `false`; request P2P servers. |
| `SECURE_CORE` | `true` / `false`; request Secure Core. |
| `TOR` | `true` / `false`; request Tor servers. |

CLI settings accept the following values. Empty means use saved settings, then the startup default shown below.

| Variable | CLI key | Values | Startup default |
| --- | --- | --- | --- |
| `NETSHIELD` | `netshield` | `off`, `malware-only`, `malware-ads-trackers` | CLI default |
| `PORT_FORWARDING` | `port-forwarding` | `off`, `on` | CLI default |
| `VPN_ACCELERATOR` | `vpn-accelerator` | `off`, `on` | CLI default |
| `MODERATE_NAT` | `moderate-nat` | `off`, `on` | CLI default |
| `IPV6` | `ipv6` | `off`, `on` | CLI default |
| `CUSTOM_DNS` | `custom-dns` | `off`, or `on --dns 1.1.1.1,8.8.8.8` (comma-separated IPv4/IPv6 addresses) | CLI default |
| `ANONYMOUS_CRASH_REPORTS` | `anonymous-crash-reports` | `off`, `on` | `off` |

Container-only configuration is not editable in the WebUI:

| Variable | Default | Purpose |
| --- | --- | --- |
| `LAN_NETWORKS` | empty | Comma-separated IPv4/IPv6 CIDRs allowed outside the tunnel, for traffic such as attached application ports. Use only trusted networks. Does not grant WebUI access. |
| `WEBUI_PORT` | `8788` | Internal WebUI/API listen port, decimal `1`–`65535` without leading zeros. Invalid values stop startup. Update Docker's port mapping if changed. |
| `WEBUI_ALLOWED_NETWORKS` | empty | Comma-separated IPv4/IPv6 CIDRs or addresses allowed to reach the WebUI and API port. Empty allows any non-VPN source. Recreate the container to change it. See [WebUI network allowlist](#webui-network-allowlist). |
| `WEBUI_PASSWORD` | empty | WebUI password, distinct from your Proton password. Empty enables open mode with a log warning and dismissible banner. |
| `API_KEY` | empty | Separate bearer credential for scripts. Empty disables bearer-token access, not open-mode access. |
| `TZ` | `UTC` | Timezone for logs. |
| `DEBUG` | `false` | `true` / `false`; verbose CLI and NetworkManager logging. Review logs before sharing them. |
| `RECONNECT_INTERVAL` | `30` | Supervisor connection-check interval in seconds (at least 1). |

### WebUI network allowlist

`WEBUI_ALLOWED_NETWORKS` filters the source address of every TCP connection to `WEBUI_PORT` before the container accepts it. It covers the whole HTTP surface: the WebUI, the API, metrics, login and logout, the API documentation, the OpenAPI JSON, and static files. It is set when the container is created and is not editable in the WebUI or API.

```bash
WEBUI_ALLOWED_NETWORKS=127.0.0.1/32,10.0.0.0/8
```

The example allows loopback and a private `10.0.0.0/8` network. Use your real LAN CIDR instead.

- **Empty or unset:** any non-VPN source may reach the port, and authentication works as before. An empty list does not disable authentication, and `API_KEY` does not restrict access by itself.
- **Set:** only sources matching a listed CIDR or address connect; all others are dropped. Each address family is checked separately, so an IPv4-only list denies every IPv6 client.
- **Loopback is not implicit.** Include `127.0.0.1/32` (and `::1/128` for IPv6 loopback) if local clients need access.
- **The Proton tunnel cannot reach the HTTP port.** TCP connections arriving through the tunnel to `WEBUI_PORT` are blocked even with `0.0.0.0/0,::/0` or a range that contains the tunnel address. Other TCP and UDP application/data ports remain usable through the tunnel.
- **Invalid values fail startup.** Entries must be IPv4 or IPv6 CIDRs or single addresses; a single address means `/32` or `/128`. Hostnames are not resolved. Wildcards, malformed CIDRs, and delimiter-only values stop startup with a `WEBUI_ALLOWED_NETWORKS` error. The container never falls back to allowing every source. Whitespace around entries is ignored.
- **The source is the address the container sees.** `X-Forwarded-For` and similar headers are ignored. A reverse proxy, or Docker's userland proxy, can replace the client address with its own, so the list must match that address. In that case, restrict real clients at the proxy.
- **Headers, API keys, and session cookies cannot bypass the list.** A denied client never completes the TCP handshake.
- **Not affected:** the Proton CLI and data tunnel, the health check (it reads a local file, not HTTP), and the outbound traffic check. `LAN_NETWORKS` does not admit WebUI clients; a LAN range must appear in this list to reach the WebUI.

**Locked out?** The list cannot be changed from the WebUI. Edit `WEBUI_ALLOWED_NETWORKS` in the Unraid template, or in your Compose file or `docker run` command, then recreate the container and its attached containers. Unraid's Console button and `docker exec` use the CLI rather than HTTP, so they stay available for diagnosis.

## Attaching containers and hardening

Use `--network=container:protonvpn-cli` with Docker run, or `network_mode: service:protonvpn-cli` with Compose. Publish attached applications' ports **on the VPN container**, not on the attached container. Allow the trusted LAN CIDR in `LAN_NETWORKS` for direct access to those application ports. All services in the namespace must use different listen ports.

Startup installs deny-only IPv4 and IPv6 filters before loading any allow rules. A later filter or configuration failure exits with those restrictions retained, including when an attached container keeps the namespace alive. If a baseline filter cannot be installed, startup disables non-loopback interfaces and exits; recreate the VPN and attached containers to obtain a fresh namespace before retrying. If interface shutdown also fails, the log explicitly says containment cannot be guaranteed. Do not attach applications to an unsuccessful startup.

Direct WebUI/LAN routes are captured from Docker's `eth0` routes at startup. Restart after changing those routes or attaching a different Docker network. Proton's `10.2.0.1` DNS/forwarding gateway stays inside the tunnel even when a broad LAN range such as `10.0.0.0/8` is allowed.

Drop `NET_RAW` from attached containers (`--cap-drop=NET_RAW`), **never grant them `NET_ADMIN`**, and start them only after the VPN container reports healthy. Do not start attached applications alongside an uninitialized VPN namespace: firewall setup happens early in startup, but not atomically with namespace creation.

Docker joins an existing network namespace, not a permanently tracked container name. **If the VPN container is recreated, recreate the attached containers too**, so they join the new namespace. A health dependency alone does not do this for already-running containers. In the Compose example, recreate both services after changing VPN configuration:

```bash
docker compose up -d --force-recreate protonvpn-cli qbittorrent
```

The firewall covers **accidental leaks**, not hostile code in an attached container. Shared networking is not a security boundary against an application that can manipulate packet marks, raw frames, or firewall rules.

### Kill-switch behavior

IPv4 and IPv6 filter rules load before NetworkManager starts and remain installed while the namespace exists. Attached applications can use the tunnel and explicitly allowed LAN networks, but cannot use the VPN container's disconnected internet exceptions. Docker's embedded DNS at `127.0.0.11` is also blocked for attached containers to prevent it forwarding queries outside the tunnel.

Only the VPN container's own cgroup, including `docker exec` sessions, can use direct TCP 443 for Proton API access and UDP/TCP 53 to the startup DNS resolvers while disconnected. Loopback, WebUI replies, encrypted WireGuard packets, and IPv6 neighbor discovery have the necessary firewall exceptions. This is not a destination allow-list for Proton domains.

Proton's additional kill-switch target is fixed to **Standard**, not exposed as an environment variable, WebUI field, or API setting. Standard blocks traffic after an accidental VPN drop but restores it after an intentional disconnect. The container firewall remains enforced in both cases: intentionally disconnecting does **not** give attached applications an unprotected internet route. Neither protection layer can be disabled through the WebUI or API.

The service applies the Standard target while disconnected. If it adopts an already connected tunnel, the CLI refuses kill-switch changes, so that tunnel retains its existing Proton setting until a disconnected opportunity; the service does not interrupt a working tunnel merely to change that setting. Do not assume Proton's Standard layer was verified for an adopted connection. The mandatory container firewall remains the primary leak protection throughout.

WireGuard is the only supported protocol: the firewall, traffic check and traffic graph all assume Proton's `proton0` WireGuard interface. The CLI has no protocol command, so before every connect the service sets `"protocol": "wireguard"` in Proton's saved settings (`/config/Proton/VPN/settings.json`) and keeps the other saved values. If it finds a tunnel over another protocol, such as OpenVPN from older saved state, it disconnects it and reconnects over WireGuard; until that disconnect succeeds, the tunnel is never reported as connected and no port is forwarded.

The WebUI uses readable labels such as **Default**, **On**, and **Off**. CLI/API values remain lowercase. The traffic check described under [Health and troubleshooting](#health-and-troubleshooting) also fills a missing exit IPv4 address from the HTTPS IP-echo service `api.ipify.org`; the CLI's own connect output stays primary. Proton's location API cannot be used here because it refuses requests from VPN exits.

## Port forwarding

Enable port forwarding in the WebUI (or set `PORT_FORWARDING=on`) and select an eligible P2P server/account. The supervisor requests 60-second NAT-PMP leases about every 45 seconds and exposes the current port in the WebUI, `/config/forwarded_port`, and the API. A port is published only when both UDP and TCP map the same number with a positive granted lifetime. Its deadline uses the shorter granted lifetime, capped at 60 seconds from the first request. A shorter grant can expire before the next scheduled renewal. A failed or mismatched refresh, expired lease, disconnect, sign-out, reconnect, or failed state check withdraws the port; a lease failure alone does not make the container unhealthy.

Switching forwarding **Off** immediately withdraws the advertised port, then makes one best-effort NAT-PMP deletion attempt per locally known live protocol before disabling the native preference. Each attempt has a two-second timeout; native Off can close the gateway endpoint, so cleanup must precede it. The tunnel stays connected. Proton uses internal port zero, so deletion covers all mappings for that tunnel's source identity and protocol, including attached applications sharing it; it cannot distinguish processes. Other Proton clients are outside that scope. Gateways may reject deletion, and mappings left by an earlier process or an unreceived response cannot be tracked. In those cases, remote access can persist until the granted lease expires; withdrawing the advertised port is not proof of immediate remote revocation.

Changing a connected server target or processing a user Disconnect uses the same bounded cleanup before the native disconnect, while the old tunnel's source identity is still available. A failed disconnect does not renew or repeatedly delete those mappings while the request remains pending.

The forwarded-port file is empty when no mapping is valid. If publishing or clearing it fails, the supervisor tries to remove the old file and retries later. Fully read-only or failed storage can prevent both operations and leave a stale number on disk: treat `/api/v1/port` as authoritative during storage errors and repair `/config` before trusting the file again.

Configure your torrent client's listening port to the reported value, and update it if the lease changes. The project does **not** configure qBittorrent automatically. VPN-forwarded traffic reaches the shared namespace through the tunnel; publishing a Docker host port is not a substitute for the Proton forwarded port.

## API

Open [the API documentation](http://192.168.1.10:8788/api) or [OpenAPI 3.1 JSON](http://192.168.1.10:8788/api/v1/openapi.json), replacing `192.168.1.10` with your published LAN address. Both are available without authentication, but `WEBUI_ALLOWED_NETWORKS` still applies: a client it denies cannot load them. The WebUI uses this same versioned API.

Set a random `API_KEY` in the VPN container's environment for bearer authentication. Generate it with either command:

```bash
openssl rand -hex 32
docker run --rm python:3-alpine python -c "import secrets; print(secrets.token_urlsafe(32))"
```

`API_KEY` is distinct from `WEBUI_PASSWORD`. **An API key does not secure the service while `WEBUI_PASSWORD` is empty:** open mode accepts unauthenticated API requests too. Set both for protected browser and script access. With a WebUI password set, protected routes accept a WebUI session cookie or the bearer key. Non-bearer POST requests also require `X-Requested-With: protonvpn-webui` and a JSON object body. Never put secrets in URLs.

```bash
export API_KEY='your-generated-key'
export VPN_URL='http://192.168.1.10:8788'
curl --fail --silent --show-error \
  -H "Authorization: Bearer $API_KEY" \
  "$VPN_URL/api/v1/status"
```

| GET endpoint | Result |
| --- | --- |
| `/api/v1/status` | Sign-in, connection, server, exit IP, forwarded port, last error, and the traffic check (`tunnel_healthy`, `health_error`, `health_checked_ago`). |
| `/api/v1/port` | `{"port": 41404}` or `{"port": null}`. |
| `/api/v1/port?format=text` | Bare port number, or an empty body when unavailable. |
| `/api/v1/traffic` | RX/TX totals and samples relative to the newest sample (0 seconds). |
| `/api/v1/settings` | Effective settings, sources, choices, and environment locks. |
| `/api/v1/state` | Aggregate WebUI state, including traffic samples with monotonic timestamps. |

Write routes cover connect, disconnect, settings, Proton sign-in/TOTP/sign-out, WebUI login/logout, and warning dismissal. See `/api` for request bodies and examples. JSON API errors use `{"error":"message"}` with a non-success HTTP status.

For qBittorrent, safely read a candidate listener port without overwriting its configuration on an empty or failed response:

```bash
port=$(curl --fail --silent --show-error \
  -H "Authorization: Bearer $API_KEY" \
  "$VPN_URL/api/v1/port?format=text") &&
case "$port" in
  ''|*[!0-9]*) printf '%s\n' 'No valid forwarded port; leave the torrent listener unchanged.' ;;
  *) if [ "${#port}" -le 5 ] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
       printf 'Set qBittorrent Settings > Connection > Listening Port to %s\n' "$port"
     else
       printf '%s\n' 'Invalid port; leave the torrent listener unchanged.'
     fi ;;
esac
```

Apply the printed port in qBittorrent's connection settings. This example reads the VPN API only; it does not authenticate to or call qBittorrent's API and is not a forwarding automation feature.

WebUI login lockout is per client IP: five failed attempts in 60 seconds lock that IP out for 60 seconds. Behind Docker Desktop, rootless Docker, or a reverse proxy, clients can share one observed IP; one person's failures can lock everyone out for that minute.

The WebUI admits at most 32 simultaneous request handlers. Excess TCP connections are closed without an HTTP response; capacity returns when clients finish or the 30-second socket timeout expires. This contains resource use, not request rate: use the network allowlist and a rate-limiting HTTPS proxy when clients are untrusted.

## Metrics

`GET /metrics` serves Prometheus 0.0.4 text on the same `WEBUI_PORT`, suitable for VictoriaMetrics/vmagent or Prometheus. It uses the API's bearer/session authentication and `WEBUI_ALLOWED_NETWORKS`; it is not a public authentication bypass. Set both `WEBUI_PASSWORD` and `API_KEY` for protected scraping, because an empty WebUI password enables open mode.

Metrics carry no labels containing account names, IP addresses, servers, errors, or credentials. A scrape reads the supervisor's current snapshot only; it does not run CLI commands or traffic probes.

| Metric | Meaning |
| --- | --- |
| `protonvpn_signed_in` | `1` when signed in, otherwise `0`. |
| `protonvpn_connected` | `1` when the CLI reports connected, otherwise `0`. |
| `protonvpn_tunnel_healthy` | `1` only for a fresh passing traffic check; failed or unknown health is `0`. |
| `protonvpn_user_disconnected` | `1` when a user disconnect has paused automatic connection, otherwise `0`. |
| `protonvpn_port_forwarding_active` | `1` while a forwarded port is advertised, otherwise `0`. |
| `protonvpn_health_check_age_seconds` | Seconds since the last traffic probe on the current connection; omitted until one completes, and while no tunnel is connected. |
| `protonvpn_receive_bytes_total`, `protonvpn_transmit_bytes_total` | Counters of bytes received and sent through `proton0` on the current connection, from the 5-second traffic samples. They restart at each connection, which `rate()` handles as a counter reset; use `rate()` for bytes per second. Omitted until the first sample. |
| `protonvpn_connect_attempts_total`, `protonvpn_connect_failures_total` | Counters of `protonvpn connect` runs since the container started, and of those that did not leave a WireGuard tunnel connected. Connects canceled by a user disconnect or shutdown are not counted. |
| `protonvpn_recovery_attempts_total` | Counter of stalled-tunnel recovery attempts since the container started. |
| `protonvpn_health_checks_total`, `protonvpn_health_check_failures_total` | Counters of traffic checks, every 30 seconds while signed in and not user-disconnected, and of failed ones. While that wanted tunnel is not connected, each check counts as failed without probing, so the failure ratio covers outages too. |

Example vmagent/Prometheus scrape configuration (store the VPN container's `API_KEY` in the referenced file, readable only by the scraper):

```yaml
scrape_configs:
  - job_name: protonvpn
    metrics_path: /metrics
    bearer_token_file: /etc/vmagent/secrets/protonvpn_api_key
    static_configs:
      - targets: ["192.168.1.10:8788"]
```

Replace the target with your published VPN address and allow the scraper's source address in `WEBUI_ALLOWED_NETWORKS`. Use a trusted HTTPS reverse proxy and `scheme: https` outside a trusted local network.

Unhealthy, signed-out, and unknown VPN states still return HTTP 200. Alert on `up{job="protonvpn"} == 0` for scrape/authentication/transport failures and on `protonvpn_signed_in{job="protonvpn"} == 0` for a lost sign-in. For tunnel health, prefer the counters to the instantaneous gauges: `increase(protonvpn_health_check_failures_total[15m]) / increase(protonvpn_health_checks_total[15m])` is the failed fraction. Over a longer window, `1 -` that ratio is the uptime while the tunnel was wanted; signed-out and user-disconnected time is not checked, so read it next to `protonvpn_signed_in` and `protonvpn_user_disconnected`, and a window without checks has no ratio. A container start makes at most one connect; repeated `increase(protonvpn_connect_attempts_total[1h]) > 2` means a flapping tunnel. Counters restart with the container, which `increase()` handles as a counter reset. `protonvpn_tunnel_healthy{job="protonvpn"} == 0` remains available for instantaneous checks; combine it with `and protonvpn_user_disconnected{job="protonvpn"} == 0` to ignore intentional disconnections. Missing health-check age means no probe on the current connection, not a zero-second-old one.

## Health and troubleshooting

Docker runs `healthcheck.sh` every 30 seconds, with a 10-second timeout, 60-second startup grace, and three retries. The container is healthy only when both of these hold:

1. The CLI reports `Status: Connected`.
2. A traffic check passed within the last 60 seconds: a WireGuard-bound IPv4 HTTPS request to `https://api.ipify.org` returned a public IPv4 address.

The check runs every 30 seconds in a worker thread inside the supervisor. It uses `curl --interface if!proton0 --ipv4` with no proxy, so it fails rather than falling back to the host's route. It sends no credentials and verifies IPv4 HTTPS only; IPv6 tunnel traffic is not separately checked. A forwarded port does not affect health.

A failed CLI state check resets traffic-chart continuity before the next connected reading, even if it recovers on the same tunnel. Samples are not combined across a period when the connection cannot be verified.

The probe depends on a third-party service. If `api.ipify.org` is down, blocked, or answers with something other than a public IPv4 address, the check fails even though the tunnel may work. **Echo failure alone never reconnects the VPN**, clears the port, or overwrites the CLI's last error. After a failed echo, the worker sends a bounded UDP datagram through `proton0` to the numeric tunnel gateway and reads `wg show proton0 latest-handshakes`. A valid zero or unchanged handshake for 180 seconds on the same connection queues recovery; handshake progress or a successful echo resets the evidence. Missing, malformed, failed or timed-out observations, or a failed UDP send, are unknown rather than proof of a dead tunnel.

The supervisor consumes that evidence separately from the health worker: it revokes connection, port and health publication, attempts a disconnect bounded to five seconds, then reconnects using the same credentials and configured target. It never signs out to recover. Failed disconnects do not connect over the old tunnel; failed recovery attempts retain the normal 30/60/120/300-second backoff, counted from completion, even if native status still says `Connected`. New connections get a fresh evidence window. Normal CLI-state reconnection still checks every `RECONNECT_INTERVAL` seconds; a WebUI disconnect pauses automatic recovery until you connect again or restart the container.

**Docker health status does not trigger restarts.** `restart: unless-stopped` handles process exits, not an unhealthy status. The supervisor's corroborated tunnel recovery is independent of Docker health status; the restart policy alone does not heal an unhealthy status. A signed-out container intentionally remains unhealthy.

```bash
docker logs --tail 100 protonvpn-cli
docker exec protonvpn-cli protonvpn status
docker inspect --format '{{.State.Health.Status}}' protonvpn-cli
```

`/api/v1/status` reports `connected`, `tunnel_healthy`, `health_error`, and `health_checked_ago` side by side. Use it to tell a CLI connection problem from a failed traffic check.

CLI logs are persisted at `/config/cache/VPN/logs/vpn-cli.log`. Check firewall startup errors for missing cgroup v2, `xt_cgroup`, kernel support, or required run flags. If an application UI is unreachable, check the VPN container's published ports, `LAN_NETWORKS`, port collisions, and whether the application joined a replaced namespace. Do not disable the firewall to work around a connection problem.

## Unraid and release checks

Use [the Unraid template](https://github.com/andrebrait/unraid-templates/blob/main/templates/protonvpn.xml) from the [andrebrait/unraid-templates](https://github.com/andrebrait/unraid-templates) catalog, which also explains manual installation. Map `/config` to `/mnt/user/appdata/protonvpn`. Set `WEBUI_PASSWORD`, leave VPN setting variables empty for WebUI control, and open **WebUI** to sign in. Use **Console** for interactive CLI access. The template is not yet listed in Community Applications.

Before a release, complete [the credentialed manual checklist](docs/manual-test.md) on the target host. FIDO2 and real arm64 VPN behavior remain unverified unless separately recorded there.

### Known dependency advisories — reviewed 2026-11-02

This release is **not a vulnerability-free image**. Its final Debian 13 dependency scan reported 124 HIGH/CRITICAL package findings representing 58 distinct CVEs, including one scanner-critical libxml2 advisory. The earlier 122-finding/56-CVE scan gained two Expat advisories when the vulnerability database refreshed. No fixed version was listed for the flagged packages. The earlier Debian 13 stable/security candidate check found no available upgrades for the original findings; rebuilding or adding `apt upgrade` was not a fix. Packages from Debian unstable are not mixed into this image, and scan findings are not suppressed.

| Area | Release disposition |
|---|---|
| aiohttp [CVE-2026-69244](https://security-tracker.debian.org/tracker/CVE-2026-69244) and [CVE-2026-54277](https://security-tracker.debian.org/tracker/CVE-2026-54277) | Unfixed, reachable outbound client paths: malformed authenticated HTTPS responses can cause a native parser out-of-bounds read/client crash or excessive memory consumption. Proton API key pinning and verified DNS-over-HTTPS narrow who can supply such responses; they do not fix parsing. These are not WebUI request-parser vulnerabilities. No crash/OOM exploit or takeover was demonstrated. |
| OpenVPN [CVE-2026-84732](https://security-tracker.debian.org/tracker/CVE-2026-84732) | The vulnerable package remains installed as an official Proton dependency. The container pins WireGuard before connecting and rejects non-WireGuard tunnels, closing the saved-protocol selection path in the supported supervisor workflow. Running native OpenVPN manually is unsupported and reopens this exposure. |
| Expat [CVE-2026-117610](https://security-tracker.debian.org/tracker/CVE-2026-117610) and [CVE-2026-118370](https://security-tracker.debian.org/tracker/CVE-2026-118370) | Unfixed. D-Bus and Fontconfig use local root-owned XML configuration; local D-Bus introspection uses ElementTree. No supported hostile-network XML path was identified for the external-entity/chunking or multi-gigabyte-attribute triggers. Transitive in-memory Fontconfig callers remain untraced, not declared safe. No crash or heap-corruption exploit was attempted. |
| libxml2, Bluetooth, printing, image/X11, Python/SQLite and local system-tool findings | Deferred for the reviewed deployment: triggering services, untrusted parsing operations or required host capabilities were not identified in supported runtime inputs. libxml2 has a real **build-time** MIME XML consumer, which relies on trusted Debian/Proton package data. Installed vulnerable code is not thereby patched or globally safe. |
| urllib3 and configuration-dependent paths | Custom transports, proxies, CA/client certificates, telemetry and added host mounts can change reachability. Do not treat the default-path review as approval of those overrides. |

Review these deferrals by **2026-11-09**, or sooner on a relevant package, Proton backend, configuration or trust-boundary change. Prefer maintained Debian 13 fixes when available. Do not use `AIOHTTP_NO_EXTENSIONS=1` as a complete mitigation: it bypasses the native overread but the inspected Python parser still buffered fragmented reason lines without an early accumulated-length bound.
