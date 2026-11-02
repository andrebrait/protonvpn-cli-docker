<p align="center"><img src="images/icon-256.png" alt="Proton VPN" width="160"></p>

# protonvpn-cli-docker

Run the official Proton VPN CLI in Docker, with a WebUI and a shared VPN network for other containers.

The image uses Debian 13 slim and includes the CLI, NetworkManager, WireGuard tools, firewall tools, and all runtime dependencies at build time. It does not install packages on startup. A supervisor manages connections and NAT-PMP port forwarding; the WebUI handles sign-in, settings, status, and traffic.

Every build installs exactly one reviewed Proton release: **CLI 1.1.0** with **API core 6.1.1**, pinned in the [`Dockerfile`](Dockerfile) and printed in the build output. A new Proton release is adopted by changing those pins after it is tested, never by merely rebuilding. Published tags are `latest` and, for each release, `X.Y.Z` and `X.Y` (the first is `0.0.1`). The Debian 13 slim base is refreshed at every build.

**Proton does not officially support headless use.** This project supplies the container integration; an upstream CLI change can break it. It is not affiliated with Proton AG. The icon is Proton AG's trademark, used to identify the Proton VPN service.

## Requirements and compatibility

- Linux Docker host with cgroup v2, the `xt_cgroup` iptables match, WireGuard kernel support (`wireguard`), and `/dev/net/tun`.
- The VPN container needs `NET_ADMIN`, the TUN device, and `net.ipv4.conf.all.src_valid_mark=1`. Do not use privileged mode or host networking.
- A Proton VPN account; some features, including port forwarding, depend on your plan and selected server.

Measured Unraid compatibility is **Unraid 7.3.4, kernel 6.18.58, Docker 29.8.2, cgroup v2, and `xt_cgroup`**. The host and container can use different iptables backends: host legacy versus container nft is not itself a compatibility problem. This is not a claim of support for all Unraid or Docker versions. The arm64 image build and Python imports have been verified; a real arm64 VPN connection has not.

## Quick start

### Docker run

Choose a strong WebUI password, and change the LAN CIDR to your own network. Leave `LAN_NETWORKS` empty if no direct LAN access is needed.

```bash
export WEBUI_PASSWORD='replace-this-with-a-strong-password'
docker run -d --name protonvpn-cli \
  --restart unless-stopped \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  -p 8788:8788 \
  -v protonvpn-config:/config \
  -e WEBUI_PASSWORD \
  -e LAN_NETWORKS=192.168.1.0/24 \
  ghcr.io/andrebrait/protonvpn-cli-docker:latest
```

Open `http://YOUR_DOCKER_HOST:8788/`, unlock the WebUI, and sign in to Proton. Until the VPN is connected and the traffic check passes, the container remains running but unhealthy. Keep the published port on a trusted network; the built-in server uses HTTP, not TLS. Use a trusted HTTPS reverse proxy for remote access, rather than exposing it directly to the internet.

To build locally instead of pulling a published image:

```bash
docker build -t ghcr.io/andrebrait/protonvpn-cli-docker:latest .
```

### Docker Compose with an attached application

Save this as `compose.yaml`. Replace the LAN CIDR, set `WEBUI_PASSWORD` as above, and run `docker compose up -d`. qBittorrent starts only after the VPN reports healthy. On first use, sign in to Proton through port 8788 while Compose waits for that health check; if the dependency times out, run `docker compose up -d` again after connecting.

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
      - "8788:8788"
      - "8080:8080" # qBittorrent WebUI, published on the VPN container
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
| `LAN_NETWORKS` | empty | Comma-separated IPv4/IPv6 CIDRs allowed outside the tunnel. Use only trusted networks. |
| `WEBUI_PORT` | `8788` | Internal WebUI/API listen port; update Docker's port mapping if changed. |
| `WEBUI_PASSWORD` | empty | WebUI password, distinct from your Proton password. Empty enables open mode with a log warning and dismissible banner. |
| `API_KEY` | empty | Separate bearer credential for scripts. Empty disables bearer-token access, not open-mode access. |
| `TZ` | `UTC` | Timezone for logs. |
| `DEBUG` | `false` | `true` / `false`; verbose CLI and NetworkManager logging. Review logs before sharing them. |
| `RECONNECT_INTERVAL` | `30` | Supervisor connection-check interval in seconds (at least 1). |

## Attaching containers and hardening

Use `--network=container:protonvpn-cli` with Docker run, or `network_mode: service:protonvpn-cli` with Compose. Publish attached applications' ports **on the VPN container**, not on the attached container. Allow the trusted LAN CIDR in `LAN_NETWORKS` for direct access to those application ports. All services in the namespace must use different listen ports.

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

Proton's additional kill switch is fixed to **Standard**, not exposed as an environment variable, WebUI field, or API setting. Standard blocks traffic after an accidental VPN drop but restores it after an intentional disconnect. The container firewall remains enforced in both cases: intentionally disconnecting does **not** give attached applications an unprotected internet route. Neither protection layer can be disabled through the WebUI or API.

The WebUI uses readable labels such as **Default**, **On**, and **Off**. CLI/API values remain lowercase. The traffic check described under [Health and troubleshooting](#health-and-troubleshooting) also fills a missing exit IPv4 address from the HTTPS IP-echo service `api.ipify.org`; the CLI's own connect output stays primary. Proton's location API cannot be used here because it refuses requests from VPN exits.

## Port forwarding

Enable port forwarding in the WebUI (or set `PORT_FORWARDING=on`) and select an eligible P2P server/account. The supervisor renews NAT-PMP leases about every 45 seconds (each lease lasts 60) and exposes the current port in the WebUI, `/config/forwarded_port`, and the API. A port is published only when the gateway maps the same number for both UDP and TCP. The file is empty when no valid port is available: a failed or mismatched refresh, a lease that runs out unrenewed, a disconnect, a sign-out, a reconnect for a new server, or a failed state check all clear it at once and log why. A lease failure alone does not make the container unhealthy.

Configure your torrent client's listening port to the reported value, and update it if the lease changes. The project does **not** configure qBittorrent automatically. VPN-forwarded traffic reaches the shared namespace through the tunnel; publishing a Docker host port is not a substitute for the Proton forwarded port.

## API

Open [the API documentation](http://localhost:8788/api) or [OpenAPI 3.1 JSON](http://localhost:8788/api/v1/openapi.json) on your Docker host (replace `localhost` for remote hosts). Both are available without authentication. The WebUI uses this same versioned API.

Set a random `API_KEY` in the VPN container's environment for bearer authentication. Generate it with either command:

```bash
openssl rand -hex 32
docker run --rm python:3-alpine python -c "import secrets; print(secrets.token_urlsafe(32))"
```

`API_KEY` is distinct from `WEBUI_PASSWORD`. **An API key does not secure the service while `WEBUI_PASSWORD` is empty:** open mode accepts unauthenticated API requests too. Set both for protected browser and script access. With a WebUI password set, protected routes accept a WebUI session cookie or the bearer key. Non-bearer POST requests also require `X-Requested-With: protonvpn-webui` and a JSON object body. Never put secrets in URLs.

```bash
export API_KEY='your-generated-key'
export VPN_URL='http://localhost:8788'
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

## Health and troubleshooting

Docker runs `healthcheck.sh` every 30 seconds, with a 10-second timeout, 60-second startup grace, and three retries. The container is healthy only when both of these hold:

1. The CLI reports `Status: Connected`.
2. A traffic check passed within the last 60 seconds: a WireGuard-bound IPv4 HTTPS request to `https://api.ipify.org` returned a public IPv4 address.

The check runs every 30 seconds in a worker thread inside the supervisor. It uses `curl --interface proton0 --ipv4` with no proxy, so it fails rather than falling back to the host's route. It sends no credentials and verifies IPv4 HTTPS only; IPv6 tunnel traffic is not separately checked. A forwarded port does not affect health.

The probe depends on a third-party service. If `api.ipify.org` is down, blocked, or answers with something other than a public IPv4 address, the check fails and the container reports unhealthy even though the tunnel works. A failed check never disconnects or reconnects the VPN, never changes the CLI's `connected` state, never clears the forwarded port, and never overwrites the CLI's last error. Automatic reconnection still follows only the CLI's own state: the supervisor checks every `RECONNECT_INTERVAL` seconds and retries failed connections with backoff up to 300 seconds. A WebUI disconnect pauses automatic reconnection until you connect again or restart the container.

**Docker health status does not trigger restarts.** `restart: unless-stopped` handles process exits, not an unhealthy status, and a failed traffic check does not restart or reconnect the VPN. The Docker restart policy alone does not heal an unhealthy status. A signed-out container intentionally remains unhealthy.

```bash
docker logs --tail 100 protonvpn-cli
docker exec protonvpn-cli protonvpn status
docker inspect --format '{{.State.Health.Status}}' protonvpn-cli
```

`/api/v1/status` reports `connected`, `tunnel_healthy`, `health_error`, and `health_checked_ago` side by side. Use it to tell a CLI connection problem from a failed traffic check.

CLI logs are persisted at `/config/cache/VPN/logs/vpn-cli.log`. Check firewall startup errors for missing cgroup v2, `xt_cgroup`, kernel support, or required run flags. If an application UI is unreachable, check the VPN container's published ports, `LAN_NETWORKS`, port collisions, and whether the application joined a replaced namespace. Do not disable the firewall to work around a connection problem.

## Unraid and release checks

Use [the Unraid template](unraid/protonvpn-cli.xml) with `/config` mapped to `/mnt/user/appdata/protonvpn-cli`. Set `WEBUI_PASSWORD`, leave VPN setting variables empty for WebUI control, and open **WebUI** to sign in. Use **Console** for interactive CLI access. This repository also includes [a Community Applications profile](ca_profile.xml); inclusion in Community Applications is not implied.

Before a release, complete [the credentialed manual checklist](docs/manual-test.md) on the target host. FIDO2 and real arm64 VPN behavior remain unverified unless separately recorded there.
