# Proton VPN CLI container — design

Date: 2026-11-02
Status: approved design, pending spec review

## Goal

A container image that runs the **official Proton VPN CLI** (`proton-vpn-cli`) headless, so other
containers can share its network namespace (`--network=container:protonvpn`), with an Unraid
template as the delivery target.

Motivation: Gluetun and similar images (protonwire, plain `wg-quick`) drive Proton through static
WireGuard configs and fail silently when a server is retired or a key goes stale. Proton's own CLI
selects servers, refreshes certificates and reports its own state, and that state is trusted as
the source of truth.

Success criteria:

1. A user signs in once, from the WebUI or the container console; the session survives container
   recreation.
2. The connection target and every CLI setting are configurable through the WebUI or environment
   variables; an environment variable, when set, wins and locks the WebUI field.
3. No traffic leaves outside the tunnel, except to configured LAN networks, while disconnected,
   reconnecting, or after a CLI crash.
4. The forwarded port (P2P servers) is kept alive and published to a file and the WebUI.
5. Docker health requires both a CLI-connected tunnel and a fresh, successful tunnel-bound traffic check.
6. A WebUI shows status, server and location, forwarded port and live traffic.
7. An Unraid template exposes the settings above as fields and links the WebUI.

Non-goals: Proton's GTK GUI, OpenVPN, Proton Stealth protocol, split tunneling, unattended login
from environment variables, port-change webhooks into other applications, persistent traffic
history, security-key (FIDO2) signin from the WebUI.

## Project

- Repository: `andrebrait/protonvpn-cli-docker` (local: `/root/git/protonvpn-cli-docker`).
- Image: `ghcr.io/andrebrait/protonvpn-cli-docker` (the repository's name), `linux/amd64` and `linux/arm64`. Tags: `latest` on
  every publication, and `X.Y.Z` / `X.Y` for release tags `vX.Y.Z` (first release `v0.0.1`).
- License: GPL-3.0 (the image redistributes GPL-3.0 Proton packages).

## Feasibility evidence (spike, 2026-11-02)

A throwaway image proved the approach on Docker 29.9 / kernel 6.12 with
`--cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.conf.all.src_valid_mark=1`:

- `protonvpn signin` through `docker exec -it` with interactive 2FA worked.
- The session persisted across `docker rm` and a fresh `docker run` with the same `/config`.
- `protonvpn connect --country NL --p2p` brought up WireGuard (`proton0`) through NetworkManager;
  the exit IP was Proton's.
- `/etc/resolv.conf` pointed at Proton DNS (`10.2.0.1`) while connected.
- `natpmpc -a 1 0 {udp,tcp} 60 -g 10.2.0.1` returned a mapped public port.
- Proton CLI 1.0.5, `python3-proton-vpn-api-core` 5.8.11, NetworkManager 1.52.1, Debian trixie.

Container workarounds the spike needed (all carried into the design):

| Problem | Cause | Workaround |
|---|---|---|
| `proton-vpn-daemon` postinst fails | Calls `systemctl`; the package only provides split tunneling (unsupported by the CLI) and pulls BCC/LLVM | Install an empty placeholder package named `proton-vpn-daemon` before the CLI |
| Keyring needs a GUI prompt | Secret Service backend | `PROTON_LOADER_OVERRIDES=keyring=json` selects proton-core's JSON-file keyring |
| State lost on recreate | As root, Proton hard-codes `/etc/Proton` and `/var/cache/Proton` | Symlink both into `/config` |
| Connect times out after 10 s | Proton's NM profiles carry `permissions=user:root:;`; NM activates them only for a user with a logind session | Write the sd-login records NM reads: `/run/systemd/seats/` and `/run/systemd/users/0` (`STATE=active`, `SESSIONS=c1`, `ACTIVE_SESSIONS=c1`) before starting NM |
| `/etc/resolv.conf` not updated | Docker bind-mounts it; NM's atomic rename fails with `EBUSY` | `rc-manager=unmanaged` plus an NM dispatcher hook that copies `/run/NetworkManager/resolv.conf` over `/etc/resolv.conf` in place, and puts Docker's saved copy back when NM has no nameserver. `/run` survives a container restart, so before NM starts the firewall init discards the previous run's NM file and, if `/etc/resolv.conf` is that file's copy, restores the saved Docker one (never saving the tunnel's DNS as Docker's) |
| NM picks systemd-resolved mode | Auto-detection | `dns=default`, `systemd-resolved=false` |
| CLI cannot reach the session bus from `docker exec` | Bus address only known to the entrypoint | `/usr/local/bin/protonvpn` wrapper sources the bus address and execs `/usr/bin/protonvpn` |

Gaps found in the CLI:

- `kill-switch` offers only `off` and `standard`; after a disconnect traffic leaves via the host's
  IP. The container provides its own fail-closed firewall (below).
- `port-forwarding on` enables forwarding server-side but the CLI does not maintain the NAT-PMP
  mapping; `/run/Proton/VPN/forwarded_port` stays empty. The container runs the refresh loop
  documented in Proton's manual port-forwarding guide.

## Architecture

```
tini (PID 1)
└── entrypoint.sh (POSIX sh)
    ├── firewall setup (default drop)               — first, before any network activity
    ├── dbus-daemon --system
    ├── fake sd-login records
    ├── NetworkManager (eth0 unmanaged; logs to stdout)
    ├── dbus-daemon --session (address in /run/session-bus.env)
    └── exec python3 -m protonvpn_container         (foreground, one process)
        ├── supervisor thread: signin wait, apply settings, connect/reconnect, NAT-PMP refresh,
        │   traffic sampling
        ├── traffic-check worker: bounded IPv4 HTTPS check bound to proton0, independent of CLI I/O
        └── WebUI: http.server.ThreadingHTTPServer on WEBUI_PORT
```

Boot and firewall stay POSIX `sh` (checked with `shellcheck`). The supervisor and WebUI are one
Python package (`protonvpn_container`) using only the standard library of the image's Debian
Python 3; it owns all runtime state (connection state, forwarded port, traffic samples, effective
settings, signin flow), so there is no inter-process protocol. It drives the CLI through
`subprocess` (`protonvpn status`, `info`, `connect`, `config set`, …) and keeps that connection
state separate from observed tunnel traffic health.
Tests use `unittest`.

### Image contents

- Base: `debian:13-slim` (latest Debian 13 slim), set as a build argument so CI rebuilds pick up
  base-image security updates.
- Everything is installed and configured at build time, in Dockerfile layers. The entrypoint never
  runs `apt`, `dpkg`, `pip` or downloads; a fresh container from the image works as-is.
- Proton apt repo via `protonvpn-stable-release_<ver>_all.deb` from `repo.protonvpn.com`; version
  and the sha256 Proton publishes for it are build arguments.
- Packages, `--no-install-recommends`: `proton-vpn-cli` and `python3-proton-vpn-api-core` at the exact
  versions of two build arguments, `network-manager`, `dbus`, `wireguard-tools`, `iproute2`,
  `iptables`, `natpmpc`, `curl`, `tini`, `ca-certificates`.
- Placeholder `proton-vpn-daemon` package built with `dpkg-deb` in the Dockerfile.
- Files: NM config (`conf.d/container.conf`), dispatcher hook (`dispatcher.d/50-resolv`),
  `protonvpn` wrapper, `entrypoint.sh`, `healthcheck.sh`.
- Fixed environment: `HOME=/config`, `PROTON_LOADER_OVERRIDES=keyring=json` (plus a transport
  override if the firewall work requires it, see Kill switch).
- Target: smaller than the spike's 489 MB; measure and record the result.

NM config:

```ini
[main]
dns=default
rc-manager=unmanaged
systemd-resolved=false

[keyfile]
unmanaged-devices=interface-name:eth*
```

### Storage

Single volume `/config`:

| Path | Content | Mode |
|---|---|---|
| `/config/Proton/` (← `/etc/Proton`) | CLI settings, JSON keyring (session tokens) | dir `700`, files `600` |
| `/config/cache/` (← `/var/cache/Proton`) | Server list, CLI logs | dir `700` |
| `/config/forwarded_port` | Current forwarded port, empty when none | `644` |
| `/config/settings.json` | Settings saved from the WebUI, plus the private `_banner_dismissed` key | `600` |

The entrypoint enforces the modes on every start (the JSON keyring writes files with the default
umask, so it runs with `umask 077` and fixes existing files).

### Login

- From the WebUI: username and password, then a 2FA code when the account has one. The service
  runs `protonvpn signin <user> --totp` in a pseudo-terminal (`pty`), writes the password at the
  `Password:` prompt and the code at the `2FA Token` prompt, and reports the CLI's own success or
  error message. One signin at a time; an abandoned flow is killed after 5 minutes. The password
  and code are never logged or stored.
- From the console: `docker exec -it <name> protonvpn signin <user>` (Unraid **Console** button).
  Required for security-key (FIDO2) accounts.
- While not signed in, the container stays running with the firewall closed, logs
  `Not signed in. Sign in from the WebUI or run: docker exec -it <name> protonvpn signin <username>`
  every 60 s, and reports unhealthy.
- Once signin is detected (`protonvpn info` prints an account name; signed out it exits 0 and prints
  `Account: 'None'`), the supervisor applies settings and connects without a restart. Sign out is a
  WebUI button (`protonvpn signout`).
- Proton resets settings on signout; effective settings are reapplied on every start and after
  every detected signin, so this does not matter.

### Configuration

Every setting below has an effective value resolved in this order:

1. Environment variable, when set and non-empty. The WebUI shows the field read-only with
   "set by container config".
2. `/config/settings.json`, written by the WebUI.
3. Image default (table below); unset means "do not pass / leave the CLI default".

The Unraid template ships the setting variables empty, so the WebUI is the normal place to
configure; environment variables serve declarative setups.

Connection target (passed to `protonvpn connect`):

| Variable | CLI argument | Notes |
|---|---|---|
| `SERVER` | positional `SERVER_NAME` | e.g. `NL#914`; when set, `COUNTRY`/`CITY` are ignored with a warning |
| `COUNTRY` | `--country` | code or full name |
| `CITY` | `--city` | |
| `P2P` | `--p2p` | `true`/`false` |
| `SECURE_CORE` | `--securecore` | `true`/`false` |
| `TOR` | `--tor` | `true`/`false` |

Settings (each runs `protonvpn config set <key> <value>` on start/signin):

| Variable | CLI key | Default in image |
|---|---|---|
| `NETSHIELD` | `netshield` | unset (CLI default) |
| `PORT_FORWARDING` | `port-forwarding` | unset |
| `VPN_ACCELERATOR` | `vpn-accelerator` | unset |
| `MODERATE_NAT` | `moderate-nat` | unset |
| `IPV6` | `ipv6` | unset |
| `CUSTOM_DNS` | `custom-dns` | unset |
| `ANONYMOUS_CRASH_REPORTS` | `anonymous-crash-reports` | `off` |

Values pass through unmodified; the CLI validates them:

- Invalid environment syntax rejected with CLI usage exit code 2 → log the error and exit non-zero.
  Other CLI failures, including runtime exit code 1, remain visible and retry without killing the WebUI.
- WebUI change while signed in → applied immediately (`config set`, or a reconnect when the
  connection target changes); saved to `settings.json` only when the CLI accepts it; the CLI's
  error is shown in the WebUI otherwise.
- WebUI change while signed out → saved, applied at signin; a rejection then is logged and shown
  in the WebUI, and the container keeps running.

The exact value syntax for multi-value settings (`custom-dns`) and the allowed values for the
WebUI dropdowns are taken from `protonvpn config set <key> --help` during implementation.

Container variables (environment only, not editable in the WebUI):

| Variable | Purpose | Default |
|---|---|---|
| `LAN_NETWORKS` | Comma-separated CIDRs reachable outside the tunnel (e.g. Unraid LAN for WebUIs of sharing containers) | empty |
| `WEBUI_PORT` | Decimal WebUI listen port `1`–`65535`, without leading zeros; invalid values stop startup after deny-only baselines load and before allow rules (attached apps must use different ports) | `8788` |
| `WEBUI_PASSWORD` | WebUI password; empty leaves the WebUI open (warning logged, dismissible banner) | empty |
| `WEBUI_ALLOWED_NETWORKS` | Optional comma-separated source IPv4/IPv6 CIDRs or IPs for all HTTP access; empty allows normal non-VPN sources | empty |
| `API_KEY` | Bearer token for scripts using the API; empty disables token access (see Public API) | empty |
| `TZ` | Log timestamps | `UTC` |
| `DEBUG` | `true` adds `--verbose` to CLI calls and NM debug logging | `false` |
| `RECONNECT_INTERVAL` | Supervisor status-check period, seconds | `30` |

### WebUI network ingress

All TCP traffic to the internal `WEBUI_PORT` reaches a dedicated access chain before generic
loopback, established-connection, LAN or tunnel accepts. Traffic arriving on `proton0` is always
dropped first, even if its source matches the allowlist or the user permits `0.0.0.0/0` / `::/0`.
This means the container's VPN interface, not all changing public Proton exit IPs on other paths.

With `WEBUI_ALLOWED_NETWORKS` nonempty, only matching source CIDRs for that family may reach any
HTTP surface: UI, API, login, docs and static files. There is no implicit loopback exception:
include `127.0.0.1/32` explicitly for local HTTP clients. The network policy cannot be bypassed by
credentials, `LAN_NETWORKS`, existing connections or forwarded headers. Empty/unset preserves
normal non-VPN access and existing application authentication.

Parse configuration as literal networks with standard-library `ipaddress`, not DNS names.
Malformed nonempty input fails startup rather than disabling the restriction. The policy uses the
kernel's source address; Docker/reverse proxies may mask it and must enforce real-client policy
upstream where necessary. Recreate the container to change the environment. Docker health reads
its private file and does not need a loopback HTTP exemption.

### Kill switch (container firewall)

Fail-closed iptables rules (IPv4 and IPv6) installed before NetworkManager starts and never
removed. Containers attached with `--network=container:…` share this network namespace, so these
rules apply to them too.

- `OUTPUT`/`INPUT` policy `DROP`; `FORWARD` `DROP`.
- Except for the HTTP access policy above, allow everyone in the namespace: `lo`;
  `ESTABLISHED,RELATED`; tunnel traffic (`proton0`); packets carrying Proton's WireGuard fwmark
  `0xea13b2c` (the encrypted packets to the VPN endpoint); `LAN_NETWORKS` on `eth0` in both
  directions. None of these generic exceptions overrides the HTTP access chain.
- Docker's embedded DNS (`127.0.0.11`, user-defined networks) is reached over `lo` and forwards
  queries outside the tunnel, so traffic to `127.0.0.11` is accepted only from this container's
  own cgroup and dropped for everyone else, ahead of the `lo` rule.
- Allow **only for this container's own processes**: TCP 443 and UDP/TCP 53 out of `eth0`, to any
  address. The CLI needs the Proton API (and possibly proton-core's DoH-based alternative routing)
  while disconnected to sign in, refresh the server list and connect.
  - Mechanism: `-m cgroup --path <own cgroup>` matches the cgroup of the sending socket. Every
    container has its own cgroup, so sockets opened by attached containers never match.
  - `<own cgroup>` is read from `/proc/self/cgroup` (`0::<path>`) at start. That works with both
    private cgroup namespaces (path `/`, Docker's default on cgroup v2) and `--cgroupns=host`
    (path `/system.slice/docker-<id>.scope`).
  - cgroup v2 is required. If `/proc/self/cgroup` has no `0::` line, or the rule cannot be
    installed, the container logs the reason and exits with the firewall still closed.
  - Deny-only filter baselines for both families precede configuration validation and allow rules.
    If baseline installation is unavailable, disable non-loopback interfaces and exit; shared
    namespace users must be recreated before retrying. Failure of that fallback explicitly logs
    that containment cannot be guaranteed rather than claiming a successful kill switch.
  - Verified 2026-11-02 on Docker 29.9 / kernel 6.12: the owning container reached the internet
    with `OUTPUT DROP` plus `-m cgroup --path / -j ACCEPT`, an attached container was blocked.
  - `docker exec` sessions join the container's cgroup, so console commands get the same
    HTTPS/DNS exception. That is intended (signin runs there).
- No hostname allow-list and no re-resolution: the exception is scoped by origin, not
  destination.
- The CLI's own kill-switch target is fixed to **Standard** as defence in depth, applied while
  disconnected. It is not configurable through the environment, UI or API. An adopted connected
  tunnel retains its prior Proton setting until a disconnected opportunity because the CLI refuses
  changes while connected; adoption does not force an interruption or verify that prior value.
  Standard restores internet after an intentional disconnect; the mandatory container firewall does not.
- OUTPUT `ESTABLISHED,RELATED` on `eth0` is accepted only for this container's own cgroup, plus
  replies from `WEBUI_PORT` (a lingering flow from an attached container must not keep leaving
  `eth0` after the tunnel drops). IPv6 neighbour discovery is accepted on `eth0` so IPv6
  `LAN_NETWORKS` work.

Threat model (decided 2026-11-02): the kill switch prevents **accidental** leaks from ordinary
applications in attached containers. It does not contain deliberately hostile code: any process
holding `CAP_NET_RAW` (granted by Docker by default) can set Proton's fwmark with `SO_MARK` or
send raw frames with `AF_PACKET`, and a process with `CAP_NET_ADMIN` can rewrite the rules; no
firewall inside a shared namespace can stop that. The README and the Unraid template recommend
`--cap-drop=NET_RAW` (and never `NET_ADMIN`) for attached containers, and starting them after this
container reports healthy (the rules load about half a second after start).

Acceptance, each case checked from this container **and** from an attached container without
`NET_RAW`/`NET_ADMIN` misuse: with the CLI killed (`pkill -f /usr/bin/protonvpn`), after
`protonvpn disconnect`, and while signed out:

- the attached container cannot reach any non-LAN address on any port, DNS included;
- this container can reach only TCP 443 and port 53 outside the tunnel.

### Supervisor

A thread in the Python service, every `RECONNECT_INTERVAL` seconds:

1. Not signed in → log the signin hint every 60 s, keep checking.
2. Signed in, settings not yet applied this session → apply effective settings.
3. `protonvpn status` first line is not `Status: Connected` → set `"protocol": "wireguard"` in Proton's
   saved `settings.json` (the CLI has no protocol command; failure counts as a failed connect), then run
   `protonvpn connect <target args>`; on failure log the CLI output and retry with backoff
   (30 s, 60 s, 120 s, capped at 300 s). A user-initiated disconnect from the WebUI suspends
   reconnecting until the user connects again or the container restarts. A connected tunnel whose
   protocol is not WireGuard is disconnected and never reported as connected; a failed Disconnect
   still deletes the forwarding mappings while the tunnel is up.
4. Connected and effective port forwarding on → every 45 s run
   `natpmpc -a 1 0 udp 60 -g 10.2.0.1` and `natpmpc -a 1 0 tcp 60 -g 10.2.0.1`, parse
   `Mapped public port N ... lifetime L` (exit code 0, 1..65535 port and positive lifetime required),
   and publish N in `/config/forwarded_port` and the API only when both protocols return the same N;
   log when N changes. The deadline is the first request's start plus the lesser of 60 seconds and
   both granted lifetimes. Renewals run before state checks; a timer withdraws an unrenewed mapping,
   even during a blocked CLI call. A short grant can expire before the next 45-second renewal.
   Failed file publication attempts unlink; storage that prevents both can retain a stale disk number,
   so the API is authoritative during storage errors. Normal CLI timeouts do not shrink with lease age.
   Turning forwarding Off withdraws publication, then attempts one bounded lifetime-zero deletion per
   locally known live protocol before disabling the native preference and its control endpoint.
   Proton uses internal port zero, so deletion is source/protocol-wide
   within the shared tunnel identity, not per process. Unknown prior-process or unreceived mappings
   and rejected/timed-out deletion rely on remote lease expiry; no immediate revocation guarantee.
   Signout, disconnect
   and reconnect immediately invalidate connection-specific state. Duplicate completion of an
   already-observed sign-in does not reapply settings or drop a healthy connection. Failed state
   checks show an error instead of silently presenting the last success as current.
5. Every 5 s while connected: read `wg show proton0 transfer`, keep the last 15 minutes of
   samples in memory (180 points), reset on a new connection or failed state check.
6. On `SIGTERM`: disconnect, stop the WebUI, NM and D-Bus, exit 0 within the shutdown budget.
   A connect already in flight must disconnect again if it finishes during shutdown. Daemon
   shutdown verifies the expected process name and signals a Linux pidfd, not a reusable PID.
   The firewall stays closed until the namespace is gone.

All output goes to stdout with `[protonvpn]`, `[natpmp]`, `[firewall]`, `[webui]` prefixes, so
`docker logs` shows the CLI's own messages unaltered.

### WebUI

- One page, plain HTML/CSS/JS shipped as static files in the package; no build step, no external
  CDN (it must work while the tunnel is down). JSON API under `/api/v1/`; the page polls
  `/api/v1/state` every 5 s.
- At most 32 request-handler threads run simultaneously; excess TCP sockets are closed without
  creating a handler or blocking admission. Every completion/start-failure path releases capacity.
- Shows: connection state; server, city and country, load, protocol (from `protonvpn status`);
  exit IPv4 address (from connect output, or the independent traffic check when missing;
  probe failure does not change CLI connection state); forwarded port with a copy
  button; traffic totals since connect and a live up/down rate graph (inline SVG) over the last
  15 minutes; account name (`protonvpn info`); last error from the CLI.
- Actions: sign in (username, password, 2FA code step), sign out, connect, disconnect, save
  settings. Settings fields locked by environment variables are rendered disabled with
  "set by container config".
- Auth: when `WEBUI_PASSWORD` is set, a login form issues a random session cookie (`HttpOnly`,
  `SameSite=Strict`), sessions held in memory (lost on restart), password compared in constant
  time, 5 failed logins per minute per client address before a 60 s lockout. When unset, the WebUI
  is open, `[webui] WARNING: WEBUI_PASSWORD is not set; the WebUI is open to anyone who can reach
  it` is logged at start, and the page shows a banner whose dismissal is stored in
  `settings.json` (private `_banner_dismissed` key), so it stays dismissed across browsers and restarts.
  Failed dismissal keeps the banner and a persistent inline error visible. HTTPS proxies add
  `Secure` to the session cookie and redirect HTTP; the direct LAN HTTP backend does not.
- State-changing requests are `POST` with a JSON body and require the `X-Requested-With` header
  (blocks cross-site form posts).
- Account takeover is out of reach by design: the WebUI never displays tokens, the password, or
  keyring contents.

### Public API

The WebUI's JSON API is public and versioned: the WebUI is one client of it, scripts and other
containers are others. There is one API, not a WebUI API plus a public one.

- Base path `/api/v1/`. Backwards-compatible changes only within v1 (new optional fields, new
  endpoints); breaking changes go to `/api/v2/`.
- Read endpoints (`GET`): `/api/v1/status` (signed_in, account, connected, server, location,
  load, protocol, exit_ip, forwarded_port, last_error), `/api/v1/port` (`{"port": 41404}` or
  `{"port": null}`; `?format=text` returns the bare number or an empty body, `text/plain`, for
  scripts such as qBittorrent port updaters), `/api/v1/traffic` (`rx_bytes`, `tx_bytes`, and
  `samples`, each `[relative_seconds, received_bytes, sent_bytes]`; newest sample is at 0 seconds,
  totals are since connection; zero totals and an empty array without samples), `/api/v1/settings`
  (`settings` array, each with env, value, locked, source, kind, and choices for choice settings).
  The WebUI's aggregate `/api/v1/state` stays, including its existing monotonic traffic times.
- Write endpoints (`POST`, JSON body): connect, disconnect, settings, signin, signin/code,
  signout, banner/dismiss, login, logout (the existing WebUI routes).
- Errors: JSON `{"error": "<message>"}` with the HTTP status (400 validation, 401 auth, 403
  missing header, 404, 409 locked setting, 429 rate limit, 500 internal).
  Failed Proton sign-in returns 400 with this error shape; a retryable two-factor step remains
  200 with `state: "need_code"` and a message, and success is `state: "done"`.
- Auth: a request is authorized when the WebUI is open (`WEBUI_PASSWORD` unset), **or** it
  carries a valid WebUI session cookie, **or** it sends `Authorization: Bearer <API_KEY>`
  (constant-time compare). `API_KEY` unset disables token access. Token-authenticated requests are
  exempt from the `X-Requested-With` check (a cross-site page cannot attach the header-borne
  token). `GET /api/v1/openapi.json` and the docs page need no auth.
- `API_KEY` should be a random secret; README, docs page and the template field description show
  how to generate one: `openssl rand -hex 32`, or without openssl
  `docker run --rm python:3-alpine python -c "import secrets; print(secrets.token_urlsafe(32))"`.
  At start, an `API_KEY` shorter than 32 characters logs `[webui] WARNING: API_KEY is shorter
  than 32 characters; generate one with: openssl rand -hex 32`.
- Contract: a hand-written **OpenAPI 3.1** document shipped in the package and served at
  `GET /api/v1/openapi.json`, with schemas for every request and response, the bearer and cookie
  security schemes, and examples. Schemas use JSON Schema 2020-12. It must validate against the
  OpenAPI 3.1 specification (`openapi-spec-validator`), and HTTP contract tests exercise every
  documented operation and check actual responses for the properties marked required.
- Docs page at `/api` (same look as the WebUI): renders the OpenAPI document client-side into a
  list of endpoints with method, path, description, parameters, request and response examples, a
  `curl` example per endpoint (with `-H "Authorization: Bearer $API_KEY"`), the key-generation
  instructions, and a link to the raw `openapi.json`. No Swagger UI or other external library.
  The WebUI header links to it.

### Health

`HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3` runs `healthcheck.sh`.
Healthy requires CLI-connected state and a successful IPv4 HTTPS traffic check no more than
60 seconds old; a forwarded port is not required.

The same Python process runs a separate worker every 30 seconds while connected, with a first
check promptly after connection. It uses image-baked curl with `--interface if!proton0 --ipv4
--max-time 5 --noproxy '*' --fail --silent --show-error https://api.ipify.org` and an outer
six-second subprocess bound. A missing interface must fail, never fall back to the host route.
Only a valid public IPv4 literal counts as success. Probe I/O holds no CLI lock and cannot delay
port renewal. Echo failure alone cannot trigger reconnects or change CLI-derived `connected` or `last_error`.
It also fills a missing exit address, replacing the old synchronous lookup.

Snapshots and `/api/v1/status` expose `tunnel_healthy` (boolean or null before the first connected
check), `health_error` (string) and `health_checked_ago` (seconds or null). Disconnection,
staleness or probe failure makes health false; stale results from an earlier connection are
discarded. The WebUI distinguishes Proton's connection status from Passed/Failed/Checking traffic
health and does not show an all-healthy green state when traffic checks fail.

Atomic ephemeral `/run/protonvpn-container/health.json` contains `healthy` and a monotonic
`checked_at` for Docker's local check; missing, malformed or stale data is unhealthy. Startup,
disconnect and stop revoke prior success. Log only health transitions or changed errors.

This checks IPv4 HTTPS reachability, not every protocol. Echo failure alone remains observational.
After a failed echo the worker sends one UDP datagram, with a one-second socket timeout and
SO_BINDTODEVICE `proton0`, to numeric gateway `10.2.0.1:9`, then runs
`wg show proton0 latest-handshakes` with a two-second timeout (never `dump`).
Only a successful send and valid unchanged/zero handshake for 180 monotonic seconds on the same
connection generation can queue recovery. A successful echo or changed handshake resets evidence;
failed/malformed/absent observations and failed stimulus are unknown, not dead. New connections
start a fresh evidence window; late results cannot affect another generation.

Only the supervisor loop under its CLI lock consumes generation-specific recovery, rechecking
health, signed-in/wanted state and stop. It revokes connection/port/health publication before a
five-second-bounded disconnect, then uses the normal configured connect without signing out.
Failed disconnects never connect over the old tunnel. Failed recovery retains completion-based
30/60/120/300-second backoff despite misleading native Connected or further health probes.
Intent changes cancel stale recovery, and existing late-connect compensation remains in force.
Docker restart policies still do not restart a merely unhealthy container.

### Unraid template

`unraid/protonvpn-cli.xml`:

- Repository `ghcr.io/andrebrait/protonvpn-cli-docker:latest`, network `bridge`.
- `ExtraParams`: `--cap-add=NET_ADMIN --device=/dev/net/tun --sysctl net.ipv4.conf.all.src_valid_mark=1`.
- `WebUI`: `http://[IP]:[PORT:8788]/`; Port `8788` → `8788` (TCP).
- Path: `/config` → `/mnt/user/appdata/protonvpn-cli`.
- Variables: every variable in Configuration, with descriptions; setting variables empty by
  default (so the WebUI configures them); `WEBUI_PASSWORD` masked.
- Overview text: open the WebUI to sign in and configure (or use the Console button), how to
  attach other containers (`--network=container:protonvpn-cli`) and publish their ports on this
  container, where the forwarded port is written.
- Publishing to Community Applications is out of scope for this spec.

## Testing

- `shellcheck` on all shell scripts; `python3 -m unittest` for the Python package, with the CLI,
  `natpmpc` and `wg` replaced by fake executables on `PATH` (CI).
- CI builds both architectures.
- Credential-free smoke test (CI, `tests/smoke.sh`): container starts, NetworkManager runs,
  `protonvpn status` prints `Status: Disconnected`, health is unhealthy with the signin hint in the
  logs, an outbound request to a public non-Proton address fails (firewall closed), the WebUI
  answers on `WEBUI_PORT` (open without a password, `401` on `/api/v1/state` with one).
- Manual credentialed checklist (`docs/manual-test.md`), run before each release: signin with 2FA
  from the WebUI and from the console; connect by country, by server, with `P2P`; DNS points at
  Proton; forwarded port file and WebUI populated and refreshed; traffic graph moves; session
  survives recreate; kill-switch acceptance cases above; reconnect after blocking the endpoint for
  5 minutes; WebUI setting changes apply live and env-locked fields are disabled; settings changes
  via env take effect on restart; a sharing container uses the tunnel.

## Risks

- Proton states headless use is unsupported; a CLI or api-core update can break a workaround. The
  release package, its sha256 (as Proton publishes it), the CLI and the api-core versions are build
  arguments whose Dockerfile defaults are the only source: tests and publication both build with
  them, and the versions that ship are printed in the build output and checked by
  `tests/versions.sh` (CLI 1.1.0, api-core 6.1.1 for the first release). A new Proton release is a
  deliberate change of those defaults plus a test run. CI smoke test catches boot regressions, the
  manual checklist catches connect regressions.
- The fake sd-login records depend on NM's session-tracking implementation (sd-login reading
  `/run/systemd/users/<uid>`). An NM change could break it; the smoke test should assert NM
  activates a `permissions=user:root` profile (a dummy connection) to catch this without
  credentials.
- The cgroup-scoped firewall exception requires cgroup v2 and the `xt_cgroup` match in the host
  kernel; the container fails closed when either is missing. Verified 2026-11-02 on the target
  Unraid 7.3.4 (kernel 6.18.58, Docker 29.8.2, cgroup v2, host iptables 1.8.13 legacy, `wireguard`
  module present): owning container allowed, attached container blocked. The test container used
  the `nf_tables` iptables backend, so the host's legacy backend does not matter.
- The WebUI signin drives the CLI's interactive prompts through a pty; a change to the CLI's
  prompt text (`Password:`, `2FA Token`) breaks it. Match the prompts loosely and surface any
  unexpected CLI output in the WebUI; the manual checklist covers it each release.
- Not yet verified: arm64, CLI behaviour after long outages (supervisor covers it), security-key
  (FIDO2) signin through `docker exec`.
