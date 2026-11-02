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
5. Docker health reflects `protonvpn status`.
6. A WebUI shows status, server and location, forwarded port and live traffic.
7. An Unraid template exposes the settings above as fields and links the WebUI.

Non-goals: Proton's GTK GUI, OpenVPN, Proton Stealth protocol, split tunneling, unattended login
from environment variables, port-change webhooks into other applications, persistent traffic
history, security-key (FIDO2) signin from the WebUI.

## Project

- Repository: `andrebrait/protonvpn-cli-docker` (local: `/root/git/protonvpn-cli-docker`).
- Image: `ghcr.io/andrebrait/protonvpn-cli`, `linux/amd64` and `linux/arm64`.
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
| `/etc/resolv.conf` not updated | Docker bind-mounts it; NM's atomic rename fails with `EBUSY` | `rc-manager=unmanaged` plus an NM dispatcher hook that copies `/run/NetworkManager/resolv.conf` over `/etc/resolv.conf` in place |
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
        └── WebUI: http.server.ThreadingHTTPServer on WEBUI_PORT
```

Boot and firewall stay POSIX `sh` (checked with `shellcheck`). The supervisor and WebUI are one
Python package (`protonvpn_container`) using only the standard library of the image's Debian
Python 3; it owns all runtime state (connection state, forwarded port, traffic samples, effective
settings, signin flow), so there is no inter-process protocol. It drives the CLI through
`subprocess` (`protonvpn status`, `info`, `connect`, `config set`, …) and trusts its output.
Tests use `unittest`.

### Image contents

- Base: `debian:13-slim` (latest Debian 13 slim), set as a build argument so CI rebuilds pick up
  base-image security updates.
- Everything is installed and configured at build time, in Dockerfile layers. The entrypoint never
  runs `apt`, `dpkg`, `pip` or downloads; a fresh container from the image works as-is.
- Proton apt repo via `protonvpn-stable-release_<ver>_all.deb` from `repo.protonvpn.com`, version
  pinned by a build argument.
- Packages, `--no-install-recommends`: `proton-vpn-cli`, `network-manager`, `dbus`,
  `wireguard-tools`, `iproute2`, `iptables`, `natpmpc`, `tini`, `ca-certificates`.
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
| `/config/settings.json` | Settings saved from the WebUI, plus `webui_banner_dismissed` | `600` |

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
| `KILL_SWITCH` | `kill-switch` | `standard` |
| `ANONYMOUS_CRASH_REPORTS` | `anonymous-crash-reports` | `off` |

Values pass through unmodified; the CLI validates them:

- Environment value rejected by the CLI at start or signin → log the CLI's error and exit non-zero
  (a misconfiguration is visible instead of silently ignored).
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
| `WEBUI_PORT` | WebUI listen port (not 8080: attached apps share this namespace's ports) | `8788` |
| `WEBUI_PASSWORD` | WebUI password; empty leaves the WebUI open (warning logged, dismissible banner) | empty |
| `TZ` | Log timestamps | `UTC` |
| `DEBUG` | `true` adds `--verbose` to CLI calls and NM debug logging | `false` |
| `RECONNECT_INTERVAL` | Supervisor status-check period, seconds | `30` |

### Kill switch (container firewall)

Fail-closed iptables rules (IPv4 and IPv6) installed before NetworkManager starts and never
removed. Containers attached with `--network=container:…` share this network namespace, so these
rules apply to them too.

- `OUTPUT`/`INPUT` policy `DROP`; `FORWARD` `DROP`.
- Allow for everyone in the namespace: `lo`; `ESTABLISHED,RELATED`; any traffic on the tunnel
  interface (`proton0`); packets carrying Proton's WireGuard fwmark `0xea13b2c` (the encrypted
  packets to the VPN endpoint, sent by the kernel); `LAN_NETWORKS` on `eth0` in both directions;
  inbound TCP `WEBUI_PORT` on `eth0` (who can reach it is decided by Docker port publishing).
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
  - Verified 2026-11-02 on Docker 29.9 / kernel 6.12: the owning container reached the internet
    with `OUTPUT DROP` plus `-m cgroup --path / -j ACCEPT`, an attached container was blocked.
  - `docker exec` sessions join the container's cgroup, so console commands get the same
    HTTPS/DNS exception. That is intended (signin runs there).
- No hostname allow-list and no re-resolution: the exception is scoped by origin, not
  destination.
- The CLI's own `standard` kill switch stays enabled as defence in depth.
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
3. `protonvpn status` first line is not `Status: Connected` → run
   `protonvpn connect <target args>`; on failure log the CLI output and retry with backoff
   (30 s, 60 s, 120 s, capped at 300 s). A user-initiated disconnect from the WebUI suspends
   reconnecting until the user connects again or the container restarts.
4. Connected and effective port forwarding on → every 45 s run
   `natpmpc -a 1 0 udp 60 -g 10.2.0.1` and `natpmpc -a 1 0 tcp 60 -g 10.2.0.1`, parse
   `Mapped public port N`, write N to `/config/forwarded_port`, log when N changes. On failure log
   a warning and empty the file.
5. Every 5 s while connected: read `wg show proton0 transfer`, keep the last 15 minutes of
   samples in memory (180 points), reset on a new connection.
6. On `SIGTERM`: `protonvpn disconnect`, stop the WebUI, NM and D-Bus, exit 0. The firewall stays
   closed until the namespace is gone.

All output goes to stdout with `[protonvpn]`, `[natpmp]`, `[firewall]`, `[webui]` prefixes, so
`docker logs` shows the CLI's own messages unaltered.

### WebUI

- One page, plain HTML/CSS/JS shipped as static files in the package; no build step, no external
  CDN (it must work while the tunnel is down). JSON API under `/api/`; the page polls
  `/api/state` every 5 s.
- Shows: connection state; server, city and country, load, protocol (from `protonvpn status`);
  exit IP (from the connect output, kept until the next connect); forwarded port with a copy
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
  `settings.json` (`webui_banner_dismissed`), so it stays dismissed across browsers and restarts.
- State-changing requests are `POST` with a JSON body and require the `X-Requested-With` header
  (blocks cross-site form posts).
- Account takeover is out of reach by design: the WebUI never displays tokens, the password, or
  keyring contents.

### Health

`HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3` runs `healthcheck.sh`:
healthy when `protonvpn status` reports `Status: Connected`. When port forwarding is enabled,
health does not depend on the port (a failing NAT-PMP refresh is logged, not fatal).

### Unraid template

`unraid/protonvpn-cli.xml`:

- Repository `ghcr.io/andrebrait/protonvpn-cli:latest`, network `bridge`.
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
  answers on `WEBUI_PORT` (open without a password, `401` on `/api/state` with one).
- Manual credentialed checklist (`docs/manual-test.md`), run before each release: signin with 2FA
  from the WebUI and from the console; connect by country, by server, with `P2P`; DNS points at
  Proton; forwarded port file and WebUI populated and refreshed; traffic graph moves; session
  survives recreate; kill-switch acceptance cases above; reconnect after blocking the endpoint for
  5 minutes; WebUI setting changes apply live and env-locked fields are disabled; settings changes
  via env take effect on restart; a sharing container uses the tunnel.

## Risks

- Proton states headless use is unsupported; a CLI or api-core update can break a workaround. Pin
  the Proton release package version and the CLI version through build arguments; CI smoke test
  catches boot regressions, the manual checklist catches connect regressions.
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
