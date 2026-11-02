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

1. A user signs in once from the container console; the session survives container recreation.
2. The connection target and every CLI setting are configurable through environment variables.
3. No traffic leaves outside the tunnel, except to configured LAN networks, while disconnected,
   reconnecting, or after a CLI crash.
4. The forwarded port (P2P servers) is kept alive and published to a file.
5. Docker health reflects `protonvpn status`.
6. An Unraid template exposes the settings above as fields.

Non-goals: GUI or WebUI, OpenVPN, Proton Stealth protocol, split tunneling, unattended login from
environment variables, port-change webhooks into other applications.

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
└── entrypoint.sh
    ├── firewall setup (default drop)               — first, before any network activity
    ├── dbus-daemon --system
    ├── fake sd-login records
    ├── NetworkManager (eth0 unmanaged; logs to stdout)
    ├── dbus-daemon --session (address in /run/session-bus.env)
    ├── apply settings (protonvpn config set …)     — only when signed in
    └── supervisor loop (foreground)
        ├── signin wait / reconnect
        └── NAT-PMP refresh
```

All scripts are POSIX `sh`, checked with `shellcheck`.

### Image contents

- Base: `debian:trixie-slim`.
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

The entrypoint enforces the modes on every start (the JSON keyring writes files with the default
umask, so it runs with `umask 077` and fixes existing files).

### Login

- Signin is interactive only: Unraid's container **Console** button or
  `docker exec -it protonvpn protonvpn signin <user>`. 2FA (TOTP) prompts work there.
- While not signed in, the container stays running with the firewall closed, logs
  `Not signed in. Run: docker exec -it <name> protonvpn signin <username>` every 60 s, and reports
  unhealthy.
- Once signin is detected (`protonvpn info` succeeds), the supervisor applies settings and
  connects without a restart.
- Proton resets settings on signout; settings are reapplied from the environment on every start
  and after every detected signin, so this does not matter.

### Configuration

Environment variables are the only source of truth for settings. Empty or unset means "do not
pass / leave the CLI default".

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

Values pass through unmodified; the CLI validates them. A rejected value logs the CLI's error and
the container exits non-zero, so a misconfiguration is visible instead of silently ignored. The
exact value syntax for multi-value settings (`custom-dns`) is taken from `protonvpn config set
<key> --help` during implementation and documented in the README and template.

Container variables:

| Variable | Purpose | Default |
|---|---|---|
| `LAN_NETWORKS` | Comma-separated CIDRs reachable outside the tunnel (e.g. Unraid LAN for WebUIs of sharing containers) | empty |
| `TZ` | Log timestamps | `UTC` |
| `DEBUG` | `true` adds `--verbose` to CLI calls and NM debug logging | `false` |
| `RECONNECT_INTERVAL` | Supervisor status-check period, seconds | `30` |

### Kill switch (container firewall)

Fail-closed iptables rules (IPv4 and IPv6) installed before NetworkManager starts and never
removed:

- `OUTPUT`/`INPUT` policy `DROP`; `FORWARD` `DROP`.
- Allow: `lo`; `ESTABLISHED,RELATED`; any traffic on the tunnel interface (`proton0`);
  packets carrying Proton's WireGuard fwmark `0xea13b2c` (the encrypted handshake/data packets to
  the VPN endpoint); `LAN_NETWORKS` on `eth0` in both directions.
- Proton API while disconnected: the CLI needs the API to sign in, refresh the server list and
  connect. Allow TCP 443 to the resolved addresses of the hosts the CLI uses, plus DNS (UDP/TCP 53)
  on `eth0` to the resolvers in Docker's original `/etc/resolv.conf` (read at start, before NM
  rewrites it). The DNS rule cannot be limited per hostname, so while disconnected DNS queries
  (not traffic) can reach that resolver; accepted. Known hosts from the
  package: `vpn-api.proton.me`, `account.proton.me`. The full set must be measured during
  implementation (capture the CLI's outbound connections during signin, server-list refresh and
  connect). proton-core's `AlternativeRoutingTransport` falls back to DoH-discovered domains when
  the API is blocked; if that fallback is needed for correct operation the allow-list must cover
  it, otherwise force a direct transport through `PROTON_LOADER_OVERRIDES`. Decide based on the
  measurement and record the decision in the README.
- API addresses are re-resolved by the supervisor before each reconnect attempt; rules are
  replaced atomically (`iptables-restore`).
- The CLI's own `standard` kill switch stays enabled as defence in depth.

Acceptance: with the CLI killed (`pkill -f /usr/bin/protonvpn`), after `protonvpn disconnect`,
and while signed out, an outbound request from the container (and from a container sharing its
namespace) to a non-LAN, non-Proton-API address fails.

### Supervisor

Foreground loop in `entrypoint.sh`:

1. Not signed in → log the signin hint every 60 s, keep checking.
2. Signed in, settings not yet applied this session → apply settings.
3. `protonvpn status` first line is not `Status: Connected` → refresh API firewall rules, run
   `protonvpn connect <target args>`; on failure log the CLI output and retry with backoff
   (30 s, 60 s, 120 s, capped at 300 s).
4. Connected and `PORT_FORWARDING=on` → every 45 s run
   `natpmpc -a 1 0 udp 60 -g 10.2.0.1` and `natpmpc -a 1 0 tcp 60 -g 10.2.0.1`, parse
   `Mapped public port N`, write N to `/config/forwarded_port`, log when N changes. On failure log
   a warning and empty the file.
5. On `SIGTERM`: `protonvpn disconnect`, stop NM and D-Bus, exit 0. The firewall stays closed
   until the namespace is gone.

All output goes to stdout with `[protonvpn]`, `[natpmp]`, `[firewall]` prefixes, so `docker logs`
shows the CLI's own messages unaltered.

### Health

`HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3` runs `healthcheck.sh`:
healthy when `protonvpn status` reports `Status: Connected`. When port forwarding is enabled,
health does not depend on the port (a failing NAT-PMP refresh is logged, not fatal).

### Unraid template

`unraid/protonvpn-cli.xml`:

- Repository `ghcr.io/andrebrait/protonvpn-cli:latest`, network `bridge`.
- `ExtraParams`: `--cap-add=NET_ADMIN --device=/dev/net/tun --sysctl net.ipv4.conf.all.src_valid_mark=1`.
- Path: `/config` → `/mnt/user/appdata/protonvpn-cli`.
- Variables: every variable in Configuration, with descriptions and defaults; settings with fixed
  value sets as dropdowns.
- Overview text: sign in once from the Console button, how to attach other containers
  (`--network=container:protonvpn-cli`), where the forwarded port is written.
- Publishing to Community Applications is out of scope for this spec.

## Testing

- `shellcheck` on all scripts (CI).
- CI builds both architectures.
- Credential-free smoke test (CI, `scripts/smoke-test`): container starts, NetworkManager runs,
  `protonvpn status` prints `Status: Disconnected`, health is unhealthy with the signin hint in the
  logs, and an outbound request to a public non-Proton address fails (firewall closed).
- Manual credentialed checklist (`docs/manual-test.md`), run before each release: signin with 2FA;
  connect by country, by server, with `P2P`; DNS points at Proton; forwarded port file populated
  and refreshed; session survives recreate; kill-switch acceptance cases above; reconnect after
  blocking the endpoint for 5 minutes; settings changes via env take effect on restart; a sharing
  container uses the tunnel.

## Risks

- Proton states headless use is unsupported; a CLI or api-core update can break a workaround. Pin
  the Proton release package version and the CLI version through build arguments; CI smoke test
  catches boot regressions, the manual checklist catches connect regressions.
- The fake sd-login records depend on NM's session-tracking implementation (sd-login reading
  `/run/systemd/users/<uid>`). An NM change could break it; the smoke test should assert NM
  activates a `permissions=user:root` profile (a dummy connection) to catch this without
  credentials.
- The API allow-list is not yet measured.
- Not yet verified: arm64, CLI behaviour after long outages (supervisor covers it), security-key
  (FIDO2) signin through `docker exec`.
