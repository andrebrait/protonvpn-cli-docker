# Proton VPN CLI container Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Debian 13 slim image that runs the official Proton VPN CLI headless with a fail-closed,
cgroup-scoped kill switch, NAT-PMP port refresh, env-driven settings, and an Unraid template.

**Architecture:** `tini` → `entrypoint.sh` (firewall, D-Bus, fake sd-login records,
NetworkManager, session bus, supervisor loop). Pure logic lives in `lib.sh` and is unit-tested with
plain `sh` asserts; container behaviour is tested by a credential-free smoke script; the
credentialed path by a manual checklist.

**Tech Stack:** POSIX `sh`, Docker/buildx, Debian 13 packages (`proton-vpn-cli` from
`repo.protonvpn.com`, `network-manager`, `dbus`, `iptables` nf_tables, `natpmpc`, `tini`),
GitHub Actions, GHCR, Unraid template XML.

**Spec:** `docs/superpowers/specs/2026-11-02-protonvpn-cli-container-design.md`

Reference implementation of every workaround (throwaway spike, read-only): `/tmp/protonvpn-spike/`
(`Dockerfile`, `entrypoint.sh`, `nm.conf`, `50-resolv`, `protonvpn-wrapper`).

## Global Constraints

- Base image `debian:13-slim`, via `ARG BASE_IMAGE=debian:13-slim`.
- All installation at build time; scripts never run `apt`, `dpkg`, `pip`, `wget` or `curl` downloads.
- `--no-install-recommends` on every `apt-get install`; apt lists removed in the same layer.
- Proton release package pinned: `ARG PROTON_RELEASE_VERSION=1.0.10`
  (`https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_${PROTON_RELEASE_VERSION}_all.deb`).
- Placeholder package `proton-vpn-daemon` version `999` installed before `proton-vpn-cli`.
- Image env: `HOME=/config`, `PROTON_LOADER_OVERRIDES=keyring=json`.
- Required run flags: `--cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.conf.all.src_valid_mark=1`.
- Persistent paths: `/etc/Proton` → `/config/Proton` (dir `700`, files `600`),
  `/var/cache/Proton` → `/config/cache` (dir `700`), `/config/forwarded_port` (`644`).
- WireGuard fwmark `0xea13b2c`; tunnel interface `proton0`; NAT-PMP gateway `10.2.0.1`.
- Log prefixes: `[protonvpn]`, `[natpmp]`, `[firewall]`, `[init]`.
- Env defaults: `KILL_SWITCH=standard`, `ANONYMOUS_CRASH_REPORTS=off`, `TZ=UTC`, `DEBUG=false`,
  `RECONNECT_INTERVAL=30`, `LAN_NETWORKS=` (empty).
- Signin hint text: `Not signed in. Run: docker exec -it <name> protonvpn signin <username>`
  (`<name>` and `<username>` are printed literally; the script cannot know the container name).
- Image `ghcr.io/andrebrait/protonvpn-cli`, platforms `linux/amd64,linux/arm64`. License GPL-3.0.
- All scripts pass `shellcheck -s sh`.

## Review Focus

1. Proton revokes or expires the session while running: the supervisor must return to the
   signin-wait state (hint every 60 s, unhealthy), not hammer `connect`. → Task 4 unit test
   `test_state_not_signed_in`.
2. Container restart (`docker restart`) with stale `/run` state (D-Bus pid file, session-bus env):
   must boot cleanly the second time. → Task 1 smoke step `restart boots`.
3. Existing `/config` with wrong modes or files written by an older run: modes are enforced at every
   start. → Task 1 smoke step `config modes`.
4. Values containing spaces or `#` (`CITY="New York"`, `SERVER="NL#914"`) must reach the CLI as one
   argument each. → Task 2 unit tests `test_connect_args_*`.
5. `natpmpc` failure or a changed port: file emptied on failure, new port written and logged on
   change. → Task 2 unit test `test_parse_natpmp_*` and Task 4 step for the loop.

---

## File Structure

```
Dockerfile
LICENSE                                         GPL-3.0 text
README.md
rootfs/etc/NetworkManager/conf.d/container.conf
rootfs/etc/NetworkManager/dispatcher.d/50-resolv
rootfs/usr/local/bin/entrypoint.sh              boot order + supervisor loop
rootfs/usr/local/bin/healthcheck.sh
rootfs/usr/local/bin/protonvpn                  wrapper: session bus + exec /usr/bin/protonvpn
rootfs/usr/local/lib/protonvpn-container/lib.sh       pure functions (no side effects)
rootfs/usr/local/lib/protonvpn-container/firewall.sh  firewall_init, firewall rules
tests/unit.sh                                   plain-sh asserts over lib.sh
tests/smoke.sh                                  credential-free container tests
docs/manual-test.md                             credentialed release checklist
unraid/protonvpn-cli.xml
.github/workflows/ci.yml
```

---

### Task 1: Bootable image (packages, D-Bus, NetworkManager, persistence)

**Files:**
- Create: `Dockerfile`, `rootfs/etc/NetworkManager/conf.d/container.conf`,
  `rootfs/etc/NetworkManager/dispatcher.d/50-resolv`, `rootfs/usr/local/bin/protonvpn`,
  `rootfs/usr/local/bin/entrypoint.sh` (boot part only; supervisor is `exec sleep infinity` for now),
  `tests/smoke.sh`, `LICENSE`, `.gitignore`

**Interfaces:**
- Produces: `/run/session-bus.env` (`export DBUS_SESSION_BUS_ADDRESS='…'`); wrapper
  `/usr/local/bin/protonvpn` usable from `docker exec`; `tests/smoke.sh` with helper
  `run_container <name> [extra docker args…]` and `assert <description> <command…>` printing
  `ok`/`FAIL` and exiting non-zero at the end on any failure; image tag from `$IMAGE`
  (default `protonvpn-cli:test`).

- [ ] **Step 1: Write the smoke tests**

`tests/smoke.sh` builds nothing; it runs `$IMAGE` with the required flags and a temp `/config`, and asserts:
- `nm running`: `docker exec $c nmcli -t -f RUNNING general` prints `running`.
- `cli disconnected`: `docker exec $c protonvpn status` first line is `Status: Disconnected`.
- `user:root profile activates` (guards the sd-login workaround):
  `nmcli con add type dummy ifname smoke0 con-name smoke connection.permissions user:root ipv4.method manual ipv4.addresses 10.250.0.1/32 ipv6.method disabled`
  then within 10 s `nmcli -t -f GENERAL.STATE device show smoke0` contains `activated`; delete it after.
- `config modes`: pre-create `$tmp/Proton/stale.json` with mode `644` before start; after start
  `stat -c %a` gives `700` for `/config/Proton` and `/config/cache`, `600` for `stale.json`.
- `symlinks`: `readlink /etc/Proton` = `/config/Proton`, `readlink /var/cache/Proton` = `/config/cache`.
- `restart boots`: `docker restart $c`, then `nm running` and `cli disconnected` pass again.
- `no runtime installs`: `docker exec $c sh -c 'ls /var/lib/apt/lists | grep -v -e lock -e partial'` is empty.

- [ ] **Step 2: Run to verify it fails**

Run: `docker build -t protonvpn-cli:test . && sh tests/smoke.sh`
Expected: build fails (no Dockerfile) / smoke FAIL.

- [ ] **Step 3: Implement the image and boot**

- `Dockerfile` layers, in order: placeholder `proton-vpn-daemon` (dpkg-deb, as spike); Proton repo
  release deb; one `apt-get install` of `proton-vpn-cli network-manager dbus wireguard-tools
  iproute2 iptables natpmpc tini ca-certificates procps tzdata`; remove the GNOME/OpenVPN NM plugin
  packages if they were pulled as hard dependencies (check with `apt-cache rdepends --installed`;
  remove only if the CLI still imports); `COPY rootfs/ /`; `ENV` from Global Constraints;
  `VOLUME /config`; `ENTRYPOINT ["tini","--","/usr/local/bin/entrypoint.sh"]`.
  Record final image size in the commit message.
- `container.conf` and `50-resolv`: as spec (`rc-manager=unmanaged`, `dns=default`,
  `systemd-resolved=false`, `unmanaged-devices=interface-name:eth*`). `50-resolv` must not fail
  when `/run/NetworkManager/resolv.conf` is missing (spike logged exit 1 at startup): skip silently.
- `entrypoint.sh` boot: `umask 077`; create `/config/Proton`, `/config/cache`; replace
  `/etc/Proton` and `/var/cache/Proton` with symlinks; `chmod 700` dirs, `chmod 600` regular files
  under `/config/Proton` (`find … -type f -exec chmod 600 {} +`); `rm -f /run/dbus/pid`; system
  bus; sd-login records (`/run/systemd/seats/`, `/run/systemd/users/0` with
  `STATE=active SESSIONS=c1 ACTIVE_SESSIONS=c1 ONLINE_SESSIONS=c1`, one per line); `NetworkManager
  --no-daemon` logging to stdout with prefix `[nm]` (`--debug` only when `DEBUG=true`); wait up
  to 15 s for `nmcli -t -f RUNNING general` = `running`, else exit 1; session bus, write
  `/run/session-bus.env`.
- Wrapper as spike.

- [ ] **Step 4: Run smoke to verify it passes**

Run: `docker build -t protonvpn-cli:test . && sh tests/smoke.sh`
Expected: all `ok`, exit 0.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: bootable Proton VPN CLI image"
```

---

### Task 2: Pure configuration and parsing functions

**Files:**
- Create: `rootfs/usr/local/lib/protonvpn-container/lib.sh`, `tests/unit.sh`

**Interfaces:**
- Produces (all read env, write stdout, no side effects):
  - `connect_args` — prints the `protonvpn connect` arguments, **one per line**. `SERVER` set →
    `SERVER` only, plus `--p2p`/`--securecore`/`--tor` flags; warns on stderr
    `[protonvpn] SERVER is set; ignoring COUNTRY/CITY` when either is also set. Otherwise
    `--country X` and/or `--city Y` as two lines each, then flags. Booleans true when the value is
    `true`, `1`, `yes`, `on` (case-insensitive).
  - `settings_pairs` — prints `key<TAB>value` lines, in the spec's table order, for each of
    `NETSHIELD PORT_FORWARDING VPN_ACCELERATOR MODERATE_NAT IPV6 CUSTOM_DNS KILL_SWITCH
    ANONYMOUS_CRASH_REPORTS` that is non-empty, mapped to CLI keys `netshield port-forwarding
    vpn-accelerator moderate-nat ipv6 custom-dns kill-switch anonymous-crash-reports`.
  - `parse_natpmp_port` — reads `natpmpc` output on stdin, prints the number from
    `Mapped public port N`, exit 1 when absent.
  - `own_cgroup` — reads `/proc/self/cgroup` (path overridable via `$1` for tests), prints the
    path after `0::`, exit 1 when there is no `0::` line.
  - `is_true <value>` — exit 0 for the boolean-true values above.
- Callers read line-wise output with `IFS='<newline>'` and `set -f`, then `set -- $(…)`.

- [ ] **Step 1: Write failing tests in `tests/unit.sh`**

Plain sh: `. lib.sh`, `check <name> <expected> <actual>`, summary + exit code. Cases:
- `test_connect_args_server`: `SERVER='NL#914' COUNTRY=NL P2P=true` → lines `NL#914`, `--p2p`; stderr contains `ignoring COUNTRY/CITY`.
- `test_connect_args_city_spaces`: `COUNTRY=US CITY='New York'` → `--country`,`US`,`--city`,`New York` (4 lines; `New York` intact).
- `test_connect_args_empty`: nothing set → no output.
- `test_connect_args_flags`: `SECURE_CORE=Yes TOR=0` → `--securecore` only.
- `test_settings_pairs_defaults`: only `KILL_SWITCH=standard ANONYMOUS_CRASH_REPORTS=off` → two lines in that order.
- `test_settings_pairs_custom_dns`: `CUSTOM_DNS='on 1.1.1.1'` → value passed unchanged.
- `test_parse_natpmp_ok`: spike output (`Mapped public port 41404 protocol TCP to local port 0 lifetime 60`) → `41404`.
- `test_parse_natpmp_fail`: `readnatpmpresponseorretry() failed : the gateway does not support nat-pmp` → exit 1, no output.
- `test_own_cgroup_private`: file `0::/` → `/`.
- `test_own_cgroup_host`: file `0::/system.slice/docker-abc.scope` → that path.
- `test_own_cgroup_v1`: file `12:cpu:/docker/abc` only → exit 1.

- [ ] **Step 2: Run to verify it fails**

Run: `sh tests/unit.sh`
Expected: FAIL (lib.sh missing).

- [ ] **Step 3: Implement the functions in `lib.sh`**

- [ ] **Step 4: Run to verify it passes**

Run: `sh tests/unit.sh && shellcheck -s sh rootfs/usr/local/lib/protonvpn-container/lib.sh tests/unit.sh`
Expected: all pass, no shellcheck findings.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add config and parsing helpers"
```

---

### Task 3: Fail-closed, cgroup-scoped kill switch

**Files:**
- Create: `rootfs/usr/local/lib/protonvpn-container/firewall.sh`
- Modify: `rootfs/usr/local/bin/entrypoint.sh` (call `firewall_init` first, before D-Bus)
- Modify: `tests/smoke.sh`

**Interfaces:**
- Consumes: `own_cgroup` (Task 2).
- Produces: `firewall_init` — reads Docker's resolvers from `/etc/resolv.conf` **before** NM
  touches it, builds the IPv4 and IPv6 rule sets, loads each with `iptables-restore` /
  `ip6tables-restore` (atomic), exits the container non-zero with `[firewall] <reason>` when
  `own_cgroup` fails or a restore fails. Rules exactly as the spec's "Kill switch" section:
  policies `DROP` on INPUT/OUTPUT/FORWARD; allow `lo`, `ESTABLISHED,RELATED`, `-o/-i proton0`,
  `-m mark --mark 0xea13b2c`, each `LAN_NETWORKS` CIDR on `eth0` both directions (IPv4 vs IPv6
  chosen by `:` in the CIDR); own-cgroup-only: `-o eth0 -m cgroup --path <own> -p tcp --dport 443`
  and `-p udp/tcp --dport 53 -d <each Docker resolver>`.
  Invalid `LAN_NETWORKS` entry → restore fails → container exits with the error (fail closed).

- [ ] **Step 1: Add failing smoke tests**

Start the container, then a second container `--network container:$c` from `$IMAGE` with
`--entrypoint sleep` (it has `wget`-less Debian; use `bash -c '</dev/tcp/1.1.1.1/443'` with
`timeout 5` as the probe, and `getent hosts example.com` for DNS):
- `own 443 allowed`: probe from `$c` to `1.1.1.1:443` succeeds.
- `own 80 blocked`: probe from `$c` to `1.1.1.1:80` fails.
- `own dns allowed`: `getent hosts example.com` succeeds in `$c`.
- `attached 443 blocked`: probe from the attached container fails.
- `attached dns blocked`: `getent hosts example.com` fails in the attached container.
- `lan allowed`: with `-e LAN_NETWORKS=<docker bridge subnet>` the attached container reaches the
  bridge gateway (`ip route` default gw) on a TCP port that answers or refuses (connect refused
  counts as reachable: distinguish timeout from refusal).
- `bad LAN fails closed`: `-e LAN_NETWORKS=not-a-cidr` → container exits non-zero within 10 s,
  logs contain `[firewall]`.

- [ ] **Step 2: Run to verify they fail**

Run: `docker build -t protonvpn-cli:test . && sh tests/smoke.sh`
Expected: the new firewall assertions FAIL (no firewall yet).

- [ ] **Step 3: Implement `firewall.sh` and call it from `entrypoint.sh`**

- [ ] **Step 4: Run to verify they pass**

Run: `docker build -t protonvpn-cli:test . && sh tests/smoke.sh && shellcheck -s sh rootfs/usr/local/lib/protonvpn-container/*.sh rootfs/usr/local/bin/*`
Expected: all `ok`; Task 1 assertions still pass.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: fail-closed cgroup-scoped kill switch"
```

---

### Task 4: Supervisor, port forwarding, health, shutdown

**Files:**
- Modify: `rootfs/usr/local/lib/protonvpn-container/lib.sh` (add `supervisor_state`)
- Modify: `rootfs/usr/local/bin/entrypoint.sh` (replace `sleep infinity` with the loop)
- Create: `rootfs/usr/local/bin/healthcheck.sh`
- Modify: `Dockerfile` (`HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 CMD ["/usr/local/bin/healthcheck.sh"]`)
- Modify: `tests/unit.sh`, `tests/smoke.sh`

**Interfaces:**
- Consumes: `connect_args`, `settings_pairs`, `parse_natpmp_port`, `is_true` (Task 2).
- Produces: `supervisor_state <info_exit> <status_first_line>` → prints `not_signed_in`
  (info_exit ≠ 0), `connected` (`Status: Connected`), else `disconnected`.

Loop behaviour (spec "Supervisor"): every `RECONNECT_INTERVAL` s compute state from
`protonvpn info` exit code and `protonvpn status` first line.
- `not_signed_in` → log the signin hint at most every 60 s; mark settings as not applied.
- First pass in a signed-in session → apply each `settings_pairs` line with
  `protonvpn config set "$key" $value` (value word-split deliberately: multi-value settings such as
  `custom-dns` take several words). A non-zero exit → log CLI output with `[protonvpn]` and
  `exit 1`.
- `disconnected` → `protonvpn connect "$@"` from `connect_args`; on failure log output, back off
  30, 60, 120, 300, 300… s; reset backoff on success.
- `connected` and `is_true "$PORT_FORWARDING"` → every 45 s run
  `natpmpc -a 1 0 udp 60 -g 10.2.0.1` and the same for `tcp`; port from the TCP run via
  `parse_natpmp_port`; write to `/config/forwarded_port` only when changed and log
  `[natpmp] forwarded port N`; on failure log `[natpmp] refresh failed` and truncate the file.
- `DEBUG=true` → add `--verbose` before the CLI subcommand.
- `SIGTERM`/`SIGINT` → `protonvpn disconnect`, kill NM and both D-Bus daemons, `exit 0`. The loop
  sleeps with `sleep N & wait $!` so the trap fires promptly.
- `healthcheck.sh`: exit 0 iff `protonvpn status` first line is `Status: Connected`.

- [ ] **Step 1: Write failing tests**

Unit (`tests/unit.sh`):
- `test_state_not_signed_in`: `supervisor_state 1 'Status: Connected'` → `not_signed_in` (session revoked while a stale connection lingers).
- `test_state_connected`: `supervisor_state 0 'Status: Connected'` → `connected`.
- `test_state_disconnected`: `supervisor_state 0 'Status: Disconnected'` → `disconnected`.

Smoke (`tests/smoke.sh`), container not signed in:
- `signin hint logged`: within 20 s `docker logs $c` contains `Not signed in. Run: docker exec -it <name> protonvpn signin <username>`.
- `unhealthy when signed out`: `docker exec $c /usr/local/bin/healthcheck.sh` exits non-zero.
- `graceful stop`: `docker stop -t 15 $c` returns in under 10 s and `docker inspect -f '{{.State.ExitCode}}' $c` is `0`.

- [ ] **Step 2: Run to verify they fail**

Run: `sh tests/unit.sh; docker build -t protonvpn-cli:test . && sh tests/smoke.sh`
Expected: new cases FAIL.

- [ ] **Step 3: Implement `supervisor_state`, the loop, the trap and `healthcheck.sh`**

- [ ] **Step 4: Run to verify they pass**

Run: `sh tests/unit.sh && docker build -t protonvpn-cli:test . && sh tests/smoke.sh && shellcheck -s sh rootfs/usr/local/lib/protonvpn-container/*.sh rootfs/usr/local/bin/*`
Expected: all pass.

- [ ] **Step 5: Credentialed check on ai-dev (needs the user to sign in once)**

Run the image with `-e COUNTRY=NL -e P2P=true -e PORT_FORWARDING=on`, ask the user to run
`docker exec -it <c> protonvpn signin <user>`, then confirm without restarting: settings applied
(`protonvpn config list` shows `port-forwarding on`), `Status: Connected`, exit IP differs from
host, `/config/forwarded_port` has a number, healthcheck exits 0. Sign out and delete the temp
`/config` afterwards.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: supervisor, port forwarding and health"
```

---

### Task 5: CI and image publishing

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `tests/unit.sh`, `tests/smoke.sh` (`$IMAGE`).

Jobs:
1. `lint`: `shellcheck -s sh` on all scripts; `sh tests/unit.sh`.
2. `smoke` (needs lint): `docker build -t protonvpn-cli:test .` on `ubuntu-latest` (amd64),
   `sudo modprobe wireguard`, `IMAGE=protonvpn-cli:test sh tests/smoke.sh`.
3. `publish` (needs smoke; `push` to `main` and tags `v*`; also weekly `schedule` so base-image
   updates land): buildx + QEMU, `linux/amd64,linux/arm64`, push to
   `ghcr.io/andrebrait/protonvpn-cli` with tags `latest` (main), `X.Y.Z` / `X.Y` (tags),
   `sha-<short>`; `permissions: packages: write`.

- [ ] **Step 1: Write the workflow**
- [ ] **Step 2: Validate locally**

Run: `docker run --rm -v "$PWD":/repo -w /repo rhysd/actionlint:latest`
Expected: no findings.

- [ ] **Step 3: Verify arm64 builds**

Run: `docker buildx build --platform linux/arm64 -t protonvpn-cli:arm64 .`
Expected: build succeeds (QEMU); record time.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "ci: lint, smoke test and multi-arch publish"
```

---

### Task 6: Unraid template, docs, release check on Unraid

**Files:**
- Create: `unraid/protonvpn-cli.xml`, `README.md`, `docs/manual-test.md`

**Interfaces:**
- Consumes: every env var from Global Constraints and the spec's Configuration tables.

- Template: `<Container version="2">`, `Name` `protonvpn-cli`, `Repository`
  `ghcr.io/andrebrait/protonvpn-cli:latest`, `Network` `bridge`, `ExtraParams` = the required run
  flags, `Config` entries: Path `/config` → `/mnt/user/appdata/protonvpn-cli`; one Variable per
  env var with description and default; dropdowns (`|`-separated `Default`) for
  `NETSHIELD`, `PORT_FORWARDING`, `VPN_ACCELERATOR`, `MODERATE_NAT`, `IPV6`, `KILL_SWITCH`,
  `ANONYMOUS_CRASH_REPORTS`, `P2P`, `SECURE_CORE`, `TOR`, `DEBUG`, with the allowed values taken
  from `protonvpn config set <key> --help` in the built image. `Overview`: sign in once from the
  Console button; attach other containers with `--network=container:protonvpn-cli`; forwarded
  port in `/config/forwarded_port`.
- README: what/why, quick start (`docker run` + compose), signin, env table, kill-switch behaviour
  (attached containers: tunnel + LAN only; own processes: 443/53), requirements (cgroup v2,
  `xt_cgroup`, `wireguard` module), port forwarding, health, troubleshooting (`docker logs`,
  `/config/cache/VPN/logs/vpn-cli.log`), limitations (headless unsupported by Proton, FIDO2 untested).
- `docs/manual-test.md`: the spec's manual checklist as checkboxes.

- [ ] **Step 1: Write the three files**
- [ ] **Step 2: Validate the template XML**

Run: `xmllint --noout unraid/protonvpn-cli.xml`
Expected: no output.

- [ ] **Step 3: Run the manual checklist on Unraid (`ssh unraid`)**

Build on Unraid from the branch (`docker build -t protonvpn-cli:test .` in a temp clone under
`/tmp`), create the container from the template's settings, user signs in once from the Console,
then work through `docs/manual-test.md` including the kill-switch cases with an attached container.
Remove the test container, image and temp clone afterwards.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "docs: Unraid template, README and manual test checklist"
```
