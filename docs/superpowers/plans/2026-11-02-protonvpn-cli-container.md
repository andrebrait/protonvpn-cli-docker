# Proton VPN CLI container Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Debian 13 slim image that runs the official Proton VPN CLI headless with a fail-closed,
cgroup-scoped kill switch, NAT-PMP port refresh, a WebUI, settings from WebUI or env, and an
Unraid template.

**Architecture:** `tini` → `entrypoint.sh` (firewall, D-Bus, fake sd-login records,
NetworkManager, session bus) → `exec python3 -m protonvpn_container` (one stdlib-only Python
process: supervisor thread + WebUI). Shell logic is unit-tested with plain `sh` asserts, Python
with `unittest` and fake executables; container behaviour by a credential-free smoke script; the
credentialed path by a manual checklist.

**Tech Stack:** POSIX `sh`, Python 3 stdlib (Debian 13), Docker/buildx, Debian 13 packages (`proton-vpn-cli` from
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
- Log prefixes: `[protonvpn]`, `[natpmp]`, `[firewall]`, `[webui]`, `[init]`, `[nm]`.
- Native Proton kill switch is fixed internally to Standard, never exposed through settings.
- Env defaults: `ANONYMOUS_CRASH_REPORTS=off`, `TZ=UTC`, `DEBUG=false`,
  `RECONNECT_INTERVAL=30`, `LAN_NETWORKS=` (empty), `WEBUI_PORT=8788`, `WEBUI_PASSWORD=` (empty),
  `API_KEY=` (empty).
- Settings precedence: env var (non-empty; locks the WebUI field) → `/config/settings.json`
  (mode `600`) → image default.
- Signin hint text: `Not signed in. Sign in from the WebUI or run: docker exec -it <name> protonvpn signin <username>`
  (`<name>` and `<username>` are printed literally; the code cannot know the container name).
- Python: standard library only, no pip; package `protonvpn_container` under
  `/usr/local/lib/protonvpn-container` (`PYTHONPATH`).
- Image `ghcr.io/andrebrait/protonvpn-cli-docker`, platforms `linux/amd64,linux/arm64`. License GPL-3.0.
- All shell scripts pass `shellcheck -s sh`.

## Review Focus

1. Proton revokes or expires the session while running: the supervisor must return to the
   signin-wait state (hint every 60 s, unhealthy), not hammer `connect`. → Task 4
   `test_decide_table`.
2. Container restart (`docker restart`) with stale `/run` state: must boot cleanly the second
   time. → Task 1 smoke `restart boots`.
3. A WebUI setting saved while an env var for it is later added: env wins and the field locks;
   the stale file value is ignored, not applied. → Task 2 `test_env_wins_and_locks`.
4. Values containing spaces or `#` (`CITY="New York"`, `SERVER="NL#914"`) must reach the CLI as one
   argument each. → Task 2 `test_connect_args_*`.
5. WebUI reachable by anyone on the LAN without a password: state-changing calls must still
   reject cross-site requests. → Task 5 `test_post_requires_header`.

---

## File Structure

```
Dockerfile
LICENSE                                         GPL-3.0 text
README.md
rootfs/etc/NetworkManager/conf.d/container.conf
rootfs/etc/NetworkManager/dispatcher.d/50-resolv
rootfs/usr/local/bin/entrypoint.sh              boot order, then exec the Python service
rootfs/usr/local/bin/healthcheck.sh
rootfs/usr/local/bin/protonvpn                  wrapper: session bus + exec /usr/bin/protonvpn
rootfs/usr/local/lib/protonvpn-container/firewall.sh   own_cgroup, firewall_rules, firewall_init
rootfs/usr/local/lib/protonvpn-container/protonvpn_container/
  __main__.py                                   wiring, signals, shutdown
  config.py                                     SETTINGS, SettingsStore, connect_args, settings_pairs
  cli.py                                        run(): protonvpn subprocess wrapper
  parsing.py                                    CLI / natpmpc / wg output parsers
  supervisor.py                                 state machine thread
  signin.py                                     pty-driven protonvpn signin
  webui.py                                      HTTP server, auth, JSON API
  static/index.html, app.js, style.css
tests/unit.sh                                   plain-sh asserts over firewall.sh
tests/python/                                   unittest suites + fakebin/
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

### Task 2: Python core — settings, CLI wrapper, parsers

**Files:**
- Create: `rootfs/usr/local/lib/protonvpn-container/protonvpn_container/__init__.py` (empty),
  `config.py`, `cli.py`, `parsing.py`; `tests/python/__init__.py`, `tests/python/test_config.py`,
  `tests/python/test_parsing.py`, `tests/python/test_cli.py`, `tests/python/fakebin/` (fake
  executables used by tests)
- Modify: `Dockerfile` (`ENV PYTHONPATH=/usr/local/lib/protonvpn-container`)

**Interfaces:**
- Produces, `config.py`:
  - `SETTINGS: tuple[Setting, ...]` with `Setting(env: str, cli_key: str | None, kind: str)`; the
    connection target `SERVER, COUNTRY, CITY, P2P, SECURE_CORE, TOR` (`cli_key=None`, kind
    `text`/`bool`) and the CLI settings in the spec's table order `NETSHIELD→netshield,
    PORT_FORWARDING→port-forwarding, VPN_ACCELERATOR→vpn-accelerator, MODERATE_NAT→moderate-nat,
    IPV6→ipv6, CUSTOM_DNS→custom-dns,
    ANONYMOUS_CRASH_REPORTS→anonymous-crash-reports` (kind `choice`, `text` for `custom-dns`).
  - `DEFAULTS = {"ANONYMOUS_CRASH_REPORTS": "off"}`.
  - `class SettingsStore(path: str = "/config/settings.json", environ: Mapping[str,str] = os.environ)`:
    `effective(env) -> str` (env non-empty → file → `DEFAULTS` → `""`), `locked(env) -> bool`
    (env var non-empty), `source(env) -> "env"|"file"|"default"`, `save(env, value) -> None`
    (raises `PermissionError` when locked; atomic write via temp file + `os.replace`, mode
    `0o600`; empty value deletes the key), `banner_dismissed() -> bool`,
    `dismiss_banner() -> None`. Thread-safe (one `threading.Lock`). Missing or corrupt file →
    treated as empty, corrupt file logged once with `[webui]` and left untouched until next save.
  - `is_true(value: str) -> bool` — `true, 1, yes, on`, case-insensitive.
  - `connect_args(store) -> list[str]` — `SERVER` set → `[SERVER]` plus flags, logs
    `[protonvpn] SERVER is set; ignoring COUNTRY/CITY` when either is also set; else
    `--country X`, `--city Y` as separate items, then `--p2p`, `--securecore`, `--tor` flags.
  - `settings_pairs(store) -> list[tuple[str, list[str]]]` — `(cli_key, value.split())` for each
    CLI setting with a non-empty effective value, in table order (split: `custom-dns` takes
    several words).
- Produces, `cli.py`: `run(*args: str, timeout: float = 120) -> Result` where
  `Result(rc: int, out: str)` (stdout+stderr merged, text). Calls `protonvpn` from `PATH` with
  `--verbose` inserted first when `is_true(os.environ.get("DEBUG",""))`. Timeout → `rc=124`,
  output says so. Never raises for CLI failures.
- Produces, `parsing.py`:
  - `parse_status(out: str) -> Status` dataclass `connected: bool, server: str, location: str,
    load: str, protocol: str` from lines `Status: …`, `Server: <name> in <location>`, `Load: …`,
    `Protocol: …` (spike output below); missing fields `""`.
  - `parse_exit_ip(connect_out: str) -> str` from `Your new IP address is X.` → `X` or `""`.
  - `parse_natpmp_mapping(out: str) -> tuple[int, int] | None` from the mapped port and positive gateway-granted lifetime.
  - `parse_wg_transfer(out: str) -> tuple[int, int] | None` from `wg show proton0 transfer`
    (`<peer-key>\t<rx>\t<tx>`; sum over peers) → `(rx, tx)`.

Spike CLI output to use verbatim in tests:
```
Status: Connected
Server: NL#914 in Amsterdam, Netherlands
Load: 31%
Protocol: wireguard
```
```
Connected to NL#810 in Amsterdam, Netherlands. 
Your new IP address is 205.147.16.78.
```

Tests run inside the built image so the Python matches Debian 13's:
`docker run --rm -v "$PWD:/src" -w /src -e PYTHONPATH=/src/rootfs/usr/local/lib/protonvpn-container --entrypoint python3 protonvpn-cli:test -m unittest discover -s tests/python -t .`

- [ ] **Step 1: Write failing tests**
- `test_config.py`: `test_env_wins_and_locks` (env `COUNTRY=NL`, file `CH` → `NL`, locked, source
  `env`); `test_file_then_default` (file overrides defaults; absent
  `ANONYMOUS_CRASH_REPORTS` becomes `off`); `test_save_locked_raises`; `test_save_atomic_mode`
  (file mode `0o600` after save; empty value removes key); `test_corrupt_file_is_empty`;
  `test_banner_flag_roundtrip`; `test_connect_args_server` (`SERVER='NL#914' COUNTRY=NL P2P=true`
  → `['NL#914','--p2p']`, warning logged); `test_connect_args_city_spaces`
  (`COUNTRY=US CITY='New York'` → `['--country','US','--city','New York']`);
  `test_connect_args_empty` → `[]`; `test_connect_args_flags` (`SECURE_CORE=Yes TOR=0` →
  `['--securecore']`);
  `test_settings_pairs_custom_dns` (`CUSTOM_DNS='on 1.1.1.1'` → `('custom-dns',['on','1.1.1.1'])`).
- `test_parsing.py`: status connected/disconnected (spike text; `Status: Disconnected` alone),
  exit IP, natpmp ok (`Mapped public port 41404 protocol TCP to local port 0 lifetime 60` → 41404)
  and failure (`readnatpmpresponseorretry() failed : the gateway does not support nat-pmp` →
  None), wg transfer (one peer `KEY\t1000\t2000` → `(1000,2000)`; empty → None).
- `test_cli.py` with `fakebin/protonvpn` echoing its args and exiting with `$FAKE_RC`:
  `test_run_merges_output_and_rc`; `test_debug_adds_verbose` (`DEBUG=true` → first arg
  `--verbose`); `test_timeout_returns_124` (fake sleeps; `timeout=0.5`).

- [ ] **Step 2: Run to verify they fail** (command above). Expected: import errors.
- [ ] **Step 3: Implement the three modules**
- [ ] **Step 4: Run to verify they pass** (command above). Expected: all pass, no warnings.
- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: python core for settings, CLI calls and parsing"
```

---

### Task 3: Fail-closed, cgroup-scoped kill switch

**Files:**
- Create: `rootfs/usr/local/lib/protonvpn-container/firewall.sh`, `tests/unit.sh`
- Modify: `rootfs/usr/local/bin/entrypoint.sh` (source `firewall.sh`, call `firewall_init` first,
  before D-Bus), `tests/smoke.sh`

**Interfaces:**
- Produces (POSIX sh, sourced):
  - `own_cgroup [file]` — reads `/proc/self/cgroup` (or `file`), prints the path after `0::`,
    exit 1 when there is no `0::` line.
  - `firewall_rules <family 4|6> <own_cgroup> <resolvers…>` — prints an `iptables-restore`
    `*filter … COMMIT` document only (no side effects), reading `LAN_NETWORKS` and `WEBUI_PORT`
    (default `8788`) from env. Rules exactly as the spec's "Kill switch" section: policies `DROP`
    on INPUT/OUTPUT/FORWARD; `-o lo -d 127.0.0.11 -m cgroup --path <own> ACCEPT` then
    `-o lo -d 127.0.0.11 DROP` (IPv4 only) ahead of `-o lo ACCEPT` / `-i lo ACCEPT`;
    `ESTABLISHED,RELATED`; `-o/-i proton0`; `-m mark --mark 0xea13b2c`; each `LAN_NETWORKS` CIDR
    of this family on `eth0` both directions (family chosen by `:` in the CIDR);
    `-i eth0 -p tcp --dport $WEBUI_PORT ACCEPT`; own-cgroup-only
    `-o eth0 -m cgroup --path <own> -p tcp --dport 443 ACCEPT` and `-p udp|tcp --dport 53 -d
    <each resolver of this family>`.
  - `firewall_init` — reads resolvers from `/etc/resolv.conf` **before** NM touches it, loads
    each family with `iptables-restore` / `ip6tables-restore` (atomic, filter table only so
    Docker's nat rules for the embedded DNS survive); on `own_cgroup` failure or a restore
    failure prints `[firewall] <reason>` and exits non-zero (fail closed).

- [ ] **Step 1: Write failing tests**

`tests/unit.sh` (plain sh asserts, `. firewall.sh`):
- `own_cgroup` private (`0::/` → `/`), host (`0::/system.slice/docker-abc.scope`), v1 only
  (`12:cpu:/docker/abc` → exit 1).
- `firewall_rules 4 / 192.168.65.7` with `LAN_NETWORKS='10.0.0.0/8,fd00::/8' WEBUI_PORT=8788`
  contains `-A OUTPUT -o eth0 -d 10.0.0.0/8 -j ACCEPT`, contains no `fd00::/8`, contains the
  127.0.0.11 cgroup ACCEPT line before the 127.0.0.11 DROP line before `-A OUTPUT -o lo -j ACCEPT`,
  contains `--dport 8788`; `firewall_rules 6 …` contains `fd00::/8` and no `127.0.0.11`.

Smoke (`tests/smoke.sh`), probes via `timeout 5 bash -c '</dev/tcp/HOST/PORT'` and
`getent hosts example.com`; attached container = `$IMAGE` with `--network container:$c
--entrypoint sleep`:
- `own 443 allowed`, `own 80 blocked`, `own dns allowed` (from `$c`).
- `attached 443 blocked`, `attached dns blocked` (default bridge).
- `attached embedded dns blocked`: same pair on a user-defined network (`docker network create`),
  attached `getent hosts example.com` fails while `$c` succeeds.
- `lan allowed`: `-e LAN_NETWORKS=<bridge subnet>`; attached reaches the bridge gateway (refused
  counts as reachable; only a timeout fails).
- `webui port open inbound`: from a third container on the same bridge (not attached),
  `bash -c '</dev/tcp/<$c ip>/8788'` is refused or connects (not a timeout).
- `bad LAN fails closed`: `-e LAN_NETWORKS=not-a-cidr` → exits non-zero within 10 s, logs
  contain `[firewall]`.

- [ ] **Step 2: Run to verify they fail**: `sh tests/unit.sh; docker build -t protonvpn-cli:test . && sh tests/smoke.sh`
- [ ] **Step 3: Implement `firewall.sh`, call it from `entrypoint.sh`**
- [ ] **Step 4: Run to verify they pass**: same commands plus `shellcheck -s sh` on all shell files.
- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: fail-closed cgroup-scoped kill switch"
```

---

### Task 4: Supervisor service, health, shutdown

**Files:**
- Create: `rootfs/usr/local/lib/protonvpn-container/protonvpn_container/supervisor.py`,
  `__main__.py`, `rootfs/usr/local/bin/healthcheck.sh`, `tests/python/test_supervisor.py`
- Modify: `rootfs/usr/local/bin/entrypoint.sh` (replace `exec sleep infinity` with
  `exec python3 -m protonvpn_container`; write the PIDs of NetworkManager and both D-Bus daemons
  to `/run/protonvpn-container/*.pid` — note NM is currently started as `NetworkManager … | sed &`
  so `$!` is sed: start NM with output to a FIFO or use `pgrep -x NetworkManager`), `Dockerfile`
  (`HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 CMD ["/usr/local/bin/healthcheck.sh"]`),
  `tests/smoke.sh`

**Interfaces:**
- Consumes: `SettingsStore`, `connect_args`, `settings_pairs`, `is_true` (config); `run`
  (cli); `parse_status`, `parse_exit_ip`, `parse_natpmp_mapping`, `parse_wg_transfer` (parsing).
- Produces, `supervisor.py`:
  - `decide(signed_in: bool, connected: bool, user_disconnected: bool) -> str` — pure:
    `"wait_signin"` | `"connected"` | `"idle"` (user disconnected) | `"connect"`.
  - `class Supervisor(store: SettingsStore, run=cli.run, clock=time.monotonic, sleep=…)` with
    `start()` (daemon thread), `stop()` (disconnect + join), `snapshot() -> dict` (keys:
    `signed_in, account, connected, server, location, load, protocol, exit_ip, forwarded_port,
    traffic: list[[t, rx, tx]], last_error, settings_errors: dict[env, str]`),
    `request_connect()`, `request_disconnect()` (sets `user_disconnected`),
    `apply_setting(env, value) -> tuple[bool, str]` (signed in: `config set`, or reconnect when a
    target field changed; returns CLI message; saves to the store only on success; signed out:
    save and return `(True, "saved; applied at sign in")`), `notify_signed_in()`.
  - Loop per spec "Supervisor": tick every `RECONNECT_INTERVAL` (wakes early on requests via a
    `threading.Event`); signin hint
    `Not signed in. Sign in from the WebUI or run: docker exec -it <name> protonvpn signin <username>`
    at most every 60 s; apply effective settings on the first signed-in tick of a session (env
    syntax rejected with rc 2 → log and exit; runtime failures including rc 1 → visible error and
    retry without terminating the WebUI); connect with backoff 30, 60, 120, 300, 300… s, reset on success; NAT-PMP
    every 45 s when `is_true(effective PORT_FORWARDING)` (`natpmpc -a 1 0 udp 60 -g 10.2.0.1`,
    then tcp; write `/config/forwarded_port` mode `0o644` only on change, log
    `[natpmp] forwarded port N`; failure → `[natpmp] refresh failed`, truncate file, port None);
    traffic sample every 5 s while connected (`wg show proton0 transfer`), keep 180 samples,
    clear on new connection.
- Produces, `__main__.py`: builds `SettingsStore` and `Supervisor`, starts it, installs
  `SIGTERM`/`SIGINT` handlers that call `supervisor.stop()`, then terminate NM and the D-Bus
  daemons from the pid files, exit 0. Blocks on a `threading.Event` (the WebUI is added in
  Task 5 and will start from here).
- `healthcheck.sh`: exit 0 iff `protonvpn status` first line is `Status: Connected`.

- [ ] **Step 1: Write failing tests**

`test_supervisor.py` with a fake `run` (scripted responses keyed by argv) and fake clock/sleep:
- `test_decide_table`: (False, True, False) → `wait_signin` (session revoked while a connection
  lingers); (True, True, False) → `connected`; (True, False, True) → `idle`; (True, False,
  False) → `connect`.
- `test_backoff_sequence`: four failing connects → sleeps 30, 60, 120, 300; success resets to 30.
- `test_env_setting_rejected_exits`: `config set` rc 2 for an env-sourced value → exit called
  with 1.
- `test_file_setting_rejected_continues`: same for a file value → `settings_errors` has the env
  name, no exit.
- `test_natpmp_port_change_written`: ports 41404 then 41405 → file content updated, two log
  lines; failure → file empty, `forwarded_port` None.
- `test_user_disconnect_suspends_reconnect`: after `request_disconnect()`, ticks issue no
  `connect` until `request_connect()`.
- `test_apply_setting_signed_out_saves`: returns `(True, …)`, store has value, no CLI call.
- `test_traffic_ring_buffer`: 200 samples → 180 kept, cleared on a new connection.

Smoke (not signed in):
- `signin hint logged` (text above, within 20 s).
- `unhealthy when signed out` (`healthcheck.sh` exits non-zero).
- `graceful stop`: `docker stop -t 15 $c` returns in under 10 s, exit code `0`.

- [ ] **Step 2: Run to verify they fail** (unittest command from Task 2; smoke)
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run to verify they pass** (unittest, smoke, shellcheck)
- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: supervisor service, health and graceful shutdown"
```

---

### Task 5: WebUI

**Files:**
- Create: `protonvpn_container/webui.py`, `protonvpn_container/signin.py`,
  `protonvpn_container/static/index.html`, `static/app.js`, `static/style.css`,
  `tests/python/test_webui.py`, `tests/python/test_signin.py`
- Modify: `protonvpn_container/__main__.py` (start the WebUI on `WEBUI_PORT`, default `8788`;
  stop it on shutdown), `tests/smoke.sh`

**Interfaces:**
- Consumes: `Supervisor` (`snapshot`, `request_connect`, `request_disconnect`, `apply_setting`,
  `notify_signed_in`), `SettingsStore` (`effective`, `locked`, `source`, `banner_dismissed`,
  `dismiss_banner`), `SETTINGS`, `cli.run`.
- Produces, `signin.py`: `class SigninFlow(argv_prefix=("protonvpn",), timeout=300)` with
  `start(username, password) -> Step` and `submit_code(code) -> Step`, `Step(state:
  "need_code"|"done"|"error", message: str)`. Spawns `protonvpn signin <user> --totp` with
  `pty.fork()`/`os.openpty`; waits for a prompt matching `/password/i`, writes the password;
  then for `/2fa|token|code/i` → `need_code`, or process exit → `done` (rc 0) / `error` (CLI
  output with prompts stripped). One flow at a time (second `start` while active → `error`
  "sign-in already in progress"); killed after `timeout` s idle. Secrets never logged.
- Produces, `webui.py`: `make_server(port, supervisor, store, signin_flow, password) ->
  ThreadingHTTPServer`. Routes:
  - `GET /` and `/static/*` — files from the package (`importlib.resources`), correct
    content types, no directory listing, path traversal rejected (404).
  - `GET /api/state` → `supervisor.snapshot()` plus `settings: [{env, value, locked, source,
    kind}]`, `auth_required: bool`, `banner: bool` (password unset and not dismissed).
  - `POST /api/login {password}` → sets `session` cookie (`secrets.token_urlsafe(32)`,
    `HttpOnly; SameSite=Strict; Path=/`); `hmac.compare_digest`; 5 failures per minute per
    client IP → 429 for 60 s.
  - `POST /api/logout`, `POST /api/connect`, `POST /api/disconnect`,
    `POST /api/settings {env, value}` → `{ok, message}` (locked → 409),
    `POST /api/signin {username, password}`, `POST /api/signin/code {code}` → `Step` as JSON
    (on `done` call `supervisor.notify_signed_in()`), `POST /api/signout` (`protonvpn signout`),
    `POST /api/banner/dismiss`.
  - Every `/api/*` except `login` requires a valid session when a password is set (401
    otherwise). Every `POST` requires header `X-Requested-With: protonvpn-webui` (403
    otherwise) and a JSON body.
  - Startup log when no password: `[webui] WARNING: WEBUI_PASSWORD is not set; the WebUI is open
    to anyone who can reach it`. Access log lines prefixed `[webui]`, never including bodies.
- Page (`static/`): status card, forwarded port with copy button, traffic totals and inline-SVG
  rate graph (rates computed client-side from samples), settings form (dropdowns for `choice`,
  disabled + "set by container config" when locked, per-field error from `settings_errors`),
  sign-in form with code step, sign out, connect/disconnect, dismissible banner, login form when
  `401`. Polls `/api/state` every 5 s. No external assets.

- [ ] **Step 1: Write failing tests**
- `test_signin.py` with `fakebin/protonvpn` scripted by env (`FAKE_SIGNIN=ok|2fa|bad`):
  `test_signin_no_2fa_done`, `test_signin_2fa_then_done` (code `123456` accepted),
  `test_signin_bad_password_error_message` (CLI's message surfaced, no password in it),
  `test_second_start_rejected`, `test_idle_timeout_kills` (timeout 1 s).
- `test_webui.py` against `make_server` on port 0 with a stub supervisor:
  `test_open_mode_state_has_banner`; `test_password_mode_requires_login` (401 then 200 after
  login cookie); `test_login_rate_limit` (6th bad attempt → 429); `test_post_requires_header`
  (403); `test_locked_setting_409`; `test_static_traversal_404` (`/static/../webui.py`);
  `test_signin_done_notifies_supervisor`; `test_banner_dismiss_persists` (store flag set).

Smoke: `webui open`: `docker exec $c python3 -c` fetching `http://127.0.0.1:8788/api/state`
returns JSON with `"signed_in": false` and `"banner": true`; with `-e WEBUI_PASSWORD=x` the same
request returns 401; logs contain the open-WebUI warning only in the first case.

- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run to verify they pass** (unittest, smoke)
- [ ] **Step 5: Visual check**: run the container locally with `-p 8788:8788`, open the page in a
  browser tab (signed out), screenshot the signed-out view and the settings form; check the
  banner dismisses and stays dismissed after reload.
- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: WebUI for status, sign-in and settings"
```

---

### Task 5b: Public API (OpenAPI 3.1, API key, docs page)

**Files:**
- Create: `protonvpn_container/openapi.json`, `protonvpn_container/static/api.html`,
  `static/api.js`, `tests/python/test_api.py`
- Modify: `protonvpn_container/webui.py` (new GET routes, bearer auth, error shape, openapi and
  docs routes), `protonvpn_container/__main__.py` (read `API_KEY`, short-key warning),
  `static/index.html` (header link "API"), `tests/smoke.sh`

**Interfaces:**
- Consumes: `ROUTES` / `Route(method, path, handler, auth)` table in `webui.py`, `make_server`,
  `Supervisor.snapshot()`, `SettingsStore`, `SETTINGS` and the dropdown values from Task 5.
- Produces: routes `GET /api/v1/status`, `GET /api/v1/port` (`?format=text`), `GET
  /api/v1/traffic`, `GET /api/v1/settings`, `GET /api/v1/openapi.json` (no auth), `GET /api` (docs
  page, no auth); auth rule and error shape exactly as the spec's "Public API" section;
  `make_server(..., api_key: str = "")`.

- [ ] **Step 1: Write failing tests** (`test_api.py`, server on port 0 with stub supervisor)
- `test_openapi_matches_routes`: every `(method, path)` in `ROUTES` appears in `openapi.json`
  `paths` and vice versa (paths without the `/api/v1` server prefix handled consistently).
- `test_openapi_document_shape`: `openapi` is `3.1.0`; every operation has `operationId`,
  `summary`, `responses`; `components.securitySchemes` has `bearerAuth` (http, bearer) and
  `cookieAuth` (apiKey in cookie `session`).
- `test_responses_have_required_fields`: for each GET route, the stubbed response contains every
  property the response schema marks `required` (walk `$ref`s into `components.schemas`).
- `test_bearer_key_authorizes_when_password_set`; `test_wrong_key_401`;
  `test_no_key_configured_rejects_bearer` (`API_KEY` empty → bearer ignored → 401 when password set);
  `test_bearer_post_skips_xrw_header`; `test_cookie_post_still_needs_xrw` (403).
- `test_port_text_format` (`41404` / empty body, `text/plain`); `test_port_json_null`.
- `test_error_shape` (`{"error": ...}` for 400/401/404/409).
- `test_openapi_and_docs_need_no_auth` (200 with password set, no cookie).
- `test_short_api_key_warning` (logged once at start for a 16-char key, not for a 64-char key).

Smoke: with `-e WEBUI_PASSWORD=x -e API_KEY=$(openssl rand -hex 32)`:
`curl -H "Authorization: Bearer $key" http://127.0.0.1:8788/api/v1/status` (via `docker exec`
python urllib) returns JSON with `"signed_in": false`; without the header → 401;
`/api/v1/openapi.json` → 200.

- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement** — write `openapi.json` by hand (OpenAPI 3.1, JSON Schema 2020-12
  schemas, examples taken from real stubbed responses); docs page renders it client-side
  (method badge, path, summary, description, parameters, request/response examples, curl example
  with `-H "Authorization: Bearer $API_KEY"`, key-generation box with `openssl rand -hex 32` and the
  python alternative from the spec), same CSS as the WebUI, no external library.
- [ ] **Step 4: Validate the document**: `docker run --rm -v "$PWD:/src" -w /src python:3-slim sh -c "pip install -q openapi-spec-validator && openapi-spec-validator rootfs/usr/local/lib/protonvpn-container/protonvpn_container/openapi.json"` → `OK`.
- [ ] **Step 5: Run all suites** (Python unit, smoke); visual check of `/api` in light and dark
  (screenshots in the workspace `screens/`).
- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: public API with OpenAPI 3.1 contract, API key and docs page"
```

---

### Task 6: CI and image publishing

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `tests/unit.sh`, `tests/python/`, `tests/smoke.sh` (`$IMAGE`).

Jobs:
1. `lint`: `shellcheck -s sh` on all shell scripts; `sh tests/unit.sh`.
2. `smoke` (needs lint): `docker build -t protonvpn-cli:test .` on `ubuntu-latest` (amd64),
   Python unit tests with the command from Task 2, OpenAPI validation (`pip install
   openapi-spec-validator` on the runner, then `openapi-spec-validator
   rootfs/usr/local/lib/protonvpn-container/protonvpn_container/openapi.json`), `sudo modprobe wireguard`,
   `IMAGE=protonvpn-cli:test sh tests/smoke.sh`.
3. `publish` (needs smoke; `push` to `main` and tags `v*`; also weekly `schedule` so base-image
   updates land): buildx + QEMU, `linux/amd64,linux/arm64`, push to
   `ghcr.io/andrebrait/protonvpn-cli-docker` with tags `latest` (every publication), `X.Y.Z` / `X.Y` (tags),
   `sha-<short>`; `permissions: packages: write`.

- [ ] **Step 1: Write the workflow**
- [ ] **Step 2: Validate locally**: `docker run --rm -v "$PWD":/repo -w /repo rhysd/actionlint:latest` → no findings.
- [ ] **Step 3: Verify arm64 builds**: `docker buildx build --platform linux/arm64 -t protonvpn-cli:arm64 .` → succeeds; record time.
- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "ci: lint, tests and multi-arch publish"
```

---

### Task 7: Unraid template, docs, release check on Unraid

**Files:**
- Create: `unraid/protonvpn-cli.xml`, `README.md`, `docs/manual-test.md`

**Interfaces:**
- Consumes: every env var from Global Constraints and the spec's Configuration tables.

- Template: `<Container version="2">`, `Name` `protonvpn-cli`, `Repository`
  `ghcr.io/andrebrait/protonvpn-cli-docker:latest`, `Network` `bridge`, `WebUI`
  `http://[IP]:[PORT:8788]/`, `ExtraParams` = the required run flags, `Config` entries: Port
  `8788`→`8788` TCP; Path `/config` → `/mnt/user/appdata/protonvpn-cli`; one Variable per env
  var with description; setting variables empty by default (the WebUI configures them);
  dropdowns (`|`-separated `Default`, first entry empty) for `NETSHIELD`, `PORT_FORWARDING`,
  `VPN_ACCELERATOR`, `MODERATE_NAT`, `IPV6`, `ANONYMOUS_CRASH_REPORTS`, `P2P`,
  `SECURE_CORE`, `TOR`, `DEBUG`, with allowed values from `protonvpn config set <key> --help` in
  the built image; `WEBUI_PASSWORD` and `API_KEY` with `Mask="true"` (the `API_KEY` description
  says how to generate one: `openssl rand -hex 32`). `Overview`: open the WebUI to sign in and
  configure (or the Console button); attach other containers with
  `--network=container:protonvpn-cli` and publish their ports on this container; forwarded port
  in `/config/forwarded_port` and the WebUI.
- README: what/why, quick start (`docker run` + compose), WebUI and sign-in, API (link to `/api`
  docs page and `openapi.json`, `API_KEY` with generation commands `openssl rand -hex 32` and the
  python alternative, a qBittorrent port example using `/api/v1/port?format=text`), settings precedence
  (env locks the WebUI field), env table, kill-switch behaviour (attached containers: tunnel +
  LAN only; own processes: 443/53), requirements (cgroup v2, `xt_cgroup`, `wireguard` module),
  port forwarding, health, troubleshooting (`docker logs`, `/config/cache/VPN/logs/vpn-cli.log`),
  limitations (headless unsupported by Proton, FIDO2 console-only and untested).
- `docs/manual-test.md`: the spec's manual checklist as checkboxes.

- [ ] **Step 1: Write the three files**
- [ ] **Step 2: Validate the template XML**: `xmllint --noout unraid/protonvpn-cli.xml` → no output.
- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "docs: Unraid template, README and manual test checklist"
```

The credentialed manual checklist on Unraid runs after Task 7 with the user (ledger Ruling R1).

---

### Task 8: Independent operational health (approved after live outage test)

This extension supersedes the earlier CLI-only healthcheck and synchronous exit-address lookup.
The live five-minute WireGuard outage kept native `connected=true`, so operational reachability
must be a separate fact. Echo failure alone is observational; corroborated stalled-handshake recovery is specified below.

**Backend ownership:** `supervisor.py`, new `health.py` / `healthcheck.py` where appropriate,
`healthcheck.sh`, image-baked curl in `Dockerfile`, startup health-file invalidation, backend tests.
**Frontend ownership:** `webui.py`, `openapi.json`, static UI, README/manual, HTTP contract fixtures.
**Controller ownership:** shared spec, CI tool version, integration and release verification.

**Interfaces:**
- Snapshot/status/state: `tunnel_healthy: bool | None`, `health_error: str`,
  `health_checked_ago: float | None` (seconds).
- One worker in the existing process, independent of CLI locks and the supervisor loop: probe
  every 30 seconds, first probe promptly after connection. Use curl bound to `if!proton0`,
  IPv4, five-second complete request limit, six-second process limit, no proxy, HTTPS ipify.
  Require a valid public IPv4 literal. No interface fallback; echo failure alone never reconnects.
  On failure, bounded independent UDP stimulus plus valid unchanged/zero WireGuard handshakes
  for 180 seconds on the same generation can queue supervisor-only disconnect/connect recovery.
  Unknown evidence does not recover; advancing handshakes or echo success reset it. Preserve
  credentials, target, kill switch, cancellation and completion-based failed-attempt backoff.
- Freshness is 60 seconds. Disconnection, stop and new connection invalidate prior success;
  old in-flight results cannot update a new connection. Log changed health states/errors only.
- Atomic `/run/protonvpn-container/health.json` with boolean `healthy` and monotonic `checked_at`
  feeds Docker health; missing, invalid or stale state is unhealthy. No unauthenticated API
  endpoint or duplicated credential handling.
- UI separates native connection from Passed/Failed/Checking traffic health, with IPv4 HTTPS
  scope and age. Existing CLI `connected` and `last_error` meanings remain unchanged.

- [ ] **Step 1:** Backend worker implements the transport, independent scheduling, stale-result
  guards, health-file reader/writer and deterministic failure/freshness/concurrency tests.
- [ ] **Step 2:** Frontend worker integrates the exact three fields in API/schema/UI and adds
  behavioral HTTP contracts, including native-connected/probe-failed state.
- [ ] **Step 3:** Controller runs Python units and JSON-schema contracts, OpenAPI validation,
  shell checks and image smoke after both slices finish. On an image without `proton0`, the real
  bound probe must fail even if ordinary direct HTTPS works.
- [ ] **Step 4:** Real Unraid run: connected probe passes; block WireGuard UDP, observe CLI still
  connected but operational API/UI/Docker health fail; remove the block and recover without
  signing in. Verify corroborated recovery and backoff, no ipify-only reconnect, and independent port renewal.
- [ ] **Step 5:** Scoped adversarial review, resolve findings, commit, update the PR and release
  `latest` / `0.0.1` only after CI and acceptance pass.

---

### Task 9: HTTP source allowlist with mandatory VPN-interface denial

**Files:** `firewall.sh`, shell unit/smoke tests; README, Unraid template, manual checklist and
API reference access-policy description. No new application auth scheme or configurable bypass.

**Interface:** `WEBUI_ALLOWED_NETWORKS`, immutable container environment, comma-separated literal
IPv4/IPv6 CIDRs or individual IPs. Empty/unset preserves normal non-VPN access. Invalid nonempty
input fails startup. The entire HTTP port, including API/docs/static/login, uses this policy.

- [ ] **Step 1:** Network worker validates/normalizes networks with stdlib `ipaddress`; generate
  a dedicated HTTP input chain ahead of all generic INPUT accepts. Drop `proton0` first,
  regardless of source or broad allowlists. If configured, permit matching source ranges then
  drop all unmatched traffic, including loopback unless explicitly included.
- [ ] **Step 2:** Exercise real allowed and denied clients, authentication/header non-bypass,
  loopback opt-in, address-family separation and malformed configuration. Prove incoming
  `proton0` traffic is denied even with an allow-all list using actual packet ingress rather
  than assuming a local request to the tunnel address traverses that interface.
- [ ] **Step 3:** Docs worker adds the advanced unmasked template variable and explains source
  IPs as seen by the container, proxy masking, no X-Forwarded-For trust, and the distinction from
  LAN_NETWORKS. Include explicit local-client example `127.0.0.1/32,10.0.0.0/8`.
- [ ] **Step 4:** Controller runs integrated network/Python/schema/lint checks and real target
  allow/deny checks. Health must remain usable via its private file even when HTTP is denied.
- [ ] **Step 5:** Scoped security/contract review, then update the PR and proceed to the already
  requested public `latest` / `0.0.1` publication and anonymous-pull verification.
