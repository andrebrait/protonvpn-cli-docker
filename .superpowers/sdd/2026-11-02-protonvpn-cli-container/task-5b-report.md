# Task 5b — Public API

## Result and scope

Implemented on `feat/image` in the assigned worktree, starting from `f58965e`. Product code uses only Python's standard library and existing plain HTML/CSS/JS. No Proton credentials were used. No primary checkout or other worktree was accessed.

- Added focused HTTP reads: status, JSON/plain-text forwarded port, traffic totals with relative samples, and settings metadata. Reused Supervisor.snapshot(), SettingsStore, existing sign-in flow, and ROUTES.
- Added API_KEY as a separate authorization alternative to WebUI cookies/open mode. Comparison is constant-time. Empty API_KEY disables bearer authentication without closing open mode. Only a verified bearer token bypasses X-Requested-With, including in open mode. Short nonempty keys warn once at startup without printing their value.
- Cut all JSON API errors over to `{ "error": "message" }`, including rejected settings, failed signout and failed Proton sign-in. Migrated app.js and existing tests; no legacy error aliases. Retryable two-factor `need_code` remains a successful flow response with its existing message.
- Shipped hand-authored OpenAPI 3.1.0 with JSON Schema 2020-12 schemas, all 15 operations, request/response examples, bearer/cookie security schemes, parameters and error statuses. Added a public, client-rendered `/api` reference using the existing CSS/header/icon, with both exact key-generation commands and executable curl examples. Header navigation links the WebUI and docs.
- Added HTTP contract/auth/error tests and real-container bearer smoke checks. Existing smoke resources now use unique `t5b-<pid>-...` names. Clarified the public API section of the design document. README remains Task 7's responsibility; no unrelated changelog file was introduced.

## Verification workflow

Tests were authored before implementation, but **no initial RED run was performed**, per the assignment's explicit prohibition on mid-flight checks. Verification began only after all implementation/test/doc changes were complete. No RED evidence is claimed.

### First verification command

```sh
docker build -t protonvpn-cli:test . &&
docker run --rm --name t5b-python-$$ -v "$PWD:/src" -w /src \
  -e PYTHONPATH=/src/rootfs/usr/local/lib/protonvpn-container \
  --entrypoint python3 protonvpn-cli:test -m unittest discover -s tests/python -t . &&
sh tests/unit.sh &&
sh tests/smoke.sh &&
docker run --rm --name t5b-openapi-$$ -v "$PWD:/src" -w /src python:3-slim sh -c \
  'pip install -q openapi-spec-validator && openapi-spec-validator rootfs/usr/local/lib/protonvpn-container/protonvpn_container/openapi.json'
```

Observed:

```text
#10 naming to docker.io/library/protonvpn-cli:test done
#10 unpacking to docker.io/library/protonvpn-cli:test 0.1s done
Ran 172 tests in 23.038s
OK
[shell unit assertions: all ok]
[existing smoke assertions: pass]
FAIL public api: real bearer HTTP contract
ok   webui stops within the shutdown budget
Command exited with code 1
```

The Python suite includes expected fake-CLI output such as `[protonvpn] Error: boom`; these are passing failure-path fixtures, not test failures. The initial smoke failure was in the new smoke helper itself: two byte literals were written `b\"{}\"` inside shell single quotes, leaving invalid Python syntax. Removed those unnecessary backslashes. No product code changed after this verification run. Because of shell `&&`, the validator had not yet run.

### Corrected smoke and validator command

```sh
sh tests/smoke.sh &&
docker run --rm --name t5b-openapi-$$ -v "$PWD:/src" -w /src python:3-slim sh -c \
  'pip install -q openapi-spec-validator && openapi-spec-validator rootfs/usr/local/lib/protonvpn-container/protonvpn_container/openapi.json'
```

Actual smoke output:

```text
ok   nm running
ok   cli disconnected
ok   user:root profile activates
ok   config modes: /config/Proton 700
ok   config modes: /config/cache 700
ok   config modes: stale.json 600
ok   symlinks: /etc/Proton
ok   symlinks: /var/cache/Proton
ok   restart boots: nm running
ok   restart boots: cli disconnected
ok   no runtime installs
ok   resolv.conf survives nm up/down
ok   own 443 allowed
ok   own 80 blocked
ok   own dns allowed
ok   attached 443 blocked
ok   attached dns blocked
ok   own embedded dns allowed
ok   attached embedded dns blocked
ok   lan allowed
ok   lan blocked without LAN_NETWORKS
ok   webui port open inbound
ok   other inbound port blocked
ok   ipv6 lan allowed
ok   ipv6 lan blocked without LAN_NETWORKS
ok   bad LAN fails closed
ok   signin hint logged
ok   unhealthy when signed out
ok   forwarded_port is empty, mode 644
ok   pid file: NetworkManager
ok   pid file: system bus
ok   pid file: session bus
ok   graceful stop
ok   webui open: state is signed out with the banner
ok   webui open: warning logged
ok   webui open: page served
ok   webui open: script served
ok   webui open: traversal refused
ok   webui password: state is 401
ok   webui password: page still loads
ok   webui password: no open warning
ok   public api: real bearer HTTP contract
ok   webui stops within the shutdown budget
all ok
rootfs/usr/local/lib/protonvpn-container/protonvpn_container/openapi.json: OK
```

Exit 0. `python:3-slim` was downloaded for validation. Pip emitted its standard root-user warning **inside that disposable tooling container only**. Nothing was installed into product containers.

The real-container bearer smoke checks signed-out status with a valid key (200), absent/wrong key (401), public OpenAPI (200), a valid bearer POST without X-Requested-With (200), and an invalid bearer POST without that header (403). Unit HTTP tests additionally cover disabled keys, open mode, cookie authentication, malformed authorization, all documented operations' actual required response fields, empty/populated port and traffic, settings locks, startup warnings, and clean error bodies for 400/401/403/404/409/413/422/429/500. Route-table/source-only assertions were intentionally not added; the old route-table introspection test was removed in favor of HTTP contracts as requested.

## Real-browser evidence

Started `t5b-docs-572e9aeb` from the built image with NET_ADMIN, tun device, src_valid_mark, a random generated API key, a test-only WebUI password and a loopback ephemeral published port. Served at `127.0.0.1:32768`. Drove Chromium using the required `browser` global, with an isolated managed tab, no external libraries or mocks.

Observed:

```text
URL: http://127.0.0.1:32768/api
Title: API · Proton VPN
endpoints: 15
OpenAPI 3.1 · JSON Schema 2020-12 · v1
Desktop overflow: false
Mobile overflow (390 × 844): false
Console: entries: []
Errors: entries: []
Migrated WebUI error: wrong password
Header navigation returns docs: API · Proton VPN
```

Inspected endpoint navigation/disclosure semantics and actual method/path/summary/parameter/curl/response rendering. Followed the forwarded-port link, checked its JSON and plain-text examples in light/dark themes. Verified the migrated WebUI displays a real 401 error from the new shape, successfully logged in with the test password, and followed the header API link back to rendered docs.

Saved screenshots (workspace `screens/`):

- [API overview, light](../../../screens/task-5b-api-light.png)
- [API overview, dark](../../../screens/task-5b-api-dark.png)
- [Forwarded-port endpoint, light](../../../screens/task-5b-endpoint-light.png)
- [Forwarded-port endpoint, dark](../../../screens/task-5b-endpoint-dark.png)

Extracted the rendered curl commands from the browser and executed them with API_KEY supplied in the subprocess environment (never printed):

```text
getStatus: rendered curl exited 0; fields=signed_in,account,connected,server,location,load,protocol,exit_ip,forwarded_port,last_error
getPort: rendered curl exited 0; fields=port
getTraffic: rendered curl exited 0; fields=rx_bytes,tx_bytes,samples
getSettings: rendered curl exited 0; fields=settings
disconnect: rendered curl exited 0; fields=ok
Product logs: no test key or password values
```

The first browser-extraction harness selected the request example `{}` instead of the curl block for the POST, causing shell exit 127; selecting the block beginning `curl ` corrected the harness. The rendered POST command itself executed successfully without edits.

## Cleanup and concerns

- Removed `t5b-docs-572e9aeb` and closed the browser tab. Smoke traps removed their containers/networks; all unit/validator containers used --rm.
- Ran `docker ps -a --filter name=t5b- --format '{{.Names}}'` and `docker network ls --filter name=t5b- --format '{{.Name}}'`: both produced no output.
- No real Proton signin, VPN connection, or live forwarded port was exercised, because credentials were prohibited. Populated port/traffic and PTY flow behavior are covered by existing/new tests with controlled collaborators; real-container checks cover the signed-out state.
- Failed Proton sign-in now returns HTTP 400 rather than a 200 `state:error`, intentionally completing the requested error cutover. Existing WebUI consumers were migrated.
- API transport remains the existing HTTP listener; use a trusted reverse proxy for TLS outside a trusted network. API_KEY does not make open mode private.
- No separate mutation-testing run, external dependency audit, or production deployment was performed. No product dependencies were added.
