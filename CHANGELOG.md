# Changelog

## 0.0.1 — 2026-11-03

### Added

- Debian 13 slim container running Proton VPN's official CLI, with persistent console or WebUI sign-in.
- Responsive light/dark WebUI showing connection, server, location, exit IP, forwarded port and live traffic.
- Environment-controlled or saved preferences, with environment overrides visibly locked in the WebUI.
- Versioned JSON API, optional separate bearer key and an OpenAPI 3.1 reference page with key-generation instructions.
- Independent WireGuard-bound traffic health in the WebUI, API and Docker healthcheck, separate from Proton's connection state and without probe-triggered reconnects.
- Always-on container firewall, fixed Proton Standard kill switch, WireGuard-only connections and renewable TCP/UDP port forwarding.
- Optional HTTP source-IP allowlist, with unconditional VPN-interface blocking on the control port while forwarded application TCP/UDP traffic remains allowed.
- Unraid template (in [andrebrait/unraid-templates](https://github.com/andrebrait/unraid-templates)), official Proton VPN icon and amd64/arm64 image builds.

### Fixed

- Recovery of DNS and WebUI access when the VPN connects or the container restarts.
- Rejection of ambiguous HTTP port values before firewall allow rules, preventing hexadecimal/octal interpretation from protecting a different port than the listener.
- Duplicate sign-in completion reapplying settings and interrupting an established connection.
- Stale forwarded ports after disconnects, failed checks or lease expiration.
- Startup deny filters for both IP families, identity-safe daemon shutdown and bounded HTTP request handlers.
- Gateway-granted forwarding lifetimes, queued/failed connection controls, canceled connects, shutdown/connect races and failed port-file replacements.
- Settings errors hidden behind save messages, rejected save batches, edits lost during pending saves and unsuccessful warning dismissal.
- LAN-bound quick-start examples, HTTPS proxy cookie guidance, JavaScript syntax checks in CI and option-safe WireGuard smoke fixtures.
- Bounded best-effort NAT-PMP deletion before disabling forwarding, changing a server target or processing a user Disconnect, without claiming immediate remote revocation if the gateway rejects it.
- Older saved Proton state could select OpenVPN; every connect now saves WireGuard first, and a non-WireGuard tunnel is disconnected instead of being reported as connected. Protocol rejection replaces stale check errors and respects cancellation without restoring an old server target.

### Limitations

- Proton does not officially support headless use. Hardware-security-key sign-in requires the console.
- The firewall protects against accidental leaks, not hostile applications with raw-packet or network-administration capabilities.
- Operational health checks IPv4 HTTPS through an external echo service; an echo-service outage can fail the check without disconnecting the VPN.
- Known Debian dependency advisories remain, including two reachable outbound aiohttp parser issues. See the README's dated security dispositions; review by 2026-11-09.
