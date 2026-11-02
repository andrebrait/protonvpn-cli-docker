# Changelog

## 0.0.1 — 2026-11-02

### Added

- Debian 13 slim container running Proton VPN's official CLI, with persistent console or WebUI sign-in.
- Responsive light/dark WebUI showing connection, server, location, exit IP, forwarded port and live traffic.
- Environment-controlled or saved preferences, with environment overrides visibly locked in the WebUI.
- Versioned JSON API, optional separate bearer key and an OpenAPI 3.1 reference page with key-generation instructions.
- Always-on container firewall, fixed Proton Standard kill switch and renewable TCP/UDP port forwarding.
- Unraid template, official Proton VPN icon and amd64/arm64 image builds.

### Fixed

- Recovery of DNS and WebUI access when the VPN connects or the container restarts.
- Duplicate sign-in completion reapplying settings and interrupting an established connection.
- Stale forwarded ports after disconnects, failed checks or lease expiration.

### Limitations

- Proton does not officially support headless use. Hardware-security-key sign-in requires the console.
- The firewall protects against accidental leaks, not hostile applications with raw-packet or network-administration capabilities.
