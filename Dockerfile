ARG BASE_IMAGE=debian:13-slim
FROM ${BASE_IMAGE}
ARG DEBIAN_FRONTEND=noninteractive
# Proton package versions of every build, tests and publication alike: the CLI's prompts and output are parsed, so a new release is
# adopted by changing these defaults (and testing), not by rebuilding. The checksum is the one Proton publishes for the release package
# (https://protonvpn.com/support/linux-vpn-debian-ubuntu); change it together with PROTON_RELEASE_VERSION.
ARG PROTON_RELEASE_VERSION=1.0.10
ARG PROTON_RELEASE_SHA256=c8a9fffb4ebdd63db08ce7f11c9b0ac394064ae6a210feb9ab63a0f7d8d060a7
ARG PROTON_CLI_VERSION=1.1.0
ARG PROTON_API_CORE_VERSION=6.1.1

# proton-vpn-daemon only provides split tunneling (unsupported by the CLI) and pulls BCC/LLVM; satisfy it with an empty package.
RUN mkdir -p /tmp/dummy/DEBIAN \
 && printf 'Package: proton-vpn-daemon\nVersion: 999\nArchitecture: all\nMaintainer: none\nDescription: placeholder\n' > /tmp/dummy/DEBIAN/control \
 && dpkg-deb -b /tmp/dummy /tmp/proton-vpn-daemon.deb \
 && dpkg -i /tmp/proton-vpn-daemon.deb \
 && rm -rf /tmp/dummy /tmp/*.deb

# Proton apt repo release package (installs the repo list and signing key).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates wget \
 && wget -q "https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_${PROTON_RELEASE_VERSION}_all.deb" \
 && echo "${PROTON_RELEASE_SHA256}  protonvpn-stable-release_${PROTON_RELEASE_VERSION}_all.deb" | sha256sum -c - \
 && apt-get install -y --no-install-recommends ./protonvpn-stable-release_*_all.deb \
 && rm -f ./*.deb \
 && apt-get purge -y --auto-remove wget \
 && rm -rf /var/lib/apt/lists/*

# The versions that ship are printed here, in the build output. curl is the tunnel health probe's transport: it binds to
# proton0 and bounds the whole request, which Python's urllib cannot do; it belongs in the image, never installed at runtime.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      "proton-vpn-cli=${PROTON_CLI_VERSION}" "python3-proton-vpn-api-core=${PROTON_API_CORE_VERSION}" \
      network-manager dbus wireguard-tools iproute2 iptables natpmpc curl tini ca-certificates procps tzdata \
 && dpkg-query -W proton-vpn-cli python3-proton-vpn-api-core \
 && rm -rf /var/lib/apt/lists/*

COPY rootfs/ /
# nm-dispatcher silently skips a script writable by group or other (a container has no syslog to say so), and COPY keeps
# the build context's modes: git archive / a umask-002 checkout ships it 775. Fix the mode here, whatever the context.
RUN chmod 0755 /etc/NetworkManager/dispatcher.d/50-resolv

ENV HOME=/config \
    PROTON_LOADER_OVERRIDES=keyring=json \
    TZ=UTC \
    DEBUG=false \
    RECONNECT_INTERVAL=30 \
    LAN_NETWORKS=

ENV PYTHONPATH=/usr/local/lib/protonvpn-container

VOLUME /config
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 CMD ["/usr/local/bin/healthcheck.sh"]
ENTRYPOINT ["tini", "--", "/usr/local/bin/entrypoint.sh"]
