ARG BASE_IMAGE=debian:13-slim
FROM ${BASE_IMAGE}
ARG DEBIAN_FRONTEND=noninteractive
ARG PROTON_RELEASE_VERSION=1.0.10

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
 && apt-get install -y --no-install-recommends ./protonvpn-stable-release_*_all.deb \
 && rm -f ./*.deb \
 && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      proton-vpn-cli network-manager dbus wireguard-tools iproute2 iptables natpmpc tini ca-certificates procps tzdata \
 && rm -rf /var/lib/apt/lists/*

COPY rootfs/ /

ENV HOME=/config \
    PROTON_LOADER_OVERRIDES=keyring=json \
    KILL_SWITCH=standard \
    ANONYMOUS_CRASH_REPORTS=off \
    TZ=UTC \
    DEBUG=false \
    RECONNECT_INTERVAL=30 \
    LAN_NETWORKS=

ENV PYTHONPATH=/usr/local/lib/protonvpn-container

VOLUME /config
ENTRYPOINT ["tini", "--", "/usr/local/bin/entrypoint.sh"]
