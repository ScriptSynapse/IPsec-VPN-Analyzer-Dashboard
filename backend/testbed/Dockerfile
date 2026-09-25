# Ubuntu 24.04's `strongswan`/`libcharon-extra-plugins`/`libstrongswan-extra-plugins`
# apt packages ship no `gcm` or `ecp` plugin at all (confirmed by grepping a built
# image for the plugin .so files -- none exist, and no separate
# "strongswan-plugin-openssl"-style package exists in the Ubuntu 24.04 repos either).
# That silently broke every AES-GCM and ECP-DH-group config in this testbed's matrix
# (6 of 17 rows) at the IKE negotiation step, before any of this repo's own code
# even ran. Building strongSwan from source with --enable-openssl adds both (OpenSSL
# provides AEAD/GCM ciphers and EC curve support) without needing a different distro.
#
# Single-stage on purpose: a multi-stage copy needs every installed binary's exact
# path guessed up front (autotools' --prefix=/usr puts charon/starter under
# /usr/libexec/ipsec/, not /usr/sbin/, which isn't obvious without inspecting a
# real build), and this is a local testbed image, not something shipped anywhere --
# image size doesn't matter here, correctness does.
FROM ubuntu:24.04

ARG STRONGSWAN_VERSION=5.9.13

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libssl-dev libgmp-dev libcurl4-openssl-dev gperf bison flex pkg-config \
    wget ca-certificates iproute2 iputils-ping tcpdump curl netcat-openbsd python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
RUN wget -q "https://download.strongswan.org/strongswan-${STRONGSWAN_VERSION}.tar.bz2" \
    && tar xjf "strongswan-${STRONGSWAN_VERSION}.tar.bz2"

WORKDIR /usr/src/strongswan-${STRONGSWAN_VERSION}
# --enable-openssl is the one flag that matters here (adds ENCR_AES_GCM_* and the
# ECP_* DH groups via OpenSSL). The rest keeps parity with what the old apt-based
# image provided (stroke/starter for ipsec.conf, updown for the routing hooks
# alice-host/bob-host's entrypoints depend on, vici/swanctl left out since this
# testbed's configs and scripts are stroke/ipsec.conf-based, not swanctl-based).
#
# `--disable-defaults` (a minimal, explicit plugin list) turned out to prune
# the SUBDIRS dependency graph in a way that broke the standard build order
# -- `src/starter` needs libstrongswan.la/libcharon.la, but with defaults
# disabled, the top-level SUBDIRS list reaches starter before either is
# built, and no combination of parallel/serial/keep-going make invocations
# fixed it (all failed identically or produced a build with missing .so
# files). Building with the full default plugin set instead -- the same
# path every distro's strongSwan package actually uses -- and adding
# --enable-openssl on top is the well-tested option; it costs build time
# and image size, not correctness, for what is a local testbed image.
RUN ./configure --prefix=/usr --sysconfdir=/etc --enable-openssl \
    && make \
    && make install \
    && ldconfig \
    && rm -rf /usr/src/strongswan-${STRONGSWAN_VERSION}*

CMD ["ipsec", "start", "--nofork"]
