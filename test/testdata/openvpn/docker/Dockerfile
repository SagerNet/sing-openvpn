ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}

ARG OPENVPN_PACKAGE_VERSION=2.6.14-0+deb12u2

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        grep \
        iproute2 \
        iputils-ping \
        openvpn="${OPENVPN_PACKAGE_VERSION}" \
        procps \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*
