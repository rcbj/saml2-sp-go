# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# `docker build --target test .` runs the suite in this image.
# The demo image below does not run it.
# trust_chain_test.go runs scripts/trust_chain.py and the install script with
# this image's python3 and openssl.
FROM golang:1.27 AS test
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Only what the build and the suite read, so a new trust chain in
# demo/generated does not retest anything.
COPY go.mod go.sum ./
COPY *.go ./
COPY cmd cmd
COPY scripts scripts
COPY demo/saml.json demo/saml.json
COPY demo/public demo/public
RUN go test ./...

FROM golang:1.27
# python3 and openssl run scripts/configure_iya_sts.py inside this image:
# the live test registers the demo here, so Go never runs on the host.
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY go.mod go.sum ./
COPY *.go ./
COPY cmd cmd
RUN go build -o /usr/local/bin/saml2-sp ./cmd/saml2-sp && go build -o /usr/local/bin/saml-demo ./cmd/demo
# demo/ comes after the build, so a new trust chain does not rebuild the
# binaries. .dockerignore admits one file of demo/generated: idp-ca.pem, the
# iya-sts listener CA trust chain scripts/configure_iya_sts.py writes where
# idpCa names it. When it exists, this COPY puts it at
# /app/demo/generated/idp-ca.pem and the image trusts that iya-sts with no
# bind mount and no fetch; rebuild after running the install script against a
# different iya-sts. When it does not (a fresh clone, CI), the build still
# succeeds: a COPY of the demo DIRECTORY always has a source, where naming the
# file or a glob that matches nothing fails in both builders. The SP key pair,
# its metadata and the IdP metadata never enter the image.
COPY demo demo
COPY scripts scripts
COPY README.md LICENSE VERSION ./
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/${PORT} && printf 'GET /healthz HTTP/1.0\\r\\nHost: 127.0.0.1\\r\\n\\r\\n' >&3 && grep -q '^ok' <&3"]
CMD ["saml-demo"]
