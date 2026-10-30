# =============================================================================
# EASM Pipeline - Multi-stage Docker Build
# Installs: subfinder, dnsx, cdncheck, naabu, httpx, tlsx, nuclei, nerva,
#           zgrab2, gowitness, waf-detect (waf-detector, Rust)
#           + Python venv (duckdb stack), jq, Chromium/Chrome
# nerva is the primary fingerprinting engine; zgrab2 is kept for fallback.
#
# Runtime base can be switched at build-time:
#   docker build --build-arg RUNTIME_BASE=ubuntu:24.04 -t easm-pipeline .
#   docker build --build-arg RUNTIME_BASE=debian:bookworm-slim -t easm-pipeline .
#
# Tool versions can be pinned at build-time:
#   --build-arg SUBFINDER_VERSION=v2.x.y --build-arg CDNCHECK_VERSION=v1.x.y
#   --build-arg WAF_DETECTOR_REF=<git sha|tag>
# =============================================================================

ARG RUNTIME_BASE=debian:bookworm-slim

# Stage 0: Pull prebuilt nuclei binary from official image
FROM projectdiscovery/nuclei:v3.8.0 AS nuclei-bin

# Stage 1: Build Go tools from source
FROM golang:1.26-bookworm AS go-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    libpcap-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV GOBIN=/go/bin
# Let `go install` fetch a newer toolchain when a module requires it (the base
# image defaults to GOTOOLCHAIN=local, which hard-fails e.g. tlsx needing go 1.27).
ENV GOTOOLCHAIN=auto

# Build tools separately for easier debugging
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
RUN go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
RUN go install -v github.com/sensepost/gowitness@latest
RUN go install -v github.com/zmap/zgrab2/cmd/zgrab2@latest
RUN go install -v github.com/praetorian-inc/nerva/cmd/nerva@latest

ARG SUBFINDER_VERSION=latest
ARG CDNCHECK_VERSION=latest
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}
RUN go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@${CDNCHECK_VERSION}

# Stage 1b: Build waf-detector (Rust) from the upstream repo.
# Pinned to a commit by default — single-maintainer project, so bump deliberately.
# bookworm base keeps the binary's glibc compatible with the default runtime.
FROM rust:1-slim-bookworm AS rust-builder

ARG WAF_DETECTOR_REPO=https://github.com/ammarion/waf-detector.git
ARG WAF_DETECTOR_REF=07ffed91

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone "${WAF_DETECTOR_REPO}" /src \
    && cd /src \
    && git checkout "${WAF_DETECTOR_REF}" \
    && cargo build --release --locked --bin waf-detect \
    && strip target/release/waf-detect

# Stage 2: Runtime image
FROM ${RUNTIME_BASE} AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Shell with pipefail for safer RUN steps
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Common runtime deps + browser install strategy:
# - Debian: install chromium package directly
# - Ubuntu 24.04: install Google Chrome (chromium is snap-only in many Ubuntu images)
RUN set -eux; \
    . /etc/os-release; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        dnsutils \
        gnupg \
        jq \
        libpcap0.8 \
        python3 \
        python3-pip \
        python3-venv \
        build-essential \
        gcc \
        python3-dev \
        sudo \
        tini; \
    if [[ "${ID}" == "ubuntu" ]]; then \
        apt-get install -y --no-install-recommends libssl3t64; \
    else \
        apt-get install -y --no-install-recommends libssl3; \
    fi; \
    if [[ "${ID}" == "ubuntu" ]]; then \
        apt-get install -y --no-install-recommends \
            fonts-liberation \
            libasound2t64 \
            libatk-bridge2.0-0 \
            libatk1.0-0 \
            libcairo2 \
            libcups2 \
            libdbus-1-3 \
            libdrm2 \
            libgbm1 \
            libglib2.0-0 \
            libgtk-3-0 \
            libnss3 \
            libnspr4 \
            libu2f-udev \
            libx11-6 \
            libx11-xcb1 \
            libxcb1 \
            libxcomposite1 \
            libxdamage1 \
            libxext6 \
            libxfixes3 \
            libxkbcommon0 \
            libxrandr2 \
            xdg-utils; \
        mkdir -p /etc/apt/keyrings; \
        curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /etc/apt/keyrings/google-linux.gpg; \
        echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/google-linux.gpg] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list; \
        apt-get update; \
        apt-get install -y --no-install-recommends google-chrome-stable; \
        ln -sf /usr/bin/google-chrome /usr/bin/chromium; \
    else \
        apt-get install -y --no-install-recommends chromium chromium-sandbox; \
    fi; \
    rm -rf /var/lib/apt/lists/*

# Copy Go binaries built locally
COPY --from=go-builder /go/bin/dnsx      /usr/local/bin/
COPY --from=go-builder /go/bin/naabu     /usr/local/bin/
COPY --from=go-builder /go/bin/httpx     /usr/local/bin/
COPY --from=go-builder /go/bin/tlsx      /usr/local/bin/
COPY --from=go-builder /go/bin/pdtm      /usr/local/bin/
COPY --from=go-builder /go/bin/gowitness /usr/local/bin/
COPY --from=go-builder /go/bin/zgrab2       /usr/local/bin/
COPY --from=go-builder /go/bin/nerva         /usr/local/bin/
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/
COPY --from=go-builder /go/bin/cdncheck  /usr/local/bin/

# Copy waf-detector built from source
COPY --from=rust-builder /src/target/release/waf-detect /usr/local/bin/waf-detect

# Copy nuclei from official prebuilt image
COPY --from=nuclei-bin /usr/local/bin/nuclei /usr/local/bin/nuclei

# Python virtual environment + deps
RUN python3 -m venv /opt/easm-venv
ENV PATH="/opt/easm-venv/bin:${PATH}"

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --upgrade pip setuptools wheel && \
    python3 -m pip install -r /tmp/requirements.txt && \
    rm -f /tmp/requirements.txt

# Set browser path for httpx/gowitness
ENV CHROMIUM_PATH=/usr/bin/chromium \
    CHROME_PATH=/usr/bin/chromium

# Working directory and source
WORKDIR /easm
COPY . /easm/

# Set permissions for shell helpers
RUN chmod +x /easm/run.sh /easm/scripts/*.sh 2>/dev/null || true

# Best-effort nuclei template refresh (non-fatal in offline/air-gapped builds)
RUN nuclei -update-templates -silent 2>/dev/null || true

# Default entrypoint via tini for proper signal handling in containers
ENTRYPOINT ["/usr/bin/tini", "--", "/easm/run.sh"]
