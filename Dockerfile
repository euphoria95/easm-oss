# =============================================================================
# EASM Pipeline - Multi-stage Docker Build
# Installs: dnsx, naabu, httpx, tlsx, nuclei, nerva, zgrab2, gowitness, subzy
#           + Python venv (duckdb stack), jq, Chromium/Chrome
# nerva is the primary fingerprinting engine; zgrab2 is kept for fallback.
#
# Runtime base can be switched at build-time:
#   docker build --build-arg RUNTIME_BASE=ubuntu:24.04 -t easm-pipeline .
#   docker build --build-arg RUNTIME_BASE=debian:bookworm-slim -t easm-pipeline .
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

# Build tools separately for easier debugging
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
RUN go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
RUN go install -v github.com/sensepost/gowitness@latest
RUN go install -v github.com/PentestPad/subzy@latest
RUN go install -v github.com/zmap/zgrab2/cmd/zgrab2@latest
RUN go install -v github.com/praetorian-inc/nerva/cmd/nerva@latest

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
        sudo \
        tini; \
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
COPY --from=go-builder /go/bin/subzy     /usr/local/bin/
COPY --from=go-builder /go/bin/zgrab2       /usr/local/bin/
COPY --from=go-builder /go/bin/nerva         /usr/local/bin/

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
