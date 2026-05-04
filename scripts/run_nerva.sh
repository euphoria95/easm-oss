#!/usr/bin/env bash
set -euo pipefail

# run_nerva.sh — Service fingerprinting via nerva
#
# Input:  ports.jsonl (naabu output: {"host":"x.x.x.x","port":22,...})
#         dns.jsonl   (dnsx output, optional — enables fqdn:port targeting)
# Output: nerva.jsonl (one fingerprint record per host:port)
#
# Usage: ./scripts/run_nerva.sh <ports.jsonl> <output.jsonl> [dns.jsonl]
#
# When dns.jsonl is supplied, targets are resolved to fqdn:port so nerva
# results map directly to FQDN-keyed assets in the normalizer. Falls back
# to ip:port for IPs with no known FQDN.
#
# Nerva flag reference:
#   -w  timeout in milliseconds (NERVA_TIMEOUT env is in seconds; converted below)
#   -W  concurrent workers
#   -U  enable UDP plugins
#   -f  fast mode (default ports only)
#   -v  verbose stderr output

PORTS_JSONL="${1:?Usage: run_nerva.sh <ports.jsonl> <output.jsonl> [dns.jsonl]}"
OUTPUT_JSONL="${2:?Usage: run_nerva.sh <ports.jsonl> <output.jsonl> [dns.jsonl]}"
DNS_JSONL="${3:-}"

NERVA_TIMEOUT="${NERVA_TIMEOUT:-10}"        # seconds; converted to ms below
NERVA_THREADS="${NERVA_THREADS:-50}"
NERVA_FAST_MODE="${NERVA_FAST_MODE:-false}"
NERVA_UDP="${NERVA_UDP:-false}"
NERVA_VERBOSE="${NERVA_VERBOSE:-false}"
NERVA_MISCONFIGS="${NERVA_MISCONFIGS:-false}"

if [[ ! -f "${PORTS_JSONL}" ]]; then
    echo "ERROR: ports file not found: ${PORTS_JSONL}" >&2
    exit 1
fi

# Build target list: fqdn:port when dns.jsonl available, else ip:port
if [[ -n "${DNS_JSONL}" && -f "${DNS_JSONL}" ]]; then
    TARGETS=$(jq -rs \
        --slurpfile dns "${DNS_JSONL}" \
        '($dns | map(.host as $f | (.a // [])[] | {(.): $f}) | add // {}) as $ip_map |
         .[] |
         (($ip_map[(.host // .ip)] // (.host // .ip))) as $h |
         "\($h):\(.port)"' \
        "${PORTS_JSONL}" 2>/dev/null | sort -u)
    echo "nerva: FQDN-resolved targets from ${DNS_JSONL}" >&2
else
    TARGETS=$(jq -r '"\(.host // .ip):\(.port)"' "${PORTS_JSONL}" 2>/dev/null | sort -u)
fi

if [[ -z "${TARGETS}" ]]; then
    echo "WARN: No targets extracted from ${PORTS_JSONL}" >&2
    > "${OUTPUT_JSONL}"
    exit 0
fi

TARGET_COUNT=$(echo "${TARGETS}" | wc -l | tr -d ' ')
echo "nerva: scanning ${TARGET_COUNT} targets (timeout=${NERVA_TIMEOUT}s, workers=${NERVA_THREADS})" >&2

TIMEOUT_MS=$(( NERVA_TIMEOUT * 1000 ))

CMD=(nerva
    -w "${TIMEOUT_MS}"
    -W "${NERVA_THREADS}"
    --json
)

[[ "${NERVA_FAST_MODE}" == "true" ]]  && CMD+=(-f)
[[ "${NERVA_UDP}" == "true" ]]        && CMD+=(-U)
[[ "${NERVA_VERBOSE}" == "true" ]]    && CMD+=(-v)
[[ "${NERVA_MISCONFIGS}" == "true" ]] && CMD+=(--misconfigs)

echo "${TARGETS}" | "${CMD[@]}" > "${OUTPUT_JSONL}" 2>/dev/null

RESULT_COUNT=$(wc -l < "${OUTPUT_JSONL}" | tr -d ' ')
echo "nerva: complete — ${RESULT_COUNT} fingerprints" >&2
