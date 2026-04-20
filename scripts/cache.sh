#!/usr/bin/env bash
# =============================================================================
# EASM Pipeline — Cache Manager
# Manages on-disk cache for pipeline stage outputs.
# Allows skipping stages when cached data is fresh.
#
# Usage:
#   ./cache.sh check dns dns.jsonl 86400   # Check if cache is fresh (exit 0=fresh)
#   ./cache.sh store dns dns.jsonl         # Store current file as cached
#   ./cache.sh clear                       # Clear all cache
#   ./cache.sh status                      # Show cache status
# =============================================================================
set -euo pipefail

CACHE_DIR="${CACHE_DIR:-data/cache}"
mkdir -p "${CACHE_DIR}"

cmd="${1:-status}"
shift || true

case "${cmd}" in
    check)
        STAGE="${1:?stage required}"
        FILE="${2:?file required}"
        TTL="${3:-86400}"

        CACHE_FILE="${CACHE_DIR}/${STAGE}.jsonl"
        if [[ ! -f "${CACHE_FILE}" ]]; then
            exit 1  # No cache
        fi

        # Check age
        if [[ "$(uname)" == "Darwin" ]]; then
            FILE_AGE=$(( $(date +%s) - $(stat -f %m "${CACHE_FILE}") ))
        else
            FILE_AGE=$(( $(date +%s) - $(stat -c %Y "${CACHE_FILE}") ))
        fi

        if [[ ${FILE_AGE} -lt ${TTL} ]]; then
            echo "Cache hit: ${STAGE} (age: ${FILE_AGE}s, ttl: ${TTL}s)"
            # Copy cache to expected location
            cp "${CACHE_FILE}" "${FILE}"
            exit 0
        else
            echo "Cache expired: ${STAGE} (age: ${FILE_AGE}s, ttl: ${TTL}s)"
            exit 1
        fi
        ;;
    store)
        STAGE="${1:?stage required}"
        FILE="${2:?file required}"
        if [[ -f "${FILE}" ]]; then
            cp "${FILE}" "${CACHE_DIR}/${STAGE}.jsonl"
            echo "Cached: ${STAGE}"
        fi
        ;;
    clear)
        rm -f "${CACHE_DIR}"/*.jsonl
        echo "Cache cleared"
        ;;
    status)
        echo "=== Cache Status ==="
        for f in "${CACHE_DIR}"/*.jsonl; do
            [[ -f "$f" ]] || continue
            NAME=$(basename "$f" .jsonl)
            SIZE=$(du -h "$f" | cut -f1)
            if [[ "$(uname)" == "Darwin" ]]; then
                AGE=$(( $(date +%s) - $(stat -f %m "$f") ))
            else
                AGE=$(( $(date +%s) - $(stat -c %Y "$f") ))
            fi
            LINES=$(wc -l < "$f" | tr -d ' ')
            echo "  ${NAME}: ${SIZE}, ${LINES} lines, age ${AGE}s"
        done
        ;;
    *)
        echo "Usage: $0 {check|store|clear|status}" >&2
        exit 1
        ;;
esac
