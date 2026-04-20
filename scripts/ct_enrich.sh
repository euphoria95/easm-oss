#!/usr/bin/env bash
# =============================================================================
# EASM Pipeline — CT Log Enrichment (standalone)
# Queries crt.sh for Certificate Transparency logs and extracts SANs.
#
# Usage: ./ct_enrich.sh example.com [example.org ...]
# Output: prints unique subdomains to stdout
# =============================================================================
set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <domain1> [domain2 ...]" >&2
    exit 1
fi

TMPFILE=$(mktemp)
trap 'rm -f "${TMPFILE}"' EXIT

for domain in "$@"; do
    echo "Querying crt.sh for *.${domain}" >&2
    curl -sf --max-time 30 \
        "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null \
        | jq -r '.[].name_value // empty' \
        | tr ',' '\n' \
        | sed 's/^\*\.//' \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "\.${domain//./\\.}$" \
        >> "${TMPFILE}" || echo "WARN: crt.sh failed for ${domain}" >&2
    # Be polite to crt.sh
    sleep 1
done

sort -u "${TMPFILE}"
