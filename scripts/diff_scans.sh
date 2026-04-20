#!/usr/bin/env bash
# =============================================================================
# EASM Pipeline — Diff Report Between Scans
# Compares two scan outputs and reports new/changed/removed assets.
#
# Usage: ./diff_scans.sh data/output/assets_prev.jsonl data/output/assets.jsonl
# =============================================================================
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <previous_assets.jsonl> <current_assets.jsonl>" >&2
    exit 1
fi

PREV="$1"
CURR="$2"

if [[ ! -f "${PREV}" ]] || [[ ! -f "${CURR}" ]]; then
    echo "ERROR: Both files must exist" >&2
    exit 1
fi

echo "=== EASM Scan Diff ==="
echo "Previous: ${PREV}"
echo "Current:  ${CURR}"
echo ""

# Extract FQDN lists
PREV_FQDNS=$(jq -r '.fqdn' "${PREV}" | sort -u)
CURR_FQDNS=$(jq -r '.fqdn' "${CURR}" | sort -u)

# New assets (in current but not previous)
NEW=$(comm -13 <(echo "${PREV_FQDNS}") <(echo "${CURR_FQDNS}"))
NEW_COUNT=$(echo "${NEW}" | grep -c . || true)

# Removed assets (in previous but not current)
REMOVED=$(comm -23 <(echo "${PREV_FQDNS}") <(echo "${CURR_FQDNS}"))
REMOVED_COUNT=$(echo "${REMOVED}" | grep -c . || true)

# Common assets
COMMON=$(comm -12 <(echo "${PREV_FQDNS}") <(echo "${CURR_FQDNS}"))
COMMON_COUNT=$(echo "${COMMON}" | grep -c . || true)

echo "--- Summary ---"
echo "Previous total: $(echo "${PREV_FQDNS}" | wc -l | tr -d ' ')"
echo "Current total:  $(echo "${CURR_FQDNS}" | wc -l | tr -d ' ')"
echo "New assets:     ${NEW_COUNT}"
echo "Removed assets: ${REMOVED_COUNT}"
echo "Common:         ${COMMON_COUNT}"
echo ""

if [[ ${NEW_COUNT} -gt 0 ]]; then
    echo "--- New Assets ---"
    echo "${NEW}"
    echo ""
fi

if [[ ${REMOVED_COUNT} -gt 0 ]]; then
    echo "--- Removed Assets ---"
    echo "${REMOVED}"
    echo ""
fi

# New open ports on existing assets
echo "--- New Port Openings on Existing Assets ---"
while IFS= read -r fqdn; do
    [[ -z "${fqdn}" ]] && continue
    PREV_PORTS=$(jq -r "select(.fqdn==\"${fqdn}\") | .network.open_ports[]?.port // empty" "${PREV}" 2>/dev/null | sort -n -u)
    CURR_PORTS=$(jq -r "select(.fqdn==\"${fqdn}\") | .network.open_ports[]?.port // empty" "${CURR}" 2>/dev/null | sort -n -u)
    NEW_PORTS=$(comm -13 <(echo "${PREV_PORTS}") <(echo "${CURR_PORTS}") | tr '\n' ',' | sed 's/,$//')
    if [[ -n "${NEW_PORTS}" ]]; then
        echo "  ${fqdn}: +ports ${NEW_PORTS}"
    fi
done <<< "${COMMON}"

echo ""
echo "--- New Findings ---"
# Compare finding counts
PREV_FINDINGS=$(jq -r 'select(.findings | length > 0) | .fqdn + " " + (.findings | length | tostring)' "${PREV}" | sort)
CURR_FINDINGS=$(jq -r 'select(.findings | length > 0) | .fqdn + " " + (.findings | length | tostring)' "${CURR}" | sort)
diff <(echo "${PREV_FINDINGS}") <(echo "${CURR_FINDINGS}") || true
