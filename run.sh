#!/usr/bin/env bash
# =============================================================================
# EASM Pipeline Orchestrator
# =============================================================================
# Funnel-based EASM discovery pipeline:
#   subfinder → CT → DNS → ASN → cdncheck → Port Scan → HTTP Probe
#   → waf-detect → TLS → nerva → Nuclei → Normalize → DuckDB
#
# Usage:
#   ./run.sh                          # full pipeline
#   ./run.sh --stage dns              # run single stage
#   ./run.sh --stage dns,ports        # run multiple stages
#   ROOT_DOMAINS=example.com ./run.sh # also enrich targets via subfinder + CT logs (crt.sh)
#   ./run.sh --dry-run                # print what would run
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths & defaults
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/config"
ENV_FILE="${CONFIG_DIR}/pipeline.env"
RESOLVERS="${CONFIG_DIR}/resolvers.txt"
NUCLEI_CONFIG="${CONFIG_DIR}/nuclei-config.yaml"

# Source configuration
if [[ -f "${ENV_FILE}" ]]; then
    set -a
    # shellcheck source=config/pipeline.env
    source "${ENV_FILE}"
    set +a
fi

# Resolve paths relative to SCRIPT_DIR
INPUT_SUBDOMAINS_VALUE="${INPUT_SUBDOMAINS_OVERRIDE:-${INPUT_SUBDOMAINS:-data/input/subdomains.txt}}"
CMDB_EXPORT_VALUE="${CMDB_EXPORT_OVERRIDE:-${CMDB_EXPORT:-data/input/cmdb_export.csv}}"
OUTPUT_DIR_VALUE="${OUTPUT_DIR_OVERRIDE:-${OUTPUT_DIR:-data/output}}"
SCREENSHOT_DIR_VALUE="${SCREENSHOT_DIR_OVERRIDE:-${SCREENSHOT_DIR:-data/screenshots}}"
CACHE_DIR_VALUE="${CACHE_DIR_OVERRIDE:-${CACHE_DIR:-data/cache}}"
LOG_DIR_VALUE="${LOG_DIR_OVERRIDE:-${LOG_DIR:-logs}}"
DUCKDB_PATH_VALUE="${DUCKDB_PATH_OVERRIDE:-${DUCKDB_PATH:-data/output/easm.duckdb}}"
ROOT_DOMAINS="${ROOT_DOMAINS_OVERRIDE:-${ROOT_DOMAINS:-}}"

INPUT_SUBDOMAINS="${SCRIPT_DIR}/${INPUT_SUBDOMAINS_VALUE}"
CMDB_EXPORT="${SCRIPT_DIR}/${CMDB_EXPORT_VALUE}"
OUTPUT_DIR="${SCRIPT_DIR}/${OUTPUT_DIR_VALUE}"
SCREENSHOT_DIR="${SCRIPT_DIR}/${SCREENSHOT_DIR_VALUE}"
CACHE_DIR="${SCRIPT_DIR}/${CACHE_DIR_VALUE}"
LOG_DIR="${SCRIPT_DIR}/${LOG_DIR_VALUE}"

# Output files
TARGETS_FILE="${OUTPUT_DIR}/targets.txt"
DNS_JSONL="${OUTPUT_DIR}/dns.jsonl"
LIVE_HOSTS="${OUTPUT_DIR}/live_hosts.txt"
PORTS_JSONL="${OUTPUT_DIR}/ports.jsonl"
WEB_TARGETS="${OUTPUT_DIR}/web_targets.txt"
HTTPX_JSONL="${OUTPUT_DIR}/httpx.jsonl"
TLS_JSONL="${OUTPUT_DIR}/tls.jsonl"
NUCLEI_JSONL="${OUTPUT_DIR}/nuclei.jsonl"
ASSETS_JSONL="${OUTPUT_DIR}/assets.jsonl"
DUCKDB_PATH="${SCRIPT_DIR}/${DUCKDB_PATH_VALUE}"
ZGRAB_DIR="${OUTPUT_DIR}/zgrab"
NERVA_JSONL="${OUTPUT_DIR}/nerva.jsonl"
SERVICE_DETECT_JSONL="${OUTPUT_DIR}/service_detection.jsonl"
VERIFY_JSONL="${OUTPUT_DIR}/takeover_verifications.jsonl"
IP_TARGETS="${OUTPUT_DIR}/ip_targets.txt"
FQDN_TARGETS="${OUTPUT_DIR}/fqdn_targets.txt"
ASN_JSONL="${OUTPUT_DIR}/asn.jsonl"
RDNS_JSONL="${OUTPUT_DIR}/rdns.jsonl"
AIMAP_JSONL="${OUTPUT_DIR}/aimap.jsonl"
CLOUD_ENUM_JSONL="${OUTPUT_DIR}/cloud_enum.jsonl"
CT_SUBDOMAINS="${OUTPUT_DIR}/ct_subdomains.txt"
SUBFINDER_JSONL="${OUTPUT_DIR}/subfinder.jsonl"
SUBFINDER_SUBDOMAINS="${OUTPUT_DIR}/subfinder_subdomains.txt"
CDNCHECK_JSONL="${OUTPUT_DIR}/cdncheck.jsonl"
WAF_JSONL="${OUTPUT_DIR}/waf.jsonl"
SUBFINDER_PROVIDER_CONFIG="${CONFIG_DIR}/subfinder-provider-config.yaml"

SCAN_ID="$(date -u +%Y%m%d_%H%M%S)"
SCAN_LOG="${LOG_DIR}/scan_${SCAN_ID}.log"
SCAN_MARKER="${OUTPUT_DIR}/scan_id.txt"

# CLI args
STAGE_ORDER="subfinder,ct,dns,asn,rdns,cdn,ports,http,waf,tls,fingerprint,nuclei,cloud_enum,aimap,normalize,load,verify,scope"
STAGE_FILTER=""
FROM_STAGE=""
DRY_RUN=false
DEBUG_MODE=${DEBUG_MODE:-false}
PIPELINE_MODE="${PIPELINE_MODE:-recon}"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --)             shift ;;
        --stage)        STAGE_FILTER="$2"; shift 2 ;;
        --from)         FROM_STAGE="$2"; shift 2 ;;
        --mode)         PIPELINE_MODE="$2"; shift 2 ;;
        --dry-run)      DRY_RUN=true; shift ;;
        --debug)        DEBUG_MODE=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--stage STAGE1,STAGE2 | --from STAGE] [--mode recon|bounty|livecheck] [--dry-run] [--debug]"
            echo ""
            echo "  --stage STAGES  Run only the specified comma-separated stages"
            echo "  --from  STAGE   Run from STAGE through the end of the pipeline"
            echo "  --mode  MODE    Pipeline mode: recon (default), bounty, or livecheck"
            echo "  --debug         Enable debug mode (detailed timing and diagnostics)"
            echo ""
            echo "Stages (in order): ${STAGE_ORDER}"
            exit 0 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# Backward-compat: --stage zgrab / --from zgrab → fingerprint
STAGE_FILTER="${STAGE_FILTER//zgrab/fingerprint}"
[[ "${FROM_STAGE}" == "zgrab" ]] && FROM_STAGE="fingerprint"

# ---------------------------------------------------------------------------
# Resolve --from STAGE → STAGE_FILTER covering STAGE..end
# ---------------------------------------------------------------------------
if [[ -n "${FROM_STAGE}" ]]; then
    if [[ -n "${STAGE_FILTER}" ]]; then
        echo "ERROR: --from and --stage are mutually exclusive"
        exit 1
    fi
    _found=false
    _filter=""
    IFS=',' read -ra _STAGES <<< "${STAGE_ORDER}"
    for _s in "${_STAGES[@]}"; do
        if [[ "${_s}" == "${FROM_STAGE}" ]]; then
            _found=true
        fi
        if ${_found}; then
            _filter="${_filter:+${_filter},}${_s}"
        fi
    done
    if ! ${_found}; then
        echo "ERROR: Unknown stage '${FROM_STAGE}'"
        echo "Valid stages: ${STAGE_ORDER}"
        exit 1
    fi
    STAGE_FILTER="${_filter}"
fi

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
mkdir -p "${OUTPUT_DIR}" "${SCREENSHOT_DIR}" "${CACHE_DIR}" "${LOG_DIR}" "${ZGRAB_DIR}"

log() {
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "[${ts}] $*" | tee -a "${SCAN_LOG}"
}

log_stage() {
    log "========== STAGE: $1 =========="
}

count_lines() {
    if [[ -f "$1" ]]; then wc -l < "$1" | tr -d ' '; else echo "0"; fi
}

should_run() {
    local stage="$1"
    if [[ -z "${STAGE_FILTER}" ]]; then return 0; fi
    echo ",${STAGE_FILTER}," | grep -q ",${stage},"
}

elapsed() {
    local start=$1
    local end
    end=$(date +%s)
    echo $(( end - start ))
}

# ---------------------------------------------------------------------------
# Debug mode helpers
# ---------------------------------------------------------------------------
declare -a DEBUG_STAGE_NAMES=()
declare -a DEBUG_STAGE_DURATIONS=()

debug_log() {
    if [[ "${DEBUG_MODE}" == "true" ]]; then
        local ts
        ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "[DEBUG ${ts}] $*" | tee -a "${SCAN_LOG}"
    fi
}

debug_stage_start() {
    if [[ "${DEBUG_MODE}" == "true" ]]; then
        local stage_name="$1"
        debug_log ">>> Stage '${stage_name}' starting"
        debug_log "    Memory: $(ps -o rss= -p $$ | awk '{printf "%.1f MB", $1/1024}')"
    fi
}

debug_stage_end() {
    if [[ "${DEBUG_MODE}" == "true" ]]; then
        local stage_name="$1"
        local duration="$2"
        local detail="${3:-}"
        DEBUG_STAGE_NAMES+=("${stage_name}")
        DEBUG_STAGE_DURATIONS+=("${duration}")
        debug_log "<<< Stage '${stage_name}' finished in ${duration}s ${detail}"
    fi
}

debug_substep() {
    if [[ "${DEBUG_MODE}" == "true" ]]; then
        local msg="$1"
        debug_log "    ↳ ${msg}"
    fi
}

debug_summary() {
    if [[ "${DEBUG_MODE}" != "true" ]]; then return; fi
    log ""
    log "==================== DEBUG: TIMING SUMMARY ===================="
    log ""
    printf "[%s] %-22s %10s %8s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "STAGE" "DURATION" "% TOTAL" | tee -a "${SCAN_LOG}"
    printf "[%s] %-22s %10s %8s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(printf '%0.s-' {1..22})" "$(printf '%0.s-' {1..10})" "$(printf '%0.s-' {1..8})" | tee -a "${SCAN_LOG}"
    local total_elapsed=$1
    for i in "${!DEBUG_STAGE_NAMES[@]}"; do
        local name="${DEBUG_STAGE_NAMES[$i]}"
        local dur="${DEBUG_STAGE_DURATIONS[$i]}"
        local pct=0
        if [[ "${total_elapsed}" -gt 0 ]]; then
            pct=$(( dur * 100 / total_elapsed ))
        fi
        printf "[%s] %-22s %9ss %7s%%\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${name}" "${dur}" "${pct}" | tee -a "${SCAN_LOG}"
    done
    log ""
    log "Total pipeline duration: ${total_elapsed}s"
    log "==============================================================="
}

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
log "EASM Pipeline started | scan_id=${SCAN_ID}"
if [[ "${DEBUG_MODE}" == "true" ]]; then
    log "DEBUG MODE enabled — detailed timing and diagnostics will be logged"
fi

BOUNTY_REPORT_JSONL="${OUTPUT_DIR}/bounty_report.jsonl"
LIVECHECK_JSONL="${OUTPUT_DIR}/livecheck_report.jsonl"
LIVECHECK_STATE="${OUTPUT_DIR}/livecheck_state.json"

# ---------------------------------------------------------------------------
# Bounty mode overrides
# ---------------------------------------------------------------------------
if [[ "${PIPELINE_MODE}" == "bounty" ]]; then
    log "BOUNTY MODE — expanded scanning configuration"
    NAABU_TOP_PORTS=1000
    NAABU_EXCLUDE_CDN=false
    NERVA_MISCONFIGS=true
    NERVA_UDP=true
    NERVA_FAST_MODE=false
    NUCLEI_CONFIG="${CONFIG_DIR}/nuclei-bounty.yaml"
fi

# ---------------------------------------------------------------------------
# Livecheck mode overrides — DNS-only pass for CMDB scope governance
# ---------------------------------------------------------------------------
if [[ "${PIPELINE_MODE}" == "livecheck" ]]; then
    log "LIVECHECK MODE — lightweight DNS-only CMDB scope validation"
    # If no explicit --stage filter, restrict to DNS + enrichment + livecheck stages
    if [[ -z "${STAGE_FILTER}" ]]; then
        STAGE_FILTER="dns,asn,rdns,cdn,normalize,load"
    fi
fi

if ${DRY_RUN}; then
    log "DRY RUN — printing stages that would execute"
    [[ -n "${FROM_STAGE}" ]] && log "Resuming from: ${FROM_STAGE} (resolved to: ${STAGE_FILTER})"
    IFS=',' read -ra _DRY_STAGES <<< "${STAGE_ORDER}"
    for s in "${_DRY_STAGES[@]}"; do
        if should_run "$s"; then echo "  Would run: $s"; fi
    done
    exit 0
fi

PIPELINE_START=$(date +%s)

# ---------------------------------------------------------------------------
# Scan isolation: archive orphaned outputs from any previous run, then write
# the current scan marker.  Skipped for --stage / --from (resume runs).
# ---------------------------------------------------------------------------
if [[ -z "${STAGE_FILTER}" ]] && [[ -z "${FROM_STAGE}" ]]; then
    if [[ -f "${SCAN_MARKER}" ]]; then
        ORPHAN_ID=$(tr -d '[:space:]' < "${SCAN_MARKER}")
        if [[ -n "${ORPHAN_ID}" ]]; then
            ORPHAN_COUNT=0
            for _f in "${DNS_JSONL}" "${PORTS_JSONL}" "${HTTPX_JSONL}" "${ASSETS_JSONL}"; do
                [[ -f "${_f}" ]] && ORPHAN_COUNT=$(( ORPHAN_COUNT + 1 ))
            done
            if [[ "${ORPHAN_COUNT}" -gt 0 ]]; then
                log "Archiving orphaned outputs from previous run: ${ORPHAN_ID}"
                python3 "${SCRIPT_DIR}/scripts/archive_scan.py" \
                    --archive-raw \
                    --scan-id "${ORPHAN_ID}" \
                    --output-dir "${OUTPUT_DIR}" \
                    --screenshot-dir "${SCREENSHOT_DIR}" \
                    --log-file "${LOG_DIR}/scan_${ORPHAN_ID}.log" \
                    --archive-dir "${SCRIPT_DIR}/data/archives" \
                    --status "partial" 2>>"${SCAN_LOG}" || \
                    log "WARN: Orphan archive failed — cleaning output directory anyway"
                # Guarantee clean slate even if archive failed mid-move
                rm -f "${TARGETS_FILE}" "${IP_TARGETS}" "${FQDN_TARGETS}" \
                      "${ASN_JSONL}" "${RDNS_JSONL}" "${DNS_JSONL}" "${LIVE_HOSTS}" "${AIMAP_JSONL}" \
                      "${PORTS_JSONL}" "${WEB_TARGETS}" "${HTTPX_JSONL}" \
                      "${TLS_JSONL}" "${NERVA_JSONL}" "${SERVICE_DETECT_JSONL}" \
                      "${NUCLEI_JSONL}" "${ASSETS_JSONL}" "${VERIFY_JSONL}" "${CLOUD_ENUM_JSONL}" \
                      "${CT_SUBDOMAINS}" "${SUBFINDER_JSONL}" "${SUBFINDER_SUBDOMAINS}" \
                      "${CDNCHECK_JSONL}" "${WAF_JSONL}"
                mkdir -p "${ZGRAB_DIR}"
            fi
        fi
    fi
    echo "${SCAN_ID}" > "${SCAN_MARKER}"
fi

if [[ ! -f "${INPUT_SUBDOMAINS}" ]]; then
    log "No input file found: ${INPUT_SUBDOMAINS} — nothing to scan"
    exit 0
fi
log "Input: ${INPUT_SUBDOMAINS} ($(count_lines "${INPUT_SUBDOMAINS}") subdomains)"

# Build normalized targets (lowercase, deduplicated)
if [[ ! -f "${TARGETS_FILE}" ]]; then
    tr '[:upper:]' '[:lower:]' < "${INPUT_SUBDOMAINS}" \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
        | grep -v '^$' \
        | sort -u > "${TARGETS_FILE}"
fi

# ===========================================================================
# STAGE 0: Passive enrichment — subfinder (passive sources)
#   Same opt-in as CT: only runs when ROOT_DOMAINS is set, and only names
#   under those domains are added. crt.sh is excluded here because the ct
#   stage already owns it. Skipped in livecheck mode.
# ===========================================================================
if should_run "subfinder" && [[ "${PIPELINE_MODE}" != "livecheck" ]]; then
    log_stage "PASSIVE SUBDOMAIN ENUMERATION (subfinder)"
    stage_start=$(date +%s)
    debug_stage_start "subfinder"

    rm -f "${SUBFINDER_JSONL}" "${SUBFINDER_SUBDOMAINS}"
    if [[ -z "${ROOT_DOMAINS// /}" ]]; then
        log "ROOT_DOMAINS not set — skipping subfinder"
        debug_stage_end "subfinder" "$(elapsed ${stage_start})" "(skipped)"
    else
        SUBFINDER_DOMAINS_FILE="${OUTPUT_DIR}/_subfinder_domains.txt"
        echo "${ROOT_DOMAINS}" | tr ', ' '\n\n' | tr '[:upper:]' '[:lower:]' \
            | sed 's/^\*\.//;s/\.$//' | grep -v '^$' | sort -u > "${SUBFINDER_DOMAINS_FILE}"

        SUBFINDER_ARGS=(
            -dL "${SUBFINDER_DOMAINS_FILE}"
            -oJ -cs -silent -duc
            -es crtsh
            -timeout "${SUBFINDER_TIMEOUT:-30}"
            -max-time "${SUBFINDER_MAX_TIME:-10}"
            -t "${SUBFINDER_THREADS:-10}"
        )
        [[ "${SUBFINDER_ALL:-false}" == "true" ]] && SUBFINDER_ARGS+=(-all)
        [[ -f "${SUBFINDER_PROVIDER_CONFIG}" ]] && SUBFINDER_ARGS+=(-pc "${SUBFINDER_PROVIDER_CONFIG}")

        timeout "${SUBFINDER_TOTAL_TIMEOUT:-900}" subfinder "${SUBFINDER_ARGS[@]}" \
            2>>"${SCAN_LOG}" > "${SUBFINDER_JSONL}" || \
            log "WARN: subfinder exited non-zero — continuing with partial results"

        # Scope filter: keep only the root domains themselves or names under them
        jq -r --rawfile roots "${SUBFINDER_DOMAINS_FILE}" '
            ($roots | split("\n") | map(select(length > 0))) as $r
            | (.host // "" | ascii_downcase | rtrimstr(".")) as $h
            | select($h != "" and any($r[]; . as $d | $h == $d or ($h | endswith("." + $d))))
            | $h
        ' "${SUBFINDER_JSONL}" 2>>"${SCAN_LOG}" | sort -u > "${SUBFINDER_SUBDOMAINS}" || true
        rm -f "${SUBFINDER_DOMAINS_FILE}"

        INPUT_COUNT=$(count_lines "${TARGETS_FILE}")
        if [[ -s "${SUBFINDER_SUBDOMAINS}" ]]; then
            cat "${TARGETS_FILE}" "${SUBFINDER_SUBDOMAINS}" | sort -u > "${TARGETS_FILE}.merged"
            mv "${TARGETS_FILE}.merged" "${TARGETS_FILE}"
        fi
        TOTAL_COUNT=$(count_lines "${TARGETS_FILE}")
        SUBFINDER_ADDED=$(( TOTAL_COUNT - INPUT_COUNT ))
        debug_substep "subfinder: input=${INPUT_COUNT} found=$(count_lines "${SUBFINDER_SUBDOMAINS}") added=${SUBFINDER_ADDED}"
        debug_stage_end "subfinder" "$(elapsed ${stage_start})"
        log "subfinder complete | input=${INPUT_COUNT} found=$(count_lines "${SUBFINDER_SUBDOMAINS}") added=${SUBFINDER_ADDED} total=${TOTAL_COUNT} elapsed=$(elapsed ${stage_start})s"
    fi
fi

# ===========================================================================
# STAGE 0.5: Passive enrichment — Certificate Transparency logs (crt.sh)
#   Opt-in: only queries the root domains listed in ROOT_DOMAINS, and only
#   names under those domains are added. Skipped in livecheck mode (which
#   validates the registered CMDB FQDNs, not newly discovered ones).
# ===========================================================================
if should_run "ct" && [[ "${PIPELINE_MODE}" != "livecheck" ]]; then
    log_stage "CT LOG ENRICHMENT (crt.sh)"
    stage_start=$(date +%s)
    debug_stage_start "ct"

    if [[ -z "${ROOT_DOMAINS// /}" ]]; then
        log "ROOT_DOMAINS not set — skipping CT enrichment"
        rm -f "${CT_SUBDOMAINS}"   # don't let a previous scan's CT list get tagged onto this one
        debug_stage_end "ct" "$(elapsed ${stage_start})" "(skipped)"
    else
        rm -f "${CT_SUBDOMAINS}"
        INPUT_COUNT=$(count_lines "${TARGETS_FILE}")
        python3 "${SCRIPT_DIR}/scripts/ct_enrich.py" \
            --domains "${ROOT_DOMAINS}" \
            --existing "${TARGETS_FILE}" \
            --output "${CT_SUBDOMAINS}" \
            --timeout "${CT_TIMEOUT:-60}" \
            --retries "${CT_RETRIES:-3}" \
            --user-agent "${USER_AGENT:-EASM-Pipeline/0.1}" 2>>"${SCAN_LOG}" || \
            log "WARN: CT enrichment failed — continuing with input targets only"

        if [[ -s "${CT_SUBDOMAINS}" ]]; then
            cat "${TARGETS_FILE}" "${CT_SUBDOMAINS}" | sort -u > "${TARGETS_FILE}.merged"
            mv "${TARGETS_FILE}.merged" "${TARGETS_FILE}"
        fi
        TOTAL_COUNT=$(count_lines "${TARGETS_FILE}")
        CT_ADDED=$(( TOTAL_COUNT - INPUT_COUNT ))
        debug_substep "CT: input=${INPUT_COUNT} added=${CT_ADDED} total=${TOTAL_COUNT}"
        debug_stage_end "ct" "$(elapsed ${stage_start})"
        log "CT enrichment complete | input=${INPUT_COUNT} ct_added=${CT_ADDED} total=${TOTAL_COUNT} elapsed=$(elapsed ${stage_start})s"
    fi
fi

# Partition targets into FQDNs and IPs (including CIDR ranges)
grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' "${TARGETS_FILE}" > "${IP_TARGETS}" || true
grep -vE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' "${TARGETS_FILE}" > "${FQDN_TARGETS}" || true

# Expand CIDRs in IP_TARGETS
if [[ -s "${IP_TARGETS}" ]]; then
    python3 -c "
import ipaddress, sys
for line in open(sys.argv[1]):
    line = line.strip()
    if '/' in line:
        for ip in ipaddress.ip_network(line, strict=False).hosts():
            print(ip)
    elif line:
        print(line)
" "${IP_TARGETS}" > "${IP_TARGETS}.expanded"
    mv "${IP_TARGETS}.expanded" "${IP_TARGETS}"
fi

log "Targets: fqdns=$(count_lines "${FQDN_TARGETS}") ips=$(count_lines "${IP_TARGETS}")"

# ===========================================================================
# STAGE 1: DNS Resolution (dnsx)
# ===========================================================================
if should_run "dns"; then
    log_stage "DNS RESOLUTION (dnsx)"
    stage_start=$(date +%s)
    debug_stage_start "dns"

    # Remove stale output
    rm -f "${DNS_JSONL}"

    # Use stdin pipe instead of -l/-o flags — dnsx 1.2.3 hangs with -l FILE on
    # large inputs (>100 hosts) combined with multi-record-type queries.
    cat "${FQDN_TARGETS}" | dnsx \
        -a -aaaa -cname -ns -mx -resp \
        -r "${RESOLVERS}" \
        -rate-limit "${DNS_RATE_LIMIT:-500}" \
        -retry "${DNS_RETRIES:-2}" \
        -silent -json \
        2>>"${SCAN_LOG}" > "${DNS_JSONL}" || {
        log "ERROR: dnsx failed (exit $?) — aborting DNS stage"
        exit 1
    }

    debug_substep "dnsx completed: input=$(count_lines "${FQDN_TARGETS}") output=$(count_lines "${DNS_JSONL}")"

    # Extract live hostnames — only FQDNs that actually resolved (have A or AAAA records)
    # Excluding NXDOMAIN/SOA-only entries prevents naabu from failing with "no valid targets"
    jq -r 'select(((.a // []) | length > 0) or ((.aaaa // []) | length > 0)) | .host' "${DNS_JSONL}" | sort -u > "${LIVE_HOSTS}"

    # Merge direct IP targets into live hosts
    if [[ -s "${IP_TARGETS}" ]]; then
        cat "${IP_TARGETS}" >> "${LIVE_HOSTS}"
        sort -u "${LIVE_HOSTS}" -o "${LIVE_HOSTS}"
    fi

    debug_substep "Live hosts extracted: $(count_lines "${LIVE_HOSTS}") IP merge included"
    debug_stage_end "dns" "$(elapsed ${stage_start})"
    log "DNS complete | resolved=$(count_lines "${LIVE_HOSTS}") elapsed=$(elapsed ${stage_start})s"
fi

# ===========================================================================
# STAGE 1.5: ASN Enrichment (offline, pyasn)
# ===========================================================================
if should_run "asn"; then
    log_stage "ASN ENRICHMENT (pyasn)"
    stage_start=$(date +%s)
    debug_stage_start "asn"

    ASN_DB="${CACHE_DIR}/ipasn.dat"
    ASN_NAMES="${CACHE_DIR}/asn_names.tsv"

    # Bootstrap ASN database if missing or stale (>7 days)
    if [[ ! -f "${ASN_DB}" ]] || [[ $(find "${CACHE_DIR}" -name "ipasn.dat" -mtime +7 2>/dev/null | wc -l) -gt 0 ]]; then
        log "Downloading fresh BGP RIB data..."
        debug_substep "RIB download triggered"
        RIB_FILE="${CACHE_DIR}/rib_latest.bz2"
        pyasn_util_download.py --latest --filename "${RIB_FILE}" 2>>"${SCAN_LOG}" || log "WARN: RIB download failed"
        if [[ -f "${RIB_FILE}" ]]; then
            pyasn_util_convert.py --single "${RIB_FILE}" "${ASN_DB}" 2>>"${SCAN_LOG}" || log "WARN: RIB conversion failed"
            rm -f "${RIB_FILE}"
        fi
    fi

    if [[ -f "${ASN_DB}" ]]; then
        ASN_ARGS=(--ips "${IP_TARGETS}" --asndb "${ASN_DB}" --output "${ASN_JSONL}")
        [[ -f "${DNS_JSONL}" ]] && ASN_ARGS+=(--dns-jsonl "${DNS_JSONL}")
        [[ -f "${ASN_NAMES}" ]] && ASN_ARGS+=(--names "${ASN_NAMES}")

        python3 "${SCRIPT_DIR}/scripts/enrich_asn.py" "${ASN_ARGS[@]}" 2>>"${SCAN_LOG}"
        debug_substep "IPs processed: $(count_lines "${IP_TARGETS}") → ASN records: $(count_lines "${ASN_JSONL}")"
        debug_stage_end "asn" "$(elapsed ${stage_start})"
        log "ASN enrichment complete | ips=$(count_lines "${ASN_JSONL}") elapsed=$(elapsed ${stage_start})s"
    else
        log "WARN: No ASN database available — skipping ASN enrichment"
        debug_stage_end "asn" "$(elapsed ${stage_start})" "(skipped)"
    fi
fi

# ===========================================================================
# STAGE 1.75: Reverse DNS (PTR lookups via dnsx)
# ===========================================================================
if should_run "rdns"; then
    log_stage "REVERSE DNS (dnsx -ptr)"
    stage_start=$(date +%s)
    debug_stage_start "rdns"

    RDNS_INPUT="${OUTPUT_DIR}/rdns_ips.txt"

    # Collect all in-scope IPs: from DNS A records + direct IP targets
    {
        [[ -f "${DNS_JSONL}" ]] && jq -r '.a[]? // empty' "${DNS_JSONL}"
        [[ -f "${IP_TARGETS}" ]] && cat "${IP_TARGETS}"
    } | sort -u > "${RDNS_INPUT}"

    IP_COUNT=$(count_lines "${RDNS_INPUT}")
    if [[ "${IP_COUNT}" -gt 0 ]]; then
        log "Reverse DNS: ${IP_COUNT} IPs"
        debug_substep "IP count: ${IP_COUNT}"
        cat "${RDNS_INPUT}" | dnsx \
            -ptr -resp \
            -r "${RESOLVERS}" \
            -rate-limit "${DNS_RATE_LIMIT:-500}" \
            -retry "${DNS_RETRIES:-2}" \
            -silent -json \
            2>>"${SCAN_LOG}" > "${RDNS_JSONL}"

        debug_substep "PTR records found: $(count_lines "${RDNS_JSONL}")"
        debug_stage_end "rdns" "$(elapsed ${stage_start})"
        log "Reverse DNS complete | records=$(count_lines "${RDNS_JSONL}") elapsed=$(elapsed ${stage_start})s"
    else
        log "WARN: No IPs for reverse DNS"
        debug_stage_end "rdns" "$(elapsed ${stage_start})" "(skipped)"
    fi
    rm -f "${RDNS_INPUT}"
fi

# ===========================================================================
# STAGE 1.9: CDN / Cloud / WAF classification (cdncheck)
#   Matches live FQDNs and IPs against cdncheck's provider IP-range index.
#   Output feeds the multi-signal CDN detector and WAF verdicts in normalize.
# ===========================================================================
if should_run "cdn"; then
    log_stage "CDN/CLOUD/WAF CLASSIFICATION (cdncheck)"
    stage_start=$(date +%s)
    debug_stage_start "cdn"

    rm -f "${CDNCHECK_JSONL}"
    if [[ ! -f "${LIVE_HOSTS}" ]] || [[ $(count_lines "${LIVE_HOSTS}") -eq 0 ]]; then
        log "WARN: No live hosts — skipping cdncheck"
        debug_stage_end "cdn" "$(elapsed ${stage_start})" "(skipped)"
    else
        # cdncheck -r takes a comma-separated list, not a file path — a path is
        # silently treated as one (unusable) resolver and every FQDN lookup fails.
        CDNCHECK_RESOLVERS=$(grep -vE '^[[:space:]]*(#|$)' "${RESOLVERS}" | paste -sd, -)
        CDNCHECK_ARGS=(
            -i "${LIVE_HOSTS}"
            -jsonl -resp -silent -duc -nc
            -retry "${DNS_RETRIES:-2}"
        )
        [[ -n "${CDNCHECK_RESOLVERS}" ]] && CDNCHECK_ARGS+=(-r "${CDNCHECK_RESOLVERS}")
        # -t (threads) exists on cdncheck main but not in release v1.3.3
        if cdncheck -h 2>&1 | grep -qE '(^|[ ,])-t[ ,]'; then
            CDNCHECK_ARGS+=(-t "${CDNCHECK_THREADS:-50}")
        fi
        cdncheck "${CDNCHECK_ARGS[@]}" 2>>"${SCAN_LOG}" > "${CDNCHECK_JSONL}" || \
            log "WARN: cdncheck exited non-zero (partial results may be available)"

        CDN_HITS=$(jq -c 'select(.cdn or .waf)' "${CDNCHECK_JSONL}" 2>/dev/null | wc -l | tr -d ' ')
        debug_substep "cdncheck: input=$(count_lines "${LIVE_HOSTS}") classified=$(count_lines "${CDNCHECK_JSONL}") cdn_or_waf=${CDN_HITS}"
        debug_stage_end "cdn" "$(elapsed ${stage_start})"
        log "cdncheck complete | classified=$(count_lines "${CDNCHECK_JSONL}") cdn_or_waf=${CDN_HITS} elapsed=$(elapsed ${stage_start})s"
    fi
fi

# ===========================================================================
# STAGE 2: Port Scanning (naabu)
# ===========================================================================
if should_run "ports"; then
    log_stage "PORT SCANNING (naabu)"
    stage_start=$(date +%s)
    debug_stage_start "ports"

    if [[ ! -f "${LIVE_HOSTS}" ]] || [[ $(count_lines "${LIVE_HOSTS}") -eq 0 ]]; then
        log "WARN: No live hosts — skipping port scan"
        debug_stage_end "ports" "$(elapsed ${stage_start})" "(skipped)"
    else
        debug_substep "live_hosts input: $(count_lines "${LIVE_HOSTS}")"
        NAABU_ARGS=(
            -l "${LIVE_HOSTS}"
            -rate "${NAABU_RATE:-1000}"
            -c "${NAABU_WORKERS:-25}"
            -retries "${NAABU_RETRIES:-1}"
            -silent -json
            -o "${PORTS_JSONL}"
        )
        if [[ -n "${NAABU_PORTS:-}" ]]; then
            NAABU_ARGS+=(-p "${NAABU_PORTS}")
        else
            NAABU_ARGS+=(-top-ports "${NAABU_TOP_PORTS:-100}")
        fi
        # CDN exclusion disabled by default: for EASM we want to discover web services
        # even on CDN-fronted hosts. Set NAABU_EXCLUDE_CDN=true to override.
        if [[ "${NAABU_EXCLUDE_CDN:-false}" == "true" ]]; then
            NAABU_ARGS+=(-exclude-cdn)
        fi

        naabu "${NAABU_ARGS[@]}" 2>>"${SCAN_LOG}" || {
            log "WARN: naabu port scan failed (non-fatal) — continuing with empty port list"
            echo -n "" > "${PORTS_JSONL}"
        }

        # Build web target list
        WEB_PORTS_PATTERN=$(echo "${WEB_PORTS}" | sed 's/,/|/g')
        jq -r --arg ports "${WEB_PORTS_PATTERN}" \
            'select(.port | tostring | test("^(" + $ports + ")$")) | "\(.host):\(.port)"' \
            "${PORTS_JSONL}" | sort -u > "${WEB_TARGETS}"

        OPEN_PORTS=$(count_lines "${PORTS_JSONL}")
        WEB_COUNT=$(count_lines "${WEB_TARGETS}")
        debug_substep "open_ports: ${OPEN_PORTS} web_targets: ${WEB_COUNT}"
        debug_stage_end "ports" "$(elapsed ${stage_start})"
        log "Port scan complete | open_ports=${OPEN_PORTS} web_targets=${WEB_COUNT} elapsed=$(elapsed ${stage_start})s"
    fi
fi

# ===========================================================================
# STAGE 3: HTTP Probing (httpx)
# ===========================================================================
if should_run "http"; then
    log_stage "HTTP PROBING (httpx)"
    stage_start=$(date +%s)
    debug_stage_start "http"

    # Fallback: if port scan found no web targets but we have live hosts,
    # feed LIVE_HOSTS directly to httpx (it probes 80+443 by default).
    # This handles CDN/WAF hosts that block SYN scans but accept full HTTP connects.
    HTTPX_FALLBACK=false
    if [[ (! -f "${WEB_TARGETS}" || $(count_lines "${WEB_TARGETS}") -eq 0) && -f "${LIVE_HOSTS}" && $(count_lines "${LIVE_HOSTS}") -gt 0 ]]; then
        log "INFO: No web targets from port scan — falling back to LIVE_HOSTS (httpx will probe 80,443)"
        cp "${LIVE_HOSTS}" "${WEB_TARGETS}"
        HTTPX_FALLBACK=true
        debug_substep "Fallback web_targets from LIVE_HOSTS: $(count_lines "${WEB_TARGETS}")"
    fi

    if [[ ! -f "${WEB_TARGETS}" ]] || [[ $(count_lines "${WEB_TARGETS}") -eq 0 ]]; then
        log "WARN: No web targets (and no live hosts) — skipping HTTP probe"
        debug_stage_end "http" "$(elapsed ${stage_start})" "(skipped)"
    else
        debug_substep "web_targets input: $(count_lines "${WEB_TARGETS}")"
        HTTPX_ARGS=(
            -l "${WEB_TARGETS}"
            -sc -cl -ct -location -title -server -td -method -websocket
            -ip -cname -asn -cdn -probe -favicon -jarm
            -hash sha256
            -rt -lc -wc
            -tls-grab -http2
            -follow-redirects
            -include-response-header
            -threads "${HTTPX_THREADS:-50}"
            -rate-limit "${HTTPX_RATE_LIMIT:-150}"
            -timeout "${HTTPX_TIMEOUT:-10}"
            -retries "${HTTPX_RETRIES:-2}"
            -max-host-error "${HTTPX_MAX_HOST_ERROR:-30}"
            -H "User-Agent: ${USER_AGENT}"
            -silent -json
        )

        # When web_targets come from naabu (host:port format), disable fallback probing.
        # When using LIVE_HOSTS fallback (bare FQDNs), let httpx probe both 80 and 443.
        if [[ "${HTTPX_FALLBACK}" != "true" ]]; then
            HTTPX_ARGS+=(-no-fallback)
        fi

        if [[ "${HTTPX_SCREENSHOTS:-true}" == "true" ]]; then
            HTTPX_ARGS+=(-screenshot -system-chrome -srd "${SCREENSHOT_DIR}")
        fi

        # Use stdout pipe (not -o) so partial output survives timeouts.
        # Timeout prevents Chromium/go-rod deadlocks (default 10 min).
        HTTPX_TOTAL_TIMEOUT="${HTTPX_TOTAL_TIMEOUT:-600}"
        timeout "${HTTPX_TOTAL_TIMEOUT}" httpx "${HTTPX_ARGS[@]}" 2>>"${SCAN_LOG}" > "${HTTPX_JSONL}" || {
            httpx_exit=$?
            if [[ ${httpx_exit} -eq 124 ]]; then
                log "WARN: httpx killed after ${HTTPX_TOTAL_TIMEOUT}s timeout (non-fatal)"
            else
                log "WARN: httpx exited with code ${httpx_exit} (non-fatal)"
            fi
        }
        # Ensure output file exists even if httpx produced nothing
        touch "${HTTPX_JSONL}"

        SCREENSHOTS_COUNT=$(find "${SCREENSHOT_DIR}" -name '*.png' 2>/dev/null | wc -l | tr -d ' ')
        debug_substep "httpx output: $(count_lines "${HTTPX_JSONL}") screenshots: ${SCREENSHOTS_COUNT}"
        debug_stage_end "http" "$(elapsed ${stage_start})"
        log "HTTP probe complete | probed=$(count_lines "${HTTPX_JSONL}") screenshots=${SCREENSHOTS_COUNT} elapsed=$(elapsed ${stage_start})s"

        # --- Service detection fallback for unprobed ports ---
        if [[ "${SERVICE_DETECT_FALLBACK:-false}" == "true" ]] && [[ -f "${PORTS_JSONL}" ]] && [[ -f "${HTTPX_JSONL}" ]]; then
            debug_substep "Computing unprobed ports for service detection fallback"

            # Build list of host:port that httpx successfully probed (use temp files, not variables)
            PROBED_SET_FILE="${OUTPUT_DIR}/_probed_set.txt"
            jq -r '
                (.input // ((.host // "") + ":" + ((.port // 443) | tostring))) as $hp |
                if ($hp | contains(":")) then $hp
                else ((.host // "") + ":" + ((.port // 443) | tostring))
                end
            ' "${HTTPX_JSONL}" 2>/dev/null | sort -u > "${PROBED_SET_FILE}"

            # All web target host:port pairs
            ALL_WEB_FILE="${OUTPUT_DIR}/_all_web_sorted.txt"
            sort -u "${WEB_TARGETS}" > "${ALL_WEB_FILE}"

            # Compute unprobed = all_web - probed
            UNPROBED_FILE="${OUTPUT_DIR}/unprobed_targets.txt"
            comm -23 "${ALL_WEB_FILE}" "${PROBED_SET_FILE}" > "${UNPROBED_FILE}"
            rm -f "${PROBED_SET_FILE}" "${ALL_WEB_FILE}"
            UNPROBED_COUNT=$(count_lines "${UNPROBED_FILE}")

            if [[ "${UNPROBED_COUNT}" -gt 0 ]]; then
                log "Service detection fallback: ${UNPROBED_COUNT} unprobed web targets"
                debug_substep "Running naabu -sV on ${UNPROBED_COUNT} targets"

                NAABU_SV_ARGS=(
                    -list "${UNPROBED_FILE}"
                    -rate "${SERVICE_DETECT_RATE:-100}"
                    -retries "${NAABU_RETRIES:-1}"
                    -sV
                    -silent -json
                    -o "${SERVICE_DETECT_JSONL}"
                )

                naabu "${NAABU_SV_ARGS[@]}" 2>>"${SCAN_LOG}" || \
                    log "WARN: naabu service detection had errors"

                log "Service detection complete | detected=$(count_lines "${SERVICE_DETECT_JSONL}") elapsed=$(elapsed ${stage_start})s"
                debug_substep "Service detection: $(count_lines "${SERVICE_DETECT_JSONL}") results"
                rm -f "${UNPROBED_FILE}"
            else
                debug_substep "All web targets successfully probed — no service detection needed"
            fi
        fi
    fi
fi

# ===========================================================================
# STAGE 3.5: WAF Detection (waf-detector)
#   PASSIVE detection only (headers, body, DNS, TLS, timing on normal
#   requests). Never add --payload-analysis, --smoke-test, --effectiveness,
#   or the hardening/va subcommands here — those send attack payloads and are
#   out of scope for EASM recon.
# ===========================================================================
if should_run "waf" && [[ "${PIPELINE_MODE}" != "livecheck" ]]; then
    log_stage "WAF DETECTION (waf-detect)"
    stage_start=$(date +%s)
    debug_stage_start "waf"

    rm -f "${WAF_JSONL}"
    WAF_TARGETS_FILE="${OUTPUT_DIR}/_waf_targets.txt"
    if [[ -f "${HTTPX_JSONL}" ]]; then
        # One URL per scheme://host:port origin
        jq -r 'select(.url != null) | .url | capture("^(?<o>[a-zA-Z]+://[^/?#]+)").o' \
            "${HTTPX_JSONL}" 2>/dev/null | sort -u | head -n "${WAF_MAX_TARGETS:-2000}" > "${WAF_TARGETS_FILE}"
    fi

    if [[ ! -s "${WAF_TARGETS_FILE}" ]]; then
        log "WARN: No HTTP origins — skipping WAF detection"
        debug_stage_end "waf" "$(elapsed ${stage_start})" "(skipped)"
    else
        # waf-detect emits results only when a whole batch finishes and its
        # internal concurrency is fixed at 3, so feed it small chunks in
        # parallel with a per-chunk timeout — a hung chunk loses only itself.
        WAF_SHARD_DIR="${OUTPUT_DIR}/_waf_shards"
        rm -rf "${WAF_SHARD_DIR}" && mkdir -p "${WAF_SHARD_DIR}"
        split -l "${WAF_BATCH_SIZE:-25}" "${WAF_TARGETS_FILE}" "${WAF_SHARD_DIR}/in_"
        find "${WAF_SHARD_DIR}" -name 'in_*' ! -name '*.out' -print0 \
            | xargs -0 -r -P "${WAF_WORKERS:-4}" -I{} \
                sh -c 'timeout "$1" waf-detect scan --stdin --ndjson < "$2" > "$2.out"' \
                _ "${WAF_BATCH_TIMEOUT:-300}" {} 2>>"${SCAN_LOG}" || \
            log "WARN: some waf-detect batches failed or timed out (partial results kept)"
        # Keep only JSON lines (tolerates any non-JSON chatter on stdout)
        cat "${WAF_SHARD_DIR}"/in_*.out 2>/dev/null | grep '^{' > "${WAF_JSONL}" || true
        rm -rf "${WAF_SHARD_DIR}"

        WAF_HITS=$(jq -c 'select(.detected_waf != null)' "${WAF_JSONL}" 2>/dev/null | wc -l | tr -d ' ')
        debug_substep "waf-detect: origins=$(count_lines "${WAF_TARGETS_FILE}") results=$(count_lines "${WAF_JSONL}") waf=${WAF_HITS}"
        debug_stage_end "waf" "$(elapsed ${stage_start})"
        log "WAF detection complete | origins=$(count_lines "${WAF_TARGETS_FILE}") results=$(count_lines "${WAF_JSONL}") waf_detected=${WAF_HITS} elapsed=$(elapsed ${stage_start})s"
    fi
    rm -f "${WAF_TARGETS_FILE}"
fi

# ===========================================================================
# STAGE 4: TLS Deep Grab (tlsx)
# ===========================================================================
if should_run "tls"; then
    log_stage "TLS ANALYSIS (tlsx)"
    stage_start=$(date +%s)
    debug_stage_start "tls"

    if [[ ! -f "${PORTS_JSONL}" ]]; then
        log "WARN: No ports data — skipping TLS"
        debug_stage_end "tls" "$(elapsed ${stage_start})" "(skipped)"
    else
        TLS_PORTS_PATTERN=$(echo "${TLS_PORTS}" | sed 's/,/|/g')
        TLS_TARGETS_FILE="${OUTPUT_DIR}/_tls_targets.txt"
        jq -r --arg ports "${TLS_PORTS_PATTERN}" \
            'select(.port | tostring | test("^(" + $ports + ")$")) | "\(.host):\(.port)"' \
            "${PORTS_JSONL}" | sort -u > "${TLS_TARGETS_FILE}"

        if [[ ! -s "${TLS_TARGETS_FILE}" ]]; then
            log "WARN: No TLS targets found"
            rm -f "${TLS_TARGETS_FILE}"
            debug_stage_end "tls" "$(elapsed ${stage_start})" "(skipped)"
        else
            TLS_TARGET_COUNT=$(count_lines "${TLS_TARGETS_FILE}")
            debug_substep "TLS targets: ${TLS_TARGET_COUNT}"
            tlsx \
                -l "${TLS_TARGETS_FILE}" \
                -ja3 -jarm -so -tv -cipher -serial \
                -hash sha256 \
                -expired -self-signed -mismatched -revoked -untrusted -wc \
                -scan-mode "${TLSX_SCAN_MODE:-auto}" \
                -c "${TLSX_CONCURRENCY:-25}" \
                -silent -json \
                -o "${TLS_JSONL}" 2>>"${SCAN_LOG}" || \
                log "WARN: tlsx had errors (partial results may be available)"
            rm -f "${TLS_TARGETS_FILE}"

            debug_substep "Certs found: $(count_lines "${TLS_JSONL}")"
            debug_stage_end "tls" "$(elapsed ${stage_start})"
            log "TLS analysis complete | certs=$(count_lines "${TLS_JSONL}") elapsed=$(elapsed ${stage_start})s"
        fi
    fi
fi

# ===========================================================================
# STAGE 5: Service Fingerprinting (nerva — replaces zgrab2)
# ===========================================================================
if should_run "fingerprint"; then
    log_stage "SERVICE FINGERPRINTING (nerva)"
    stage_start=$(date +%s)
    debug_stage_start "fingerprint"

    if [[ ! -f "${PORTS_JSONL}" ]]; then
        log "WARN: No ports data — skipping fingerprinting"
        debug_stage_end "fingerprint" "$(elapsed ${stage_start})" "(skipped)"
    else
        NERVA_TIMEOUT="${NERVA_TIMEOUT:-10}"
        NERVA_THREADS="${NERVA_THREADS:-50}"
        NERVA_FAST_MODE="${NERVA_FAST_MODE:-false}"
        NERVA_UDP="${NERVA_UDP:-false}"
        NERVA_MISCONFIGS="${NERVA_MISCONFIGS:-false}"

        # Prefer fqdn:port over ip:port so nerva results map to FQDN-keyed assets.
        # Join ports.jsonl with dns.jsonl (ip → fqdn). Fall back to ip:port when
        # no FQDN is known for an IP.
        # NOTE: Uses temp file instead of bash variable to avoid OOM on large scans.
        NERVA_TARGETS_FILE="${OUTPUT_DIR}/_nerva_targets.txt"
        if [[ -f "${DNS_JSONL}" ]]; then
            python3 -c "
import sys, os
try:
    import orjson as json_mod
    def loads(b): return json_mod.loads(b)
except ImportError:
    import json as json_mod
    def loads(b): return json_mod.loads(b)

ip_map = {}
with open(sys.argv[1], 'rb') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            rec = loads(line)
            host = rec.get('host', '')
            for a in (rec.get('a') or []):
                if a and host:
                    ip_map[a] = host
        except Exception:
            pass

seen = set()
with open(sys.argv[2], 'rb') as f, open(sys.argv[3], 'w') as out:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            rec = loads(line)
            h = rec.get('host') or rec.get('ip', '')
            port = rec.get('port')
            if not h or port is None: continue
            resolved = ip_map.get(h, h)
            key = f'{resolved}:{port}'
            if key not in seen:
                seen.add(key)
                out.write(key + '\n')
        except Exception:
            pass
" "${DNS_JSONL}" "${PORTS_JSONL}" "${NERVA_TARGETS_FILE}"
        else
            jq -r '"\(.host // .ip):\(.port)"' "${PORTS_JSONL}" 2>/dev/null | sort -u > "${NERVA_TARGETS_FILE}"
        fi
        TARGET_COUNT=$(count_lines "${NERVA_TARGETS_FILE}")

        if [[ ! -s "${NERVA_TARGETS_FILE}" || "${TARGET_COUNT}" -eq 0 ]]; then
            log "WARN: No targets for fingerprinting"
            rm -f "${NERVA_TARGETS_FILE}"
            debug_stage_end "fingerprint" "$(elapsed ${stage_start})" "(skipped)"
        else
            TIMEOUT_MS=$(( NERVA_TIMEOUT * 1000 ))
            log "nerva: ${TARGET_COUNT} targets (timeout=${NERVA_TIMEOUT}s, workers=${NERVA_THREADS}, misconfigs=${NERVA_MISCONFIGS})"
            debug_substep "nerva target count: ${TARGET_COUNT}"

            NERVA_CMD=(nerva
                -w "${TIMEOUT_MS}"
                -W "${NERVA_THREADS}"
                --json
            )
            [[ "${NERVA_FAST_MODE}" == "true" ]]  && NERVA_CMD+=(-f)
            [[ "${NERVA_UDP}" == "true" ]]         && NERVA_CMD+=(-U)
            [[ "${NERVA_MISCONFIGS}" == "true" ]]  && NERVA_CMD+=(--misconfigs)

            "${NERVA_CMD[@]}" < "${NERVA_TARGETS_FILE}" > "${NERVA_JSONL}" 2>>"${SCAN_LOG}" || \
                log "WARN: nerva had errors (partial results may be available)"
            rm -f "${NERVA_TARGETS_FILE}"

            debug_substep "nerva fingerprints: $(count_lines "${NERVA_JSONL}")"
            debug_stage_end "fingerprint" "$(elapsed ${stage_start})"
            log "nerva complete | fingerprints=$(count_lines "${NERVA_JSONL}") elapsed=$(elapsed ${stage_start})s"
        fi

        # --- Optional zgrab2 fallback ---
        if [[ "${FINGERPRINT_BACKEND:-nerva}" == "zgrab2" ]] || [[ "${ZGRAB2_FALLBACK:-false}" == "true" ]]; then
            log "NOTICE: zgrab2 is deprecated. Set FINGERPRINT_BACKEND=nerva to suppress this fallback."

            declare -A ZGRAB_MODULES=(
                [ssh]=22  [ftp]=21  [smtp]=25  [imap]=143  [pop3]=110
                [mysql]=3306  [postgres]=5432  [redis]=6379
                [mongodb]=27017  [mssql]=1433  [smb]=445
            )

            ZGRAB_TOTAL=0
            for module in "${!ZGRAB_MODULES[@]}"; do
                port="${ZGRAB_MODULES[$module]}"
                HOSTS=$(jq -r "select(.port==${port}) | .host // empty" "${PORTS_JSONL}" 2>/dev/null | sort -u)
                if [[ -z "${HOSTS}" ]]; then continue; fi

                OUTPUT_FILE="${ZGRAB_DIR}/zgrab_${module}.jsonl"
                log "zgrab2 ${module} (port ${port}) — $(echo "${HOSTS}" | wc -l | tr -d ' ') hosts"

                echo "${HOSTS}" | \
                    zgrab2 "${module}" \
                        --port="${port}" \
                        --timeout="${ZGRAB_TIMEOUT:-10}" \
                        --output-file="${OUTPUT_FILE}" 2>>"${SCAN_LOG}" || \
                    log "WARN: zgrab2 ${module} had errors"

                COUNT=$(count_lines "${OUTPUT_FILE}")
                ZGRAB_TOTAL=$(( ZGRAB_TOTAL + COUNT ))
            done

            debug_substep "zgrab2 fallback banner count: ${ZGRAB_TOTAL}"
            log "zgrab2 fallback complete | total_banners=${ZGRAB_TOTAL} elapsed=$(elapsed ${stage_start})s"
        fi
    fi
fi

# ===========================================================================
# STAGE 6: Nuclei — Two-pass exposure scanning
#   Pass 1: Generic broad scan (all URLs, generic tags from config)
#   Pass 2: Technology-targeted scans (per-technology URLs, specific tags)
# ===========================================================================
if should_run "nuclei"; then
    log_stage "EXPOSURE SCANNING (nuclei)"
    stage_start=$(date +%s)
    debug_stage_start "nuclei"

    NUCLEI_TMPL_COUNT=$(nuclei -tl 2>/dev/null | wc -l | tr -d ' ')
    if [[ "${NUCLEI_TMPL_COUNT}" -eq 0 ]]; then
        log "Nuclei templates missing — attempting update"
        nuclei -update-templates 2>>"${SCAN_LOG}" || log "WARN: nuclei template update failed"
        NUCLEI_TMPL_COUNT=$(nuclei -tl 2>/dev/null | wc -l | tr -d ' ')
    fi
    log "Nuclei templates loaded: ${NUCLEI_TMPL_COUNT}"
    debug_substep "Templates loaded: ${NUCLEI_TMPL_COUNT}"

    if [[ ! -f "${HTTPX_JSONL}" ]]; then
        log "WARN: No HTTP data — skipping nuclei (run from 'http' stage first)"
        debug_stage_end "nuclei" "$(elapsed ${stage_start})" "(skipped)"
    else
        NUCLEI_URLS_FILE="${OUTPUT_DIR}/_nuclei_urls.txt"
        jq -r '.url // empty' "${HTTPX_JSONL}" | sort -u > "${NUCLEI_URLS_FILE}"
        URL_COUNT=$(count_lines "${NUCLEI_URLS_FILE}")
        if [[ ! -s "${NUCLEI_URLS_FILE}" ]] || [[ "${URL_COUNT}" -eq 0 ]]; then
            log "WARN: No URLs extracted from ${HTTPX_JSONL}"
            rm -f "${NUCLEI_URLS_FILE}"
            debug_stage_end "nuclei" "$(elapsed ${stage_start})" "(skipped)"
        else
            debug_substep "URLs for pass 1: ${URL_COUNT}"
            # --- Pass 1: Generic broad scan ---
            log "Nuclei pass 1 (generic): scanning ${URL_COUNT} URLs"
            nuclei \
                -config "${NUCLEI_CONFIG}" \
                -l "${NUCLEI_URLS_FILE}" \
                -H "User-Agent: ${USER_AGENT}" \
                -o "${NUCLEI_JSONL}" 2>>"${SCAN_LOG}" || \
                log "WARN: nuclei pass 1 had errors"
            rm -f "${NUCLEI_URLS_FILE}"

            debug_substep "Pass 1 findings: $(count_lines "${NUCLEI_JSONL}")"
            log "Pass 1 complete | findings=$(count_lines "${NUCLEI_JSONL}")"

            # --- Pass 2: Technology-targeted scans ---
            NUCLEI_JOBS="${OUTPUT_DIR}/nuclei_jobs.json"
            ENRICH_ARGS=(--output "${NUCLEI_JOBS}")
            [[ -f "${HTTPX_JSONL}" ]] && ENRICH_ARGS+=(--httpx "${HTTPX_JSONL}")
            [[ -f "${NERVA_JSONL}" ]] && ENRICH_ARGS+=(--nerva "${NERVA_JSONL}")
            [[ -f "${TLS_JSONL}" ]]   && ENRICH_ARGS+=(--tls "${TLS_JSONL}")
            [[ -f "${PORTS_JSONL}" ]] && ENRICH_ARGS+=(--ports "${PORTS_JSONL}")

            python3 "${SCRIPT_DIR}/scripts/enrich_nuclei.py" "${ENRICH_ARGS[@]}" 2>>"${SCAN_LOG}" || \
                log "WARN: nuclei enrichment failed — skipping pass 2"

            if [[ -f "${NUCLEI_JOBS}" ]]; then
                JOB_COUNT=$(jq '. | length' "${NUCLEI_JOBS}")
                debug_substep "Pass 2 job count: ${JOB_COUNT}"
                if [[ "${JOB_COUNT}" -gt 0 ]]; then
                    log "Nuclei pass 2 (targeted): ${JOB_COUNT} technology-specific jobs"

                    for (( i=0; i<JOB_COUNT; i++ )); do
                        JOB_LABEL=$(jq -r ".[$i].label" "${NUCLEI_JOBS}")
                        JOB_TAGS=$(jq -r ".[$i].tags" "${NUCLEI_JOBS}")
                        TARGETS_FILE="${OUTPUT_DIR}/nuclei_targets_${i}.txt"
                        PASS2_OUT="${OUTPUT_DIR}/nuclei_pass2_${i}.jsonl"

                        jq -r ".[$i].targets[]" "${NUCLEI_JOBS}" > "${TARGETS_FILE}"
                        TARGET_COUNT=$(count_lines "${TARGETS_FILE}")
                        log "  ${JOB_LABEL}: ${TARGET_COUNT} targets [tags=${JOB_TAGS}]"

                        nuclei \
                            -config "${NUCLEI_CONFIG}" \
                            -l "${TARGETS_FILE}" \
                            -tags "${JOB_TAGS}" \
                            -H "User-Agent: ${USER_AGENT}" \
                            -o "${PASS2_OUT}" 2>>"${SCAN_LOG}" || \
                            log "WARN: nuclei ${JOB_LABEL} had errors"

                        if [[ -f "${PASS2_OUT}" ]] && [[ $(count_lines "${PASS2_OUT}") -gt 0 ]]; then
                            cat "${PASS2_OUT}" >> "${NUCLEI_JSONL}"
                            log "  ${JOB_LABEL}: $(count_lines "${PASS2_OUT}") findings"
                        fi

                        rm -f "${TARGETS_FILE}" "${PASS2_OUT}"
                    done
                fi
                rm -f "${NUCLEI_JOBS}"
            fi

            debug_substep "Pass 2 findings: $(count_lines "${NUCLEI_JSONL}")"

            # --- Pass 3: Cloud endpoint detection (Azure, AWS, GCP templates) ---
            CLOUD_TEMPLATES="${SCRIPT_DIR}/config/nuclei-templates/cloud"
            if [[ -d "${CLOUD_TEMPLATES}" ]]; then
                CLOUD_TMPL_COUNT=$(find "${CLOUD_TEMPLATES}" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
                if [[ "${CLOUD_TMPL_COUNT}" -gt 0 ]]; then
                    log "Nuclei pass 3 (cloud): ${CLOUD_TMPL_COUNT} cloud templates against ${URL_COUNT:-0} URLs"
                    NUCLEI_URLS_FILE="${OUTPUT_DIR}/_nuclei_urls.txt"
                    if [[ ! -f "${NUCLEI_URLS_FILE}" ]]; then
                        jq -r '.url // empty' "${HTTPX_JSONL}" | sort -u > "${NUCLEI_URLS_FILE}"
                    fi
                    PASS3_OUT="${OUTPUT_DIR}/nuclei_cloud.jsonl"
                    nuclei \
                        -t "${CLOUD_TEMPLATES}" \
                        -l "${NUCLEI_URLS_FILE}" \
                        -H "User-Agent: ${USER_AGENT}" \
                        -o "${PASS3_OUT}" 2>>"${SCAN_LOG}" || \
                        log "WARN: nuclei pass 3 (cloud) had errors"

                    if [[ -f "${PASS3_OUT}" ]] && [[ $(count_lines "${PASS3_OUT}") -gt 0 ]]; then
                        cat "${PASS3_OUT}" >> "${NUCLEI_JSONL}"
                        log "  Cloud: $(count_lines "${PASS3_OUT}") findings"
                    fi
                    rm -f "${PASS3_OUT}" "${NUCLEI_URLS_FILE}"
                fi
            fi

            debug_stage_end "nuclei" "$(elapsed ${stage_start})"
            log "Nuclei complete | findings=$(count_lines "${NUCLEI_JSONL}") elapsed=$(elapsed ${stage_start})s"
        fi
    fi
fi

# ===========================================================================
# STAGE 6.5: Cloud Enumeration — Identify Azure/AWS/GCP endpoints
#   Scans DNS, HTTP, and TLS data for cloud provider patterns (blob storage,
#   azurewebsites, S3, App Engine, etc.) and outputs cloud_enum.jsonl.
# ===========================================================================
if should_run "cloud_enum"; then
    log_stage "CLOUD ENUMERATION"
    stage_start=$(date +%s)
    debug_stage_start "cloud_enum"

    CLOUD_ENUM_ARGS=(--output "${CLOUD_ENUM_JSONL}")
    [[ -f "${DNS_JSONL}" ]]   && CLOUD_ENUM_ARGS+=(--dns "${DNS_JSONL}")
    [[ -f "${HTTPX_JSONL}" ]] && CLOUD_ENUM_ARGS+=(--http "${HTTPX_JSONL}")
    [[ -f "${TLS_JSONL}" ]]   && CLOUD_ENUM_ARGS+=(--tls "${TLS_JSONL}")

    python3 "${SCRIPT_DIR}/scripts/cloud_enum.py" "${CLOUD_ENUM_ARGS[@]}" 2>>"${SCAN_LOG}" || \
        log "WARN: Cloud enumeration had errors (partial results may be available)"

    CLOUD_ENUM_COUNT=$(count_lines "${CLOUD_ENUM_JSONL}")
    debug_substep "Cloud endpoints: ${CLOUD_ENUM_COUNT}"
    debug_stage_end "cloud_enum" "$(elapsed ${stage_start})"
    log "Cloud enumeration complete | endpoints=${CLOUD_ENUM_COUNT} elapsed=$(elapsed ${stage_start})s"
fi

# ===========================================================================
# STAGE 7.5: AIMAP — AI Agent Discovery
#   Detects exposed AI agents (MCP, Ollama, OpenAI-compat, LangServe,
#   Gradio, Streamlit, ComfyUI, etc.) using AIMAP Nuclei templates and
#   Python HTTP probes against the pipeline's discovered web targets.
# ===========================================================================
if should_run "aimap"; then
    log_stage "AI AGENT DISCOVERY (aimap)"
    stage_start=$(date +%s)
    debug_stage_start "aimap"

    AIMAP_TEMPLATES="${SCRIPT_DIR}/aimap/templates"

    if [[ ! -d "${AIMAP_TEMPLATES}" ]]; then
        log "WARN: AIMAP templates not found at ${AIMAP_TEMPLATES} — skipping"
        debug_stage_end "aimap" "$(elapsed ${stage_start})" "(skipped)"
    elif [[ (! -f "${HTTPX_JSONL}" || $(count_lines "${HTTPX_JSONL}") -eq 0) && \
            (! -f "${WEB_TARGETS}" || $(count_lines "${WEB_TARGETS}") -eq 0) ]]; then
        log "WARN: No HTTP data or web targets — skipping AIMAP"
        debug_stage_end "aimap" "$(elapsed ${stage_start})" "(skipped)"
    else
        AIMAP_ARGS=(
            --output "${AIMAP_JSONL}"
            --templates-dir "${AIMAP_TEMPLATES}"
            --scan-id "${SCAN_ID}"
            --workers "${AIMAP_WORKERS:-20}"
            --probe-timeout "${AIMAP_PROBE_TIMEOUT:-5}"
            --nuclei-rate-limit "${AIMAP_NUCLEI_RATE:-100}"
        )
        [[ -f "${HTTPX_JSONL}" ]]   && AIMAP_ARGS+=(--httpx "${HTTPX_JSONL}")
        [[ -f "${WEB_TARGETS}" ]]   && AIMAP_ARGS+=(--web-targets "${WEB_TARGETS}")

        python3 "${SCRIPT_DIR}/scripts/run_aimap.py" "${AIMAP_ARGS[@]}" 2>>"${SCAN_LOG}" || \
            log "WARN: AIMAP stage had errors (partial results may be available)"

        AIMAP_COUNT=$(count_lines "${AIMAP_JSONL}")
        debug_substep "AIMAP findings: ${AIMAP_COUNT}"
        debug_stage_end "aimap" "$(elapsed ${stage_start})"
        log "AIMAP complete | findings=${AIMAP_COUNT} elapsed=$(elapsed ${stage_start})s"
    fi
fi

# ===========================================================================
# STAGE 8: Normalize all outputs into unified asset records
# ===========================================================================
if should_run "normalize"; then
    log_stage "NORMALIZATION"
    stage_start=$(date +%s)
    debug_stage_start "normalize"

    NORMALIZE_ARGS=(
        --output "${ASSETS_JSONL}"
        --scan-id "${SCAN_ID}"
    )

    [[ -f "${DNS_JSONL}" ]]   && NORMALIZE_ARGS+=(--dns "${DNS_JSONL}")
    [[ -f "${PORTS_JSONL}" ]] && NORMALIZE_ARGS+=(--ports "${PORTS_JSONL}")
    [[ -f "${HTTPX_JSONL}" ]] && NORMALIZE_ARGS+=(--http "${HTTPX_JSONL}")
    [[ -f "${TLS_JSONL}" ]]    && NORMALIZE_ARGS+=(--tls "${TLS_JSONL}")
    [[ -f "${NERVA_JSONL}" ]] && NORMALIZE_ARGS+=(--nerva "${NERVA_JSONL}")
    [[ -f "${SERVICE_DETECT_JSONL}" ]] && NORMALIZE_ARGS+=(--service-detect "${SERVICE_DETECT_JSONL}")
    [[ -f "${NUCLEI_JSONL}" ]] && NORMALIZE_ARGS+=(--nuclei "${NUCLEI_JSONL}")
    [[ -f "${AIMAP_JSONL}" ]] && NORMALIZE_ARGS+=(--aimap "${AIMAP_JSONL}")
    [[ -f "${CLOUD_ENUM_JSONL}" ]] && NORMALIZE_ARGS+=(--cloud-enum "${CLOUD_ENUM_JSONL}")
    [[ -s "${CT_SUBDOMAINS}" ]] && NORMALIZE_ARGS+=(--ct "${CT_SUBDOMAINS}")
    [[ -s "${SUBFINDER_SUBDOMAINS}" ]] && NORMALIZE_ARGS+=(--subfinder "${SUBFINDER_SUBDOMAINS}")
    [[ -s "${CDNCHECK_JSONL}" ]] && NORMALIZE_ARGS+=(--cdncheck "${CDNCHECK_JSONL}")
    [[ -s "${WAF_JSONL}" ]] && NORMALIZE_ARGS+=(--waf "${WAF_JSONL}")
    [[ -f "${CMDB_EXPORT}" ]] && NORMALIZE_ARGS+=(--cmdb "${CMDB_EXPORT}")
    [[ -f "${ASN_JSONL}" ]]   && NORMALIZE_ARGS+=(--asn "${ASN_JSONL}")
    [[ -f "${RDNS_JSONL}" ]]  && NORMALIZE_ARGS+=(--rdns "${RDNS_JSONL}")

    # Collect all zgrab files
    for zgf in "${ZGRAB_DIR}"/zgrab_*.jsonl; do
        if [[ -f "$zgf" ]]; then
            NORMALIZE_ARGS+=(--zgrab "$zgf")
        fi
    done

    python3 "${SCRIPT_DIR}/scripts/normalize.py" "${NORMALIZE_ARGS[@]}"

    debug_substep "Assets output: $(count_lines "${ASSETS_JSONL}")"
    debug_stage_end "normalize" "$(elapsed ${stage_start})"
    log "Normalization complete | assets=$(count_lines "${ASSETS_JSONL}") elapsed=$(elapsed ${stage_start})s"
fi

# ===========================================================================
# STAGE 9: Archive previous scan, then Load into DuckDB
# ===========================================================================
if should_run "load"; then
    # Archive existing scan before overwriting
    if [[ -f "${DUCKDB_PATH}" ]]; then
        log_stage "ARCHIVING PREVIOUS SCAN"
        stage_start=$(date +%s)
        debug_stage_start "load_archive"

        ARCHIVE_DIR="${SCRIPT_DIR}/data/archives"
        PREV_SCAN_ID=$(python3 -c "
import duckdb, sys
try:
    con = duckdb.connect('${DUCKDB_PATH}', read_only=True)
    row = con.execute('SELECT scan_id FROM v_scan_stats LIMIT 1').fetchone()
    print(row[0] if row else '')
    con.close()
except: pass
" 2>/dev/null)

        if [[ -n "${PREV_SCAN_ID}" ]] && [[ ! -d "${ARCHIVE_DIR}/${PREV_SCAN_ID}" ]]; then
            debug_substep "prev_scan_id: ${PREV_SCAN_ID} archive_path: ${ARCHIVE_DIR}/${PREV_SCAN_ID}"
            python3 "${SCRIPT_DIR}/scripts/archive_scan.py" \
                --db "${DUCKDB_PATH}" \
                --scan-id "${PREV_SCAN_ID}" \
                --archive-dir "${ARCHIVE_DIR}" \
                --input-file "${INPUT_SUBDOMAINS}" 2>>"${SCAN_LOG}" || \
                log "WARN: Archive failed (non-fatal)"

            debug_stage_end "load_archive" "$(elapsed ${stage_start})"
            log "Archive complete | prev_scan=${PREV_SCAN_ID} elapsed=$(elapsed ${stage_start})s"
        else
            log "No previous scan to archive (first run or already archived)"
            debug_stage_end "load_archive" "$(elapsed ${stage_start})" "(skipped)"
        fi
    fi

    log_stage "DUCKDB LOAD"
    stage_start=$(date +%s)
    debug_stage_start "load_duckdb"

    if [[ ! -f "${ASSETS_JSONL}" ]]; then
        log "WARN: No assets file — skipping DuckDB load"
        debug_stage_end "load_duckdb" "$(elapsed ${stage_start})" "(skipped)"
    else
        debug_substep "Assets file: $(count_lines "${ASSETS_JSONL}") records"
        python3 "${SCRIPT_DIR}/scripts/load_duckdb.py" \
            --input "${ASSETS_JSONL}" \
            --db "${DUCKDB_PATH}" \
            --scan-id "${SCAN_ID}"

        debug_stage_end "load_duckdb" "$(elapsed ${stage_start})"
        log "DuckDB load complete | db=${DUCKDB_PATH} elapsed=$(elapsed ${stage_start})s"
    fi
fi

# ===========================================================================
# STAGE 10: Verify takeover candidates (live DNS + HTTP fingerprint)
# ===========================================================================
if should_run "verify"; then
    log_stage "TAKEOVER VERIFICATION"
    stage_start=$(date +%s)
    debug_stage_start "verify"

    if [[ ! -f "${DUCKDB_PATH}" ]]; then
        log "WARN: DuckDB not found — skipping takeover verification"
        debug_stage_end "verify" "$(elapsed ${stage_start})" "(skipped)"
    else
        python3 "${SCRIPT_DIR}/scripts/verify_takeovers.py" \
            --db  "${DUCKDB_PATH}" \
            --out "${VERIFY_JSONL}" 2>>"${SCAN_LOG}" || \
            log "WARN: takeover verification completed with warnings"

        debug_substep "Candidates verified: $(count_lines "${VERIFY_JSONL}")"
        debug_stage_end "verify" "$(elapsed ${stage_start})"
        log "Takeover verification complete | elapsed=$(elapsed ${stage_start})s"
    fi
fi

# ===========================================================================
# STAGE 10.5: Tenable scan-scope routing (recon mode only)
#   Routes every asset to Tenable VM (unique IPs) and/or Tenable WAS (URLs,
#   standard / waf / api profiles) per TENABLE_SCOPE_PIPELINE.MD. Runs after
#   verify so confirmed takeovers are kept out of both scanners.
# ===========================================================================
if should_run "scope" && [[ "${PIPELINE_MODE}" == "recon" ]]; then
    log_stage "TENABLE SCOPE ROUTING"
    stage_start=$(date +%s)
    debug_stage_start "scope"

    if [[ ! -f "${DUCKDB_PATH}" ]]; then
        log "WARN: DuckDB not found — skipping Tenable scope routing"
        debug_stage_end "scope" "$(elapsed ${stage_start})" "(skipped)"
    else
        SCOPE_ARGS=(
            --db "${DUCKDB_PATH}"
            --output-dir "${OUTPUT_DIR}"
            --cdn-min-confidence "${TENABLE_CDN_MIN_CONFIDENCE:-0.35}"
            --waf-min-confidence "${TENABLE_WAF_MIN_CONFIDENCE:-0.5}"
        )
        [[ -n "${TENABLE_OWNED_CIDRS:-}" ]] && SCOPE_ARGS+=(--owned-cidrs "${TENABLE_OWNED_CIDRS}")
        [[ -n "${TENABLE_OWNED_ASNS:-}" ]]  && SCOPE_ARGS+=(--owned-asns "${TENABLE_OWNED_ASNS}")
        [[ "${TENABLE_SCOPE_CMDB_ONLY:-false}" == "true" ]]  && SCOPE_ARGS+=(--cmdb-only)
        [[ "${TENABLE_VM_REQUIRE_OWNED:-false}" == "true" ]] && SCOPE_ARGS+=(--require-owned)
        [[ "${TENABLE_WAS_INCLUDE_SAAS:-false}" == "true" ]] && SCOPE_ARGS+=(--was-include-saas)

        python3 "${SCRIPT_DIR}/scripts/cmdb_scope_export.py" "${SCOPE_ARGS[@]}" 2>>"${SCAN_LOG}" || \
            log "WARN: Tenable scope routing completed with warnings"

        debug_stage_end "scope" "$(elapsed ${stage_start})"
        log "Scope routing complete | vm_include=$(count_lines "${OUTPUT_DIR}/tenable_vm_include.txt") vm_exclude=$(count_lines "${OUTPUT_DIR}/tenable_vm_exclude.txt") was=$(count_lines "${OUTPUT_DIR}/tenable_was_targets.txt") was_waf=$(count_lines "${OUTPUT_DIR}/tenable_was_waf_targets.txt") was_api=$(count_lines "${OUTPUT_DIR}/tenable_was_api_targets.txt") xlsx=$([[ -f "${OUTPUT_DIR}/tenable_scope.xlsx" ]] && echo yes || echo no) elapsed=$(elapsed ${stage_start})s"
    fi
fi

# ===========================================================================
# STAGE 11: Bounty Scoring (bounty mode only)
# ===========================================================================
if [[ "${PIPELINE_MODE}" == "bounty" ]] && should_run "load"; then
    log_stage "BOUNTY SCORING"
    stage_start=$(date +%s)
    debug_stage_start "bounty_scoring"

    if [[ ! -f "${DUCKDB_PATH}" ]]; then
        log "WARN: DuckDB not found — skipping bounty scoring"
        debug_stage_end "bounty_scoring" "$(elapsed ${stage_start})" "(skipped)"
    else
        python3 "${SCRIPT_DIR}/scripts/score_bounty.py" \
            --db "${DUCKDB_PATH}" \
            --output "${BOUNTY_REPORT_JSONL}" 2>>"${SCAN_LOG}" || \
            log "WARN: bounty scoring completed with warnings"

        debug_substep "Bounty report: $(count_lines "${BOUNTY_REPORT_JSONL}")"
        debug_stage_end "bounty_scoring" "$(elapsed ${stage_start})"
        log "Bounty scoring complete | records=$(count_lines "${BOUNTY_REPORT_JSONL}") elapsed=$(elapsed ${stage_start})s"
    fi
fi

# ===========================================================================
# STAGE 12: Livecheck Analysis (livecheck mode only)
# ===========================================================================
if [[ "${PIPELINE_MODE}" == "livecheck" ]] && should_run "load"; then
    log_stage "LIVECHECK ANALYSIS"
    stage_start=$(date +%s)
    debug_stage_start "livecheck"

    LIVECHECK_ARGS=(
        --scan-id "${SCAN_ID}"
        --output "${LIVECHECK_JSONL}"
        --state "${LIVECHECK_STATE}"
        --deadline-days "${LIVECHECK_DEADLINE_DAYS:-30}"
        --cname-depth-threshold "${LIVECHECK_CNAME_DEPTH_THRESHOLD:-3}"
    )
    [[ -f "${DNS_JSONL}" ]]    && LIVECHECK_ARGS+=(--dns "${DNS_JSONL}")
    [[ -f "${ASN_JSONL}" ]]    && LIVECHECK_ARGS+=(--asn "${ASN_JSONL}")
    [[ -f "${CMDB_EXPORT}" ]]  && LIVECHECK_ARGS+=(--cmdb "${CMDB_EXPORT}")

    python3 "${SCRIPT_DIR}/scripts/livecheck.py" "${LIVECHECK_ARGS[@]}" 2>>"${SCAN_LOG}" || \
        log "WARN: livecheck analysis completed with warnings"

    debug_substep "Livecheck report: $(count_lines "${LIVECHECK_JSONL}")"

    # Generate Tenable scope files
    if [[ -f "${LIVECHECK_JSONL}" ]]; then
        python3 "${SCRIPT_DIR}/scripts/cmdb_scope_export.py" \
            --report "${LIVECHECK_JSONL}" \
            --output-dir "${OUTPUT_DIR}" 2>>"${SCAN_LOG}" || \
            log "WARN: Tenable scope export completed with warnings"
        debug_substep "Tenable include: $(count_lines "${OUTPUT_DIR}/tenable_include.txt") exclude: $(count_lines "${OUTPUT_DIR}/tenable_exclude.txt")"
    fi

    # Load livecheck results into DuckDB
    if [[ -f "${DUCKDB_PATH}" ]] && [[ -f "${LIVECHECK_JSONL}" ]]; then
        python3 -c "
import duckdb, sys
con = duckdb.connect('${DUCKDB_PATH}')
try:
    con.execute('DROP TABLE IF EXISTS livecheck')
    con.execute(\"\"\"
        CREATE TABLE livecheck AS
        SELECT * FROM read_ndjson_auto('${LIVECHECK_JSONL}',
            maximum_object_size=10485760, ignore_errors=true)
    \"\"\")
    cnt = con.execute('SELECT COUNT(*) FROM livecheck').fetchone()[0]
    print(f'Loaded {cnt} livecheck records into DuckDB', file=sys.stderr)
finally:
    con.close()
" 2>>"${SCAN_LOG}" || log "WARN: livecheck DuckDB load failed"
    fi

    debug_stage_end "livecheck" "$(elapsed ${stage_start})"
    log "Livecheck complete | records=$(count_lines "${LIVECHECK_JSONL}") elapsed=$(elapsed ${stage_start})s"
fi

# ===========================================================================
# Summary
# ===========================================================================
PIPELINE_ELAPSED=$(elapsed ${PIPELINE_START})
debug_summary "${PIPELINE_ELAPSED}"
log "=========================================="
log "EASM Pipeline complete"
log "  Scan ID:      ${SCAN_ID}"
log "  Mode:         ${PIPELINE_MODE}"
log "  Wall clock:   ${PIPELINE_ELAPSED}s"
log "  Targets:      $(count_lines "${TARGETS_FILE}")"
log "  Subfinder:    $(count_lines "${SUBFINDER_SUBDOMAINS}" 2>/dev/null || echo 0) in-scope names"
log "  Live hosts:   $(count_lines "${LIVE_HOSTS}" 2>/dev/null || echo 0)"
log "  CDN check:    $(count_lines "${CDNCHECK_JSONL}" 2>/dev/null || echo 0) classified"
log "  Open ports:   $(count_lines "${PORTS_JSONL}" 2>/dev/null || echo 0)"
log "  HTTP probed:  $(count_lines "${HTTPX_JSONL}" 2>/dev/null || echo 0)"
log "  WAF detect:   $(count_lines "${WAF_JSONL}" 2>/dev/null || echo 0) origins"
log "  TLS certs:    $(count_lines "${TLS_JSONL}" 2>/dev/null || echo 0)"
log "  Nuclei finds: $(count_lines "${NUCLEI_JSONL}" 2>/dev/null || echo 0)"
log "  Assets:       $(count_lines "${ASSETS_JSONL}" 2>/dev/null || echo 0)"
log "  Takeover chk: $(count_lines "${VERIFY_JSONL}" 2>/dev/null || echo 0) verified"
log "  Tenable VM:   $(count_lines "${OUTPUT_DIR}/tenable_vm_include.txt" 2>/dev/null || echo 0) IPs  WAS: $(cat "${OUTPUT_DIR}"/tenable_was_*targets.txt 2>/dev/null | wc -l | tr -d ' ') URLs"
log "  Livecheck:    $(count_lines "${LIVECHECK_JSONL}" 2>/dev/null || echo 0) checked"
log "  Screenshots:  $(find "${SCREENSHOT_DIR}" -name '*.png' 2>/dev/null | wc -l | tr -d ' ')"
log "  DuckDB:       ${DUCKDB_PATH}"
log "  Log:          ${SCAN_LOG}"
log "=========================================="

# ===========================================================================
# Move intermediate outputs into the scan archive and clean data/output/
# Skipped for --stage / --from (resume runs leave files in place).
# ===========================================================================
if [[ -z "${STAGE_FILTER}" ]] && [[ -z "${FROM_STAGE}" ]]; then
    log "Archiving scan outputs: ${SCAN_ID}"
    python3 "${SCRIPT_DIR}/scripts/archive_scan.py" \
        --archive-raw \
        --scan-id "${SCAN_ID}" \
        --output-dir "${OUTPUT_DIR}" \
        --screenshot-dir "${SCREENSHOT_DIR}" \
        --log-file "${SCAN_LOG}" \
        --archive-dir "${SCRIPT_DIR}/data/archives" \
        --status "completed" 2>>"${SCAN_LOG}" || \
        log "WARN: Archive failed — outputs remain in ${OUTPUT_DIR}"
fi
