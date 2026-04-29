#!/usr/bin/env bash
# =============================================================================
# EASM Pipeline Orchestrator
# =============================================================================
# Funnel-based EASM discovery pipeline:
#   CT Enrichment → DNS → Port Scan → HTTP Probe → TLS → zgrab2 → Nuclei
#   → Normalize → DuckDB
#
# Usage:
#   ./run.sh                          # full pipeline
#   ./run.sh --stage dns              # run single stage
#   ./run.sh --stage dns,ports        # run multiple stages
#   ./run.sh --skip-passive           # skip CT log enrichment
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
SUBZY_JSON="${OUTPUT_DIR}/subzy.json"
ASSETS_JSONL="${OUTPUT_DIR}/assets.jsonl"
DUCKDB_PATH="${SCRIPT_DIR}/${DUCKDB_PATH_VALUE}"
ZGRAB_DIR="${OUTPUT_DIR}/zgrab"

SCAN_ID="$(date -u +%Y%m%d_%H%M%S)"
SCAN_LOG="${LOG_DIR}/scan_${SCAN_ID}.log"

# CLI args
STAGE_ORDER="passive,dns,ports,http,tls,zgrab,nuclei,takeover,normalize,load"
STAGE_FILTER=""
FROM_STAGE=""
SKIP_PASSIVE=false
DRY_RUN=false

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --stage)        STAGE_FILTER="$2"; shift 2 ;;
        --from)         FROM_STAGE="$2"; shift 2 ;;
        --skip-passive) SKIP_PASSIVE=true; shift ;;
        --dry-run)      DRY_RUN=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--stage STAGE1,STAGE2 | --from STAGE] [--skip-passive] [--dry-run]"
            echo ""
            echo "  --stage STAGES  Run only the specified comma-separated stages"
            echo "  --from  STAGE   Run from STAGE through the end of the pipeline"
            echo ""
            echo "Stages (in order): ${STAGE_ORDER}"
            exit 0 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

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
# Validation
# ---------------------------------------------------------------------------
if [[ ! -f "${INPUT_SUBDOMAINS}" ]]; then
    log "ERROR: Input file not found: ${INPUT_SUBDOMAINS}"
    log "Place your subdomain list at data/input/subdomains.txt"
    exit 1
fi

log "EASM Pipeline started | scan_id=${SCAN_ID}"
log "Input: ${INPUT_SUBDOMAINS} ($(count_lines "${INPUT_SUBDOMAINS}") subdomains)"

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

# ===========================================================================
# STAGE 0: Passive enrichment — CT logs via crt.sh
# ===========================================================================
if should_run "passive" && ! ${SKIP_PASSIVE}; then
    log_stage "PASSIVE ENRICHMENT (crt.sh)"
    stage_start=$(date +%s)

    cp "${INPUT_SUBDOMAINS}" "${TARGETS_FILE}.base"

    IFS=',' read -ra DOMAINS <<< "${ROOT_DOMAINS:-}"
    for domain in "${DOMAINS[@]}"; do
        domain=$(echo "$domain" | xargs)  # trim
        if [[ -z "$domain" ]]; then continue; fi
        log "Querying crt.sh for *.${domain}"
        # Rate-limit crt.sh: 1 request per domain, with timeout
        curl -sf --max-time 30 \
            "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null \
            | jq -r '.[].name_value // empty' 2>/dev/null \
            | tr ',' '\n' \
            | sed 's/^\*\.//' \
            | grep -E "\.${domain//./\\.}$" \
            >> "${TARGETS_FILE}.ct" || log "WARN: crt.sh query failed for ${domain}"
    done

    # Union and deduplicate
    cat "${TARGETS_FILE}.base" "${TARGETS_FILE}.ct" 2>/dev/null \
        | tr '[:upper:]' '[:lower:]' \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
        | grep -v '^$' \
        | sort -u > "${TARGETS_FILE}"
    rm -f "${TARGETS_FILE}.base" "${TARGETS_FILE}.ct"

    INPUT_COUNT=$(count_lines "${INPUT_SUBDOMAINS}")
    TOTAL_COUNT=$(count_lines "${TARGETS_FILE}")
    CT_ADDED=$(( TOTAL_COUNT - INPUT_COUNT ))

    log "Passive enrichment complete | input=${INPUT_COUNT} ct_added=${CT_ADDED} total=${TOTAL_COUNT} elapsed=$(elapsed ${stage_start})s"
else
    # No passive enrichment: use input directly
    if [[ ! -f "${TARGETS_FILE}" ]]; then
        tr '[:upper:]' '[:lower:]' < "${INPUT_SUBDOMAINS}" \
            | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
            | grep -v '^$' \
            | sort -u > "${TARGETS_FILE}"
    fi
fi

# ===========================================================================
# STAGE 1: DNS Resolution (dnsx)
# ===========================================================================
if should_run "dns"; then
    log_stage "DNS RESOLUTION (dnsx)"
    stage_start=$(date +%s)

    dnsx -l "${TARGETS_FILE}" \
        -a -aaaa -cname -ns -mx -resp \
        -r "${RESOLVERS}" \
        -rate-limit "${DNS_RATE_LIMIT:-500}" \
        -retry "${DNS_RETRIES:-2}" \
        -silent -json \
        -o "${DNS_JSONL}" 2>>"${SCAN_LOG}"

    # Extract live hostnames
    jq -r '.host // empty' "${DNS_JSONL}" | sort -u > "${LIVE_HOSTS}"

    log "DNS complete | resolved=$(count_lines "${LIVE_HOSTS}") elapsed=$(elapsed ${stage_start})s"
fi

# ===========================================================================
# STAGE 2: Port Scanning (naabu)
# ===========================================================================
if should_run "ports"; then
    log_stage "PORT SCANNING (naabu)"
    stage_start=$(date +%s)

    if [[ ! -f "${LIVE_HOSTS}" ]] || [[ $(count_lines "${LIVE_HOSTS}") -eq 0 ]]; then
        log "WARN: No live hosts — skipping port scan"
    else
        NAABU_ARGS=(
            -l "${LIVE_HOSTS}"
            -top-ports "${NAABU_TOP_PORTS:-100}"
            -rate "${NAABU_RATE:-1000}"
            -c "${NAABU_WORKERS:-25}"
            -retries "${NAABU_RETRIES:-1}"
            -silent -json
            -o "${PORTS_JSONL}"
        )
        if [[ "${NAABU_EXCLUDE_CDN:-true}" == "true" ]]; then
            NAABU_ARGS+=(-exclude-cdn)
        fi

        naabu "${NAABU_ARGS[@]}" 2>>"${SCAN_LOG}"

        # Build web target list
        WEB_PORTS_PATTERN=$(echo "${WEB_PORTS}" | sed 's/,/|/g')
        jq -r --arg ports "${WEB_PORTS_PATTERN}" \
            'select(.port | tostring | test("^(" + $ports + ")$")) | "\(.host):\(.port)"' \
            "${PORTS_JSONL}" | sort -u > "${WEB_TARGETS}"

        OPEN_PORTS=$(count_lines "${PORTS_JSONL}")
        WEB_COUNT=$(count_lines "${WEB_TARGETS}")
        log "Port scan complete | open_ports=${OPEN_PORTS} web_targets=${WEB_COUNT} elapsed=$(elapsed ${stage_start})s"
    fi
fi

# ===========================================================================
# STAGE 3: HTTP Probing (httpx)
# ===========================================================================
if should_run "http"; then
    log_stage "HTTP PROBING (httpx)"
    stage_start=$(date +%s)

    if [[ ! -f "${WEB_TARGETS}" ]] || [[ $(count_lines "${WEB_TARGETS}") -eq 0 ]]; then
        log "WARN: No web targets — skipping HTTP probe"
    else
        HTTPX_ARGS=(
            -l "${WEB_TARGETS}"
            -sc -cl -ct -location -title -server -td -method -websocket
            -ip -cname -asn -cdn -probe -favicon -jarm
            -hash sha256
            -rt -lc -wc
            -tls-grab -http2
            -follow-redirects
            -include-response-header
            -no-fallback
            -threads "${HTTPX_THREADS:-50}"
            -rate-limit "${HTTPX_RATE_LIMIT:-150}"
            -timeout "${HTTPX_TIMEOUT:-10}"
            -retries "${HTTPX_RETRIES:-2}"
            -max-host-error "${HTTPX_MAX_HOST_ERROR:-30}"
            -H "User-Agent: ${USER_AGENT}"
            -silent -json
            -o "${HTTPX_JSONL}"
        )

        if [[ "${HTTPX_SCREENSHOTS:-true}" == "true" ]]; then
            HTTPX_ARGS+=(-screenshot -system-chrome -srd "${SCREENSHOT_DIR}")
        fi

        httpx "${HTTPX_ARGS[@]}" 2>>"${SCAN_LOG}"

        log "HTTP probe complete | probed=$(count_lines "${HTTPX_JSONL}") screenshots=$(find "${SCREENSHOT_DIR}" -name '*.png' 2>/dev/null | wc -l | tr -d ' ') elapsed=$(elapsed ${stage_start})s"
    fi
fi

# ===========================================================================
# STAGE 4: TLS Deep Grab (tlsx)
# ===========================================================================
if should_run "tls"; then
    log_stage "TLS ANALYSIS (tlsx)"
    stage_start=$(date +%s)

    if [[ ! -f "${PORTS_JSONL}" ]]; then
        log "WARN: No ports data — skipping TLS"
    else
        TLS_PORTS_PATTERN=$(echo "${TLS_PORTS}" | sed 's/,/|/g')
        TLS_TARGETS=$(jq -r --arg ports "${TLS_PORTS_PATTERN}" \
            'select(.port | tostring | test("^(" + $ports + ")$")) | "\(.host):\(.port)"' \
            "${PORTS_JSONL}" | sort -u)

        if [[ -z "${TLS_TARGETS}" ]]; then
            log "WARN: No TLS targets found"
        else
            echo "${TLS_TARGETS}" | \
            tlsx \
                -ja3 -jarm -so -tv -cipher -serial \
                -hash sha256 \
                -expired -self-signed -mismatched -revoked -untrusted -wc \
                -scan-mode "${TLSX_SCAN_MODE:-auto}" \
                -c "${TLSX_CONCURRENCY:-25}" \
                -silent -json \
                -o "${TLS_JSONL}" 2>>"${SCAN_LOG}" || \
                log "WARN: tlsx had errors (partial results may be available)"

            log "TLS analysis complete | certs=$(count_lines "${TLS_JSONL}") elapsed=$(elapsed ${stage_start})s"
        fi
    fi
fi

# ===========================================================================
# STAGE 5: Non-HTTP Service Fingerprinting (zgrab2)
# ===========================================================================
if should_run "zgrab"; then
    log_stage "SERVICE FINGERPRINTING (zgrab2)"
    stage_start=$(date +%s)

    if [[ ! -f "${PORTS_JSONL}" ]]; then
        log "WARN: No ports data — skipping zgrab2"
    else
        # Map service ports to zgrab2 modules
        declare -A ZGRAB_MODULES=(
            [ssh]=22
            [ftp]=21
            [smtp]=25
            [imap]=143
            [pop3]=110
            [mysql]=3306
            [postgres]=5432
            [redis]=6379
            [mongodb]=27017
            [mssql]=1433
            [smb]=445
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

        log "zgrab2 complete | total_banners=${ZGRAB_TOTAL} elapsed=$(elapsed ${stage_start})s"
    fi
fi

# ===========================================================================
# STAGE 6: Nuclei — Low-noise exposure scanning
# ===========================================================================
if should_run "nuclei"; then
    log_stage "EXPOSURE SCANNING (nuclei)"
    stage_start=$(date +%s)

    if [[ ! -f "${HTTPX_JSONL}" ]]; then
        log "WARN: No HTTP data — skipping nuclei"
    else
        URLS=$(jq -r '.url // empty' "${HTTPX_JSONL}" | sort -u)
        if [[ -z "${URLS}" ]]; then
            log "WARN: No URLs extracted"
        else
            echo "${URLS}" | \
            nuclei \
                -config "${NUCLEI_CONFIG}" \
                -H "User-Agent: ${USER_AGENT}" \
                -o "${NUCLEI_JSONL}" 2>>"${SCAN_LOG}" || \
                log "WARN: nuclei had errors (partial results may be available)"

            log "Nuclei complete | findings=$(count_lines "${NUCLEI_JSONL}") elapsed=$(elapsed ${stage_start})s"
        fi
    fi
fi

# ===========================================================================
# STAGE 7: Subdomain takeover check
# ===========================================================================
if should_run "takeover"; then
    log_stage "TAKEOVER CHECK (subzy)"
    stage_start=$(date +%s)

    if [[ ! -f "${LIVE_HOSTS}" ]]; then
        log "WARN: No live hosts — skipping takeover check"
    else
        subzy run \
            --targets "${LIVE_HOSTS}" \
            --hide_fails \
            --output "${SUBZY_JSON}" 2>>"${SCAN_LOG}" || \
            log "WARN: subzy completed with warnings"

        log "Takeover check complete | elapsed=$(elapsed ${stage_start})s"
    fi
fi

# ===========================================================================
# STAGE 8: Normalize all outputs into unified asset records
# ===========================================================================
if should_run "normalize"; then
    log_stage "NORMALIZATION"
    stage_start=$(date +%s)

    NORMALIZE_ARGS=(
        --output "${ASSETS_JSONL}"
        --scan-id "${SCAN_ID}"
    )

    [[ -f "${DNS_JSONL}" ]]   && NORMALIZE_ARGS+=(--dns "${DNS_JSONL}")
    [[ -f "${PORTS_JSONL}" ]] && NORMALIZE_ARGS+=(--ports "${PORTS_JSONL}")
    [[ -f "${HTTPX_JSONL}" ]] && NORMALIZE_ARGS+=(--http "${HTTPX_JSONL}")
    [[ -f "${TLS_JSONL}" ]]   && NORMALIZE_ARGS+=(--tls "${TLS_JSONL}")
    [[ -f "${NUCLEI_JSONL}" ]] && NORMALIZE_ARGS+=(--nuclei "${NUCLEI_JSONL}")
    [[ -f "${SUBZY_JSON}" ]]  && NORMALIZE_ARGS+=(--subzy "${SUBZY_JSON}")
    [[ -f "${CMDB_EXPORT}" ]] && NORMALIZE_ARGS+=(--cmdb "${CMDB_EXPORT}")

    # Collect all zgrab files
    for zgf in "${ZGRAB_DIR}"/zgrab_*.jsonl; do
        if [[ -f "$zgf" ]]; then
            NORMALIZE_ARGS+=(--zgrab "$zgf")
        fi
    done

    python3 "${SCRIPT_DIR}/scripts/normalize.py" "${NORMALIZE_ARGS[@]}"

    log "Normalization complete | assets=$(count_lines "${ASSETS_JSONL}") elapsed=$(elapsed ${stage_start})s"
fi

# ===========================================================================
# STAGE 9: Load into DuckDB
# ===========================================================================
if should_run "load"; then
    log_stage "DUCKDB LOAD"
    stage_start=$(date +%s)

    if [[ ! -f "${ASSETS_JSONL}" ]]; then
        log "WARN: No assets file — skipping DuckDB load"
    else
        python3 "${SCRIPT_DIR}/scripts/load_duckdb.py" \
            --input "${ASSETS_JSONL}" \
            --db "${DUCKDB_PATH}" \
            --scan-id "${SCAN_ID}"

        log "DuckDB load complete | db=${DUCKDB_PATH} elapsed=$(elapsed ${stage_start})s"
    fi
fi

# ===========================================================================
# Summary
# ===========================================================================
PIPELINE_ELAPSED=$(elapsed ${PIPELINE_START})
log "=========================================="
log "EASM Pipeline complete"
log "  Scan ID:      ${SCAN_ID}"
log "  Wall clock:   ${PIPELINE_ELAPSED}s"
log "  Targets:      $(count_lines "${TARGETS_FILE}")"
log "  Live hosts:   $(count_lines "${LIVE_HOSTS}" 2>/dev/null || echo 0)"
log "  Open ports:   $(count_lines "${PORTS_JSONL}" 2>/dev/null || echo 0)"
log "  HTTP probed:  $(count_lines "${HTTPX_JSONL}" 2>/dev/null || echo 0)"
log "  TLS certs:    $(count_lines "${TLS_JSONL}" 2>/dev/null || echo 0)"
log "  Nuclei finds: $(count_lines "${NUCLEI_JSONL}" 2>/dev/null || echo 0)"
log "  Assets:       $(count_lines "${ASSETS_JSONL}" 2>/dev/null || echo 0)"
log "  Screenshots:  $(find "${SCREENSHOT_DIR}" -name '*.png' 2>/dev/null | wc -l | tr -d ' ')"
log "  DuckDB:       ${DUCKDB_PATH}"
log "  Log:          ${SCAN_LOG}"
log "=========================================="
