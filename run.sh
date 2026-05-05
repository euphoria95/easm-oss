#!/usr/bin/env bash
# =============================================================================
# EASM Pipeline Orchestrator
# =============================================================================
# Funnel-based EASM discovery pipeline:
#   DNS → ASN → Port Scan → HTTP Probe → TLS → nerva → Nuclei
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
NERVA_JSONL="${OUTPUT_DIR}/nerva.jsonl"
VERIFY_JSONL="${OUTPUT_DIR}/takeover_verifications.jsonl"
IP_TARGETS="${OUTPUT_DIR}/ip_targets.txt"
FQDN_TARGETS="${OUTPUT_DIR}/fqdn_targets.txt"
ASN_JSONL="${OUTPUT_DIR}/asn.jsonl"
RDNS_JSONL="${OUTPUT_DIR}/rdns.jsonl"

SCAN_ID="$(date -u +%Y%m%d_%H%M%S)"
SCAN_LOG="${LOG_DIR}/scan_${SCAN_ID}.log"
SCAN_MARKER="${OUTPUT_DIR}/scan_id.txt"

# CLI args
STAGE_ORDER="dns,asn,rdns,ports,http,tls,fingerprint,nuclei,takeover,normalize,load,verify"
STAGE_FILTER=""
FROM_STAGE=""
DRY_RUN=false

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --)             shift ;;
        --stage)        STAGE_FILTER="$2"; shift 2 ;;
        --from)         FROM_STAGE="$2"; shift 2 ;;
        --dry-run)      DRY_RUN=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--stage STAGE1,STAGE2 | --from STAGE] [--dry-run]"
            echo ""
            echo "  --stage STAGES  Run only the specified comma-separated stages"
            echo "  --from  STAGE   Run from STAGE through the end of the pipeline"
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
                      "${ASN_JSONL}" "${RDNS_JSONL}" "${DNS_JSONL}" "${LIVE_HOSTS}" \
                      "${PORTS_JSONL}" "${WEB_TARGETS}" "${HTTPX_JSONL}" \
                      "${TLS_JSONL}" "${NERVA_JSONL}" "${NUCLEI_JSONL}" \
                      "${SUBZY_JSON}" "${ASSETS_JSONL}" "${VERIFY_JSONL}"
                mkdir -p "${ZGRAB_DIR}"
            fi
        fi
    fi
    echo "${SCAN_ID}" > "${SCAN_MARKER}"
fi

# Build normalized targets (lowercase, deduplicated)
if [[ ! -f "${TARGETS_FILE}" ]]; then
    tr '[:upper:]' '[:lower:]' < "${INPUT_SUBDOMAINS}" \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
        | grep -v '^$' \
        | sort -u > "${TARGETS_FILE}"
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

    dnsx -l "${FQDN_TARGETS}" \
        -a -aaaa -cname -ns -mx -resp \
        -r "${RESOLVERS}" \
        -rate-limit "${DNS_RATE_LIMIT:-500}" \
        -retry "${DNS_RETRIES:-2}" \
        -silent -json \
        -o "${DNS_JSONL}" 2>>"${SCAN_LOG}"

    # Extract live hostnames
    jq -r '.host // empty' "${DNS_JSONL}" | sort -u > "${LIVE_HOSTS}"

    # Merge direct IP targets into live hosts
    if [[ -s "${IP_TARGETS}" ]]; then
        cat "${IP_TARGETS}" >> "${LIVE_HOSTS}"
        sort -u "${LIVE_HOSTS}" -o "${LIVE_HOSTS}"
    fi

    log "DNS complete | resolved=$(count_lines "${LIVE_HOSTS}") elapsed=$(elapsed ${stage_start})s"
fi

# ===========================================================================
# STAGE 1.5: ASN Enrichment (offline, pyasn)
# ===========================================================================
if should_run "asn"; then
    log_stage "ASN ENRICHMENT (pyasn)"
    stage_start=$(date +%s)

    ASN_DB="${CACHE_DIR}/ipasn.dat"
    ASN_NAMES="${CACHE_DIR}/asn_names.tsv"

    # Bootstrap ASN database if missing or stale (>7 days)
    if [[ ! -f "${ASN_DB}" ]] || [[ $(find "${CACHE_DIR}" -name "ipasn.dat" -mtime +7 2>/dev/null | wc -l) -gt 0 ]]; then
        log "Downloading fresh BGP RIB data..."
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
        log "ASN enrichment complete | ips=$(count_lines "${ASN_JSONL}") elapsed=$(elapsed ${stage_start})s"
    else
        log "WARN: No ASN database available — skipping ASN enrichment"
    fi
fi

# ===========================================================================
# STAGE 1.75: Reverse DNS (PTR lookups via dnsx)
# ===========================================================================
if should_run "rdns"; then
    log_stage "REVERSE DNS (dnsx -ptr)"
    stage_start=$(date +%s)

    RDNS_INPUT="${OUTPUT_DIR}/rdns_ips.txt"

    # Collect all in-scope IPs: from DNS A records + direct IP targets
    {
        [[ -f "${DNS_JSONL}" ]] && jq -r '.a[]? // empty' "${DNS_JSONL}"
        [[ -f "${IP_TARGETS}" ]] && cat "${IP_TARGETS}"
    } | sort -u > "${RDNS_INPUT}"

    IP_COUNT=$(count_lines "${RDNS_INPUT}")
    if [[ "${IP_COUNT}" -gt 0 ]]; then
        log "Reverse DNS: ${IP_COUNT} IPs"
        dnsx -l "${RDNS_INPUT}" \
            -ptr -resp \
            -r "${RESOLVERS}" \
            -rate-limit "${DNS_RATE_LIMIT:-500}" \
            -retry "${DNS_RETRIES:-2}" \
            -silent -json \
            -o "${RDNS_JSONL}" 2>>"${SCAN_LOG}"

        log "Reverse DNS complete | records=$(count_lines "${RDNS_JSONL}") elapsed=$(elapsed ${stage_start})s"
    else
        log "WARN: No IPs for reverse DNS"
    fi
    rm -f "${RDNS_INPUT}"
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
# STAGE 5: Service Fingerprinting (nerva — replaces zgrab2)
# ===========================================================================
if should_run "fingerprint"; then
    log_stage "SERVICE FINGERPRINTING (nerva)"
    stage_start=$(date +%s)

    if [[ ! -f "${PORTS_JSONL}" ]]; then
        log "WARN: No ports data — skipping fingerprinting"
    else
        NERVA_TIMEOUT="${NERVA_TIMEOUT:-10}"
        NERVA_THREADS="${NERVA_THREADS:-50}"
        NERVA_FAST_MODE="${NERVA_FAST_MODE:-false}"
        NERVA_UDP="${NERVA_UDP:-false}"
        NERVA_MISCONFIGS="${NERVA_MISCONFIGS:-false}"

        # Prefer fqdn:port over ip:port so nerva results map to FQDN-keyed assets.
        # Join ports.jsonl with dns.jsonl (ip → fqdn). Fall back to ip:port when
        # no FQDN is known for an IP.
        if [[ -f "${DNS_JSONL}" ]]; then
            TARGETS=$(jq -rs \
                --slurpfile dns "${DNS_JSONL}" \
                '($dns | map(.host as $f | (.a // [])[] | {(.): $f}) | add // {}) as $ip_map |
                 .[] |
                 (($ip_map[(.host // .ip)] // (.host // .ip))) as $h |
                 "\($h):\(.port)"' \
                "${PORTS_JSONL}" 2>/dev/null | sort -u)
        else
            TARGETS=$(jq -r '"\(.host // .ip):\(.port)"' "${PORTS_JSONL}" 2>/dev/null | sort -u)
        fi
        TARGET_COUNT=$(echo "${TARGETS}" | wc -l | tr -d ' ')

        if [[ -z "${TARGETS}" || "${TARGET_COUNT}" -eq 0 ]]; then
            log "WARN: No targets for fingerprinting"
        else
            TIMEOUT_MS=$(( NERVA_TIMEOUT * 1000 ))
            log "nerva: ${TARGET_COUNT} targets (timeout=${NERVA_TIMEOUT}s, workers=${NERVA_THREADS}, misconfigs=${NERVA_MISCONFIGS})"

            NERVA_CMD=(nerva
                -w "${TIMEOUT_MS}"
                -W "${NERVA_THREADS}"
                --json
            )
            [[ "${NERVA_FAST_MODE}" == "true" ]]  && NERVA_CMD+=(-f)
            [[ "${NERVA_UDP}" == "true" ]]         && NERVA_CMD+=(-U)
            [[ "${NERVA_MISCONFIGS}" == "true" ]]  && NERVA_CMD+=(--misconfigs)

            echo "${TARGETS}" | "${NERVA_CMD[@]}" > "${NERVA_JSONL}" 2>>"${SCAN_LOG}" || \
                log "WARN: nerva had errors (partial results may be available)"

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

    NUCLEI_TMPL_COUNT=$(nuclei -tl 2>/dev/null | wc -l | tr -d ' ')
    if [[ "${NUCLEI_TMPL_COUNT}" -eq 0 ]]; then
        log "Nuclei templates missing — attempting update"
        nuclei -update-templates 2>>"${SCAN_LOG}" || log "WARN: nuclei template update failed"
        NUCLEI_TMPL_COUNT=$(nuclei -tl 2>/dev/null | wc -l | tr -d ' ')
    fi
    log "Nuclei templates loaded: ${NUCLEI_TMPL_COUNT}"

    if [[ ! -f "${HTTPX_JSONL}" ]]; then
        log "WARN: No HTTP data — skipping nuclei (run from 'http' stage first)"
    else
        URLS=$(jq -r '.url // empty' "${HTTPX_JSONL}" | sort -u)
        URL_COUNT=$(echo "${URLS}" | grep -c . || true)
        if [[ -z "${URLS}" ]] || [[ "${URL_COUNT}" -eq 0 ]]; then
            log "WARN: No URLs extracted from ${HTTPX_JSONL}"
        else
            # --- Pass 1: Generic broad scan ---
            log "Nuclei pass 1 (generic): scanning ${URL_COUNT} URLs"
            echo "${URLS}" | \
            nuclei \
                -config "${NUCLEI_CONFIG}" \
                -H "User-Agent: ${USER_AGENT}" \
                -o "${NUCLEI_JSONL}" 2>>"${SCAN_LOG}" || \
                log "WARN: nuclei pass 1 had errors"

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
    [[ -f "${TLS_JSONL}" ]]    && NORMALIZE_ARGS+=(--tls "${TLS_JSONL}")
    [[ -f "${NERVA_JSONL}" ]] && NORMALIZE_ARGS+=(--nerva "${NERVA_JSONL}")
    [[ -f "${NUCLEI_JSONL}" ]] && NORMALIZE_ARGS+=(--nuclei "${NUCLEI_JSONL}")
    [[ -f "${SUBZY_JSON}" ]]  && NORMALIZE_ARGS+=(--subzy "${SUBZY_JSON}")
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
            python3 "${SCRIPT_DIR}/scripts/archive_scan.py" \
                --db "${DUCKDB_PATH}" \
                --scan-id "${PREV_SCAN_ID}" \
                --archive-dir "${ARCHIVE_DIR}" \
                --input-file "${INPUT_SUBDOMAINS}" 2>>"${SCAN_LOG}" || \
                log "WARN: Archive failed (non-fatal)"

            log "Archive complete | prev_scan=${PREV_SCAN_ID} elapsed=$(elapsed ${stage_start})s"
        else
            log "No previous scan to archive (first run or already archived)"
        fi
    fi

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
# STAGE 10: Verify takeover candidates (live DNS + HTTP fingerprint)
# ===========================================================================
if should_run "verify"; then
    log_stage "TAKEOVER VERIFICATION"
    stage_start=$(date +%s)

    if [[ ! -f "${DUCKDB_PATH}" ]]; then
        log "WARN: DuckDB not found — skipping takeover verification"
    else
        python3 "${SCRIPT_DIR}/scripts/verify_takeovers.py" \
            --db  "${DUCKDB_PATH}" \
            --out "${VERIFY_JSONL}" 2>>"${SCAN_LOG}" || \
            log "WARN: takeover verification completed with warnings"

        log "Takeover verification complete | elapsed=$(elapsed ${stage_start})s"
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
log "  Takeover chk: $(count_lines "${VERIFY_JSONL}" 2>/dev/null || echo 0) verified"
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
