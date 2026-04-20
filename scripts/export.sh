#!/usr/bin/env bash
# =============================================================================
# EASM Pipeline — Export Utilities
# Export DuckDB data to various formats for downstream consumption.
#
# Usage:
#   ./export.sh --db data/output/easm.duckdb --format csv --query stats
#   ./export.sh --db data/output/easm.duckdb --format parquet --all
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB=""
FORMAT="csv"
QUERY=""
ALL=false
OUTPUT_DIR="data/output/exports"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --db)      DB="$2"; shift 2 ;;
        --format)  FORMAT="$2"; shift 2 ;;
        --query)   QUERY="$2"; shift 2 ;;
        --all)     ALL=true; shift ;;
        --output)  OUTPUT_DIR="$2"; shift 2 ;;
        *)         echo "Unknown: $1"; exit 1 ;;
    esac
done

DB="${DB:?--db required}"
mkdir -p "${OUTPUT_DIR}"

export_query() {
    local name="$1"
    local sql="$2"
    local out="${OUTPUT_DIR}/${name}.${FORMAT}"

    case "${FORMAT}" in
        csv)
            python3 -c "
import duckdb, sys
con = duckdb.connect('${DB}', read_only=True)
df = con.execute(\"\"\"${sql}\"\"\").fetchdf()
df.to_csv('${out}', index=False)
con.close()
print(f'Exported: ${out} ({len(df)} rows)')
"
            ;;
        parquet)
            python3 -c "
import duckdb
con = duckdb.connect('${DB}', read_only=True)
con.execute(\"COPY (${sql}) TO '${out}' (FORMAT PARQUET, COMPRESSION ZSTD)\")
con.close()
print(f'Exported: ${out}')
"
            ;;
        json)
            python3 -c "
import duckdb, json, sys
con = duckdb.connect('${DB}', read_only=True)
df = con.execute(\"\"\"${sql}\"\"\").fetchdf()
df.to_json('${out}', orient='records', indent=2)
con.close()
print(f'Exported: ${out} ({len(df)} rows)')
"
            ;;
        *)
            echo "Unknown format: ${FORMAT}" >&2
            exit 1
            ;;
    esac
}

if ${ALL}; then
    export_query "assets" "SELECT * FROM assets"
    export_query "findings" "SELECT * FROM v_findings"
    export_query "tls_issues" "SELECT * FROM v_tls_issues"
    export_query "cmdb_gaps" "SELECT * FROM v_cmdb_gaps"
    export_query "tech_stack" "SELECT * FROM v_tech_stack"
    export_query "open_ports" "SELECT * FROM v_open_ports"
    export_query "scan_stats" "SELECT * FROM v_scan_stats"
    echo "All exports complete: ${OUTPUT_DIR}/"
elif [[ -n "${QUERY}" ]]; then
    export_query "${QUERY}" "SELECT * FROM ${QUERY}"
else
    echo "Provide --query <view_name> or --all" >&2
    exit 1
fi
