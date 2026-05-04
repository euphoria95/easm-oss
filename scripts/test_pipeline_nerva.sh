#!/usr/bin/env bash
# Integration test: normalize + DuckDB load with mock Nerva output.
# Requires: python3, duckdb python package
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_DIR=$(mktemp -d)
trap 'rm -rf "${TEST_DIR}"' EXIT

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

echo "=== Nerva Pipeline Integration Test ==="
echo "Test dir: ${TEST_DIR}"

# ---------------------------------------------------------------------------
# 1. Mock DNS
# ---------------------------------------------------------------------------
cat > "${TEST_DIR}/dns.jsonl" << 'JSONL'
{"host":"app.example.com","a":["10.0.0.1"]}
{"host":"db.example.com","a":["10.0.0.2"]}
{"host":"cache.example.com","a":["10.0.0.3"]}
{"host":"ftp.example.com","a":["10.0.0.4"]}
JSONL

# ---------------------------------------------------------------------------
# 2. Mock ports
# ---------------------------------------------------------------------------
cat > "${TEST_DIR}/ports.jsonl" << 'JSONL'
{"host":"10.0.0.1","port":22,"protocol":"tcp"}
{"host":"10.0.0.1","port":443,"protocol":"tcp"}
{"host":"10.0.0.2","port":3306,"protocol":"tcp"}
{"host":"10.0.0.3","port":6379,"protocol":"tcp"}
{"host":"10.0.0.4","port":21,"protocol":"tcp"}
JSONL

# ---------------------------------------------------------------------------
# 3. Mock Nerva output (matches ingest_nerva() expected fields)
#    - "protocol" field = service name
#    - "metadata" contains version/banner
#    - top-level "cpe" for CPE 2.3
#    - "security_findings" for --misconfigs output
# ---------------------------------------------------------------------------
cat > "${TEST_DIR}/nerva.jsonl" << 'JSONL'
{"host":"10.0.0.1","ip":"10.0.0.1","port":22,"protocol":"ssh","transport":"tcp","metadata":{"version":"OpenSSH 8.9p1","banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7"},"cpe":"cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*","security_findings":[]}
{"host":"10.0.0.1","ip":"10.0.0.1","port":443,"protocol":"http","transport":"tcp","metadata":{"server_version":"nginx/1.25.0"},"cpe":"cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*","security_findings":[]}
{"host":"10.0.0.2","ip":"10.0.0.2","port":3306,"protocol":"mysql","transport":"tcp","metadata":{"server_version":"8.0.36"},"cpe":"cpe:2.3:a:oracle:mysql:8.0.36:*:*:*:*:*:*:*","security_findings":[]}
{"host":"10.0.0.3","ip":"10.0.0.3","port":6379,"protocol":"redis","transport":"tcp","metadata":{},"security_findings":[{"id":"redis-no-auth","description":"Redis requires no authentication","severity":"critical"}]}
{"host":"10.0.0.4","ip":"10.0.0.4","port":21,"protocol":"ftp","transport":"tcp","metadata":{"banner":"220 (vsFTPd 3.0.5)","version":"vsftpd 3.0.5"},"cpe":"cpe:2.3:a:beasts:vsftpd:3.0.5:*:*:*:*:*:*:*","security_findings":[]}
JSONL

# ---------------------------------------------------------------------------
# 4. Run normalize.py
# ---------------------------------------------------------------------------
echo ""
echo "--- Running normalize.py ---"
python3 "${SCRIPT_DIR}/normalize.py" \
    --dns   "${TEST_DIR}/dns.jsonl" \
    --ports "${TEST_DIR}/ports.jsonl" \
    --nerva "${TEST_DIR}/nerva.jsonl" \
    --output "${TEST_DIR}/assets.jsonl" \
    --scan-id "test_nerva_001"

# ---------------------------------------------------------------------------
# 5. Verify assets.jsonl
# ---------------------------------------------------------------------------
echo ""
echo "--- Verifying assets.jsonl ---"
ASSET_COUNT=$(wc -l < "${TEST_DIR}/assets.jsonl" | tr -d ' ')
echo "Assets generated: ${ASSET_COUNT}"
[[ "${ASSET_COUNT}" -ge 4 ]] || fail "Expected >= 4 assets, got ${ASSET_COUNT}"
pass "asset count >= 4"

python3 - << PYEOF
import json, sys

path = "${TEST_DIR}/assets.jsonl"
assets = []
with open(path) as f:
    for line in f:
        assets.append(json.loads(line))

# All services must have fingerprint sub-dict with required keys
required_fp_keys = {"vendor","product","version","cpe23","os_vendor","os_product","os_version","certainty","source"}
for a in assets:
    for svc in a.get("services", []):
        fp = svc.get("fingerprint")
        if fp is None:
            print(f"FAIL: no fingerprint on {a['fqdn']}:{svc['port']}")
            sys.exit(1)
        missing = required_fp_keys - fp.keys()
        if missing:
            print(f"FAIL: missing fingerprint keys {missing} on {a['fqdn']}:{svc['port']}")
            sys.exit(1)
print("PASS: fingerprint structure on all services")

# CPE propagated for known services
with_cpe = [a for a in assets if any(s["fingerprint"]["cpe23"] for s in a.get("services", []))]
if len(with_cpe) < 3:
    print(f"FAIL: expected >= 3 assets with CPE, got {len(with_cpe)}")
    sys.exit(1)
print(f"PASS: CPE on {len(with_cpe)} assets")

# Misconfig finding from redis security_findings
findings = [f for a in assets for f in a.get("findings", []) if f.get("source") == "nerva_misconfig"]
if not findings:
    print("FAIL: no nerva_misconfig findings found")
    sys.exit(1)
print(f"PASS: {len(findings)} nerva_misconfig finding(s) ingested")

# OS hint extracted for SSH asset
ssh_assets = [a for a in assets if any(s["service"] == "ssh" for s in a.get("services", []))]
if ssh_assets:
    fp = next(s["fingerprint"] for s in ssh_assets[0]["services"] if s["service"] == "ssh")
    if fp["os_product"] != "Ubuntu":
        print(f"FAIL: expected Ubuntu OS hint, got '{fp['os_product']}'")
        sys.exit(1)
    print(f"PASS: OS hint Ubuntu extracted from SSH banner")
PYEOF

pass "assets.jsonl structure"

# ---------------------------------------------------------------------------
# 6. Load into DuckDB
# ---------------------------------------------------------------------------
echo ""
echo "--- Loading DuckDB ---"
python3 "${SCRIPT_DIR}/load_duckdb.py" \
    --input   "${TEST_DIR}/assets.jsonl" \
    --db      "${TEST_DIR}/test.duckdb" \
    --scan-id "test_nerva_001" \
    --no-parquet

# ---------------------------------------------------------------------------
# 7. Verify DuckDB views
# ---------------------------------------------------------------------------
echo ""
echo "--- Verifying DuckDB views ---"
python3 - << PYEOF
import duckdb, sys

con = duckdb.connect("${TEST_DIR}/test.duckdb", read_only=True)

# v_services exists and has rows
rows = con.execute("SELECT COUNT(*) FROM v_services").fetchone()[0]
print(f"v_services rows: {rows}")
if rows < 5:
    print(f"FAIL: expected >= 5 service rows, got {rows}")
    sys.exit(1)
print("PASS: v_services has data")

# CPE propagated through DuckDB
cpe_rows = con.execute(
    "SELECT COUNT(*) FROM v_services WHERE fp_cpe23 IS NOT NULL AND fp_cpe23 != ''"
).fetchone()[0]
print(f"Services with CPE: {cpe_rows}")
if cpe_rows < 3:
    print(f"FAIL: expected >= 3 CPE rows, got {cpe_rows}")
    sys.exit(1)
print("PASS: CPE values in v_services")

# Confidence scores present
conf_rows = con.execute(
    "SELECT COUNT(*) FROM v_services WHERE fp_certainty IS NOT NULL"
).fetchone()[0]
print(f"Services with certainty: {conf_rows}")
if conf_rows < 1:
    print("FAIL: no certainty values in v_services")
    sys.exit(1)
print("PASS: certainty values in v_services")

# v_software_inventory populated
inv = con.execute("SELECT COUNT(*) FROM v_software_inventory").fetchone()[0]
print(f"Software inventory entries: {inv}")
if inv < 3:
    print(f"FAIL: expected >= 3 inventory entries, got {inv}")
    sys.exit(1)
print("PASS: v_software_inventory has data")

# v_scan_stats includes service columns
stats = con.execute(
    "SELECT total_services, assets_with_services FROM v_scan_stats"
).fetchone()
if stats is None or stats[0] is None:
    print("FAIL: v_scan_stats missing total_services")
    sys.exit(1)
print(f"Scan stats — total_services={stats[0]}, assets_with_services={stats[1]}")
if stats[0] < 5:
    print(f"FAIL: expected >= 5 total_services, got {stats[0]}")
    sys.exit(1)
print("PASS: v_scan_stats service columns")

# v_asset_summary includes service_count
sc = con.execute(
    "SELECT SUM(service_count) FROM v_asset_summary"
).fetchone()[0]
if sc is None or sc < 5:
    print(f"FAIL: v_asset_summary.service_count sum too low: {sc}")
    sys.exit(1)
print(f"PASS: v_asset_summary.service_count (sum={sc})")

con.close()
print("")
print("All DuckDB view checks passed.")
PYEOF

echo ""
echo "=== All Nerva integration tests PASSED ==="
