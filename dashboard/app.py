#!/usr/bin/env python3
"""
EASM Dashboard — FastAPI Application

Serves the EASM dashboard SPA and provides REST API endpoints
for querying the DuckDB database.

Usage:
    uvicorn dashboard.app:app --host 0.0.0.0 --port 8443
    python3 -m uvicorn dashboard.app:app --host 0.0.0.0 --port 8443
"""

import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import duckdb
import orjson
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Import create_views from pipeline scripts
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
try:
    from load_duckdb import create_views as _duckdb_create_views
except ImportError:
    _duckdb_create_views = None

try:
    from load_duckdb import create_bounty_views as _duckdb_create_bounty_views
except ImportError:
    _duckdb_create_bounty_views = None

DB_PATH = os.environ.get("EASM_DB_PATH", "data/output/easm.duckdb")
STATIC_DIR = Path(__file__).parent / "static"
PROJECT_ROOT = Path(__file__).parent.parent
ARCHIVE_DIR = PROJECT_ROOT / "data" / "archives"
INPUT_DIR = PROJECT_ROOT / "data" / "input"
SCAN_STATE_FILE = PROJECT_ROOT / "data" / ".scan_state.json"

app = FastAPI(title="EASM Dashboard", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

_scan_lock = threading.Lock()

SCAN_ID_RE = re.compile(r"^\d{8}_\d{6}$")

_ARCHIVE_CACHE_MAX = 3
_archive_cache: "OrderedDict[str, duckdb.DuckDBPyConnection]" = OrderedDict()
_archive_cache_lock = threading.Lock()

_MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB


class ORJSONResponse(JSONResponse):
    media_type = "application/json"

    def render(self, content) -> bytes:
        return orjson.dumps(content, option=orjson.OPT_NON_STR_KEYS)


def get_db():
    db_path = Path(DB_PATH)
    if not db_path.exists():
        raise HTTPException(
            status_code=503,
            detail="Database not found. Run the EASM pipeline first.",
        )
    con = duckdb.connect(str(db_path), read_only=True)
    try:
        yield con
    finally:
        con.close()


def query_rows(con, sql, params=None):
    result = con.execute(sql, params or [])
    columns = [desc[0] for desc in result.description]
    return [dict(zip(columns, row)) for row in result.fetchall()]


def query_one(con, sql, params=None):
    rows = query_rows(con, sql, params)
    return rows[0] if rows else None


def safe_query(con, sql, params=None, default=None):
    try:
        return query_rows(con, sql, params)
    except Exception:
        return default if default is not None else []


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.get("/", response_class=FileResponse)
def root():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/favicon.ico")
def favicon():
    return JSONResponse(status_code=204, content=None)


# ---------------------------------------------------------------------------
# API — Overview (executive dashboard)
# ---------------------------------------------------------------------------

def _get_overview(con) -> dict:
    scan = query_one(con, "SELECT * FROM v_scan_stats LIMIT 1") or {}

    findings_by_severity = safe_query(
        con,
        """
        SELECT severity, COUNT(*) AS count
        FROM v_findings
        GROUP BY severity
        ORDER BY CASE severity
            WHEN 'critical' THEN 1 WHEN 'high' THEN 2
            WHEN 'medium' THEN 3 WHEN 'low' THEN 4
            WHEN 'info' THEN 5 ELSE 6
        END
        """,
    )
    sev_map = {r["severity"]: r["count"] for r in findings_by_severity}

    tls_health = query_one(
        con,
        """
        SELECT
            (SELECT COUNT(*) FROM assets WHERE len(tls) > 0) AS total_certs,
            COUNT(*) FILTER (WHERE expired) AS expired,
            COUNT(*) FILTER (WHERE self_signed) AS self_signed,
            COUNT(*) FILTER (WHERE mismatched) AS mismatched,
            COUNT(*) FILTER (WHERE days_to_expiry BETWEEN 0 AND 30) AS expiring_30d,
            COUNT(*) FILTER (WHERE revoked) AS revoked,
            COUNT(*) FILTER (WHERE untrusted) AS untrusted
        FROM v_tls_issues
        """,
    ) or {}

    top_tech = safe_query(
        con,
        """
        SELECT tech_name AS name, COUNT(*) AS count
        FROM v_tech_stack
        GROUP BY tech_name
        ORDER BY count DESC
        LIMIT 12
        """,
    )

    port_dist = safe_query(
        con,
        """
        SELECT port, COUNT(*) AS count
        FROM v_open_ports
        GROUP BY port
        ORDER BY count DESC
        LIMIT 15
        """,
    )

    cdn_dist = safe_query(
        con,
        """
        SELECT
            COALESCE(network.cdn, 'Direct') AS cdn,
            COUNT(*) AS count,
            ROUND(COUNT(*) * 100.0 / NULLIF(SUM(COUNT(*)) OVER(), 0), 1) AS pct
        FROM assets
        GROUP BY cdn
        ORDER BY count DESC
        """,
    )

    critical_findings = safe_query(
        con,
        """
        SELECT * FROM v_findings
        WHERE severity IN ('critical', 'high')
        LIMIT 20
        """,
    )

    service_dist = safe_query(
        con,
        """
        SELECT service, COUNT(*) AS count
        FROM v_services
        GROUP BY service
        ORDER BY count DESC
        LIMIT 15
        """,
    )

    top_software = safe_query(
        con,
        """
        SELECT product, vendor, version, host_count, cpe23
        FROM v_software_inventory
        LIMIT 10
        """,
    )

    total = scan.get("total_assets", 0) or 0
    tls_total = tls_health.get("total_certs", 0) or 0
    tls_issues_count = sum(
        tls_health.get(k, 0) or 0
        for k in ("expired", "self_signed", "mismatched", "expiring_30d")
    )
    tls_healthy = max(0, tls_total - tls_issues_count)

    risk_score = _calculate_risk_score(
        total=total,
        critical=sev_map.get("critical", 0),
        high=sev_map.get("high", 0),
        medium=sev_map.get("medium", 0),
        tls_issues=tls_issues_count,
        shadow_it=scan.get("shadow_it", 0) or 0,
    )

    return {
        "scan": scan,
        "risk_score": risk_score,
        "findings_by_severity": findings_by_severity,
        "severity_map": sev_map,
        "tls_health": {**tls_health, "healthy": tls_healthy, "issues_total": tls_issues_count},
        "top_technologies": top_tech,
        "port_distribution": port_dist,
        "cdn_distribution": cdn_dist,
        "critical_findings": critical_findings,
        "service_distribution": service_dist,
        "top_software": top_software,
    }


@app.get("/api/overview", response_class=ORJSONResponse)
def overview(db=Depends(get_db)):
    return _get_overview(db)


def _calculate_risk_score(total, critical, high, medium, tls_issues, shadow_it):
    if total == 0:
        return 0
    score = 0
    score += min(40, critical * 12)
    score += min(25, high * 3)
    score += min(10, medium * 0.4)
    tls_rate = tls_issues / max(total, 1)
    score += min(15, tls_rate * 150)
    shadow_rate = shadow_it / max(total, 1)
    score += min(10, shadow_rate * 80)
    return min(100, round(score))


# ---------------------------------------------------------------------------
# API — Assets
# ---------------------------------------------------------------------------

def _get_assets(
    con,
    page: int,
    limit: int,
    search: str,
    sort: str,
    order: str,
    tag: str,
    gap_type: str,
    has_findings: str,
) -> dict:
    allowed_sorts = {
        "fqdn", "port_count", "web_entry_count", "finding_count",
        "tls_cert_count", "cdn", "asn_org", "gap_type", "service_count",
    }
    sort_col = sort if sort in allowed_sorts else "fqdn"
    sort_dir = "DESC" if order.lower() == "desc" else "ASC"
    offset = (page - 1) * limit

    where_clauses = []
    params = []
    if search:
        where_clauses.append("fqdn ILIKE ?")
        params.append(f"%{search}%")
    if tag:
        where_clauses.append("list_contains(tags, ?)")
        params.append(tag)
    if gap_type:
        where_clauses.append("gap_type = ?")
        params.append(gap_type)
    if has_findings == "true":
        where_clauses.append("finding_count > 0")

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    count_sql = f"SELECT COUNT(*) AS total FROM v_asset_summary{where_sql}"
    total = (query_one(con, count_sql, params) or {}).get("total", 0)

    data_sql = f"""
        SELECT * FROM v_asset_summary
        {where_sql}
        ORDER BY {sort_col} {sort_dir}
        LIMIT ? OFFSET ?
    """
    items = query_rows(con, data_sql, params + [limit, offset])

    return {
        "items": items,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": math.ceil(total / limit) if limit else 0,
    }


@app.get("/api/assets", response_class=ORJSONResponse)
def list_assets(
    db=Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    search: str = Query(""),
    sort: str = Query("fqdn"),
    order: str = Query("asc"),
    tag: str = Query(""),
    gap_type: str = Query(""),
    has_findings: str = Query(""),
):
    return _get_assets(db, page, limit, search, sort, order, tag, gap_type, has_findings)


def _get_asset(con, fqdn: str) -> dict:
    rows = query_rows(con, "SELECT * FROM assets WHERE fqdn = ?", [fqdn.lower()])
    if not rows:
        raise HTTPException(status_code=404, detail="Asset not found")
    asset = rows[0]
    _convert_nested(asset)
    return asset


@app.get("/api/assets/{fqdn}", response_class=ORJSONResponse)
def get_asset(fqdn: str, db=Depends(get_db)):
    return _get_asset(db, fqdn)


def _convert_nested(asset):
    """Ensure nested DuckDB structs are JSON-serializable."""
    for key in ("dns", "network", "cmdb"):
        val = asset.get(key)
        if val is not None and not isinstance(val, dict):
            asset[key] = dict(val) if hasattr(val, "_asdict") else val
    for key in ("web", "tls", "services", "findings"):
        val = asset.get(key)
        if val is not None and not isinstance(val, list):
            asset[key] = list(val)


# ---------------------------------------------------------------------------
# API — Findings
# ---------------------------------------------------------------------------

def _get_findings(con, severity: str, source: str, search: str, tag: str, limit: int) -> dict:
    where = []
    params = []
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if source:
        where.append("finding_source = ?")
        params.append(source)
    if search:
        where.append("(fqdn ILIKE ? OR finding_name ILIKE ? OR template_id ILIKE ?)")
        params.extend([f"%{search}%"] * 3)
    if tag:
        where.append("list_contains(tags, ?)")
        params.append(tag)

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    sql = f"SELECT * FROM v_findings{where_sql} LIMIT ?"
    params.append(limit)
    items = query_rows(con, sql, params)

    summary = safe_query(
        con,
        """
        SELECT severity, COUNT(*) AS count
        FROM v_findings
        GROUP BY severity
        ORDER BY CASE severity
            WHEN 'critical' THEN 1 WHEN 'high' THEN 2
            WHEN 'medium' THEN 3 WHEN 'low' THEN 4
            WHEN 'info' THEN 5 ELSE 6
        END
        """,
    )

    return {"items": items, "summary": summary}


@app.get("/api/findings", response_class=ORJSONResponse)
def list_findings(
    db=Depends(get_db),
    severity: str = Query(""),
    source: str = Query(""),
    search: str = Query(""),
    tag: str = Query(""),
    limit: int = Query(200, ge=1, le=1000),
):
    return _get_findings(db, severity, source, search, tag, limit)


def _get_findings_tags(con) -> dict:
    rows = safe_query(
        con,
        """
        WITH expanded AS (
            SELECT UNNEST(tags) AS tag FROM v_findings WHERE tags IS NOT NULL
        )
        SELECT tag, COUNT(*) AS count
        FROM expanded
        WHERE tag IS NOT NULL AND tag != ''
        GROUP BY tag
        ORDER BY count DESC
        """,
    )
    return {"tags": rows}


@app.get("/api/findings/tags", response_class=ORJSONResponse)
def findings_tags(db=Depends(get_db)):
    return _get_findings_tags(db)


# ---------------------------------------------------------------------------
# API — TLS
# ---------------------------------------------------------------------------

def _get_tls(con, limit: int) -> dict:
    items = safe_query(con, f"SELECT * FROM v_tls_issues LIMIT {limit}")

    summary = query_one(
        con,
        """
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE expired) AS expired,
            COUNT(*) FILTER (WHERE self_signed) AS self_signed,
            COUNT(*) FILTER (WHERE mismatched) AS mismatched,
            COUNT(*) FILTER (WHERE revoked) AS revoked,
            COUNT(*) FILTER (WHERE untrusted) AS untrusted,
            COUNT(*) FILTER (WHERE days_to_expiry BETWEEN 0 AND 30) AS expiring_30d
        FROM v_tls_issues
        """,
    ) or {}

    return {"items": items, "summary": summary}


@app.get("/api/tls", response_class=ORJSONResponse)
def list_tls_issues(db=Depends(get_db), limit: int = Query(200, ge=1, le=1000)):
    return _get_tls(db, limit)


# ---------------------------------------------------------------------------
# API — CMDB Gaps
# ---------------------------------------------------------------------------

def _get_cmdb(con, gap_type: str, limit: int) -> dict:
    where = []
    params = []
    if gap_type:
        where.append("gap_type = ?")
        params.append(gap_type)

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    items = query_rows(
        con, f"SELECT * FROM v_cmdb_gaps{where_sql} LIMIT ?", params + [limit]
    )

    summary = safe_query(
        con,
        """
        SELECT
            gap_type,
            COUNT(*) AS count
        FROM v_cmdb_gaps
        WHERE gap_type IS NOT NULL
        GROUP BY gap_type
        ORDER BY count DESC
        """,
    )

    scan = query_one(con, "SELECT * FROM v_scan_stats LIMIT 1") or {}

    return {
        "items": items,
        "summary": summary,
        "coverage": {
            "total": scan.get("total_assets", 0),
            "in_cmdb": scan.get("in_cmdb", 0),
            "not_in_cmdb": scan.get("not_in_cmdb", 0),
            "shadow_it": scan.get("shadow_it", 0),
            "stale_ci": scan.get("stale_ci", 0),
        },
    }


@app.get("/api/cmdb", response_class=ORJSONResponse)
def list_cmdb_gaps(
    db=Depends(get_db),
    gap_type: str = Query(""),
    limit: int = Query(300, ge=1, le=1000),
):
    return _get_cmdb(db, gap_type, limit)


# ---------------------------------------------------------------------------
# API — Network
# ---------------------------------------------------------------------------

def _get_network_ports(con, port) -> dict:
    heatmap = safe_query(
        con,
        """
        SELECT port, COUNT(*) AS count
        FROM v_open_ports
        GROUP BY port
        ORDER BY count DESC
        """,
    )
    if port is not None:
        details = safe_query(
            con,
            """
            SELECT fqdn, port, protocol, cdn, asn_org
            FROM v_open_ports
            WHERE port = ?
            ORDER BY fqdn
            """,
            [port],
        )
    else:
        details = []
    return {"heatmap": heatmap, "details": details}


@app.get("/api/network/ports", response_class=ORJSONResponse)
def port_distribution(
    db=Depends(get_db),
    port: int = Query(None, description="Filter details to a specific port"),
):
    return _get_network_ports(db, port)


def _get_network_tech(con) -> dict:
    summary = safe_query(
        con,
        """
        SELECT tech_name AS name, COUNT(*) AS count
        FROM v_tech_stack
        GROUP BY tech_name
        ORDER BY count DESC
        """,
    )
    details = safe_query(
        con,
        """
        SELECT tech_name AS name, tech_version AS version, COUNT(*) AS count
        FROM v_tech_stack
        GROUP BY tech_name, tech_version
        ORDER BY count DESC
        LIMIT 100
        """,
    )
    return {"summary": summary, "details": details}


@app.get("/api/network/tech", response_class=ORJSONResponse)
def tech_distribution(db=Depends(get_db)):
    return _get_network_tech(db)


def _get_network_cdn(con) -> dict:
    summary = safe_query(
        con,
        """
        SELECT
            COALESCE(network.cdn, 'Direct') AS cdn,
            COUNT(*) AS count,
            ROUND(COUNT(*) * 100.0 / NULLIF(SUM(COUNT(*)) OVER(), 0), 1) AS pct
        FROM assets
        GROUP BY cdn
        ORDER BY count DESC
        """,
    )
    details = safe_query(con, "SELECT * FROM v_cdn_analysis LIMIT 500")
    return {"summary": summary, "details": details}


@app.get("/api/network/cdn", response_class=ORJSONResponse)
def cdn_distribution(db=Depends(get_db)):
    return _get_network_cdn(db)


def _get_network_rdns(con) -> list:
    return safe_query(
        con,
        """
        SELECT fqdn, dns.a AS ips, dns.ptr AS ptr_records
        FROM assets
        WHERE dns.ptr IS NOT NULL
        ORDER BY fqdn
        LIMIT 500
        """,
    )


@app.get("/api/network/rdns", response_class=ORJSONResponse)
def reverse_dns(db=Depends(get_db)):
    return _get_network_rdns(db)


def _get_network_asn(con) -> list:
    return safe_query(
        con,
        """
        SELECT
            network.asn.number AS asn_number,
            network.asn.org AS asn_org,
            COUNT(*) AS count
        FROM assets
        WHERE network.asn.number IS NOT NULL
        GROUP BY asn_number, asn_org
        ORDER BY count DESC
        LIMIT 30
        """,
    )


@app.get("/api/network/asn", response_class=ORJSONResponse)
def asn_distribution(db=Depends(get_db)):
    return _get_network_asn(db)


# ---------------------------------------------------------------------------
# API — Services / Fingerprints
# ---------------------------------------------------------------------------

def _get_services(con, service: str, search: str, limit: int) -> dict:
    where = []
    params = []
    if service:
        where.append("service = ?")
        params.append(service)
    if search:
        where.append(
            "(fqdn ILIKE ? OR fp_product ILIKE ? OR fp_cpe23 ILIKE ? OR banner ILIKE ?)"
        )
        params.extend([f"%{search}%"] * 4)

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    items = safe_query(
        con, f"SELECT * FROM v_services{where_sql} LIMIT ?", params + [limit]
    )

    summary = safe_query(
        con,
        """
        SELECT service, COUNT(*) AS count
        FROM v_services
        GROUP BY service
        ORDER BY count DESC
        """,
    )

    return {"items": items, "summary": summary}


@app.get("/api/services", response_class=ORJSONResponse)
def list_services(
    db=Depends(get_db),
    service: str = Query(""),
    search: str = Query(""),
    limit: int = Query(300, ge=1, le=2000),
):
    return _get_services(db, service, search, limit)


def _get_software_inventory(con) -> dict:
    return {"items": safe_query(con, "SELECT * FROM v_software_inventory LIMIT 500")}


@app.get("/api/services/inventory", response_class=ORJSONResponse)
def software_inventory(db=Depends(get_db)):
    return _get_software_inventory(db)


# ---------------------------------------------------------------------------
# API — Takeover Verifications
# ---------------------------------------------------------------------------

def _get_takeovers(con, status: str, limit: int) -> dict:
    has_table = safe_query(
        con,
        "SELECT 1 FROM information_schema.tables WHERE table_name = 'takeover_verifications'",
    )
    if not has_table:
        return {"items": [], "summary": {}, "verified_at": None}

    where = []
    params: list = []
    if status:
        where.append("status = ?")
        params.append(status)

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    items = safe_query(
        con,
        f"""
        SELECT
            fqdn,
            service,
            stored_cname,
            live_cname_chain,
            cname_target_nxdomain,
            http_fingerprint_matched,
            http_matched_snippet,
            http_status_code,
            status,
            confidence,
            evidence
        FROM takeover_verifications
        {where_sql}
        ORDER BY
            CASE status WHEN 'confirmed' THEN 1 WHEN 'unverified' THEN 2 ELSE 3 END,
            CASE confidence WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
            fqdn
        LIMIT ?
        """,
        params + [limit],
    )

    summary = safe_query(
        con,
        """
        SELECT status, confidence, COUNT(*) AS count
        FROM takeover_verifications
        GROUP BY status, confidence
        ORDER BY status, confidence
        """,
    )

    verified_at = safe_query(
        con,
        """
        SELECT takeover_verified_at
        FROM assets
        WHERE takeover_verified_at IS NOT NULL
        LIMIT 1
        """,
    )
    last_run = verified_at[0]["takeover_verified_at"] if verified_at else None

    return {"items": items, "summary": summary, "verified_at": last_run}


@app.get("/api/takeovers", response_class=ORJSONResponse)
def list_takeovers(
    db=Depends(get_db),
    status: str = Query(""),
    limit: int = Query(500, ge=1, le=2000),
):
    return _get_takeovers(db, status, limit)


# ---------------------------------------------------------------------------
# API — Bug Bounty
# ---------------------------------------------------------------------------

def _get_bounty(con) -> dict:
    has_table = safe_query(
        con,
        "SELECT 1 FROM information_schema.tables WHERE table_name = 'bounty_scores'",
    )
    if not has_table:
        return {"items": [], "summary": [], "available": False}

    items = safe_query(con, """
        SELECT
            fqdn,
            bounty_score,
            tier,
            score_breakdown.attack_surface   AS score_attack_surface,
            score_breakdown.technology        AS score_technology,
            score_breakdown.security_posture  AS score_security_posture,
            score_breakdown.criticality       AS score_criticality,
            highlights,
            recommended_focus,
            attack_surface_summary.open_ports AS open_ports,
            attack_surface_summary.services   AS services,
            attack_surface_summary.technologies AS technologies,
            attack_surface_summary.has_auth   AS has_auth,
            attack_surface_summary.behind_cdn AS behind_cdn,
            attack_surface_summary.nuclei_findings  AS nuclei_findings,
            attack_surface_summary.critical_findings AS critical_findings
        FROM bounty_scores
        ORDER BY bounty_score DESC
    """)
    summary = safe_query(con, "SELECT * FROM v_bounty_summary")
    return {"items": items, "summary": summary, "available": True}


def _export_bounty(con, fmt: str) -> dict:
    has_table = safe_query(
        con,
        "SELECT 1 FROM information_schema.tables WHERE table_name = 'bounty_scores'",
    )
    if not has_table:
        raise HTTPException(status_code=404, detail="No bounty data available")

    rows = query_rows(con, "SELECT * FROM bounty_scores ORDER BY bounty_score DESC")
    if fmt == "csv":
        import io, csv as _csv
        buf = io.StringIO()
        if rows:
            flat = []
            for r in rows:
                flat.append({
                    "fqdn": r.get("fqdn", ""),
                    "bounty_score": r.get("bounty_score", 0),
                    "tier": r.get("tier", ""),
                    "score_attack_surface": (r.get("score_breakdown") or {}).get("attack_surface", ""),
                    "score_technology": (r.get("score_breakdown") or {}).get("technology", ""),
                    "score_security_posture": (r.get("score_breakdown") or {}).get("security_posture", ""),
                    "score_criticality": (r.get("score_breakdown") or {}).get("criticality", ""),
                    "highlights": "; ".join(r.get("highlights") or []),
                    "recommended_focus": "; ".join(r.get("recommended_focus") or []),
                })
            writer = _csv.DictWriter(buf, fieldnames=list(flat[0].keys()))
            writer.writeheader()
            writer.writerows(flat)
        return {"csv": buf.getvalue()}
    return {"items": rows}


@app.get("/api/bounty", response_class=ORJSONResponse)
def bounty_report(db=Depends(get_db)):
    return _get_bounty(db)


@app.get("/api/bounty/export", response_class=ORJSONResponse)
def bounty_export(db=Depends(get_db), format: str = Query("json")):
    return _export_bounty(db, format)


# ---------------------------------------------------------------------------
# API — Search
# ---------------------------------------------------------------------------

def _get_search(con, q: str) -> dict:
    if len(q) < 2:
        return {"assets": [], "findings": []}

    pattern = f"%{q}%"
    assets = safe_query(
        con,
        """
        SELECT fqdn, source, tags, network.cdn AS cdn,
               len(findings) AS finding_count
        FROM assets
        WHERE fqdn ILIKE ?
        ORDER BY fqdn
        LIMIT 20
        """,
        [pattern],
    )

    findings = safe_query(
        con,
        """
        SELECT fqdn, finding_name, severity, template_id, matched_at
        FROM v_findings
        WHERE fqdn ILIKE ? OR finding_name ILIKE ? OR template_id ILIKE ?
        LIMIT 20
        """,
        [pattern, pattern, pattern],
    )

    return {"assets": assets, "findings": findings}


@app.get("/api/search", response_class=ORJSONResponse)
def global_search(q: str = Query("", min_length=2), db=Depends(get_db)):
    return _get_search(db, q)


# ---------------------------------------------------------------------------
# API — Scan Management
# ---------------------------------------------------------------------------

def _read_scan_state() -> dict:
    if SCAN_STATE_FILE.exists():
        try:
            return json.loads(SCAN_STATE_FILE.read_text())
        except Exception:
            pass
    return {}


def _write_scan_state(state: dict):
    SCAN_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCAN_STATE_FILE.write_text(json.dumps(state, default=str))


def _run_pipeline(scan_id: str, input_file: str, stages: str = "", mode: str = "recon"):
    """Run the pipeline in a background thread."""
    try:
        _write_scan_state({
            "scan_id": scan_id,
            "status": "running",
            "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "input_file": input_file,
            "stages": stages or "full",
            "mode": mode or "recon",
        })

        run_sh = PROJECT_ROOT / "run.sh"
        env = os.environ.copy()
        env["INPUT_SUBDOMAINS_OVERRIDE"] = str(Path(input_file).relative_to(PROJECT_ROOT))

        cmd = ["bash", str(run_sh)]
        if stages:
            cmd.extend(["--stage", stages])
        if mode and mode != "recon":
            cmd.extend(["--mode", mode])

        result = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=3600,
        )

        status = "completed" if result.returncode == 0 else "failed"
        state = _read_scan_state()
        state["status"] = status
        state["finished_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        state["exit_code"] = result.returncode
        if result.returncode != 0:
            state["error"] = (result.stderr or "")[-500:]
        _write_scan_state(state)

    except subprocess.TimeoutExpired:
        state = _read_scan_state()
        state["status"] = "failed"
        state["error"] = "Pipeline timed out after 3600s"
        _write_scan_state(state)
    except Exception as e:
        state = _read_scan_state()
        state["status"] = "failed"
        state["error"] = str(e)
        _write_scan_state(state)


# ---------------------------------------------------------------------------
# Archive DB helper
# ---------------------------------------------------------------------------

def _check_archive_path(scan_id: str) -> Path:
    """Validate scan_id and return a ready easm.duckdb path, building from raw JSONL if needed."""
    if not SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    archive_dir = ARCHIVE_DIR / scan_id
    db_path = archive_dir / "easm.duckdb"
    # Path-traversal guard
    try:
        if not db_path.resolve().is_relative_to(ARCHIVE_DIR.resolve()):
            raise HTTPException(status_code=400, detail="Invalid scan ID")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID")

    if db_path.exists():
        return db_path

    # New archive format: build DuckDB on demand from raw/assets.jsonl
    raw_jsonl = archive_dir / "raw" / "assets.jsonl"
    if not raw_jsonl.exists():
        raise HTTPException(status_code=404, detail="Archived database not found")

    try:
        con = duckdb.connect(str(db_path))
        con.execute(f"""
            CREATE TABLE assets AS
            SELECT * FROM read_ndjson_auto('{raw_jsonl}',
                maximum_object_size=10485760, ignore_errors=true)
        """)
        if _duckdb_create_views:
            _duckdb_create_views(con)
        con.close()
    except Exception as exc:
        db_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Failed to build archive DB: {exc}")

    return db_path


def _open_archive_db(scan_id: str) -> duckdb.DuckDBPyConnection:
    """Return a cached read-only connection for an archived scan.

    Connections are kept in an LRU cache (max _ARCHIVE_CACHE_MAX). Callers must
    NOT close the returned connection — eviction handles teardown.
    DuckDB serialises concurrent execute() calls internally, so sharing is safe.
    """
    db_path = _check_archive_path(scan_id)

    with _archive_cache_lock:
        if scan_id in _archive_cache:
            con = _archive_cache[scan_id]
            try:
                con.execute("SELECT 1")
                _archive_cache.move_to_end(scan_id)
                return con
            except Exception:
                del _archive_cache[scan_id]

        con = duckdb.connect(str(db_path), read_only=True)
        _archive_cache[scan_id] = con
        _archive_cache.move_to_end(scan_id)

        while len(_archive_cache) > _ARCHIVE_CACHE_MAX:
            _, old_con = _archive_cache.popitem(last=False)
            try:
                old_con.close()
            except Exception:
                pass

        return con


def _evict_archive_cache(scan_id: str) -> None:
    """Remove an entry from the connection cache and close it."""
    with _archive_cache_lock:
        con = _archive_cache.pop(scan_id, None)
    if con:
        try:
            con.close()
        except Exception:
            pass


def _resolve_scan_db_path(scan_id: str) -> Path:
    """Return the filesystem path for a scan ID. Accepts 'current' for the active DB."""
    if scan_id == "current":
        db = Path(DB_PATH)
        if not db.exists():
            raise HTTPException(status_code=503, detail="Active database not found")
        return db
    # Reuse _check_archive_path which handles both old (easm.duckdb) and
    # new (raw/assets.jsonl → auto-build) archive formats.
    return _check_archive_path(scan_id)


def _build_comparison(scan_id_a: str, scan_id_b: str, limit: int = 200) -> dict:
    """Diff two scan databases using DuckDB ATTACH for cross-DB queries.

    Uses inline SQL against schema.assets instead of schema.view_name because
    DuckDB views store unqualified table references that don't resolve when the
    database is ATTACHed to a separate in-memory connection.
    """
    path_a = _resolve_scan_db_path(scan_id_a)
    path_b = _resolve_scan_db_path(scan_id_b)

    con = duckdb.connect(":memory:")
    try:
        # Paths are validated/constructed from trusted sources — no injection risk
        con.execute(f"ATTACH '{path_a}' AS scan_a (READ_ONLY)")
        con.execute(f"ATTACH '{path_b}' AS scan_b (READ_ONLY)")

        def _stats(schema: str) -> dict:
            # trim('"' FROM ...) handles both old JSON-typed and new VARCHAR gap_type
            return query_one(con, f"""
                SELECT
                    COUNT(*) AS total_assets,
                    COUNT(*) FILTER (WHERE len(web) > 0) AS web_assets,
                    SUM(len(findings)) AS total_findings,
                    COUNT(*) FILTER (WHERE cmdb.in_cmdb) AS in_cmdb,
                    COUNT(*) FILTER (WHERE NOT cmdb.in_cmdb) AS not_in_cmdb,
                    COUNT(*) FILTER (WHERE trim('"' FROM cmdb.gap_type::VARCHAR) = 'shadow_it') AS shadow_it,
                    COUNT(*) FILTER (WHERE trim('"' FROM cmdb.gap_type::VARCHAR) = 'stale_ci') AS stale_ci
                FROM {schema}.assets
            """) or {}

        def _sev(schema: str) -> dict:
            rows = safe_query(con, f"""
                WITH f AS (SELECT UNNEST(findings) AS fi FROM {schema}.assets WHERE len(findings) > 0)
                SELECT fi.severity AS severity, COUNT(*) AS count FROM f GROUP BY 1
            """)
            return {r["severity"]: r["count"] for r in rows}

        def _tls_count(schema: str) -> int:
            return (query_one(con, f"""
                WITH t AS (SELECT UNNEST(tls) AS ti FROM {schema}.assets WHERE len(tls) > 0)
                SELECT COUNT(*) AS n FROM t
                WHERE ti.expired OR ti.self_signed OR ti.mismatched OR ti.revoked
                   OR ti.untrusted OR ti.days_to_expiry < 30
            """) or {}).get("n", 0) or 0

        stats_a = _stats("scan_a")
        stats_b = _stats("scan_b")
        sev_a = _sev("scan_a")
        sev_b = _sev("scan_b")
        tls_a = _tls_count("scan_a")
        tls_b = _tls_count("scan_b")

        def _risk(stats, sev, tls_issues):
            return _calculate_risk_score(
                total=stats.get("total_assets", 0) or 0,
                critical=sev.get("critical", 0),
                high=sev.get("high", 0),
                medium=sev.get("medium", 0),
                tls_issues=tls_issues,
                shadow_it=stats.get("shadow_it", 0) or 0,
            )

        risk_a = _risk(stats_a, sev_a, tls_a)
        risk_b = _risk(stats_b, sev_b, tls_b)

        kpi_keys = ["total_assets", "web_assets", "total_findings", "in_cmdb", "shadow_it", "stale_ci"]
        kpis = {
            k: {"a": stats_a.get(k, 0) or 0, "b": stats_b.get(k, 0) or 0,
                "delta": (stats_b.get(k, 0) or 0) - (stats_a.get(k, 0) or 0)}
            for k in kpi_keys
        }
        kpis["tls_issues"] = {"a": tls_a, "b": tls_b, "delta": tls_b - tls_a}

        # Total counts for pagination metadata
        total_new = (query_one(con, """
            SELECT COUNT(*) AS n FROM scan_b.assets sb
            LEFT JOIN scan_a.assets sa ON sb.fqdn = sa.fqdn WHERE sa.fqdn IS NULL
        """) or {}).get("n", 0) or 0
        total_removed = (query_one(con, """
            SELECT COUNT(*) AS n FROM scan_a.assets sa
            LEFT JOIN scan_b.assets sb ON sa.fqdn = sb.fqdn WHERE sb.fqdn IS NULL
        """) or {}).get("n", 0) or 0
        total_new_findings = (query_one(con, """
            WITH sa_f AS (SELECT fqdn, UNNEST(findings).template_id AS tid FROM scan_a.assets WHERE len(findings) > 0),
                 sb_f AS (SELECT fqdn, UNNEST(findings).template_id AS tid FROM scan_b.assets WHERE len(findings) > 0)
            SELECT COUNT(*) AS n FROM sb_f
            LEFT JOIN sa_f ON sb_f.fqdn = sa_f.fqdn AND sb_f.tid = sa_f.tid
            WHERE sa_f.fqdn IS NULL
        """) or {}).get("n", 0) or 0
        total_resolved_findings = (query_one(con, """
            WITH sa_f AS (SELECT fqdn, UNNEST(findings).template_id AS tid FROM scan_a.assets WHERE len(findings) > 0),
                 sb_f AS (SELECT fqdn, UNNEST(findings).template_id AS tid FROM scan_b.assets WHERE len(findings) > 0)
            SELECT COUNT(*) AS n FROM sa_f
            LEFT JOIN sb_f ON sa_f.fqdn = sb_f.fqdn AND sa_f.tid = sb_f.tid
            WHERE sb_f.fqdn IS NULL
        """) or {}).get("n", 0) or 0

        new_assets = safe_query(con, f"""
            SELECT sb.fqdn,
                   len(sb.network.open_ports) AS port_count,
                   len(sb.web)                AS web_count,
                   len(sb.findings)           AS finding_count,
                   sb.network.cdn             AS cdn,
                   sb.network.asn.org         AS asn_org
            FROM scan_b.assets sb
            LEFT JOIN scan_a.assets sa ON sb.fqdn = sa.fqdn
            WHERE sa.fqdn IS NULL
            ORDER BY sb.fqdn
            LIMIT {limit}
        """)

        removed_assets = safe_query(con, f"""
            SELECT sa.fqdn
            FROM scan_a.assets sa
            LEFT JOIN scan_b.assets sb ON sa.fqdn = sb.fqdn
            WHERE sb.fqdn IS NULL
            ORDER BY sa.fqdn
            LIMIT {limit}
        """)

        new_findings = safe_query(con, f"""
            WITH sa_f AS (SELECT fqdn, UNNEST(findings).template_id AS tid FROM scan_a.assets WHERE len(findings) > 0),
                 sb_f AS (SELECT fqdn, UNNEST(findings) AS f FROM scan_b.assets WHERE len(findings) > 0)
            SELECT sb_f.fqdn, sb_f.f.severity AS severity, sb_f.f.name AS finding_name,
                   sb_f.f.template_id AS template_id, sb_f.f.matched_at AS matched_at
            FROM sb_f
            LEFT JOIN sa_f ON sb_f.fqdn = sa_f.fqdn AND sb_f.f.template_id = sa_f.tid
            WHERE sa_f.fqdn IS NULL
            ORDER BY CASE sb_f.f.severity
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
            END, sb_f.fqdn
            LIMIT {limit}
        """)

        resolved_findings = safe_query(con, f"""
            WITH sb_f AS (SELECT fqdn, UNNEST(findings).template_id AS tid FROM scan_b.assets WHERE len(findings) > 0),
                 sa_f AS (SELECT fqdn, UNNEST(findings) AS f FROM scan_a.assets WHERE len(findings) > 0)
            SELECT sa_f.fqdn, sa_f.f.severity AS severity, sa_f.f.name AS finding_name,
                   sa_f.f.template_id AS template_id, sa_f.f.matched_at AS matched_at
            FROM sa_f
            LEFT JOIN sb_f ON sa_f.fqdn = sb_f.fqdn AND sa_f.f.template_id = sb_f.tid
            WHERE sb_f.fqdn IS NULL
            ORDER BY sa_f.fqdn
            LIMIT {limit}
        """)

        port_changes_raw = safe_query(con, """
            WITH sa_p AS (SELECT fqdn, UNNEST(network.open_ports).port AS port FROM scan_a.assets WHERE len(network.open_ports) > 0),
                 sb_p AS (SELECT fqdn, UNNEST(network.open_ports).port AS port FROM scan_b.assets WHERE len(network.open_ports) > 0)
            SELECT 'new' AS change_type, sb_p.fqdn, sb_p.port
            FROM sb_p
            INNER JOIN scan_a.assets sa ON sb_p.fqdn = sa.fqdn
            LEFT JOIN sa_p ON sb_p.fqdn = sa_p.fqdn AND sb_p.port = sa_p.port
            WHERE sa_p.port IS NULL
            UNION ALL
            SELECT 'closed' AS change_type, sa_p.fqdn, sa_p.port
            FROM sa_p
            INNER JOIN scan_b.assets sb ON sa_p.fqdn = sb.fqdn
            LEFT JOIN sb_p ON sa_p.fqdn = sb_p.fqdn AND sa_p.port = sb_p.port
            WHERE sb_p.port IS NULL
            ORDER BY fqdn, port
        """)

        finding_changes_raw = safe_query(con, """
            WITH sa_f AS (SELECT fqdn, UNNEST(findings) AS f FROM scan_a.assets WHERE len(findings) > 0),
                 sb_f AS (SELECT fqdn, UNNEST(findings) AS f FROM scan_b.assets WHERE len(findings) > 0)
            SELECT 'new' AS change_type, sb_f.fqdn, sb_f.f.severity AS severity,
                   sb_f.f.name AS finding_name, sb_f.f.template_id AS template_id
            FROM sb_f
            INNER JOIN scan_a.assets sa ON sb_f.fqdn = sa.fqdn
            LEFT JOIN sa_f ON sb_f.fqdn = sa_f.fqdn AND sb_f.f.template_id = sa_f.f.template_id
            WHERE sa_f.fqdn IS NULL
            UNION ALL
            SELECT 'resolved' AS change_type, sa_f.fqdn, sa_f.f.severity AS severity,
                   sa_f.f.name AS finding_name, sa_f.f.template_id AS template_id
            FROM sa_f
            INNER JOIN scan_b.assets sb ON sa_f.fqdn = sb.fqdn
            LEFT JOIN sb_f ON sa_f.fqdn = sb_f.fqdn AND sa_f.f.template_id = sb_f.f.template_id
            WHERE sb_f.fqdn IS NULL
        """)

        by_fqdn: dict = defaultdict(
            lambda: {"new_ports": [], "closed_ports": [], "new_findings": [], "resolved_findings": []}
        )
        for r in port_changes_raw:
            key = "new_ports" if r["change_type"] == "new" else "closed_ports"
            by_fqdn[r["fqdn"]][key].append(r["port"])
        for r in finding_changes_raw:
            key = "new_findings" if r["change_type"] == "new" else "resolved_findings"
            by_fqdn[r["fqdn"]][key].append({
                "severity": r["severity"],
                "name": r["finding_name"],
                "template_id": r["template_id"],
            })
        changed_assets = [
            {"fqdn": fqdn, **changes}
            for fqdn, changes in sorted(by_fqdn.items())
            if any(v for v in changes.values())
        ]

        return {
            "scan_a": {"scan_id": scan_id_a, "total_assets": stats_a.get("total_assets", 0)},
            "scan_b": {"scan_id": scan_id_b, "total_assets": stats_b.get("total_assets", 0)},
            "risk_score": {"a": risk_a, "b": risk_b, "delta": risk_b - risk_a},
            "kpis": kpis,
            "totals": {
                "new_assets": total_new,
                "removed_assets": total_removed,
                "new_findings": total_new_findings,
                "resolved_findings": total_resolved_findings,
                "changed_assets": len(changed_assets),
            },
            "limit": limit,
            "new_assets": new_assets,
            "removed_assets": removed_assets,
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "changed_assets": changed_assets,
        }
    finally:
        con.close()


@app.post("/api/scans/new", response_class=ORJSONResponse)
async def create_scan(request: Request):
    body = await request.json()
    subdomains_text = body.get("subdomains", "").strip()
    notes = body.get("notes", "")
    stages = body.get("stages", "").strip()
    mode = body.get("mode", "recon").strip() or "recon"
    if mode not in ("recon", "bounty"):
        mode = "recon"

    if not subdomains_text:
        raise HTTPException(status_code=400, detail="No subdomains provided")

    lines = [
        line.strip().lower()
        for line in subdomains_text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not lines:
        raise HTTPException(status_code=400, detail="No valid subdomains found")

    current = _read_scan_state()
    if current.get("status") == "running":
        raise HTTPException(
            status_code=409,
            detail=f"Scan {current.get('scan_id')} is already running",
        )

    scan_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    input_file = INPUT_DIR / f"scan_{scan_id}.txt"
    input_file.write_text("\n".join(sorted(set(lines))) + "\n")

    thread = threading.Thread(
        target=_run_pipeline,
        args=(scan_id, str(input_file), stages, mode),
        daemon=True,
    )
    thread.start()

    return {
        "scan_id": scan_id,
        "status": "started",
        "subdomain_count": len(lines),
        "input_file": str(input_file),
    }


@app.get("/api/scans/active", response_class=ORJSONResponse)
def active_scan():
    state = _read_scan_state()
    if not state:
        return {"status": "idle"}
    return state


@app.get("/api/scans", response_class=ORJSONResponse)
def list_scans():
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    archives = []
    for scan_dir in sorted(ARCHIVE_DIR.iterdir(), reverse=True):
        if not scan_dir.is_dir():
            continue
        meta_path = scan_dir / "metadata.json"
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
                archives.append(meta)
            except Exception:
                archives.append({
                    "scan_id": scan_dir.name,
                    "status": "completed",
                    "results": {},
                })
        else:
            archives.append({
                "scan_id": scan_dir.name,
                "archived_at": datetime.fromtimestamp(
                    scan_dir.stat().st_mtime, tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "status": "completed",
                "results": {},
            })

    current = _read_scan_state()

    return {
        "archives": archives,
        "active": current if current.get("status") == "running" else None,
        "total": len(archives),
    }


@app.get("/api/scans/{scan_id}", response_class=ORJSONResponse)
def get_scan(scan_id: str):
    if not SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    scan_dir = ARCHIVE_DIR / scan_id
    if not scan_dir.exists():
        raise HTTPException(status_code=404, detail="Archive not found")
    meta_path = scan_dir / "metadata.json"
    if not meta_path.exists():
        return {"scan_id": scan_id, "status": "completed", "results": {}}
    return json.loads(meta_path.read_text())


@app.post("/api/scans/{scan_id}/restore", response_class=ORJSONResponse)
def restore_scan(scan_id: str):
    if not SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    current = _read_scan_state()
    if current.get("status") == "running":
        raise HTTPException(status_code=409, detail="A scan is currently running")

    scan_dir = ARCHIVE_DIR / scan_id
    archived_db = scan_dir / "easm.duckdb"
    if not archived_db.exists():
        raise HTTPException(status_code=404, detail="Archived database not found")

    import shutil
    target = Path(DB_PATH)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(archived_db), str(target))

    return {"status": "restored", "scan_id": scan_id}


@app.delete("/api/scans/{scan_id}", response_class=ORJSONResponse)
def delete_scan(scan_id: str):
    if not SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    scan_dir = ARCHIVE_DIR / scan_id
    if not scan_dir.exists():
        raise HTTPException(status_code=404, detail="Archive not found")

    _evict_archive_cache(scan_id)
    shutil.rmtree(str(scan_dir))
    return {"status": "deleted", "scan_id": scan_id}


# ---------------------------------------------------------------------------
# API — Scoped archive endpoints (read-only views of historical scans)
# ---------------------------------------------------------------------------

@app.get("/api/scans/{scan_id}/overview", response_class=ORJSONResponse)
def archive_overview(scan_id: str):
    return _get_overview(_open_archive_db(scan_id))


@app.get("/api/scans/{scan_id}/assets", response_class=ORJSONResponse)
def archive_assets(
    scan_id: str,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    search: str = Query(""),
    sort: str = Query("fqdn"),
    order: str = Query("asc"),
    tag: str = Query(""),
    gap_type: str = Query(""),
    has_findings: str = Query(""),
):
    return _get_assets(
        _open_archive_db(scan_id),
        page, limit, search, sort, order, tag, gap_type, has_findings,
    )


@app.get("/api/scans/{scan_id}/assets/{fqdn}", response_class=ORJSONResponse)
def archive_asset_detail(scan_id: str, fqdn: str):
    return _get_asset(_open_archive_db(scan_id), fqdn)


@app.get("/api/scans/{scan_id}/findings", response_class=ORJSONResponse)
def archive_findings(
    scan_id: str,
    severity: str = Query(""),
    source: str = Query(""),
    search: str = Query(""),
    tag: str = Query(""),
    limit: int = Query(200, ge=1, le=1000),
):
    return _get_findings(_open_archive_db(scan_id), severity, source, search, tag, limit)


@app.get("/api/scans/{scan_id}/tls", response_class=ORJSONResponse)
def archive_tls(scan_id: str, limit: int = Query(200, ge=1, le=1000)):
    return _get_tls(_open_archive_db(scan_id), limit)


@app.get("/api/scans/{scan_id}/network/ports", response_class=ORJSONResponse)
def archive_network_ports(scan_id: str, port: int = Query(None)):
    return _get_network_ports(_open_archive_db(scan_id), port)


@app.get("/api/scans/{scan_id}/takeovers", response_class=ORJSONResponse)
def archive_takeovers(
    scan_id: str,
    status: str = Query(""),
    limit: int = Query(500, ge=1, le=2000),
):
    return _get_takeovers(_open_archive_db(scan_id), status, limit)


# ---------------------------------------------------------------------------
# API — Scan Comparison
# ---------------------------------------------------------------------------

@app.get("/api/compare/{scan_a}/{scan_b}", response_class=ORJSONResponse)
def compare_scans(scan_a: str, scan_b: str, limit: int = Query(200, ge=1, le=1000)):
    if scan_a == scan_b:
        raise HTTPException(status_code=400, detail="Cannot compare a scan with itself")
    return _build_comparison(scan_a, scan_b, limit=limit)


# ---------------------------------------------------------------------------
# API — Import / Export
# ---------------------------------------------------------------------------

_PARQUET_MAGIC = b"PAR1"
_REQUIRED_IMPORT_COLUMNS = {
    "fqdn", "scan_id", "dns", "network", "tls", "findings", "services", "web", "cmdb",
}


def _validate_import_schema(con) -> list:
    try:
        rows = con.execute("DESCRIBE assets").fetchall()
        present = {r[0].lower() for r in rows}
        return [c for c in _REQUIRED_IMPORT_COLUMNS if c not in present]
    except Exception as exc:
        return [str(exc)]


def _make_archive_metadata(con, scan_id: str, archived_at: str, notes: str, source: str) -> dict:
    try:
        stats = query_one(con, "SELECT * FROM v_scan_stats LIMIT 1") or {}
    except Exception:
        stats = {}
    return {
        "scan_id": scan_id,
        "archived_at": archived_at,
        "source": source,
        "notes": notes,
        "stats": {
            "total_assets": stats.get("total_assets", 0),
            "total_findings": stats.get("total_findings", 0),
            "assets_with_findings": stats.get("assets_with_findings", 0),
        },
    }


@app.post("/api/scans/import", response_class=ORJSONResponse)
async def import_scan(
    file: UploadFile = File(...),
    scan_id: str = Form(""),
    notes: str = Form(""),
):
    data = await file.read(4)
    rest = await file.read()
    full = data + rest

    if len(full) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large (max {_MAX_UPLOAD_BYTES // 1024 // 1024} MB)",
        )

    is_parquet = data == _PARQUET_MAGIC
    if not is_parquet and not (file.filename or "").endswith(".duckdb"):
        raise HTTPException(status_code=400, detail="File must be a .duckdb or .parquet file")

    now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    effective_scan_id = scan_id.strip() if scan_id.strip() else now_str
    if not SCAN_ID_RE.match(effective_scan_id):
        raise HTTPException(status_code=400, detail="scan_id must be YYYYMMDD_HHMMSS format")

    dest_dir = ARCHIVE_DIR / effective_scan_id
    if dest_dir.exists():
        raise HTTPException(status_code=409, detail=f"Scan {effective_scan_id} already exists")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        if is_parquet:
            parquet_path = tmp_path / "import.parquet"
            parquet_path.write_bytes(full)
            db_path = tmp_path / "easm.duckdb"
            con = duckdb.connect(str(db_path))
            try:
                con.execute(f"CREATE TABLE assets AS SELECT * FROM read_parquet('{parquet_path}')")
                missing = _validate_import_schema(con)
                if missing:
                    raise HTTPException(
                        status_code=422,
                        detail=f"Missing required columns: {', '.join(missing)}",
                    )
                if _duckdb_create_views:
                    _duckdb_create_views(con)
                archived_at = datetime.now(timezone.utc).isoformat()
                meta = _make_archive_metadata(con, effective_scan_id, archived_at, notes, "import_parquet")
            finally:
                con.close()
        else:
            db_path = tmp_path / "easm.duckdb"
            db_path.write_bytes(full)
            con = duckdb.connect(str(db_path), read_only=True)
            try:
                missing = _validate_import_schema(con)
                if missing:
                    raise HTTPException(
                        status_code=422,
                        detail=f"Missing required columns: {', '.join(missing)}",
                    )
            finally:
                con.close()
            if _duckdb_create_views:
                con2 = duckdb.connect(str(db_path))
                try:
                    _duckdb_create_views(con2)
                except Exception:
                    pass
                finally:
                    con2.close()
            con_meta = duckdb.connect(str(db_path), read_only=True)
            try:
                archived_at = datetime.now(timezone.utc).isoformat()
                meta = _make_archive_metadata(con_meta, effective_scan_id, archived_at, notes, "import_duckdb")
            finally:
                con_meta.close()

        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(db_path), str(dest_dir / "easm.duckdb"))
        (dest_dir / "metadata.json").write_text(json.dumps(meta, indent=2))

    return {"scan_id": effective_scan_id, "status": "imported", "stats": meta.get("stats", {})}


@app.get("/api/scans/{scan_id}/export")
def export_scan(scan_id: str):
    if not SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    archive_dir = ARCHIVE_DIR / scan_id
    if not archive_dir.exists():
        raise HTTPException(status_code=404, detail="Archived scan not found")

    parquet_path = archive_dir / "parquet" / f"assets_{scan_id}.parquet"
    if not parquet_path.exists():
        db_path = archive_dir / "easm.duckdb"
        if not db_path.exists():
            raise HTTPException(status_code=404, detail="No database or parquet found for this scan")
        parquet_path.parent.mkdir(exist_ok=True)
        con = duckdb.connect(str(db_path), read_only=True)
        try:
            con.execute(f"COPY assets TO '{parquet_path}' (FORMAT PARQUET, COMPRESSION ZSTD)")
        finally:
            con.close()

    return FileResponse(
        str(parquet_path),
        media_type="application/octet-stream",
        filename=f"assets_{scan_id}.parquet",
        headers={"Content-Disposition": f'attachment; filename="assets_{scan_id}.parquet"'},
    )


# ---------------------------------------------------------------------------
# SPA fallback
# ---------------------------------------------------------------------------

@app.get("/{path:path}")
def spa_fallback(path: str):
    return FileResponse(STATIC_DIR / "index.html")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "dashboard.app:app",
        host="0.0.0.0",
        port=int(os.environ.get("DASHBOARD_PORT", "8443")),
        reload=True,
    )
