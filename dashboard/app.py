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
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

import duckdb
import orjson
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

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

@app.get("/api/overview", response_class=ORJSONResponse)
def overview(db=Depends(get_db)):
    scan = query_one(db, "SELECT * FROM v_scan_stats LIMIT 1") or {}

    findings_by_severity = safe_query(
        db,
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
        db,
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
        db,
        """
        SELECT tech_name AS name, COUNT(*) AS count
        FROM v_tech_stack
        GROUP BY tech_name
        ORDER BY count DESC
        LIMIT 12
        """,
    )

    port_dist = safe_query(
        db,
        """
        SELECT port, COUNT(*) AS count
        FROM v_open_ports
        GROUP BY port
        ORDER BY count DESC
        LIMIT 15
        """,
    )

    cdn_dist = safe_query(
        db,
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
        db,
        """
        SELECT * FROM v_findings
        WHERE severity IN ('critical', 'high')
        LIMIT 20
        """,
    )

    service_dist = safe_query(
        db,
        """
        SELECT service, COUNT(*) AS count
        FROM v_services
        GROUP BY service
        ORDER BY count DESC
        LIMIT 15
        """,
    )

    top_software = safe_query(
        db,
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
    total = (query_one(db, count_sql, params) or {}).get("total", 0)

    data_sql = f"""
        SELECT * FROM v_asset_summary
        {where_sql}
        ORDER BY {sort_col} {sort_dir}
        LIMIT ? OFFSET ?
    """
    items = query_rows(db, data_sql, params + [limit, offset])

    return {
        "items": items,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": math.ceil(total / limit) if limit else 0,
    }


@app.get("/api/assets/{fqdn}", response_class=ORJSONResponse)
def get_asset(fqdn: str, db=Depends(get_db)):
    rows = query_rows(db, "SELECT * FROM assets WHERE fqdn = ?", [fqdn.lower()])
    if not rows:
        raise HTTPException(status_code=404, detail="Asset not found")
    asset = rows[0]
    _convert_nested(asset)
    return asset


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

@app.get("/api/findings", response_class=ORJSONResponse)
def list_findings(
    db=Depends(get_db),
    severity: str = Query(""),
    source: str = Query(""),
    search: str = Query(""),
    limit: int = Query(200, ge=1, le=1000),
):
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

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    sql = f"SELECT * FROM v_findings{where_sql} LIMIT ?"
    params.append(limit)
    items = query_rows(db, sql, params)

    summary = safe_query(
        db,
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


# ---------------------------------------------------------------------------
# API — TLS
# ---------------------------------------------------------------------------

@app.get("/api/tls", response_class=ORJSONResponse)
def list_tls_issues(db=Depends(get_db), limit: int = Query(200, ge=1, le=1000)):
    items = safe_query(db, f"SELECT * FROM v_tls_issues LIMIT {limit}")

    summary = query_one(
        db,
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


# ---------------------------------------------------------------------------
# API — CMDB Gaps
# ---------------------------------------------------------------------------

@app.get("/api/cmdb", response_class=ORJSONResponse)
def list_cmdb_gaps(
    db=Depends(get_db),
    gap_type: str = Query(""),
    limit: int = Query(300, ge=1, le=1000),
):
    where = []
    params = []
    if gap_type:
        where.append("gap_type = ?")
        params.append(gap_type)

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    items = query_rows(
        db, f"SELECT * FROM v_cmdb_gaps{where_sql} LIMIT ?", params + [limit]
    )

    summary = safe_query(
        db,
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

    scan = query_one(db, "SELECT * FROM v_scan_stats LIMIT 1") or {}

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


# ---------------------------------------------------------------------------
# API — Network
# ---------------------------------------------------------------------------

@app.get("/api/network/ports", response_class=ORJSONResponse)
def port_distribution(
    db=Depends(get_db),
    port: int = Query(None, description="Filter details to a specific port"),
):
    heatmap = safe_query(
        db,
        """
        SELECT port, COUNT(*) AS count
        FROM v_open_ports
        GROUP BY port
        ORDER BY count DESC
        """,
    )
    if port is not None:
        details = safe_query(
            db,
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


@app.get("/api/network/tech", response_class=ORJSONResponse)
def tech_distribution(db=Depends(get_db)):
    summary = safe_query(
        db,
        """
        SELECT tech_name AS name, COUNT(*) AS count
        FROM v_tech_stack
        GROUP BY tech_name
        ORDER BY count DESC
        """,
    )
    details = safe_query(
        db,
        """
        SELECT tech_name AS name, tech_version AS version, COUNT(*) AS count
        FROM v_tech_stack
        GROUP BY tech_name, tech_version
        ORDER BY count DESC
        LIMIT 100
        """,
    )
    return {"summary": summary, "details": details}


@app.get("/api/network/cdn", response_class=ORJSONResponse)
def cdn_distribution(db=Depends(get_db)):
    return safe_query(
        db,
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


@app.get("/api/network/asn", response_class=ORJSONResponse)
def asn_distribution(db=Depends(get_db)):
    return safe_query(
        db,
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


# ---------------------------------------------------------------------------
# API — Services / Fingerprints
# ---------------------------------------------------------------------------

@app.get("/api/services", response_class=ORJSONResponse)
def list_services(
    db=Depends(get_db),
    service: str = Query(""),
    search: str = Query(""),
    limit: int = Query(300, ge=1, le=2000),
):
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
        db, f"SELECT * FROM v_services{where_sql} LIMIT ?", params + [limit]
    )

    summary = safe_query(
        db,
        """
        SELECT service, COUNT(*) AS count
        FROM v_services
        GROUP BY service
        ORDER BY count DESC
        """,
    )

    return {"items": items, "summary": summary}


@app.get("/api/services/inventory", response_class=ORJSONResponse)
def software_inventory(db=Depends(get_db)):
    items = safe_query(db, "SELECT * FROM v_software_inventory LIMIT 500")
    return {"items": items}


# ---------------------------------------------------------------------------
# API — Takeover Verifications
# ---------------------------------------------------------------------------

@app.get("/api/takeovers", response_class=ORJSONResponse)
def list_takeovers(
    db=Depends(get_db),
    status: str = Query(""),
    limit: int = Query(500, ge=1, le=2000),
):
    has_table = safe_query(
        db,
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
        db,
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
        db,
        """
        SELECT status, confidence, COUNT(*) AS count
        FROM takeover_verifications
        GROUP BY status, confidence
        ORDER BY status, confidence
        """,
    )

    verified_at = safe_query(
        db,
        """
        SELECT takeover_verified_at
        FROM assets
        WHERE takeover_verified_at IS NOT NULL
        LIMIT 1
        """,
    )
    last_run = verified_at[0]["takeover_verified_at"] if verified_at else None

    return {"items": items, "summary": summary, "verified_at": last_run}


# ---------------------------------------------------------------------------
# API — Search
# ---------------------------------------------------------------------------

@app.get("/api/search", response_class=ORJSONResponse)
def global_search(q: str = Query("", min_length=2), db=Depends(get_db)):
    if len(q) < 2:
        return {"assets": [], "findings": []}

    pattern = f"%{q}%"
    assets = safe_query(
        db,
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
        db,
        """
        SELECT fqdn, finding_name, severity, template_id, matched_at
        FROM v_findings
        WHERE fqdn ILIKE ? OR finding_name ILIKE ? OR template_id ILIKE ?
        LIMIT 20
        """,
        [pattern, pattern, pattern],
    )

    return {"assets": assets, "findings": findings}


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


def _run_pipeline(scan_id: str, input_file: str, stages: str = ""):
    """Run the pipeline in a background thread."""
    try:
        _write_scan_state({
            "scan_id": scan_id,
            "status": "running",
            "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "input_file": input_file,
        })

        run_sh = PROJECT_ROOT / "run.sh"
        env = os.environ.copy()
        env["INPUT_SUBDOMAINS_OVERRIDE"] = str(Path(input_file).relative_to(PROJECT_ROOT))

        cmd = ["bash", str(run_sh)]
        if stages:
            cmd.extend(["--stage", stages])

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


@app.post("/api/scans/new", response_class=ORJSONResponse)
async def create_scan(request: Request):
    body = await request.json()
    subdomains_text = body.get("subdomains", "").strip()
    notes = body.get("notes", "")

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
        args=(scan_id, str(input_file)),
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

    import shutil
    shutil.rmtree(str(scan_dir))
    return {"status": "deleted", "scan_id": scan_id}


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
