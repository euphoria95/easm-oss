#!/usr/bin/env python3
"""
EASM Pipeline — CMDB Gap Report Generator

Produces a structured gap analysis report from the normalized asset data,
suitable for management presentation and ticketing integration.

Usage:
    python3 cmdb_report.py \
        --db data/output/easm.duckdb \
        --output data/output/cmdb_gap_report.json
"""

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import duckdb
import orjson


def generate_report(con: duckdb.DuckDBPyConnection) -> dict:
    """Generate CMDB gap analysis report."""
    report = {
        "report_type": "cmdb_gap_analysis",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {},
        "shadow_it": [],
        "stale_cis": [],
        "unmanaged": [],
        "orphan_certs": [],
        "tls_issues": [],
        "critical_findings": [],
        "recommendations": [],
    }

    # Summary stats
    try:
        stats = con.execute("""
            SELECT
                COUNT(*) AS total_assets,
                COUNT(*) FILTER (WHERE cmdb.in_cmdb) AS in_cmdb,
                COUNT(*) FILTER (WHERE NOT cmdb.in_cmdb) AS not_in_cmdb,
                COUNT(*) FILTER (WHERE cmdb.gap_type = 'shadow_it') AS shadow_it,
                COUNT(*) FILTER (WHERE cmdb.gap_type = 'stale_ci') AS stale_ci,
                COUNT(*) FILTER (WHERE cmdb.gap_type = 'unmanaged') AS unmanaged,
                COUNT(*) FILTER (WHERE cmdb.gap_type = 'orphan_cert') AS orphan_cert,
                ROUND(
                    COUNT(*) FILTER (WHERE cmdb.gap_type = 'shadow_it') * 100.0
                    / NULLIF(COUNT(*), 0), 1
                ) AS shadow_it_pct,
                COUNT(*) FILTER (WHERE len(web) > 0) AS web_assets,
                COUNT(*) FILTER (WHERE len(findings) > 0) AS assets_with_findings,
                SUM(len(findings)) AS total_findings
            FROM assets
        """).fetchone()

        cols = [
            "total_assets", "in_cmdb", "not_in_cmdb", "shadow_it",
            "stale_ci", "unmanaged", "orphan_cert", "shadow_it_pct",
            "web_assets", "assets_with_findings", "total_findings"
        ]
        report["summary"] = dict(zip(cols, stats))
    except Exception as e:
        print(f"WARN: Stats query failed: {e}", file=sys.stderr)

    # Shadow IT details
    try:
        rows = con.execute("""
            SELECT
                fqdn,
                dns.a AS ips,
                network.cdn AS cdn,
                network.asn.org AS asn_org,
                len(network.open_ports) AS port_count,
                len(web) > 0 AS has_web,
                array_to_string(source, ', ') AS sources
            FROM assets
            WHERE cmdb.gap_type = 'shadow_it'
            ORDER BY fqdn
        """).fetchall()
        for row in rows:
            report["shadow_it"].append({
                "fqdn": row[0],
                "ips": row[1],
                "cdn": row[2],
                "asn_org": row[3],
                "port_count": row[4],
                "has_web": row[5],
                "sources": row[6],
            })
    except Exception:
        pass

    # Stale CIs
    try:
        rows = con.execute("""
            SELECT
                fqdn,
                cmdb.matched_ci AS ci_id,
                len(dns.a) AS has_dns,
                len(network.open_ports) AS port_count
            FROM assets
            WHERE cmdb.gap_type = 'stale_ci'
            ORDER BY fqdn
        """).fetchall()
        for row in rows:
            report["stale_cis"].append({
                "fqdn": row[0],
                "ci_id": row[1],
                "has_dns": row[2] > 0,
                "port_count": row[3],
            })
    except Exception:
        pass

    # TLS issues
    try:
        rows = con.execute("""
            SELECT
                a.fqdn,
                t.port,
                t.issuer,
                t.not_after,
                t.days_to_expiry,
                t.expired,
                t.self_signed,
                t.mismatched
            FROM assets a, UNNEST(a.tls) AS t
            WHERE t.expired = true
               OR t.self_signed = true
               OR t.mismatched = true
               OR t.days_to_expiry < 30
            ORDER BY COALESCE(t.days_to_expiry, -999)
            LIMIT 100
        """).fetchall()
        for row in rows:
            report["tls_issues"].append({
                "fqdn": row[0],
                "port": row[1],
                "issuer": row[2],
                "not_after": row[3],
                "days_to_expiry": row[4],
                "expired": row[5],
                "self_signed": row[6],
                "mismatched": row[7],
            })
    except Exception:
        pass

    # Critical/High findings
    try:
        rows = con.execute("""
            SELECT
                a.fqdn,
                f.template_id,
                f.name,
                f.severity,
                f.matched_at
            FROM assets a, UNNEST(a.findings) AS f
            WHERE f.severity IN ('critical', 'high')
            ORDER BY
                CASE f.severity WHEN 'critical' THEN 1 ELSE 2 END,
                a.fqdn
            LIMIT 100
        """).fetchall()
        for row in rows:
            report["critical_findings"].append({
                "fqdn": row[0],
                "template_id": row[1],
                "name": row[2],
                "severity": row[3],
                "matched_at": row[4],
            })
    except Exception:
        pass

    # Recommendations
    s = report["summary"]
    if s.get("shadow_it", 0) > 0:
        report["recommendations"].append({
            "priority": "high",
            "category": "shadow_it",
            "action": f"Investigate {s['shadow_it']} shadow IT assets not tracked in CMDB. "
                      f"These represent {s.get('shadow_it_pct', 0)}% of the discovered attack surface.",
        })
    if len(report["tls_issues"]) > 0:
        expired = sum(1 for t in report["tls_issues"] if t.get("expired"))
        expiring = sum(1 for t in report["tls_issues"] if (t.get("days_to_expiry") or 999) < 30 and not t.get("expired"))
        if expired:
            report["recommendations"].append({
                "priority": "critical",
                "category": "tls",
                "action": f"Renew {expired} expired TLS certificates immediately.",
            })
        if expiring:
            report["recommendations"].append({
                "priority": "high",
                "category": "tls",
                "action": f"Renew {expiring} TLS certificates expiring within 30 days.",
            })
    if len(report["critical_findings"]) > 0:
        report["recommendations"].append({
            "priority": "critical",
            "category": "vulnerabilities",
            "action": f"Triage {len(report['critical_findings'])} critical/high findings from nuclei scan.",
        })
    if s.get("stale_ci", 0) > 0:
        report["recommendations"].append({
            "priority": "medium",
            "category": "cmdb_hygiene",
            "action": f"Review {s['stale_ci']} stale CMDB entries with no corresponding live asset.",
        })

    return report


def main():
    parser = argparse.ArgumentParser(description="EASM CMDB Gap Report")
    parser.add_argument("--db", required=True, help="DuckDB database path")
    parser.add_argument("--output", required=True, help="Output JSON report path")
    args = parser.parse_args()

    if not Path(args.db).exists():
        print(f"ERROR: Database not found: {args.db}", file=sys.stderr)
        sys.exit(1)

    con = duckdb.connect(args.db, read_only=True)
    report = generate_report(con)
    con.close()

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "wb") as f:
        f.write(orjson.dumps(report, option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS))

    # Print summary
    s = report["summary"]
    print(f"\n=== CMDB Gap Report ===", file=sys.stderr)
    print(f"  Total assets:  {s.get('total_assets', 0)}", file=sys.stderr)
    print(f"  In CMDB:       {s.get('in_cmdb', 0)}", file=sys.stderr)
    print(f"  Shadow IT:     {s.get('shadow_it', 0)} ({s.get('shadow_it_pct', 0)}%)", file=sys.stderr)
    print(f"  Stale CIs:     {s.get('stale_ci', 0)}", file=sys.stderr)
    print(f"  TLS issues:    {len(report['tls_issues'])}", file=sys.stderr)
    print(f"  Critical/High: {len(report['critical_findings'])}", file=sys.stderr)
    print(f"\nReport: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
