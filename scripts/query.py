#!/usr/bin/env python3
"""
EASM Pipeline — DuckDB Query Runner

Interactive and scripted query interface for the EASM database.
Provides pre-built analytical queries and ad-hoc SQL.

Usage:
    python3 query.py --db data/output/easm.duckdb --query stats
    python3 query.py --db data/output/easm.duckdb --sql "SELECT * FROM v_findings LIMIT 10"
    python3 query.py --db data/output/easm.duckdb --query all --format csv
"""

import argparse
import sys
from pathlib import Path

import duckdb


QUERIES = {
    "stats": {
        "desc": "Overall scan statistics",
        "sql": "SELECT * FROM v_scan_stats",
    },
    "gaps": {
        "desc": "CMDB gap analysis",
        "sql": "SELECT * FROM v_cmdb_gaps",
    },
    "shadow_it": {
        "desc": "Shadow IT assets (not in CMDB)",
        "sql": """
            SELECT fqdn, dns.a AS ips, network.cdn, network.asn.org,
                   len(network.open_ports) AS ports
            FROM assets
            WHERE cmdb.gap_type = 'shadow_it'
            ORDER BY fqdn
        """,
    },
    "tls_issues": {
        "desc": "TLS certificate issues",
        "sql": "SELECT * FROM v_tls_issues",
    },
    "tls_expiring": {
        "desc": "Certificates expiring within 30 days",
        "sql": """
            WITH expanded AS (
                SELECT fqdn, UNNEST(tls) AS t FROM assets WHERE len(tls) > 0
            )
            SELECT fqdn, t.port, t.subject, t.not_after, t.days_to_expiry, t.issuer
            FROM expanded
            WHERE t.days_to_expiry BETWEEN 0 AND 30
            ORDER BY t.days_to_expiry
        """,
    },
    "findings": {
        "desc": "All vulnerability findings",
        "sql": "SELECT * FROM v_findings",
    },
    "findings_critical": {
        "desc": "Critical and high severity findings",
        "sql": """
            SELECT * FROM v_findings
            WHERE severity IN ('critical', 'high')
        """,
    },
    "tech": {
        "desc": "Technology stack across all assets",
        "sql": "SELECT * FROM v_tech_stack",
    },
    "tech_summary": {
        "desc": "Technology distribution (count per tech)",
        "sql": """
            SELECT tech_name, tech_version, COUNT(*) AS asset_count
            FROM v_tech_stack
            GROUP BY tech_name, tech_version
            ORDER BY asset_count DESC
        """,
    },
    "ports": {
        "desc": "All open ports",
        "sql": "SELECT * FROM v_open_ports",
    },
    "port_heatmap": {
        "desc": "Port frequency distribution",
        "sql": """
            SELECT port, COUNT(*) AS host_count
            FROM v_open_ports
            GROUP BY port
            ORDER BY host_count DESC
        """,
    },
    "cdn_distribution": {
        "desc": "CDN provider distribution",
        "sql": """
            SELECT
                COALESCE(network.cdn, 'direct') AS cdn,
                COUNT(*) AS asset_count,
                ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 1) AS pct
            FROM assets
            GROUP BY cdn
            ORDER BY asset_count DESC
        """,
    },
    "asn_distribution": {
        "desc": "ASN/hosting provider distribution",
        "sql": """
            SELECT
                network.asn.number AS asn_number,
                network.asn.org AS asn_org,
                COUNT(*) AS asset_count
            FROM assets
            WHERE network.asn.number IS NOT NULL
            GROUP BY asn_number, asn_org
            ORDER BY asset_count DESC
        """,
    },
    "favicon_clusters": {
        "desc": "Favicon hash clusters (shared applications)",
        "sql": """
            WITH expanded AS (
                SELECT fqdn, UNNEST(web) AS w FROM assets WHERE len(web) > 0
            )
            SELECT
                w.favicon_mmh3,
                COUNT(DISTINCT fqdn) AS host_count,
                LIST(DISTINCT fqdn) AS hosts
            FROM expanded
            WHERE w.favicon_mmh3 IS NOT NULL
            GROUP BY w.favicon_mmh3
            HAVING COUNT(DISTINCT fqdn) > 1
            ORDER BY host_count DESC
        """,
    },
    "takeovers": {
        "desc": "Subdomain takeover candidates",
        "sql": """
            WITH expanded AS (
                SELECT fqdn, UNNEST(findings) AS f FROM assets WHERE len(findings) > 0
            )
            SELECT
                fqdn,
                f.name,
                f.severity,
                f.matched_at
            FROM expanded
            WHERE f.template_id LIKE '%takeover%'
               OR f.source = 'subzy'
            ORDER BY fqdn
        """,
    },
}


def main():
    parser = argparse.ArgumentParser(description="EASM DuckDB Query Runner")
    parser.add_argument("--db", required=True, help="DuckDB database path")
    parser.add_argument("--query", help="Pre-built query name (use 'list' to see all, 'all' to run all)")
    parser.add_argument("--sql", help="Custom SQL query")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format")
    parser.add_argument("--limit", type=int, help="Limit rows")
    args = parser.parse_args()

    if args.query == "list":
        print("Available queries:")
        for name, q in QUERIES.items():
            print(f"  {name:20s} — {q['desc']}")
        return

    if not Path(args.db).exists():
        print(f"ERROR: Database not found: {args.db}", file=sys.stderr)
        sys.exit(1)

    con = duckdb.connect(args.db, read_only=True)

    if args.query == "all":
        for name, q in QUERIES.items():
            print(f"\n{'='*60}")
            print(f"  {name}: {q['desc']}")
            print(f"{'='*60}")
            try:
                sql = q["sql"]
                if args.limit:
                    sql += f" LIMIT {args.limit}"
                result = con.execute(sql)
                _print_result(result, args.format)
            except Exception as e:
                print(f"  ERROR: {e}")
        con.close()
        return

    # Single query
    sql = None
    if args.query and args.query in QUERIES:
        sql = QUERIES[args.query]["sql"]
        print(f"# {QUERIES[args.query]['desc']}")
    elif args.sql:
        sql = args.sql
    else:
        print("ERROR: Provide --query <name> or --sql <SQL>", file=sys.stderr)
        con.close()
        sys.exit(1)

    if args.limit:
        sql += f" LIMIT {args.limit}"

    try:
        result = con.execute(sql)
        _print_result(result, args.format)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        con.close()


def _print_result(result, fmt):
    if fmt == "csv":
        df = result.fetchdf()
        print(df.to_csv(index=False))
    elif fmt == "json":
        df = result.fetchdf()
        print(df.to_json(orient="records", indent=2))
    else:
        # Table format
        print(result.fetchdf().to_string(max_rows=200, max_colwidth=60))


if __name__ == "__main__":
    main()
