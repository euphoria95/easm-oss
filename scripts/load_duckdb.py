#!/usr/bin/env python3
"""
EASM Pipeline — DuckDB Loader

Loads normalized asset JSONL into DuckDB with proper schema,
creates analytical views, and exports Parquet for archival.

Usage:
    python3 load_duckdb.py \
        --input assets.jsonl \
        --db easm.duckdb \
        --scan-id 20260419_021509
"""

import argparse
import sys
from pathlib import Path

import duckdb


def load_assets(con: duckdb.DuckDBPyConnection, jsonl_path: str, scan_id: str):
    """Load JSONL into the assets table."""
    p = Path(jsonl_path)
    if not p.exists() or p.stat().st_size == 0:
        print(f"ERROR: No data to load from {jsonl_path}", file=sys.stderr)
        return

    con.execute("DROP TABLE IF EXISTS assets")
    con.execute(f"""
        CREATE TABLE assets AS
        SELECT * FROM read_ndjson_auto('{jsonl_path}',
            maximum_object_size=10485760,
            ignore_errors=true
        )
    """)

    count = con.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    print(f"Loaded {count} assets into DuckDB", file=sys.stderr)

    # Recreate views after table creation
    create_views(con)

    return count


def create_views(con: duckdb.DuckDBPyConnection):
    """Create analytical views (must be called after assets table exists).

    DuckDB UNNEST of struct-lists: we use a CTE with UNNEST(col) AS alias
    in the SELECT clause, which produces a struct column. Then we access
    struct fields via alias.field in the outer query.
    """

    con.execute("""
        CREATE OR REPLACE VIEW v_asset_summary AS
        SELECT
            fqdn,
            scan_id,
            first_seen,
            last_seen,
            source,
            tags,
            dns.a AS ips,
            dns.cname_chain AS cnames,
            network.cdn AS cdn,
            network.asn.org AS asn_org,
            network.asn.number AS asn_number,
            len(network.open_ports) AS port_count,
            len(web) AS web_entry_count,
            len(tls) AS tls_cert_count,
            len(findings) AS finding_count,
            len(services) AS service_count,
            cmdb.in_cmdb AS in_cmdb,
            json_extract_string(cmdb.gap_type, '$') AS gap_type,
            json_extract_string(cmdb.matched_ci, '$') AS ci_id
        FROM assets
    """)

    con.execute("""
        CREATE OR REPLACE VIEW v_cmdb_gaps AS
        SELECT
            fqdn,
            json_extract_string(cmdb.gap_type, '$') AS gap_type,
            json_extract_string(cmdb.matched_ci, '$') AS ci_id,
            cmdb.match_basis AS match_basis,
            dns.a AS ips,
            network.cdn AS cdn,
            len(web) > 0 AS has_web,
            len(network.open_ports) AS port_count
        FROM assets
        WHERE cmdb.in_cmdb = false
           OR cmdb.gap_type IS NOT NULL
        ORDER BY json_extract_string(cmdb.gap_type, '$'), fqdn
    """)

    # TLS issues: use CTE to unnest tls array, then filter
    con.execute("""
        CREATE OR REPLACE VIEW v_tls_issues AS
        WITH expanded AS (
            SELECT fqdn, UNNEST(tls) AS t FROM assets WHERE len(tls) > 0
        )
        SELECT
            fqdn,
            t.port,
            t.issuer,
            t.subject,
            t.not_after,
            t.days_to_expiry,
            t.expired,
            t.self_signed,
            t.mismatched,
            t.revoked,
            t.untrusted,
            t.version AS tls_version
        FROM expanded
        WHERE t.expired = true
           OR t.self_signed = true
           OR t.mismatched = true
           OR t.revoked = true
           OR t.untrusted = true
           OR t.days_to_expiry < 30
        ORDER BY COALESCE(t.days_to_expiry, -999)
    """)

    # Findings: CTE unnest
    con.execute("""
        CREATE OR REPLACE VIEW v_findings AS
        WITH expanded AS (
            SELECT fqdn, UNNEST(findings) AS f FROM assets WHERE len(findings) > 0
        )
        SELECT
            fqdn,
            f.source AS finding_source,
            f.template_id,
            f.name AS finding_name,
            f.severity,
            f.matched_at,
            f.timestamp AS found_at
        FROM expanded
        ORDER BY
            CASE f.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                WHEN 'info' THEN 5
                ELSE 6
            END,
            fqdn
    """)

    # Tech stack: double unnest (web → tech) via CTEs.
    # Guard: bind fails when no assets have web data (empty-array type inference).
    try:
        con.execute("""
            CREATE OR REPLACE VIEW v_tech_stack AS
            WITH web_expanded AS (
                SELECT fqdn, UNNEST(web) AS w FROM assets WHERE len(web) > 0
            ),
            tech_expanded AS (
                SELECT fqdn, w.url, UNNEST(w.tech) AS t FROM web_expanded
            )
            SELECT
                fqdn,
                url,
                t.name AS tech_name,
                t.version AS tech_version
            FROM tech_expanded
            ORDER BY t.name, fqdn
        """)
    except Exception:
        pass

    # Open ports: CTE unnest
    con.execute("""
        CREATE OR REPLACE VIEW v_open_ports AS
        WITH expanded AS (
            SELECT fqdn, network.cdn AS cdn, network.asn.org AS asn_org,
                   UNNEST(network.open_ports) AS p
            FROM assets
            WHERE len(network.open_ports) > 0
        )
        SELECT
            fqdn,
            p.port,
            p.protocol,
            cdn,
            asn_org
        FROM expanded
        ORDER BY p.port, fqdn
    """)

    # Services / fingerprints: CTE unnest
    con.execute("""
        CREATE OR REPLACE VIEW v_services AS
        WITH expanded AS (
            SELECT fqdn, UNNEST(services) AS s FROM assets WHERE len(services) > 0
        )
        SELECT
            fqdn,
            s.port,
            s.protocol,
            s.transport,
            s.service,
            s.status,
            s.banner,
            s.fingerprint.vendor    AS fp_vendor,
            s.fingerprint.product   AS fp_product,
            s.fingerprint.version   AS fp_version,
            s.fingerprint.cpe23     AS fp_cpe23,
            s.fingerprint.os_vendor AS fp_os_vendor,
            s.fingerprint.os_product AS fp_os_product,
            s.fingerprint.os_version AS fp_os_version,
            s.fingerprint.certainty AS fp_certainty,
            s.fingerprint.source    AS fp_source
        FROM expanded
        ORDER BY fqdn, s.port
    """)

    # Software inventory: unique vendor/product/version combos across the estate
    con.execute("""
        CREATE OR REPLACE VIEW v_software_inventory AS
        WITH expanded AS (
            SELECT fqdn, UNNEST(services) AS s FROM assets WHERE len(services) > 0
        )
        SELECT
            s.fingerprint.product   AS product,
            s.fingerprint.vendor    AS vendor,
            s.fingerprint.version   AS version,
            s.fingerprint.cpe23     AS cpe23,
            s.service               AS service_type,
            COUNT(DISTINCT fqdn)    AS host_count,
            ROUND(AVG(s.fingerprint.certainty), 2) AS avg_certainty
        FROM expanded
        WHERE s.fingerprint.product IS NOT NULL
          AND s.fingerprint.product != ''
        GROUP BY product, vendor, version, cpe23, service_type
        ORDER BY host_count DESC
    """)

    con.execute("""
        CREATE OR REPLACE VIEW v_scan_stats AS
        SELECT
            scan_id,
            COUNT(*) AS total_assets,
            COUNT(*) FILTER (WHERE len(web) > 0) AS web_assets,
            COUNT(*) FILTER (WHERE len(tls) > 0) AS tls_assets,
            COUNT(*) FILTER (WHERE len(findings) > 0) AS assets_with_findings,
            SUM(len(findings)) AS total_findings,
            COUNT(*) FILTER (WHERE cmdb.in_cmdb) AS in_cmdb,
            COUNT(*) FILTER (WHERE NOT cmdb.in_cmdb) AS not_in_cmdb,
            COUNT(*) FILTER (WHERE json_extract_string(cmdb.gap_type, '$') = 'shadow_it') AS shadow_it,
            COUNT(*) FILTER (WHERE json_extract_string(cmdb.gap_type, '$') = 'stale_ci') AS stale_ci,
            ROUND(
                COUNT(*) FILTER (WHERE json_extract_string(cmdb.gap_type, '$') = 'shadow_it') * 100.0 / NULLIF(COUNT(*), 0),
                1
            ) AS shadow_it_pct,
            SUM(len(services)) AS total_services,
            COUNT(*) FILTER (WHERE len(services) > 0) AS assets_with_services
        FROM assets
        GROUP BY scan_id
    """)


def export_parquet(con: duckdb.DuckDBPyConnection, db_path: str, scan_id: str):
    """Export assets table as Parquet for archival."""
    parquet_dir = Path(db_path).parent / "parquet"
    parquet_dir.mkdir(exist_ok=True)
    parquet_path = parquet_dir / f"assets_{scan_id}.parquet"
    con.execute(f"COPY assets TO '{parquet_path}' (FORMAT PARQUET, COMPRESSION ZSTD)")
    print(f"Exported Parquet: {parquet_path}", file=sys.stderr)


def print_stats(con: duckdb.DuckDBPyConnection):
    """Print scan statistics."""
    try:
        stats = con.execute("SELECT * FROM v_scan_stats").fetchdf()
        if not stats.empty:
            print("\n=== Scan Statistics ===", file=sys.stderr)
            for col in stats.columns:
                print(f"  {col}: {stats[col].iloc[0]}", file=sys.stderr)
    except Exception as e:
        print(f"WARN: Could not print stats: {e}", file=sys.stderr)

    # Top findings
    try:
        findings = con.execute("""
            SELECT severity, COUNT(*) AS cnt
            FROM v_findings
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                    ELSE 6
                END
        """).fetchall()
        if findings:
            print("\n=== Findings by Severity ===", file=sys.stderr)
            for sev, cnt in findings:
                print(f"  {sev}: {cnt}", file=sys.stderr)
    except Exception:
        pass

    # TLS issues
    try:
        tls_issues = con.execute("SELECT COUNT(*) FROM v_tls_issues").fetchone()[0]
        print(f"\n  TLS issues: {tls_issues}", file=sys.stderr)
    except Exception:
        pass

    # Service fingerprints
    try:
        svc_rows = con.execute("""
            SELECT service, COUNT(*) AS cnt,
                   COUNT(*) FILTER (WHERE fp_cpe23 IS NOT NULL AND fp_cpe23 != '') AS with_cpe
            FROM v_services
            GROUP BY service
            ORDER BY cnt DESC
            LIMIT 15
        """).fetchall()
        if svc_rows:
            print("\n=== Services by Protocol ===", file=sys.stderr)
            for svc, cnt, cpe_cnt in svc_rows:
                print(f"  {svc or 'unknown'}: {cnt} (CPE: {cpe_cnt})", file=sys.stderr)
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="EASM DuckDB Loader")
    parser.add_argument("--input", required=True, help="Normalized assets JSONL")
    parser.add_argument("--db", required=True, help="DuckDB database path")
    parser.add_argument("--scan-id", default="unknown", help="Scan identifier")
    parser.add_argument("--no-parquet", action="store_true", help="Skip Parquet export")
    args = parser.parse_args()

    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    con = duckdb.connect(str(db_path))
    try:
        # Load
        count = load_assets(con, args.input, args.scan_id)
        if not count:
            return

        # Export Parquet
        if not args.no_parquet:
            export_parquet(con, str(db_path), args.scan_id)

        # Stats
        print_stats(con)

        print(f"\nDuckDB ready: {db_path}", file=sys.stderr)
    finally:
        con.close()


if __name__ == "__main__":
    main()
