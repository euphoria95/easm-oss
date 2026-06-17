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


def _has_column(con: duckdb.DuckDBPyConnection, table: str, column: str) -> bool:
    """Check if a column exists in a DuckDB table."""
    try:
        con.execute(f"SELECT \"{column}\" FROM \"{table}\" LIMIT 0")
        return True
    except Exception:
        return False


def create_views(con: duckdb.DuckDBPyConnection):
    """Create analytical views (must be called after assets table exists).

    DuckDB UNNEST of struct-lists: we use a CTE with UNNEST(col) AS alias
    in the SELECT clause, which produces a struct column. Then we access
    struct fields via alias.field in the outer query.
    """

    has_cloud = _has_column(con, "assets", "cloud")

    cloud_summary_cols = (
        "len(cloud.endpoints) AS cloud_endpoint_count,\n"
        "            cloud.risk_summary AS cloud_risk,\n"
        "            cloud.providers AS cloud_providers,"
    ) if has_cloud else (
        "0 AS cloud_endpoint_count,\n"
        "            NULL AS cloud_risk,\n"
        "            NULL AS cloud_providers,"
    )

    con.execute(f"""
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
            network.cdn_detection.provider AS cdn_provider,
            network.cdn_detection.confidence AS cdn_confidence,
            network.shared_hosting.detected AS shared_hosting_detected,
            network.shared_hosting.confidence AS shared_hosting_confidence,
            network.shared_hosting.cohosted_count AS cohosted_count,
            network.asn.org AS asn_org,
            network.asn.number AS asn_number,
            len(network.open_ports) AS port_count,
            len(web) AS web_entry_count,
            len(tls) AS tls_cert_count,
            len(findings) AS finding_count,
            len(services) AS service_count,
            {cloud_summary_cols}
            cmdb.in_cmdb AS in_cmdb,
            cmdb.gap_type AS gap_type,
            cmdb.matched_ci AS ci_id
        FROM assets
    """)

    con.execute("""
        CREATE OR REPLACE VIEW v_cmdb_gaps AS
        SELECT
            fqdn,
            cmdb.gap_type AS gap_type,
            cmdb.matched_ci AS ci_id,
            cmdb.match_basis AS match_basis,
            dns.a AS ips,
            network.cdn AS cdn,
            len(web) > 0 AS has_web,
            len(network.open_ports) AS port_count
        FROM assets
        WHERE cmdb.in_cmdb = false
           OR cmdb.gap_type IS NOT NULL
        ORDER BY cmdb.gap_type, fqdn
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
            f.timestamp AS found_at,
            f.tags AS tags,
            f.description AS description
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

    # Services / fingerprints: CTE unnest (guard: old archives store services as JSON[])
    try:
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
    except Exception:
        pass

    # Software inventory: unique vendor/product/version combos across the estate
    try:
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
    except Exception:
        pass

    try:
        con.execute("""
            CREATE OR REPLACE VIEW v_reverse_dns AS
            SELECT
                fqdn,
                dns.a AS ips,
                dns.ptr AS ptr_records
            FROM assets
            WHERE dns.ptr IS NOT NULL
              AND len(dns.ptr) > 0
            ORDER BY fqdn
        """)
    except Exception:
        pass

    try:
        con.execute("""
            CREATE OR REPLACE VIEW v_cdn_analysis AS
            SELECT
                fqdn,
                network.cdn AS cdn,
                network.cdn_detection.provider AS detected_provider,
                network.cdn_detection.confidence AS detection_confidence,
                network.cdn_detection.signals AS detection_signals,
                dns.cname_chain AS cnames,
                network.asn.number AS asn_number,
                network.asn.org AS asn_org,
                dns.a AS ips
            FROM assets
            WHERE network.cdn IS NOT NULL
               OR network.cdn_detection IS NOT NULL
            ORDER BY detected_provider, fqdn
        """)
    except Exception:
        pass

    try:
        con.execute("""
            CREATE OR REPLACE VIEW v_shared_hosting AS
            SELECT
                fqdn,
                network.shared_hosting.confidence AS confidence,
                network.shared_hosting.cohosted_count AS cohosted_count,
                network.shared_hosting.signals AS signals,
                network.asn.number AS asn_number,
                network.asn.org AS asn_org,
                dns.a AS ips
            FROM assets
            WHERE network.shared_hosting.detected = true
            ORDER BY cohosted_count DESC, fqdn
        """)
    except Exception:
        pass

    cloud_stats_cols = (
        "COUNT(*) FILTER (WHERE len(cloud.endpoints) > 0) AS cloud_assets,\n"
        "            SUM(len(cloud.endpoints)) AS cloud_endpoints"
    ) if has_cloud else (
        "0 AS cloud_assets,\n"
        "            0 AS cloud_endpoints"
    )

    con.execute(f"""
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
            COUNT(*) FILTER (WHERE trim('"' FROM cmdb.gap_type::VARCHAR) = 'shadow_it') AS shadow_it,
            COUNT(*) FILTER (WHERE trim('"' FROM cmdb.gap_type::VARCHAR) = 'stale_ci') AS stale_ci,
            ROUND(
                COUNT(*) FILTER (WHERE trim('"' FROM cmdb.gap_type::VARCHAR) = 'shadow_it') * 100.0 / NULLIF(COUNT(*), 0),
                1
            ) AS shadow_it_pct,
            SUM(len(services)) AS total_services,
            COUNT(*) FILTER (WHERE len(services) > 0) AS assets_with_services,
            {cloud_stats_cols}
        FROM assets
        GROUP BY scan_id
    """)

    if has_cloud:
        create_cloud_views(con)
    create_bounty_views(con)
    create_livecheck_views(con)


def create_cloud_views(con: duckdb.DuckDBPyConnection):
    """Create cloud endpoint analysis views.

    Caller must verify that the 'cloud' column exists before calling.
    """
    try:
        con.execute("""
            CREATE OR REPLACE VIEW v_cloud_endpoints AS
            WITH expanded AS (
                SELECT fqdn, UNNEST(cloud.endpoints) AS e
                FROM assets
                WHERE len(cloud.endpoints) > 0
            )
            SELECT
                fqdn,
                e.provider,
                e.service,
                e.service_label,
                e.risk,
                e.resource_name,
                e.hostname,
                e.pattern,
                e.signals
            FROM expanded
            ORDER BY
                CASE e.risk
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                    ELSE 6
                END,
                e.provider, fqdn
        """)
    except Exception as e:
        print(f"WARN: Could not create v_cloud_endpoints view: {e}", file=sys.stderr)

    try:
        con.execute("""
            CREATE OR REPLACE VIEW v_cloud_summary AS
            WITH expanded AS (
                SELECT fqdn, UNNEST(cloud.endpoints) AS e
                FROM assets
                WHERE len(cloud.endpoints) > 0
            )
            SELECT
                e.provider,
                e.service,
                e.service_label,
                e.risk,
                COUNT(*) AS count,
                COUNT(DISTINCT fqdn) AS affected_hosts
            FROM expanded
            GROUP BY e.provider, e.service, e.service_label, e.risk
            ORDER BY count DESC
        """)
    except Exception as e:
        print(f"WARN: Could not create v_cloud_summary view: {e}", file=sys.stderr)

    try:
        con.execute("""
            CREATE OR REPLACE VIEW v_cloud_providers AS
            WITH expanded AS (
                SELECT fqdn, UNNEST(cloud.providers) AS provider
                FROM assets
                WHERE len(cloud.providers) > 0
            )
            SELECT
                provider,
                COUNT(DISTINCT fqdn) AS host_count,
                ROUND(COUNT(DISTINCT fqdn) * 100.0 /
                    NULLIF((SELECT COUNT(*) FROM assets), 0), 1) AS pct
            FROM expanded
            GROUP BY provider
            ORDER BY host_count DESC
        """)
    except Exception as e:
        print(f"WARN: Could not create v_cloud_providers view: {e}", file=sys.stderr)

    try:
        con.execute("""
            CREATE OR REPLACE VIEW v_cloud_risk AS
            WITH expanded AS (
                SELECT fqdn, UNNEST(cloud.endpoints) AS e
                FROM assets
                WHERE len(cloud.endpoints) > 0
            )
            SELECT
                e.risk,
                COUNT(*) AS count,
                COUNT(DISTINCT fqdn) AS affected_hosts
            FROM expanded
            GROUP BY e.risk
            ORDER BY
                CASE e.risk
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                    ELSE 6
                END
        """)
    except Exception as e:
        print(f"WARN: Could not create v_cloud_risk view: {e}", file=sys.stderr)


def create_livecheck_views(con: duckdb.DuckDBPyConnection):
    """Create livecheck views if livecheck table exists."""
    try:
        has_table = con.execute("""
            SELECT 1 FROM information_schema.tables WHERE table_name = 'livecheck'
        """).fetchone()
        if not has_table:
            return

        con.execute("""
            CREATE OR REPLACE VIEW v_livecheck_summary AS
            SELECT
                COUNT(*) AS total_fqdns,
                COUNT(*) FILTER (WHERE resolves) AS resolving,
                COUNT(*) FILTER (WHERE NOT resolves) AS not_resolving,
                ROUND(COUNT(*) FILTER (WHERE resolves) * 100.0 / NULLIF(COUNT(*), 0), 1) AS resolution_pct,
                COUNT(*) FILTER (WHERE in_cmdb) AS in_cmdb,
                COUNT(*) FILTER (WHERE exclude_proposal) AS cdn_excluded,
                COUNT(*) FILTER (WHERE recommend_remove) AS removal_candidates,
                COUNT(*) FILTER (WHERE cname_bloated) AS cname_bloated,
                COUNT(*) FILTER (WHERE is_leaf) AS leaf_domains,
                COUNT(*) FILTER (WHERE ns_is_third_party) AS third_party_ns
            FROM livecheck
        """)

        con.execute("""
            CREATE OR REPLACE VIEW v_scope_removals AS
            SELECT
                fqdn,
                ci_id,
                owner,
                days_unavailable,
                days_remaining,
                consecutive_scans_down,
                removal_deadline,
                scope_action,
                dns_status
            FROM livecheck
            WHERE recommend_remove = true
            ORDER BY days_unavailable DESC, fqdn
        """)

        con.execute("""
            CREATE OR REPLACE VIEW v_cname_bloat AS
            SELECT
                fqdn,
                cname_chain_depth,
                cname_chain,
                cname_fan_in_target,
                cname_fan_in_count,
                resolves,
                cdn_provider,
                in_cmdb
            FROM livecheck
            WHERE cname_bloated = true
            ORDER BY cname_chain_depth DESC, fqdn
        """)

        con.execute("""
            CREATE OR REPLACE VIEW v_cdn_exclusions AS
            SELECT
                fqdn,
                ci_id,
                owner,
                cdn_provider,
                cdn_confidence,
                cdn_signals,
                a_records,
                cname_chain,
                scope_action
            FROM livecheck
            WHERE exclude_proposal = true
            ORDER BY cdn_provider, fqdn
        """)

        con.execute("""
            CREATE OR REPLACE VIEW v_leaf_domains AS
            SELECT
                fqdn,
                in_cmdb,
                resolves,
                dns_status,
                scope_action,
                days_unavailable,
                cdn_provider
            FROM livecheck
            WHERE is_leaf = true
            ORDER BY resolves, fqdn
        """)

        con.execute("""
            CREATE OR REPLACE VIEW v_third_party_ns AS
            SELECT
                fqdn,
                ns_provider,
                ns_is_third_party,
                ns_records,
                in_cmdb,
                resolves,
                cdn_provider
            FROM livecheck
            WHERE ns_is_third_party = true
            ORDER BY ns_provider, fqdn
        """)

    except Exception as e:
        print(f"WARN: Could not create livecheck views: {e}", file=sys.stderr)


def create_bounty_views(con: duckdb.DuckDBPyConnection):
    """Create bounty scoring views if bounty_scores table exists."""
    try:
        has_table = con.execute("""
            SELECT 1 FROM information_schema.tables WHERE table_name = 'bounty_scores'
        """).fetchone()
        if not has_table:
            return

        con.execute("""
            CREATE OR REPLACE VIEW v_bounty_scores AS
            SELECT
                fqdn,
                bounty_score,
                tier,
                score_breakdown.attack_surface   AS score_attack_surface,
                score_breakdown.technology        AS score_technology,
                score_breakdown.security_posture  AS score_security_posture,
                score_breakdown.criticality       AS score_criticality,
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

        try:
            con.execute("""
                CREATE OR REPLACE VIEW v_bounty_highlights AS
                WITH expanded AS (
                    SELECT fqdn, bounty_score, tier, UNNEST(highlights) AS highlight
                    FROM bounty_scores WHERE len(highlights) > 0
                )
                SELECT fqdn, bounty_score, tier, highlight
                FROM expanded
                ORDER BY bounty_score DESC, fqdn
            """)
        except Exception:
            pass

        con.execute("""
            CREATE OR REPLACE VIEW v_bounty_summary AS
            SELECT
                tier,
                COUNT(*) AS count,
                ROUND(AVG(bounty_score), 1) AS avg_score,
                MAX(bounty_score) AS max_score
            FROM bounty_scores
            GROUP BY tier
            ORDER BY CASE tier WHEN 'S' THEN 1 WHEN 'A' THEN 2 WHEN 'B' THEN 3 WHEN 'C' THEN 4 ELSE 5 END
        """)
    except Exception as e:
        print(f"WARN: Could not create bounty views: {e}", file=sys.stderr)


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
