#!/usr/bin/env python3
"""
EASM Pipeline — Tenable Scope Exporter

Routing mode (recon pipeline, stage "scope"; --db or --assets)
  Routes every discovered asset to Tenable VM / WAS following
  TENABLE_SCOPE_PIPELINE.MD (rules: tenable_scope.py) and writes:
    tenable_vm_include.txt       unique IPs for Tenable VM (network scan)
    tenable_vm_exclude.txt       IPs that must not be network-scanned
                                 (CDN/WAF edge, 3rd-party, PaaS, takeover)
    tenable_vm_review.txt        IPs awaiting ownership confirmation (--require-owned)
    tenable_was_targets.txt      WAS standard-profile URLs
    tenable_was_waf_targets.txt  WAF-fronted URLs — allow-list scanner egress first
    tenable_was_api_targets.txt  API / AI endpoints — attach an OpenAPI definition
    tenable_scope.jsonl          per-asset decisions with reasons (audit trail)
    tenable_vm_targets.jsonl     per-IP VM decisions
    tenable_scope_meta.json      routing settings used (ownership, thresholds, ...)
    tenable_scope.xlsx           analyst workbook: Summary / All / VM / WAS candidates (--db only)
  With --db these are also loaded as the tenable_scope / tenable_vm_targets /
  tenable_scope_meta tables behind the v_tenable_* views and the dashboard.

Livecheck mode (--report)
  Reads livecheck_report.jsonl and writes tenable_include.txt /
  tenable_exclude.txt for CMDB-registered FQDNs.

Usage:
    python3 cmdb_scope_export.py --db data/output/easm.duckdb --output-dir data/output
    python3 cmdb_scope_export.py --assets assets.jsonl --takeovers takeover_verifications.jsonl
    python3 cmdb_scope_export.py --report livecheck_report.jsonl --output-dir data/output
"""

import argparse
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    import orjson
    def _json_loads(b): return orjson.loads(b)
    def _json_line(o): return orjson.dumps(o, option=orjson.OPT_APPEND_NEWLINE)
except ImportError:
    import json
    def _json_loads(b): return json.loads(b)
    def _json_line(o): return (json.dumps(o) + "\n").encode()


def read_jsonl(path: str) -> list[dict]:
    records = []
    p = Path(path)
    if not p.exists():
        print(f"ERROR: Report file not found: {path}", file=sys.stderr)
        return records
    with open(p, "rb") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(_json_loads(line))
            except Exception:
                pass
    return records


def export_scope(args):
    report = read_jsonl(args.report)
    if not report:
        print("No livecheck records to process", file=sys.stderr)
        return

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    include_path = output_dir / "tenable_include.txt"
    exclude_path = output_dir / "tenable_exclude.txt"

    include_targets = []
    exclude_targets = []
    exclude_reasons: dict[str, list[str]] = {}

    for rec in report:
        fqdn = rec.get("fqdn", "")
        if not fqdn:
            continue

        # Only process CMDB-registered assets for Tenable scope
        if not rec.get("in_cmdb", False):
            continue

        action = rec.get("scope_action", "keep")

        if action in ("remove", "review_remove", "exclude_cdn"):
            exclude_targets.append(fqdn)
            reasons = []
            if action == "remove":
                days = rec.get("days_unavailable", 0)
                reasons.append(f"unavailable_{days}d")
            if action == "exclude_cdn":
                provider = rec.get("cdn_provider", "unknown")
                reasons.append(f"cdn_{provider}")
            if action == "review_remove":
                reasons.append("leaf_unresolvable")
            # Also add IPs to exclude
            for ip in rec.get("a_records", []):
                exclude_targets.append(ip)
            exclude_reasons[fqdn] = reasons
        else:
            include_targets.append(fqdn)
            # Include resolved IPs
            for ip in rec.get("a_records", []):
                include_targets.append(ip)

    # Deduplicate while preserving order
    include_targets = list(dict.fromkeys(include_targets))
    exclude_targets = list(dict.fromkeys(exclude_targets))

    with open(include_path, "w") as f:
        for target in sorted(include_targets):
            f.write(target + "\n")

    with open(exclude_path, "w") as f:
        for target in sorted(exclude_targets):
            reason = ", ".join(exclude_reasons.get(target, []))
            if reason:
                f.write(f"{target}  # {reason}\n")
            else:
                f.write(target + "\n")

    print(f"\n=== Tenable Scope Export ===", file=sys.stderr)
    print(f"  Include: {len(include_targets)} targets → {include_path}", file=sys.stderr)
    print(f"  Exclude: {len(exclude_targets)} targets → {exclude_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Routing mode
# ---------------------------------------------------------------------------

# Asset columns the router reads; the last two only exist on some scans
# (aimap hits / after the verify stage).
ROUTING_COLUMNS = ["fqdn", "scan_id", "dns", "network", "web", "findings", "cloud",
                   "cmdb", "ai_protocols", "takeover_status"]

SCOPE_TABLE_COLUMNS = {
    "scan_id": "VARCHAR", "fqdn": "VARCHAR", "in_cmdb": "BOOLEAN",
    "category": "VARCHAR", "categories": "VARCHAR[]",
    "ips": "VARCHAR[]", "ports": "INTEGER[]", "asn_org": "VARCHAR",
    "cdn_provider": "VARCHAR", "waf_provider": "VARCHAR", "platforms": "VARCHAR[]",
    "takeover_status": "VARCHAR",
    "vm_action": "VARCHAR", "vm_ips": "VARCHAR[]", "vm_reasons": "VARCHAR[]",
    "was_action": "VARCHAR", "was_profile": "VARCHAR",
    "was_reasons": "VARCHAR[]", "was_urls": "VARCHAR[]",
}

VM_TABLE_COLUMNS = {
    "scan_id": "VARCHAR", "target_ip": "VARCHAR", "action": "VARCHAR",
    "vm_category": "VARCHAR", "primary_fqdn": "VARCHAR", "fqdns": "VARCHAR[]",
    "fqdn_count": "INTEGER", "ports": "INTEGER[]", "asn_org": "VARCHAR",
    "owned": "BOOLEAN", "reasons": "VARCHAR[]",
}


def read_assets_db(con) -> list[dict]:
    from load_duckdb import _has_column
    cols = [c for c in ROUTING_COLUMNS if _has_column(con, "assets", c)]
    cur = con.execute(f"SELECT {', '.join(cols)} FROM assets")
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row)) for row in cur.fetchall()]


def read_assets_jsonl(assets_path: str, takeovers_path: str | None) -> list[dict]:
    assets = read_jsonl(assets_path)
    if takeovers_path and Path(takeovers_path).exists():
        status = {r.get("fqdn"): r.get("status") for r in read_jsonl(takeovers_path)}
        for a in assets:
            if a.get("fqdn") in status:
                a["takeover_status"] = status[a["fqdn"]]
    return assets


def _write_lines(path: Path, lines) -> int:
    lines = list(lines)
    path.write_text("".join(f"{line}\n" for line in lines))
    return len(lines)


def _write_jsonl(path: Path, rows: list[dict]):
    with open(path, "wb") as f:
        for row in rows:
            f.write(_json_line(row))


META_TABLE_COLUMNS = {
    "scan_id": "VARCHAR", "routed_at": "VARCHAR",
    "cdn_min_confidence": "DOUBLE", "waf_min_confidence": "DOUBLE",
    "cmdb_only": "BOOLEAN", "require_owned": "BOOLEAN", "was_include_saas": "BOOLEAN",
    "owned_cidrs": "VARCHAR[]", "owned_asns": "BIGINT[]",
}


def routing_meta(cfg, scan_id: str | None) -> dict:
    """The settings a routing run used — shown by the dashboard so the
    operator can tell e.g. whether ownership was enforced."""
    return {
        "scan_id": scan_id,
        "routed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cdn_min_confidence": cfg.cdn_min_confidence,
        "waf_min_confidence": cfg.waf_min_confidence,
        "cmdb_only": cfg.cmdb_only,
        "require_owned": cfg.require_owned,
        "was_include_saas": cfg.was_include_saas,
        "owned_cidrs": [str(n) for n in cfg.owned_networks],
        "owned_asns": sorted(cfg.owned_asns),
    }


def load_routing_tables(con, scope_path: Path, vm_path: Path, meta: dict):
    """(Re)create tenable_scope / tenable_vm_targets / tenable_scope_meta with
    explicit types — read_ndjson_auto would turn all-empty lists into JSON."""
    from load_duckdb import create_tenable_views
    for table, path, columns in (("tenable_scope", scope_path, SCOPE_TABLE_COLUMNS),
                                 ("tenable_vm_targets", vm_path, VM_TABLE_COLUMNS)):
        con.execute(f"DROP TABLE IF EXISTS {table}")
        con.execute(f"CREATE TABLE {table} ({', '.join(f'{k} {v}' for k, v in columns.items())})")
        if path.stat().st_size:
            spec = ", ".join(f"'{k}': '{v}'" for k, v in columns.items())
            con.execute(f"""
                INSERT INTO {table}
                SELECT * FROM read_json('{path}', format='newline_delimited', columns={{{spec}}})
            """)
    con.execute("DROP TABLE IF EXISTS tenable_scope_meta")
    con.execute(f"CREATE TABLE tenable_scope_meta ({', '.join(f'{k} {v}' for k, v in META_TABLE_COLUMNS.items())})")
    con.execute(f"INSERT INTO tenable_scope_meta VALUES ({', '.join('?' * len(META_TABLE_COLUMNS))})",
                [meta[k] for k in META_TABLE_COLUMNS])
    create_tenable_views(con)


def write_routing(asset_rows: list[dict], ip_rows: list[dict], output_dir: Path, meta: dict) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)

    def ips(action):
        return [r["target_ip"] for r in ip_rows if r["action"] == action]

    def urls(profile):
        return sorted({u for r in asset_rows if r["was_profile"] == profile for u in r["was_urls"]})

    counts = {
        "vm_include": _write_lines(output_dir / "tenable_vm_include.txt", ips("include")),
        "vm_exclude": _write_lines(output_dir / "tenable_vm_exclude.txt", ips("exclude")),
        "vm_review": _write_lines(output_dir / "tenable_vm_review.txt", ips("review")),
        "was_standard": _write_lines(output_dir / "tenable_was_targets.txt", urls("standard")),
        "was_waf": _write_lines(output_dir / "tenable_was_waf_targets.txt", urls("waf")),
        "was_api": _write_lines(output_dir / "tenable_was_api_targets.txt", urls("api")),
    }
    _write_jsonl(output_dir / "tenable_scope.jsonl", asset_rows)
    _write_jsonl(output_dir / "tenable_vm_targets.jsonl", ip_rows)
    (output_dir / "tenable_scope_meta.json").write_bytes(_json_line(meta))
    return counts


def write_xlsx(con, path: Path):
    """Analyst workbook (tenable_xlsx.py). Optional: a failure never fails routing."""
    try:
        from tenable_xlsx import write_tenable_xlsx
        write_tenable_xlsx(con, str(path))
    except Exception as e:  # missing XlsxWriter, unexpected data, ...
        print(f"WARN: Tenable scope workbook not written: {e}", file=sys.stderr)


def export_routing(args):
    from tenable_scope import ScopeConfig, parse_owned_asns, parse_owned_networks, route_assets

    cfg = ScopeConfig(
        cdn_min_confidence=args.cdn_min_confidence,
        waf_min_confidence=args.waf_min_confidence,
        cmdb_only=args.cmdb_only,
        owned_networks=parse_owned_networks(args.owned_cidrs),
        owned_asns=parse_owned_asns(args.owned_asns),
        require_owned=args.require_owned,
        was_include_saas=args.was_include_saas,
    )
    output_dir = Path(args.output_dir)

    con = None
    if args.db:
        import duckdb
        con = duckdb.connect(args.db)
        assets = read_assets_db(con)
    else:
        assets = read_assets_jsonl(args.assets, args.takeovers)

    try:
        asset_rows, ip_rows = route_assets(assets, cfg)
        meta = routing_meta(cfg, next((a.get("scan_id") for a in assets if a.get("scan_id")), None))
        counts = write_routing(asset_rows, ip_rows, output_dir, meta)
        if con is not None:
            load_routing_tables(con, output_dir / "tenable_scope.jsonl",
                                output_dir / "tenable_vm_targets.jsonl", meta)
            write_xlsx(con, output_dir / "tenable_scope.xlsx")
    finally:
        if con is not None:
            con.close()

    print("\n=== Tenable Scope Routing ===", file=sys.stderr)
    print(f"  Assets routed: {len(asset_rows)}", file=sys.stderr)
    owned = ", ".join(meta["owned_cidrs"] + [f"AS{a}" for a in meta["owned_asns"]]) or "none declared"
    print(f"  Ownership:    {'enforced (unowned IPs → review)' if cfg.require_owned else 'not enforced'}"
          f" | owned ranges: {owned} | CMDB-only: {'yes' if cfg.cmdb_only else 'no'}", file=sys.stderr)
    for category, n in Counter(r["category"] for r in asset_rows).most_common():
        print(f"    {category}: {n}", file=sys.stderr)
    print(f"  VM include:   {counts['vm_include']} IPs  "
          f"(exclude {counts['vm_exclude']}, review {counts['vm_review']})", file=sys.stderr)
    print(f"  WAS standard: {counts['was_standard']} URLs", file=sys.stderr)
    print(f"  WAS WAF:      {counts['was_waf']} URLs (allow-list scanner egress first)", file=sys.stderr)
    print(f"  WAS API:      {counts['was_api']} URLs (attach API definitions)", file=sys.stderr)
    print(f"  Output:       {output_dir}", file=sys.stderr)
    return counts


def main():
    parser = argparse.ArgumentParser(description="EASM Tenable Scope Exporter")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--report", help="livecheck_report.jsonl (livecheck mode)")
    src.add_argument("--db", help="DuckDB database to route assets from (writes tenable_* tables)")
    src.add_argument("--assets", help="Normalized assets.jsonl to route (offline; files only)")
    parser.add_argument("--takeovers", help="With --assets: takeover_verifications.jsonl")
    parser.add_argument("--output-dir", default="data/output",
                        help="Output directory for scope files")
    parser.add_argument("--cdn-min-confidence", type=float, default=0.35,
                        help="CDN detector confidence that excludes an IP from VM (0.35 = any signal)")
    parser.add_argument("--waf-min-confidence", type=float, default=0.5,
                        help="WAF verdict confidence that routes an asset to the WAF profile")
    parser.add_argument("--cmdb-only", action="store_true",
                        help="Only route CMDB-registered assets into scan scope")
    parser.add_argument("--owned-cidrs", default="",
                        help="Comma-separated CIDRs/IPs you own (override CDN/3rd-party/PaaS heuristics)")
    parser.add_argument("--owned-asns", default="",
                        help="Comma-separated ASNs you own, e.g. AS64500,64501")
    parser.add_argument("--require-owned", action="store_true",
                        help="Send VM-eligible IPs outside owned CIDRs/ASNs to review instead of include")
    parser.add_argument("--was-include-saas", action="store_true",
                        help="Also route third-party SaaS-hosted apps to WAS (check vendor terms first)")
    args = parser.parse_args()

    if args.report:
        export_scope(args)
    else:
        export_routing(args)


if __name__ == "__main__":
    main()
