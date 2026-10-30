#!/usr/bin/env python3
"""
EASM Pipeline — Tenable scan-scope workbook (XLSX).

Built on xlsx_workbook.py from the tables the scope stage writes
(tenable_scope, tenable_vm_targets, tenable_scope_meta) plus asset enrichment
(DNS, ASN, HTTP, TLS, CMDB) from the assets table:

  Summary                  routing settings, totals, category matrix, caveats
  All                      every routed asset with its VM and WAS decision
  Tenable VM Candidates    IPs to network-scan (include) or confirm (review)
  Tenable WAS Candidates   URLs to DAST, with the scan policy each needs
  Columns                  data dictionary

Used by the scope stage (cmdb_scope_export.py → tenable_scope.xlsx) and the
dashboard (/api/tenable-scope/export?kind=xlsx).

Usage:
    python3 tenable_xlsx.py --db data/output/easm.duckdb --output tenable_scope.xlsx
"""

import argparse
import sys
from datetime import datetime, timezone

from tenable_scope import _dict, _int, _list, _origin, ip_sort_key
from xlsx_workbook import Column, Sheet, write_workbook

ENRICH_COLUMNS = ["fqdn", "dns", "network", "web", "tls", "cmdb", "source", "first_seen", "last_seen"]

VM_COLORS = {"include": "#C9F2E6", "review": "#FBEFC2", "exclude": "#E1E6E4"}
WAS_COLORS = {"standard": "#C9F2E6", "waf": "#FDDCC3", "api": "#CFE3FF", "exclude": "#E1E6E4"}

WAS_POLICY = {
    "standard": "Standard DAST",
    "waf": "WAF: allow-list scanner egress first",
    "api": "API: attach OpenAPI / Postman definition",
}

TLS_FLAGS = ("expired", "self_signed", "mismatched", "untrusted", "revoked")

CAVEATS = [
    ["Before importing into Tenable"],
    ["VM: confirm ownership of every IP — routing uses observed signals (CDN, WAF, 3rd-party, PaaS), "
     "not proof of ownership, unless ownership was enforced."],
    ["VM review: IPs outside the declared owned ranges — confirm, then move to include."],
    ["WAS waf: scan only once the WAF allow-lists Tenable's scanner egress IPs or a custom header."],
    ["WAS api: attach an OpenAPI / Swagger / Postman definition; DOM crawling finds little on pure APIs."],
]


def _rows(con, sql: str, params=None) -> list[dict]:
    cur = con.execute(sql, params or [])
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row)) for row in cur.fetchall()]


def _has_table(con, name: str) -> bool:
    return con.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?",
                       [name]).fetchone()[0] > 0


def _uniq(values) -> list:
    return list(dict.fromkeys(v for v in values if v not in (None, "")))


# ---------------------------------------------------------------------------
# Asset enrichment
# ---------------------------------------------------------------------------

def _web_summary(web: list) -> dict:
    entries = [_dict(w) for w in web]
    return {
        "http_status": _uniq(_int(w.get("status_code")) for w in entries),
        "title": next((w["title"] for w in entries if w.get("title")), None),
        "server": _uniq(w.get("server") for w in entries),
        "tech": _uniq(t for w in entries for t in _list(w.get("tech"))),
        "content_type": _uniq((w.get("content_type") or "").split(";")[0].strip() for w in entries),
    }


def _web_by_origin(web: list) -> dict[str, dict]:
    """WAS URLs are origins of httpx final URLs (tenable_scope.analyze_web)."""
    out = {}
    for w in map(_dict, web):
        for url in (w.get("final_url"), w.get("url")):
            origin = _origin(url) if url and "://" in url else None
            if origin:
                out.setdefault(origin, w)
    return out


def _tls_summary(tls: list) -> dict:
    entries = [_dict(t) for t in tls]
    if not entries:
        return {}
    soonest = min(entries, key=lambda t: t.get("not_after") or "9999")
    return {
        "tls_issuer": soonest.get("issuer"),
        "tls_expiry": soonest.get("not_after"),
        "tls_days": _int(soonest.get("days_to_expiry")),
        "tls_issues": _uniq(f for t in entries for f in TLS_FLAGS if t.get(f)),
    }


def _enrichment(con) -> dict[str, dict]:
    if not _has_table(con, "assets"):
        return {}
    from load_duckdb import _has_column
    cols = [c for c in ENRICH_COLUMNS if _has_column(con, "assets", c)]
    out = {}
    for a in _rows(con, f"SELECT {', '.join(cols)} FROM assets"):
        dns, network, cmdb = _dict(a.get("dns")), _dict(a.get("network")), _dict(a.get("cmdb"))
        asn = _dict(network.get("asn"))
        web = _list(a.get("web"))
        out[(a.get("fqdn") or "").lower()] = {
            "cname_chain": _list(dns.get("cname_chain")),
            "asn_number": _int(asn.get("number")),
            "asn_country": asn.get("country"),
            "cmdb_ci": cmdb.get("matched_ci"),
            "cmdb_match": _list(cmdb.get("match_basis")),
            "cmdb_gap": cmdb.get("gap_type"),
            "sources": _list(a.get("source")),
            "first_seen": a.get("first_seen"),
            "last_seen": a.get("last_seen"),
            "web_by_origin": _web_by_origin(web),
            **_web_summary(web),
            **_tls_summary(_list(a.get("tls"))),
        }
    return out


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------

def tenable_workbook_data(con) -> dict:
    """Everything the workbook shows, as plain rows (SELECTs only)."""
    meta = _rows(con, "SELECT * FROM tenable_scope_meta LIMIT 1") if _has_table(con, "tenable_scope_meta") else []
    meta = meta[0] if meta else {}
    enrich = _enrichment(con)

    assets = []
    for r in _rows(con, "SELECT * FROM tenable_scope ORDER BY fqdn"):
        assets.append({**enrich.get(r["fqdn"], {}), **r})
    by_fqdn = {a["fqdn"]: a for a in assets}

    vm = []
    for r in _rows(con, "SELECT * FROM tenable_vm_targets WHERE action IN ('include', 'review')"):
        hosts = [by_fqdn[f] for f in (r.get("fqdns") or []) if f in by_fqdn]
        vm.append({
            **r,
            "any_in_cmdb": any(h.get("in_cmdb") for h in hosts),
            "cmdb_cis": _uniq(h.get("cmdb_ci") for h in hosts),
        })
    vm.sort(key=lambda r: (r["action"] != "include", ip_sort_key(r["target_ip"])))

    was = []
    for a in assets:
        if a.get("was_action") != "include":
            continue
        for url in _uniq(a.get("was_urls") or []):
            w = a.get("web_by_origin", {}).get(url, {})
            was.append({
                **a,
                "target_url": url,
                "policy": WAS_POLICY.get(a.get("was_profile"), ""),
                "url_status": _int(w.get("status_code")),
                "url_title": w.get("title"),
                "url_server": w.get("server"),
                "url_tech": _list(w.get("tech")),
                "url_content_type": (w.get("content_type") or "").split(";")[0].strip() or None,
            })
    was.sort(key=lambda r: ({"standard": 0, "waf": 1, "api": 2}.get(r.get("was_profile"), 9),
                            r["fqdn"], r["target_url"]))

    summary = _rows(con, "SELECT * FROM v_tenable_scope_summary") if _has_table(con, "v_tenable_scope_summary") else []
    return {"meta": meta, "assets": assets, "vm": vm, "was": was, "summary": summary}


# ---------------------------------------------------------------------------
# Sheets
# ---------------------------------------------------------------------------

def _scan_id(data: dict) -> str | None:
    return data["meta"].get("scan_id") or next((a.get("scan_id") for a in data["assets"] if a.get("scan_id")), None)


ALL_COLUMNS = [
    Column("FQDN", "fqdn", width=36, note="Discovered hostname (or IP, for IP targets)"),
    Column("Primary category", "category", width=16,
           note="Routing-matrix category that decided the routing (TENABLE_SCOPE_PIPELINE.MD)"),
    Column("All categories", "categories", "list", 24, "Every matrix category the asset matched"),
    Column("In CMDB", "in_cmdb", "bool", 9, "Registered in the CMDB export"),
    Column("CMDB CI", "cmdb_ci", width=14, note="Matched CMDB configuration item ID"),
    Column("CMDB match", "cmdb_match", "list", 12, "How the CI matched: fqdn, ip or cert_san"),
    Column("CMDB gap", "cmdb_gap", width=13, note="shadow_it / unmanaged / orphan_cert / stale_ci"),
    Column("IPs", "ips", "list", 24, "Resolved A records"),
    Column("Open ports", "ports", "list", 18, "Open TCP ports (naabu / nerva)"),
    Column("ASN", "asn_number", "int", 9, "Autonomous system number"),
    Column("ASN org", "asn_org", width=26, note="Autonomous system owner"),
    Column("ASN country", "asn_country", width=8),
    Column("CNAME chain", "cname_chain", "list", 30, "CNAME chain from the hostname"),
    Column("CDN provider", "cdn_provider", width=14, note="CDN detected above TENABLE_CDN_MIN_CONFIDENCE"),
    Column("WAF provider", "waf_provider", width=14, note="WAF detected above TENABLE_WAF_MIN_CONFIDENCE"),
    Column("Platforms", "platforms", "list", 22,
           note="Managed platforms as platform:class (cloud_enum, hostname suffix, ASN org)"),
    Column("Takeover status", "takeover_status", width=12, note="confirmed / candidate subdomain takeover"),
    Column("VM decision", "vm_action", width=11, colors=VM_COLORS,
           note="include = network-scan its IPs; review = confirm ownership; exclude = keep out of VM"),
    Column("VM IPs", "vm_ips", "list", 22, "IPs of this asset in the VM include list"),
    Column("VM reasons", "vm_reasons", "list", 30, "Why the asset's IPs are not VM targets"),
    Column("WAS decision", "was_action", width=11, colors=WAS_COLORS),
    Column("WAS profile", "was_profile", width=10, colors=WAS_COLORS,
           note="standard / waf (allow-list first) / api (needs a definition)"),
    Column("WAS reasons", "was_reasons", "list", 26, "Why the asset is not a DAST target"),
    Column("WAS URLs", "was_urls", "list", 36, "Origins to add to Tenable WAS"),
    Column("HTTP status", "http_status", "list", 10, "Status codes seen by httpx"),
    Column("Title", "title", width=30, note="First non-empty HTML title"),
    Column("Web server", "server", "list", 16),
    Column("Technologies", "tech", "list", 30, "httpx technology fingerprints"),
    Column("Content type", "content_type", "list", 16),
    Column("TLS issuer", "tls_issuer", width=28, note="Issuer of the soonest-expiring certificate"),
    Column("TLS expiry", "tls_expiry", "date", 11, "Soonest certificate expiry"),
    Column("TLS days left", "tls_days", "int", 9),
    Column("TLS issues", "tls_issues", "list", 18, "expired / self_signed / mismatched / untrusted / revoked"),
    Column("Sources", "sources", "list", 18, "Pipeline sources that contributed the asset"),
    Column("First seen", "first_seen", "date", 11),
    Column("Last seen", "last_seen", "date", 11),
    Column("Scan ID", "scan_id", width=16),
]

VM_COLUMNS = [
    Column("Target IP", "target_ip", width=18, note="IP to add to the Tenable VM scan"),
    Column("Decision", "action", width=10, colors=VM_COLORS,
           note="include = ready to scan; review = outside the declared owned ranges, confirm first"),
    Column("VM category", "vm_category", width=13,
           note="direct = one FQDN; owned_shared = LB / ingress serving several FQDNs (scan the IP once)"),
    Column("Owned", "owned", "bool", 8, "Inside TENABLE_OWNED_CIDRS / TENABLE_OWNED_ASNS"),
    Column("Primary FQDN", "primary_fqdn", width=34, note="Representative hostname (CMDB-registered first)"),
    Column("FQDN count", "fqdn_count", "int", 8, "Hostnames resolving to the IP"),
    Column("All FQDNs", "fqdns", "list", 50),
    Column("Ports", "ports", "list", 22, "Open ports across all hostnames"),
    Column("ASN org", "asn_org", width=26),
    Column("Any FQDN in CMDB", "any_in_cmdb", "bool", 10),
    Column("CMDB CIs", "cmdb_cis", "list", 18),
    Column("Review reason", "reasons", "list", 22, "Set for review rows (ownership_unverified)"),
    Column("Scan ID", "scan_id", width=16),
]

WAS_COLUMNS = [
    Column("Target URL", "target_url", "url", 40, "Origin to add to Tenable WAS"),
    Column("FQDN", "fqdn", width=34),
    Column("Scan profile", "was_profile", width=10, colors=WAS_COLORS),
    Column("Recommended policy", "policy", width=38, note="What to set up in Tenable WAS before scanning"),
    Column("Category", "category", width=14),
    Column("WAF provider", "waf_provider", width=14),
    Column("CDN provider", "cdn_provider", width=14),
    Column("Platforms", "platforms", "list", 22),
    Column("HTTP status", "url_status", "int", 9, "httpx status for this origin"),
    Column("Title", "url_title", width=30),
    Column("Server", "url_server", width=16),
    Column("Technologies", "url_tech", "list", 30),
    Column("Content type", "url_content_type", width=16),
    Column("TLS expiry", "tls_expiry", "date", 11),
    Column("IPs", "ips", "list", 22),
    Column("In CMDB", "in_cmdb", "bool", 9),
    Column("CMDB CI", "cmdb_ci", width=14),
    Column("Scan ID", "scan_id", width=16),
]


def build_sheets(data: dict) -> list[Sheet]:
    return [
        Sheet("All", ALL_COLUMNS, data["assets"], "Every routed asset with its VM and WAS decision and enrichment"),
        Sheet("Tenable VM Candidates", VM_COLUMNS, data["vm"],
              "IPs for Tenable VM — include first, then review (confirm ownership)"),
        Sheet("Tenable WAS Candidates", WAS_COLUMNS, data["was"],
              "URLs for Tenable WAS, ordered by profile: standard, waf, api"),
    ]


def build_metadata(data: dict) -> list[tuple]:
    meta, assets = data["meta"], data["assets"]
    vm_counts = {a: sum(1 for r in data["vm"] if r["action"] == a) for a in ("include", "review")}
    was_counts = {p: len({r["target_url"] for r in data["was"] if r["was_profile"] == p})
                  for p in ("standard", "waf", "api")}
    owned = [*(meta.get("owned_cidrs") or []), *(f"AS{a}" for a in meta.get("owned_asns") or [])]
    yes_no = lambda v: "Yes" if v else "No"  # noqa: E731

    return [
        ("Scan ID", _scan_id(data) or "-"),
        ("Routed at", meta.get("routed_at") or "-"),
        ("Generated at", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
        ("Ownership enforced", yes_no(meta.get("require_owned"))),
        ("Owned ranges", ", ".join(owned) or "none declared"),
        ("CMDB-registered only", yes_no(meta.get("cmdb_only"))),
        ("CDN / WAF thresholds", f"CDN ≥ {meta.get('cdn_min_confidence', '-')} · WAF ≥ {meta.get('waf_min_confidence', '-')}"),
        ("Vendor SaaS in WAS", yes_no(meta.get("was_include_saas"))),
        ("Assets routed", len(assets)),
        ("Assets in CMDB", sum(1 for a in assets if a.get("in_cmdb"))),
        ("VM IPs — include", vm_counts["include"]),
        ("VM IPs — review", vm_counts["review"]),
        ("WAS URLs — standard", was_counts["standard"]),
        ("WAS URLs — waf (allow-list first)", was_counts["waf"]),
        ("WAS URLs — api (definition needed)", was_counts["api"]),
    ]


def build_sections(data: dict) -> list[tuple]:
    sections = []
    if data["summary"]:
        keys = ["category", "assets", "vm_include", "vm_exclude", "vm_review",
                "was_standard", "was_waf", "was_api", "was_exclude"]
        sections.append(("Routing matrix (assets)", [
            ["Category", "Assets", "VM incl", "VM excl", "VM review", "WAS std", "WAS waf", "WAS api", "WAS excl"],
            *([r.get(k) or 0 if k != "category" else r[k] for k in keys] for r in data["summary"]),
        ]))
    sections.append(("Caveats", CAVEATS))
    return sections


def xlsx_filename(data: dict) -> str:
    scan_id = _scan_id(data)
    return f"tenable_scope_{scan_id}.xlsx" if scan_id else "tenable_scope.xlsx"


def write_tenable_xlsx(con, target, data: dict | None = None) -> dict[str, int]:
    """Write the workbook to target (path or BytesIO). Returns sheet row counts."""
    data = data or tenable_workbook_data(con)
    return write_workbook(
        target, build_sheets(data),
        title="EASM — Tenable VM / WAS scan scope",
        metadata=build_metadata(data),
        sections=build_sections(data),
    )


def main():
    parser = argparse.ArgumentParser(description="Write the Tenable scan-scope workbook")
    parser.add_argument("--db", required=True, help="DuckDB with the scope stage's tenable_* tables")
    parser.add_argument("--output", required=True, help="Output .xlsx path")
    args = parser.parse_args()

    import duckdb
    con = duckdb.connect(args.db, read_only=True)
    try:
        counts = write_tenable_xlsx(con, args.output)
    finally:
        con.close()
    print(f"Wrote {args.output}: " + ", ".join(f"{k}={v}" for k, v in counts.items()), file=sys.stderr)


if __name__ == "__main__":
    main()
