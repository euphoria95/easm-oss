#!/usr/bin/env python3
"""
EASM Pipeline — CMDB Livecheck Mode

Validates CMDB-registered FQDNs for DNS liveness, detects CDN/WAF presence,
analyzes CNAME chain bloat, identifies leaf domains, tracks unavailability
over time, and classifies 3rd-party nameservers.

Designed for Tenable scanning scope governance: proposes inclusions and
exclusions based on resolution status, CDN fronting, and staleness.

Usage:
    python3 livecheck.py \
        --dns dns.jsonl \
        --asn asn.jsonl \
        --cmdb cmdb_export.csv \
        --state livecheck_state.json \
        --output livecheck_report.jsonl \
        --scan-id 20260522_143015 \
        --deadline-days 30 \
        --cname-depth-threshold 3
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    import orjson
    def _json_loads(b): return orjson.loads(b)
    def _json_dumps(obj): return orjson.dumps(obj)
except ImportError:
    def _json_loads(b): return json.loads(b)
    def _json_dumps(obj): return json.dumps(obj, separators=(',', ':')).encode()

# ---------------------------------------------------------------------------
# Import CDN detection from sibling module
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent))
from detect_cdn import CNAME_PATTERNS, CDN_ASNS  # noqa: E402

# ---------------------------------------------------------------------------
# 3rd-party NS provider patterns
# ---------------------------------------------------------------------------
NS_PROVIDERS: dict[str, str] = {
    ".ns.cloudflare.com": "cloudflare",
    ".cloudflare.com": "cloudflare",
    ".awsdns-": "route53",
    ".amazonaws.com": "route53",
    ".azure-dns.com": "azure_dns",
    ".azure-dns.net": "azure_dns",
    ".azure-dns.org": "azure_dns",
    ".azure-dns.info": "azure_dns",
    ".googledomains.com": "google_dns",
    ".google.com": "google_dns",
    ".nsone.net": "ns1",
    ".p0": "ns1",          # ns1 pattern: ns1.p01.nsone.net
    ".dynect.net": "dyn",
    ".ultradns.com": "ultradns",
    ".ultradns.net": "ultradns",
    ".ultradns.org": "ultradns",
    ".domaincontrol.com": "godaddy",
    ".registrar-servers.com": "namecheap",
    ".name-services.com": "enom",
    ".dnsmadeeasy.com": "dnsmadeeasy",
    ".he.net": "hurricane_electric",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path: str) -> list[dict]:
    records = []
    p = Path(path)
    if not p.exists():
        return records
    with open(p, "rb") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(_json_loads(line))
            except (json.JSONDecodeError, Exception):
                pass
    return records


def load_cmdb(path: str) -> list[dict]:
    """Load CMDB CSV with flexible column detection."""
    p = Path(path)
    if not p.exists():
        print(f"WARN: CMDB file not found: {path}", file=sys.stderr)
        return []
    rows = []
    with open(p, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            fqdn = (
                row.get("fqdn", "")
                or row.get("hostname", "")
                or row.get("name", "")
            ).strip().lower()
            if fqdn:
                rows.append({
                    "ci_id": row.get("ci_id", ""),
                    "fqdn": fqdn,
                    "ip": row.get("ip", "").strip(),
                    "owner": row.get("owner", ""),
                    "cost_center": row.get("cost_center", ""),
                })
    return rows


def load_state(path: str) -> dict:
    """Load persistent unavailability tracking state."""
    p = Path(path)
    if p.exists():
        with open(p) as f:
            return json.load(f)
    return {}


def save_state(path: str, state: dict):
    """Persist unavailability tracking state."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)


# ---------------------------------------------------------------------------
# UC1: FQDN resolution check
# ---------------------------------------------------------------------------
def check_resolution(dns_records: list[dict]) -> dict[str, dict]:
    """Map FQDN → resolution info from dnsx output."""
    result = {}
    for rec in dns_records:
        host = rec.get("host", "").lower().strip()
        if not host:
            continue
        a_records = rec.get("a", []) or []
        aaaa_records = rec.get("aaaa", []) or []
        cname = rec.get("cname", []) or []
        ns = rec.get("ns", []) or []
        mx = rec.get("mx", []) or []
        status = rec.get("status_code", "")

        resolves = len(a_records) > 0 or len(aaaa_records) > 0
        result[host] = {
            "resolves": resolves,
            "a": a_records,
            "aaaa": aaaa_records,
            "cname": cname if isinstance(cname, list) else [cname] if cname else [],
            "ns": ns if isinstance(ns, list) else [ns] if ns else [],
            "mx": mx,
            "status_code": status,
        }
    return result


# ---------------------------------------------------------------------------
# UC2: CDN/WAF detection for scope exclusion
# ---------------------------------------------------------------------------
def detect_cdn_for_livecheck(dns_info: dict, asn_by_ip: dict) -> dict | None:
    """Lightweight CDN detection using DNS CNAME + ASN (no HTTP needed)."""
    votes: dict[str, list[str]] = {}

    # CNAME signal
    for cname in dns_info.get("cname", []):
        cname_lower = cname.lower().rstrip(".")
        for suffix, provider in CNAME_PATTERNS.items():
            if cname_lower.endswith(suffix):
                votes.setdefault(provider, []).append(f"cname:{cname_lower}")
                break

    # ASN signal (from resolved IPs)
    for ip in dns_info.get("a", []):
        asn_info = asn_by_ip.get(ip)
        if asn_info:
            asn_num = asn_info.get("asn")
            if asn_num and asn_num in CDN_ASNS:
                votes.setdefault(CDN_ASNS[asn_num], []).append(f"asn:{asn_num}")

    if not votes:
        return None

    best = max(votes, key=lambda p: len(votes[p]))
    signals = votes[best]
    signal_types = {s.split(":")[0] for s in signals}
    confidence = min(1.0, len(signal_types) * 0.35)

    return {
        "provider": best,
        "confidence": round(confidence, 2),
        "signals": signals,
    }


# ---------------------------------------------------------------------------
# UC3: CNAME chain bloat
# ---------------------------------------------------------------------------
def analyze_cname_chains(resolution_map: dict[str, dict], depth_threshold: int) -> dict:
    """Detect CNAME chain bloat and fan-in grouping."""
    bloated = {}
    terminal_targets: dict[str, list[str]] = defaultdict(list)

    for fqdn, info in resolution_map.items():
        chain = info.get("cname", [])
        depth = len(chain)
        if depth > 0:
            terminal = chain[-1].lower().rstrip(".")
            terminal_targets[terminal].append(fqdn)

        if depth > depth_threshold:
            bloated[fqdn] = {
                "chain_depth": depth,
                "cname_chain": chain,
                "terminal_target": chain[-1].lower().rstrip(".") if chain else None,
            }

    # Detect fan-in: multiple FQDNs sharing a terminal target
    fan_in = {
        target: fqdns
        for target, fqdns in terminal_targets.items()
        if len(fqdns) > 1
    }

    return {"bloated": bloated, "fan_in": fan_in}


# ---------------------------------------------------------------------------
# UC4: Leaf domain identification
# ---------------------------------------------------------------------------
def identify_leaf_domains(all_fqdns: set[str]) -> set[str]:
    """A leaf domain has no child subdomains in the set."""
    leaves = set()
    for fqdn in all_fqdns:
        has_child = any(
            other.endswith("." + fqdn) for other in all_fqdns if other != fqdn
        )
        if not has_child:
            leaves.add(fqdn)
    return leaves


# ---------------------------------------------------------------------------
# UC5: Unavailability tracking with 30-day deadline
# ---------------------------------------------------------------------------
def update_unavailability(
    state: dict,
    resolution_map: dict[str, dict],
    cmdb_fqdns: set[str],
    scan_id: str,
    deadline_days: int,
) -> dict:
    """Update unavailability state and compute removal recommendations."""
    now = now_iso()
    now_dt = datetime.now(timezone.utc)

    # Process all CMDB FQDNs
    for fqdn in cmdb_fqdns:
        dns_info = resolution_map.get(fqdn, {})
        resolves = dns_info.get("resolves", False)

        if resolves:
            # Asset is alive — clear any unavailability tracking
            if fqdn in state:
                del state[fqdn]
        else:
            # Asset is down
            if fqdn not in state:
                state[fqdn] = {
                    "first_unavailable": now,
                    "consecutive_scans_down": 1,
                    "last_scan_id": scan_id,
                }
            else:
                state[fqdn]["consecutive_scans_down"] += 1
                state[fqdn]["last_scan_id"] = scan_id

    # Compute recommendations
    recommendations = {}
    for fqdn, entry in state.items():
        first_down = datetime.fromisoformat(
            entry["first_unavailable"].replace("Z", "+00:00")
        )
        days_down = (now_dt - first_down).days
        days_remaining = max(0, deadline_days - days_down)

        recommendations[fqdn] = {
            "first_unavailable": entry["first_unavailable"],
            "consecutive_scans_down": entry["consecutive_scans_down"],
            "days_unavailable": days_down,
            "days_remaining": days_remaining,
            "recommend_remove": days_down >= deadline_days,
            "deadline_date": (
                first_down.replace(tzinfo=timezone.utc)
                + __import__("datetime").timedelta(days=deadline_days)
            ).strftime("%Y-%m-%d"),
        }

    return recommendations


# ---------------------------------------------------------------------------
# UC6: 3rd-party nameserver detection
# ---------------------------------------------------------------------------
def classify_nameservers(
    dns_info: dict, root_domains: set[str]
) -> dict:
    """Classify NS records as 1st-party or 3rd-party."""
    ns_records = dns_info.get("ns", [])
    if not ns_records:
        return {"ns_records": [], "ns_provider": None, "ns_is_third_party": None}

    results = []
    for ns in ns_records:
        ns_lower = ns.lower().rstrip(".")
        provider = None
        is_third_party = True

        # Check if NS belongs to any known root domain
        for rd in root_domains:
            if ns_lower.endswith("." + rd) or ns_lower == rd:
                is_third_party = False
                break

        # Classify provider
        for suffix, prov in NS_PROVIDERS.items():
            if suffix in ns_lower:
                provider = prov
                break

        results.append({
            "ns": ns,
            "provider": provider,
            "is_third_party": is_third_party,
        })

    # Summarize: majority vote for overall classification
    third_party_count = sum(1 for r in results if r["is_third_party"])
    primary_provider = None
    if results:
        providers = [r["provider"] for r in results if r["provider"]]
        if providers:
            primary_provider = max(set(providers), key=providers.count)

    return {
        "ns_records": results,
        "ns_provider": primary_provider,
        "ns_is_third_party": third_party_count > len(results) / 2 if results else None,
    }


# ---------------------------------------------------------------------------
# Main: orchestrate all use cases and produce report
# ---------------------------------------------------------------------------
def run_livecheck(args):
    scan_id = args.scan_id
    deadline_days = args.deadline_days
    cname_depth_threshold = args.cname_depth_threshold
    now = now_iso()

    # --- Load inputs ---
    dns_records = read_jsonl(args.dns) if args.dns else []
    asn_records = read_jsonl(args.asn) if args.asn else []
    cmdb_rows = load_cmdb(args.cmdb) if args.cmdb else []
    state = load_state(args.state)

    print(f"Livecheck inputs: dns={len(dns_records)} asn={len(asn_records)} "
          f"cmdb={len(cmdb_rows)} state_entries={len(state)}", file=sys.stderr)

    # --- Build lookup maps ---
    # UC1: resolution map
    resolution_map = check_resolution(dns_records)

    # ASN by IP lookup
    asn_by_ip = {}
    for rec in asn_records:
        ip = rec.get("ip", "")
        if ip:
            asn_by_ip[ip] = rec

    # CMDB FQDNs
    cmdb_fqdns = {row["fqdn"] for row in cmdb_rows}
    cmdb_by_fqdn = {row["fqdn"]: row for row in cmdb_rows}

    # All known FQDNs (CMDB + discovered)
    all_fqdns = cmdb_fqdns | set(resolution_map.keys())

    # Root domains (extract from CMDB FQDNs — 2nd-level domains)
    root_domains = set()
    for fqdn in all_fqdns:
        parts = fqdn.split(".")
        if len(parts) >= 2:
            root_domains.add(".".join(parts[-2:]))

    # --- UC3: CNAME chain analysis ---
    cname_analysis = analyze_cname_chains(resolution_map, cname_depth_threshold)

    # --- UC4: Leaf domains ---
    leaf_domains = identify_leaf_domains(all_fqdns)

    # --- UC5: Unavailability tracking ---
    unavail_recommendations = update_unavailability(
        state, resolution_map, cmdb_fqdns, scan_id, deadline_days
    )

    # --- Build fan-in lookup ---
    fqdn_fan_in_group: dict[str, str] = {}
    for terminal, members in cname_analysis["fan_in"].items():
        for fqdn in members:
            fqdn_fan_in_group[fqdn] = terminal

    # --- Produce per-FQDN report ---
    report = []
    for fqdn in sorted(all_fqdns):
        dns_info = resolution_map.get(fqdn, {})
        cmdb_entry = cmdb_by_fqdn.get(fqdn)
        resolves = dns_info.get("resolves", False)

        # UC2: CDN detection
        cdn_result = detect_cdn_for_livecheck(dns_info, asn_by_ip)
        cdn_provider = cdn_result["provider"] if cdn_result else None
        cdn_confidence = cdn_result["confidence"] if cdn_result else 0.0
        exclude_proposal = cdn_result is not None and cdn_confidence >= 0.7

        # UC3: CNAME bloat
        bloat_info = cname_analysis["bloated"].get(fqdn)
        cname_chain = dns_info.get("cname", [])
        chain_depth = len(cname_chain)
        fan_in_target = fqdn_fan_in_group.get(fqdn)

        # UC4: Leaf domain
        is_leaf = fqdn in leaf_domains

        # UC5: Unavailability
        unavail = unavail_recommendations.get(fqdn)

        # UC6: NS classification
        ns_info = classify_nameservers(dns_info, root_domains)

        # --- Assemble record ---
        record: dict = {
            "fqdn": fqdn,
            "scan_id": scan_id,
            "timestamp": now,
            "in_cmdb": cmdb_entry is not None,
            "ci_id": cmdb_entry["ci_id"] if cmdb_entry else None,
            "owner": cmdb_entry.get("owner") if cmdb_entry else None,
            # UC1
            "resolves": resolves,
            "a_records": dns_info.get("a", []),
            "aaaa_records": dns_info.get("aaaa", []),
            "dns_status": dns_info.get("status_code", "NO_DATA"),
            # UC2
            "cdn_provider": cdn_provider,
            "cdn_confidence": cdn_confidence,
            "cdn_signals": cdn_result["signals"] if cdn_result else [],
            "exclude_proposal": exclude_proposal,
            # UC3
            "cname_chain": cname_chain,
            "cname_chain_depth": chain_depth,
            "cname_bloated": bloat_info is not None,
            "cname_fan_in_target": fan_in_target,
            "cname_fan_in_count": (
                len(cname_analysis["fan_in"].get(fan_in_target, []))
                if fan_in_target else 0
            ),
            # UC4
            "is_leaf": is_leaf,
            # UC5
            "unavailable": unavail is not None,
            "days_unavailable": unavail["days_unavailable"] if unavail else 0,
            "days_remaining": unavail["days_remaining"] if unavail else None,
            "consecutive_scans_down": (
                unavail["consecutive_scans_down"] if unavail else 0
            ),
            "recommend_remove": (
                unavail["recommend_remove"] if unavail else False
            ),
            "removal_deadline": unavail["deadline_date"] if unavail else None,
            # UC6
            "ns_provider": ns_info["ns_provider"],
            "ns_is_third_party": ns_info["ns_is_third_party"],
            "ns_records": ns_info["ns_records"],
            # Composite scope recommendation
            "scope_action": _scope_action(
                resolves, exclude_proposal, unavail, is_leaf, bloat_info
            ),
        }
        report.append(record)

    # --- Write output ---
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        for rec in report:
            f.write(_json_dumps(rec) + b"\n")

    # --- Persist state ---
    save_state(args.state, state)

    # --- Summary ---
    total = len(report)
    resolved = sum(1 for r in report if r["resolves"])
    cdn_excluded = sum(1 for r in report if r["exclude_proposal"])
    removals = sum(1 for r in report if r["recommend_remove"])
    bloated = sum(1 for r in report if r["cname_bloated"])
    leaves = sum(1 for r in report if r["is_leaf"])
    third_party_ns = sum(1 for r in report if r["ns_is_third_party"])

    print(f"\n=== Livecheck Summary ===", file=sys.stderr)
    print(f"  Total FQDNs:         {total}", file=sys.stderr)
    print(f"  Resolving:           {resolved} ({resolved*100//max(total,1)}%)", file=sys.stderr)
    print(f"  CDN exclude propsd:  {cdn_excluded}", file=sys.stderr)
    print(f"  Removal candidates:  {removals} (>={deadline_days}d unavailable)", file=sys.stderr)
    print(f"  CNAME bloated:       {bloated} (>{cname_depth_threshold} hops)", file=sys.stderr)
    print(f"  Leaf domains:        {leaves}", file=sys.stderr)
    print(f"  3rd-party NS:        {third_party_ns}", file=sys.stderr)
    print(f"  Report:              {output_path}", file=sys.stderr)

    return report


def _scope_action(
    resolves: bool,
    exclude_proposal: bool,
    unavail: dict | None,
    is_leaf: bool,
    bloat_info: dict | None,
) -> str:
    """Determine composite scope recommendation."""
    if unavail and unavail.get("recommend_remove"):
        return "remove"
    if not resolves and is_leaf:
        return "review_remove"
    if exclude_proposal:
        return "exclude_cdn"
    if bloat_info:
        return "review_cname_bloat"
    if not resolves:
        return "monitor"
    return "keep"


def main():
    parser = argparse.ArgumentParser(description="EASM Livecheck Mode")
    parser.add_argument("--dns", help="Path to dns.jsonl")
    parser.add_argument("--asn", help="Path to asn.jsonl")
    parser.add_argument("--cmdb", help="Path to CMDB CSV export")
    parser.add_argument("--state", default="data/output/livecheck_state.json",
                        help="Path to persistent state file")
    parser.add_argument("--output", default="data/output/livecheck_report.jsonl",
                        help="Output livecheck report JSONL")
    parser.add_argument("--scan-id", default="unknown", help="Scan identifier")
    parser.add_argument("--deadline-days", type=int, default=30,
                        help="Days of unavailability before removal recommendation")
    parser.add_argument("--cname-depth-threshold", type=int, default=3,
                        help="CNAME chain depth threshold for bloat detection")
    args = parser.parse_args()
    run_livecheck(args)


if __name__ == "__main__":
    main()
