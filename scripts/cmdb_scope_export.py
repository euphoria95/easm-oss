#!/usr/bin/env python3
"""
EASM Pipeline — Tenable Scope Exporter

Reads livecheck report and produces Tenable-compatible scope files:
  - tenable_include.txt  — targets to keep in scanning scope
  - tenable_exclude.txt  — targets to remove / exclude from scope

Usage:
    python3 cmdb_scope_export.py \
        --report livecheck_report.jsonl \
        --output-dir data/output
"""

import argparse
import sys
from pathlib import Path

try:
    import orjson
    def _json_loads(b): return orjson.loads(b)
except ImportError:
    import json
    def _json_loads(b): return json.loads(b)


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


def main():
    parser = argparse.ArgumentParser(description="EASM Tenable Scope Exporter")
    parser.add_argument("--report", required=True,
                        help="Path to livecheck_report.jsonl")
    parser.add_argument("--output-dir", default="data/output",
                        help="Output directory for scope files")
    args = parser.parse_args()
    export_scope(args)


if __name__ == "__main__":
    main()
