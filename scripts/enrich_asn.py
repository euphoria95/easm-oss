#!/usr/bin/env python3
"""
Offline ASN enrichment for IP addresses using pyasn (BGP RIB data).
Outputs JSONL: {"ip": "1.2.3.4", "asn": 13335, "prefix": "1.2.3.0/24", "org": "CLOUDFLARENET"}
"""
import argparse
import sys
from pathlib import Path

import orjson
import pyasn


def load_asn_names(names_file: str) -> dict[int, str]:
    names = {}
    if not names_file or not Path(names_file).exists():
        return names
    with open(names_file) as f:
        for line in f:
            parts = line.strip().split("\t", 1)
            if len(parts) == 2 and parts[0].isdigit():
                names[int(parts[0])] = parts[1]
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ips", required=True, help="File with one IP per line")
    ap.add_argument("--dns-jsonl", help="dnsx JSONL to extract IPs from A records")
    ap.add_argument("--asndb", required=True, help="pyasn IPASN database file")
    ap.add_argument("--names", help="ASN names TSV (asn_number<TAB>org_name)")
    ap.add_argument("--output", required=True, help="Output JSONL path")
    args = ap.parse_args()

    asndb = pyasn.pyasn(args.asndb)
    names = load_asn_names(args.names)

    ips: set[str] = set()
    if Path(args.ips).exists():
        for line in open(args.ips):
            ip = line.strip()
            if ip:
                ips.add(ip)

    if args.dns_jsonl and Path(args.dns_jsonl).exists():
        with open(args.dns_jsonl, "rb") as f:
            for line in f:
                try:
                    rec = orjson.loads(line)
                    for a in rec.get("a") or []:
                        if a:
                            ips.add(a)
                except Exception:
                    pass

    with open(args.output, "wb") as out:
        for ip in sorted(ips):
            try:
                asn_num, prefix = asndb.lookup(ip)
            except Exception:
                asn_num, prefix = None, None
            org = names.get(asn_num, "") if asn_num else ""
            rec = {"ip": ip, "asn": asn_num, "prefix": prefix or "", "org": org}
            out.write(orjson.dumps(rec) + b"\n")

    print(f"ASN enrichment: {len(ips)} IPs processed", file=sys.stderr)


if __name__ == "__main__":
    main()
