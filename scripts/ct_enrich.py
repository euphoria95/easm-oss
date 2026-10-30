#!/usr/bin/env python3
"""
EASM Pipeline — Certificate Transparency enrichment (crt.sh).

Passive discovery: queries crt.sh for every certificate ever logged for the
given root domains and extracts the hostnames (SANs) from them. Only names
that are the root domain itself or a subdomain of it are kept, so a stray SAN
for a third-party domain on a shared certificate never enters the scan scope.

Usage:
    python3 scripts/ct_enrich.py --domains example.com,example.org \
        --existing data/output/targets.txt \
        --output data/output/ct_subdomains.txt

Output: one lowercase hostname per line (sorted, unique) — every in-scope name
CT returned, including ones already in --existing. The new/known split is
reported on stderr.

Exit codes: 0 = at least one domain queried successfully (or nothing to do),
            1 = every query failed (crt.sh down / blocked).
"""

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CRTSH_URL = "https://crt.sh/?q={query}&output=json"

_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
HOSTNAME_RE = re.compile(rf"^(?:{_LABEL}\.)+{_LABEL}$")


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def parse_domains(raw: str) -> list[str]:
    """Split a comma/space separated list into valid, unique root domains."""
    domains: list[str] = []
    for token in re.split(r"[,\s]+", raw.lower()):
        token = token.strip().strip(".")
        if token.startswith("*."):
            token = token[2:]
        if not token:
            continue
        if not HOSTNAME_RE.match(token):
            log(f"WARN: ignoring invalid root domain '{token}'")
            continue
        if token not in domains:
            domains.append(token)
    return domains


def extract_names(records: list[dict], domain: str) -> set[str]:
    """Pull in-scope hostnames out of crt.sh JSON records."""
    suffix = "." + domain
    names: set[str] = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        # name_value is newline-separated SANs; common_name is the subject CN.
        raw = f"{rec.get('name_value') or ''}\n{rec.get('common_name') or ''}"
        for name in raw.split("\n"):
            name = name.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if not name or "*" in name or not HOSTNAME_RE.match(name):
                continue
            if name == domain or name.endswith(suffix):
                names.add(name)
    return names


def fetch_crtsh(domain: str, timeout: int, retries: int, user_agent: str) -> list[dict]:
    """Query crt.sh for %.domain. Retries with backoff; raises on final failure."""
    url = CRTSH_URL.format(query=urllib.parse.quote(f"%.{domain}"))
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body)
            if not isinstance(data, list):
                raise ValueError("unexpected crt.sh response shape")
            return data
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as e:
            # crt.sh regularly answers 502/503 or truncated JSON under load.
            last_err = e
            if attempt < retries:
                wait = 2 ** attempt
                log(f"  attempt {attempt}/{retries} failed ({e}); retrying in {wait}s")
                time.sleep(wait)
    raise RuntimeError(str(last_err))


def read_names(path: str | None) -> set[str]:
    if not path or not Path(path).is_file():
        return set()
    return {
        line.strip().lower()
        for line in Path(path).read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }


def main(argv: list[str] | None = None, fetch=fetch_crtsh) -> int:
    ap = argparse.ArgumentParser(description="crt.sh Certificate Transparency enrichment")
    ap.add_argument("--domains", required=True, help="Comma-separated root domains")
    ap.add_argument("--existing", help="File of already-known targets (for the new/known split)")
    ap.add_argument("--output", required=True, help="Where to write discovered hostnames")
    ap.add_argument("--timeout", type=int, default=60, help="Per-request timeout in seconds")
    ap.add_argument("--retries", type=int, default=3, help="Attempts per domain")
    ap.add_argument("--delay", type=float, default=1.0, help="Seconds between domains")
    ap.add_argument("--user-agent", default="EASM-Pipeline/0.1")
    args = ap.parse_args(argv)

    domains = parse_domains(args.domains)
    if not domains:
        log("No valid root domains — nothing to query")
        Path(args.output).write_text("")
        return 0

    existing = read_names(args.existing)
    found: set[str] = set()
    failures = 0

    for i, domain in enumerate(domains):
        if i:
            time.sleep(args.delay)
        log(f"Querying crt.sh for %.{domain}")
        try:
            records = fetch(domain, args.timeout, args.retries, args.user_agent)
        except RuntimeError as e:
            failures += 1
            log(f"WARN: crt.sh query failed for {domain}: {e}")
            continue
        names = extract_names(records, domain)
        log(f"  {domain}: {len(records)} certificates → {len(names)} hostnames")
        found |= names

    Path(args.output).write_text("".join(f"{n}\n" for n in sorted(found)))

    new = found - existing
    log(f"CT enrichment: found={len(found)} new={len(new)} known={len(found) - len(new)} "
        f"domains={len(domains)} failed={failures}")
    return 1 if failures == len(domains) else 0


if __name__ == "__main__":
    sys.exit(main())
