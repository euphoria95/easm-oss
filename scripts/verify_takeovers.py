#!/usr/bin/env python3
"""
Automated verification of subdomain takeover candidates.

Reads takeover candidates from the DuckDB assets table (subzy/nuclei findings
that the scanning pipeline already confirmed as live), performs live DNS CNAME
resolution and HTTP fingerprint checks, then:
  1. Writes detailed evidence to a takeover_verifications table + JSONL.
  2. Updates takeover_status / takeover_confidence / takeover_verified_at
     columns directly on the assets table so the main store reflects
     live-verified outcomes.

Usage:
    python3 verify_takeovers.py --db /data/output/easm.duckdb \
                                --out /data/output/takeover_verifications.jsonl
"""
import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import dns.resolver
import dns.exception
import duckdb
import orjson
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Fingerprint database
# Keyed by the service name subzy/nuclei report.  Each entry is a list of
# lowercase substrings that appear in the HTTP response body when the resource
# is unclaimed.  Based on https://github.com/EdOverflow/can-i-take-over-xyz
# ---------------------------------------------------------------------------
FINGERPRINTS: dict[str, list[str]] = {
    "github":      ["there isn't a github pages site here",
                    "for root urls (like http://example.com/) you must provide an index.html"],
    "heroku":      ["no such app", "there's nothing here, yet."],
    "netlify":     ["not found - request id:", "netlify"],
    "ghost":       ["the thing you were looking for is no longer here, or never was"],
    "tumblr":      ["whatever you were looking for doesn't currently exist at this address"],
    "wordpress":   ["do you want to register", "doesn't exist"],
    "zendesk":     ["help center closed"],
    "readme":      ["project doesnt exist... yet!"],
    "fastly":      ["fastly error: unknown domain"],
    "s3":          ["nosuchbucket", "the specified bucket does not exist"],
    "azure":       ["404 web site not found"],
    "shopify":     ["sorry, this shop is currently unavailable."],
    "cargo":       ["if you're moving your domain away from cargo"],
    "helpjuice":   ["we could not find what you're looking for."],
    "helpscout":   ["no settings were found for this company:"],
    "squarespace": ["no such account"],
    "strikingly":  ["but if you're looking to build your own website"],
    "surge":       ["project not found"],
    "teamwork":    ["oops - we didn't find your site."],
    "unbounce":    ["the requested url / was not found on this server."],
    "uberflip":    ["non-hub domain, the url you've accessed does not provide a hub."],
    "uptimerobot": ["page not found"],
    "webflow":     ["the page you are looking for doesn't exist or has been moved."],
    "feedpress":   ["the feed has not been found."],
    "fly.io":      ["404 - page not found"],
    "bigcartel":   ["the requested url was not found on this server."],
    "bitbucket":   ["repository not found"],
    "intercom":    ["this page is reserved for artistic dogs"],
    "kinsta":      ["no site found"],
    "launchrock":  ["it looks like you may have taken a wrong turn somewhere"],
    "mashery":     ["mashery is not serving dns"],
    "smugmug":     ["page not found"],
    "tilda":       ["please renew your subscription"],
    "wufoo":       ["profile no longer available"],
    "sendgrid":    ["the page you are looking for does not exist",
                    "this page has been deactivated"],
    "mailgun":     ["page not found"],
    "gemfury":     ["404: this page could not be found!"],
}

# ---------------------------------------------------------------------------
# CNAME-pattern → service mapping for DNS-based candidate discovery.
# These are matched as substrings against the full lowercased CNAME chain.
# ---------------------------------------------------------------------------
CNAME_PATTERNS: dict[str, list[str]] = {
    "github":    ["github.io"],
    "heroku":    ["herokuapp.com"],
    "netlify":   ["netlify.app", "netlify.com"],
    "ghost":     ["ghost.io"],
    "s3":        ["s3.amazonaws.com", "s3-website"],
    "azure":     ["azurewebsites.net"],
    "shopify":   ["myshopify.com"],
    "cargo":     ["cargocollective.com"],
    "mailgun":   ["mailgun.org"],
    "sendgrid":  ["sendgrid.net"],
    "fastly":    ["fastly.net"],
    "surge":     ["surge.sh"],
    "webflow":   ["webflow.io"],
    "fly.io":    ["fly.dev"],
    "bitbucket": ["bitbucket.io"],
    "gemfury":   ["gemfury.com"],
    "uptimerobot": ["stats.uptimerobot.com"],
}


def _cname_service(chain_str: str) -> str:
    """Return the first matching service name for a lowercased CNAME chain string."""
    for svc, patterns in CNAME_PATTERNS.items():
        for pat in patterns:
            if pat in chain_str:
                return svc
    return ""


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = 5
    r.lifetime = 8
    return r


def resolve_cname_chain(fqdn: str) -> tuple[list[str], bool]:
    """
    Walk the CNAME chain for *fqdn*.

    Returns (chain, cname_target_is_nxdomain):
    - chain: list of CNAME targets in order
    - cname_target_is_nxdomain: True when the final hop has no A/AAAA record
    """
    resolver = _resolver()
    chain: list[str] = []
    current = fqdn

    for _ in range(10):  # guard against loops
        try:
            answers = resolver.resolve(current, "CNAME")
            target = str(answers[0].target).rstrip(".")
            chain.append(target)
            current = target
        except dns.resolver.NoAnswer:
            break
        except dns.resolver.NXDOMAIN:
            return chain, True
        except dns.exception.DNSException:
            break

    if not chain:
        return chain, False

    # Check whether the final CNAME target has any A record.
    for rdtype in ("A", "AAAA"):
        try:
            resolver.resolve(chain[-1], rdtype)
            return chain, False  # resolves → not dangling
        except dns.resolver.NXDOMAIN:
            return chain, True
        except dns.exception.DNSException:
            pass

    return chain, False


# ---------------------------------------------------------------------------
# HTTP fingerprinting
# ---------------------------------------------------------------------------

def http_fingerprint(fqdn: str, service: str, timeout: int = 10) -> tuple[bool, str, int]:
    """
    Try HTTPS then HTTP; match body against known fingerprints for *service*.

    Returns (matched, matched_snippet, http_status_code).
    status_code is -1 on connection failure.
    """
    svc = service.lower()
    needles = FINGERPRINTS.get(svc) or next(
        (v for k, v in FINGERPRINTS.items() if k in svc), []
    )
    headers = {"User-Agent": "Mozilla/5.0 (EASM-verifier/1.0; +security-scan)"}

    for scheme in ("https", "http"):
        url = f"{scheme}://{fqdn}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True,
                                verify=False, headers=headers)
            body_lower = resp.text.lower()
            for needle in needles:
                if needle in body_lower:
                    return True, needle, resp.status_code
            return False, "", resp.status_code
        except requests.exceptions.SSLError:
            continue  # try http
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout):
            return False, "", -1
        except Exception:
            return False, "", -1

    return False, "", -1


# ---------------------------------------------------------------------------
# Single-candidate verification
# ---------------------------------------------------------------------------

def verify_candidate(fqdn: str, service: str, stored_cname: str) -> dict:
    """
    Run live DNS + HTTP checks for one takeover candidate.

    Returned dict schema:
        fqdn, service, stored_cname,
        live_cname_chain, cname_target_nxdomain,
        http_fingerprint_matched, http_matched_snippet, http_status_code,
        status (confirmed | likely_fp | unverified),
        confidence (high | medium | low),
        evidence (list[str])
    """
    result: dict = {
        "fqdn": fqdn,
        "service": service,
        "stored_cname": stored_cname,
        "live_cname_chain": [],
        "cname_target_nxdomain": False,
        "http_fingerprint_matched": False,
        "http_matched_snippet": "",
        "http_status_code": -1,
        "status": "unverified",
        "confidence": "low",
        "evidence": [],
    }

    chain, is_nxdomain = resolve_cname_chain(fqdn)
    result["live_cname_chain"] = chain
    result["cname_target_nxdomain"] = is_nxdomain

    if not chain:
        result["status"] = "likely_fp"
        result["confidence"] = "high"
        result["evidence"].append("No CNAME record on live DNS — subdomain no longer delegated")
        return result

    result["evidence"].append("CNAME chain: " + " -> ".join(chain))

    fp_matched, fp_snippet, http_status = http_fingerprint(fqdn, service)
    result["http_fingerprint_matched"] = fp_matched
    result["http_matched_snippet"] = fp_snippet
    result["http_status_code"] = http_status

    if http_status > 0:
        result["evidence"].append(f"HTTP {http_status} from {fqdn}")
    if fp_matched:
        result["evidence"].append(f"Fingerprint matched: '{fp_snippet}'")

    # Confidence matrix:
    #   NXDOMAIN + fingerprint → confirmed / high
    #   NXDOMAIN only          → confirmed / medium
    #   fingerprint only       → confirmed / medium
    #   HTTP 200/404 no match  → likely_fp / medium  (service actively serving content)
    #   connection failure     → unverified / low
    if is_nxdomain and fp_matched:
        result["status"], result["confidence"] = "confirmed", "high"
    elif is_nxdomain:
        result["status"], result["confidence"] = "confirmed", "medium"
        result["evidence"].append("CNAME target is NXDOMAIN — dangling delegation")
    elif fp_matched:
        result["status"], result["confidence"] = "confirmed", "medium"
        result["evidence"].append("Unclaimed-resource page fingerprint detected")
    elif http_status in (200, 404) and not fp_matched:
        result["status"], result["confidence"] = "likely_fp", "medium"
        result["evidence"].append("HTTP response does not match any takeover fingerprint")
    # else: unverified / low (connection failure, etc.)

    return result


# ---------------------------------------------------------------------------
# DuckDB helpers
# ---------------------------------------------------------------------------

def load_candidates(con: duckdb.DuckDBPyConnection) -> list[tuple[str, str, str]]:
    """
    Return (fqdn, service, cname) for all takeover candidates.

    Two sources are merged:
    1. Subzy/nuclei findings already confirmed in the pipeline.
    2. Assets whose DNS CNAME chain points to a known takeover-vulnerable
       service — catches everything subzy missed due to HTTP errors.
    """
    # Source 1: pipeline findings
    src1: list[tuple[str, str, str]] = con.execute("""
        WITH expanded AS (
            SELECT fqdn, UNNEST(findings) AS f
            FROM assets
            WHERE len(findings) > 0
        )
        SELECT DISTINCT
            fqdn,
            COALESCE(f.service, '') AS service,
            COALESCE(CAST(f.cname AS VARCHAR), '') AS cname
        FROM expanded
        WHERE (f.source = 'subzy'  AND f.vulnerable = true)
           OR (f.source = 'nuclei' AND f.template_id LIKE '%takeover%')
    """).fetchall()

    # FQDNs already covered by subzy/nuclei — DNS source won't add duplicates for these
    src1_fqdns: set[str] = {r[0] for r in src1}

    # Source 2: DNS CNAME chain pattern matching
    cname_rows = con.execute("""
        SELECT
            fqdn,
            list_aggregate(
                list_transform(dns.cname_chain, x -> lower(x)),
                'string_agg', ','
            ) AS chain_str,
            dns.cname_chain[1] AS first_cname
        FROM assets
        WHERE len(dns.cname_chain) > 0
    """).fetchall()

    # Pure DNS infrastructure labels that are never HTTP-accessible and carry
    # no takeover risk; skip to avoid noise.  Note: _domainkey is intentionally
    # kept — a dangling DKIM CNAME (NXDOMAIN) is a real email-spoofing risk.
    _DNS_CONTROL = ("_acme-challenge.", "_mta-sts.", "_spf.")

    seen_dns: set[str] = set(src1_fqdns)
    src2: list[tuple[str, str, str]] = []
    for fqdn, chain_str, first_cname in cname_rows:
        if not chain_str or fqdn in seen_dns:
            continue
        if any(fqdn.startswith(pfx) or f".{pfx}" in fqdn for pfx in _DNS_CONTROL):
            continue
        service = _cname_service(chain_str)
        if not service:
            continue
        seen_dns.add(fqdn)
        src2.append((fqdn, service, first_cname or ""))

    return sorted(src1 + src2, key=lambda r: r[0])


def write_results(con: duckdb.DuckDBPyConnection, results: list[dict], out_path: Path) -> None:
    """Persist results to JSONL, load into DuckDB, and update asset statuses."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as fh:
        for r in results:
            fh.write(orjson.dumps(r, option=orjson.OPT_APPEND_NEWLINE))

    con.execute("DROP TABLE IF EXISTS takeover_verifications")
    con.execute(f"""
        CREATE TABLE takeover_verifications AS
        SELECT * FROM read_ndjson_auto('{out_path}', ignore_errors=true)
    """)

    con.execute("""
        CREATE OR REPLACE VIEW v_confirmed_takeovers AS
        SELECT
            fqdn,
            service,
            stored_cname,
            live_cname_chain,
            cname_target_nxdomain,
            http_fingerprint_matched,
            http_matched_snippet,
            http_status_code,
            status,
            confidence,
            evidence
        FROM takeover_verifications
        WHERE status = 'confirmed'
        ORDER BY
            CASE confidence WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
            fqdn
    """)

    # Enrich the assets table with live-verification outcomes so that the
    # main asset store reflects actual confirmed/fp status rather than keeping
    # it isolated in a side table.
    for col, col_type in [
        ("takeover_status",     "VARCHAR"),
        ("takeover_confidence", "VARCHAR"),
        ("takeover_verified_at","VARCHAR"),
    ]:
        try:
            con.execute(f"ALTER TABLE assets ADD COLUMN {col} {col_type}")
        except Exception:
            pass  # column already exists from a previous verify run

    verified_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for r in results:
        con.execute(
            """
            UPDATE assets
            SET takeover_status     = ?,
                takeover_confidence = ?,
                takeover_verified_at = ?
            WHERE fqdn = ?
            """,
            (r["status"], r["confidence"], verified_at, r["fqdn"]),
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

STATUS_ICON = {"confirmed": "CONFIRMED", "likely_fp": "LIKELY_FP", "unverified": "UNVERIFIED"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify subdomain takeover candidates")
    parser.add_argument("--db",    required=True, help="DuckDB database path")
    parser.add_argument("--out",   required=True, help="Output JSONL path for verification results")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Seconds to wait between checks (default: 0.5)")
    args = parser.parse_args()

    con = duckdb.connect(args.db, read_only=False)
    candidates = load_candidates(con)

    if not candidates:
        print("No takeover candidates found in database.")
        con.close()
        sys.exit(0)

    print(f"Verifying {len(candidates)} candidate(s)…")

    results: list[dict] = []
    for fqdn, service, cname in candidates:
        result = verify_candidate(fqdn, service, cname)
        results.append(result)
        icon = STATUS_ICON[result["status"]]
        evidence_preview = "; ".join(result["evidence"][:2]) or "no evidence"
        print(f"  [{icon:<12}] {fqdn} ({service or 'unknown'}) — {evidence_preview}")
        time.sleep(args.delay)

    out_path = Path(args.out)
    write_results(con, results, out_path)
    con.close()

    confirmed  = sum(1 for r in results if r["status"] == "confirmed")
    likely_fp  = sum(1 for r in results if r["status"] == "likely_fp")
    unverified = sum(1 for r in results if r["status"] == "unverified")

    print(f"\nDone — confirmed: {confirmed}  likely_fp: {likely_fp}  unverified: {unverified}")
    print(f"Results written to {out_path}")
    print(f"DuckDB table: takeover_verifications  |  view: v_confirmed_takeovers")
    print(f"Assets table updated: takeover_status / takeover_confidence / takeover_verified_at")


if __name__ == "__main__":
    main()
