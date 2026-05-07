#!/usr/bin/env python3
"""
Bug Bounty target scoring engine.

Reads the unified asset table from DuckDB and computes a bounty priority
score (0-100) for each subdomain based on attack surface, technology,
security posture, and criticality signals.

Usage:
    python3 score_bounty.py --db data/output/easm.duckdb \
                            --output data/output/bounty_report.jsonl
"""

import argparse
import json
import re
import sys
from pathlib import Path

import duckdb


TIER_THRESHOLDS = [(80, "S"), (60, "A"), (40, "B"), (20, "C"), (0, "D")]

ADMIN_PANEL_KEYWORDS = {
    "jenkins", "grafana", "kibana", "phpmyadmin", "adminer",
    "portainer", "webmin", "cockpit", "gitlab", "sonarqube",
    "harbor", "rancher", "traefik", "consul",
}

SENSITIVE_SUBDOMAIN_PATTERNS = [
    "api", "admin", "staging", "dev", "internal", "portal",
    "vpn", "mail", "git", "ci", "cd", "jira", "confluence",
    "test", "uat", "preprod", "beta", "debug", "mgmt",
    "backoffice", "dashboard", "monitor", "grafana", "jenkins",
]

VULNERABLE_FRAMEWORKS = {
    "wordpress", "joomla", "drupal", "magento", "moodle",
    "sharepoint", "coldfusion", "weblogic", "struts",
}

SERVER_SIDE_LANGS = {"php", "java", "asp.net", "python", "ruby", "node.js"}

STANDARD_WEB_PORTS = {80, 443, 8080, 8443}

NON_HTTP_SERVICES = {"ssh", "ftp", "smtp", "mysql", "postgres", "redis",
                     "mongodb", "mssql", "smb", "imap", "pop3", "telnet",
                     "rdp", "vnc", "ldap"}

AUTH_TITLE_RE = re.compile(r'\b(login|sign.?in|authenticat|log.?on|password)\b', re.IGNORECASE)
UPLOAD_TITLE_RE = re.compile(r'\b(upload|file.?manag|attach)\b', re.IGNORECASE)


def _tier(score: int) -> str:
    for threshold, label in TIER_THRESHOLDS:
        if score >= threshold:
            return label
    return "D"


def _safe_list(val) -> list:
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return list(val)


def _safe_str(val) -> str:
    return str(val).lower() if val else ""


class BountyScorer:

    def score(self, asset: dict) -> dict:
        a_pts, a_highlights = self._score_attack_surface(asset)
        b_pts, b_highlights = self._score_technology(asset)
        c_pts, c_highlights = self._score_security_posture(asset)
        d_pts, d_highlights = self._score_criticality(asset)

        total = min(100, a_pts + b_pts + c_pts + d_pts)
        highlights = a_highlights + b_highlights + c_highlights + d_highlights

        recommendations = self._build_recommendations(asset, highlights)

        open_ports = [p.get("port") for p in _safe_list(
            asset.get("network", {}).get("open_ports") if isinstance(asset.get("network"), dict)
            else []
        ) if isinstance(p, dict)]
        services = _safe_list(asset.get("services"))
        service_names = [_safe_str(s.get("service")) for s in services if isinstance(s, dict)]
        findings = _safe_list(asset.get("findings"))
        web = _safe_list(asset.get("web"))
        techs = []
        for w in web:
            if isinstance(w, dict):
                for t in _safe_list(w.get("tech")):
                    if isinstance(t, dict) and t.get("name"):
                        techs.append(t["name"])

        network = asset.get("network") or {}
        if not isinstance(network, dict):
            network = {}
        cdn = network.get("cdn")

        critical_count = sum(1 for f in findings if isinstance(f, dict)
                             and _safe_str(f.get("severity")) in ("critical", "high"))

        return {
            "fqdn": asset.get("fqdn", ""),
            "bounty_score": total,
            "tier": _tier(total),
            "score_breakdown": {
                "attack_surface": a_pts,
                "technology": b_pts,
                "security_posture": c_pts,
                "criticality": d_pts,
            },
            "highlights": highlights[:10],
            "recommended_focus": recommendations[:5],
            "attack_surface_summary": {
                "open_ports": open_ports,
                "services": list(set(filter(None, service_names))),
                "technologies": list(set(techs)),
                "has_auth": self._has_auth(asset),
                "behind_cdn": cdn is not None and cdn != "",
                "nuclei_findings": len(findings),
                "critical_findings": critical_count,
            },
        }

    def _score_attack_surface(self, asset: dict) -> tuple:
        pts = 0
        highlights = []
        network = asset.get("network") or {}
        if not isinstance(network, dict):
            network = {}

        open_ports = _safe_list(network.get("open_ports"))
        port_numbers = [p.get("port") for p in open_ports if isinstance(p, dict)]
        port_count = len(port_numbers)

        if port_count > 20:
            pts += 8
            highlights.append(f"{port_count} open ports — broad attack surface")
        elif port_count > 10:
            pts += 5
            highlights.append(f"{port_count} open ports")

        non_standard = [p for p in port_numbers if p not in STANDARD_WEB_PORTS]
        if non_standard:
            pts += 4
            highlights.append(f"Non-standard ports open: {', '.join(str(p) for p in non_standard[:5])}")

        services = _safe_list(asset.get("services"))
        non_http = [s for s in services if isinstance(s, dict)
                    and _safe_str(s.get("service")) in NON_HTTP_SERVICES]
        if non_http:
            pts += 5
            svc_names = list({_safe_str(s.get("service")) for s in non_http})
            highlights.append(f"Non-HTTP services: {', '.join(svc_names[:4])}")

        web = _safe_list(asset.get("web"))
        web_ports = {w.get("port") for w in web if isinstance(w, dict) and w.get("port")}
        if len(web_ports) > 1:
            pts += 4
            highlights.append(f"{len(web_ports)} web entry points on distinct ports")

        udp_services = [s for s in services if isinstance(s, dict)
                        and _safe_str(s.get("transport")) == "udp"]
        if udp_services:
            pts += 4
            highlights.append(f"UDP services detected: {len(udp_services)}")

        return min(pts, 25), highlights

    def _score_technology(self, asset: dict) -> tuple:
        pts = 0
        highlights = []
        web = _safe_list(asset.get("web"))

        all_techs = []
        all_titles = []
        for w in web:
            if not isinstance(w, dict):
                continue
            all_titles.append(_safe_str(w.get("title")))
            for t in _safe_list(w.get("tech")):
                if isinstance(t, dict):
                    all_techs.append(t)

        tech_names = {_safe_str(t.get("name")) for t in all_techs}

        vuln_found = tech_names & VULNERABLE_FRAMEWORKS
        if vuln_found:
            pts += 6
            highlights.append(f"Vulnerable framework: {', '.join(vuln_found)}")

        ss_langs = tech_names & SERVER_SIDE_LANGS
        if ss_langs:
            pts += 3
            highlights.append(f"Server-side stack: {', '.join(ss_langs)}")

        admin_techs = tech_names & ADMIN_PANEL_KEYWORDS
        admin_titles = [t for t in all_titles if any(kw in t for kw in ADMIN_PANEL_KEYWORDS)]
        if admin_techs or admin_titles:
            pts += 6
            detected = list(admin_techs) or admin_titles
            highlights.append(f"Admin/management panel: {detected[0]}")

        api_indicators = any(
            "api" in t or "swagger" in t or "graphql" in t or "rest" in t
            for t in all_titles
        ) or any(
            "x-api-version" in _safe_str(w.get("headers_of_interest"))
            for w in web if isinstance(w, dict)
        ) or any(
            "application/json" in _safe_str(w.get("content_type"))
            for w in web if isinstance(w, dict)
        )
        if api_indicators:
            pts += 4
            highlights.append("API endpoints detected")

        services = _safe_list(asset.get("services"))
        outdated = []
        for s in services:
            if not isinstance(s, dict):
                continue
            fp = s.get("fingerprint") or {}
            if not isinstance(fp, dict):
                continue
            if fp.get("version") and fp.get("product"):
                outdated.append(f"{fp['product']} {fp['version']}")
        if outdated:
            pts += 3
            highlights.append(f"Versioned software detected: {outdated[0]}")

        if len(tech_names) > 5:
            pts += 3
            highlights.append(f"Complex technology stack ({len(tech_names)} technologies)")

        return min(pts, 25), highlights

    def _score_security_posture(self, asset: dict) -> tuple:
        pts = 0
        highlights = []
        findings = _safe_list(asset.get("findings"))

        if findings:
            pts += 3
            highlights.append(f"{len(findings)} nuclei finding(s) confirmed")

        critical_high = [f for f in findings if isinstance(f, dict)
                         and _safe_str(f.get("severity")) in ("critical", "high")]
        if critical_high:
            pts += 8
            sev = _safe_str(critical_high[0].get("severity"))
            name = critical_high[0].get("name") or critical_high[0].get("template_id") or "finding"
            highlights.append(f"{len(critical_high)} critical/high finding(s) — e.g. {name}")

        web = _safe_list(asset.get("web"))
        missing_headers = []
        for w in web:
            if not isinstance(w, dict):
                continue
            headers = _safe_str(w.get("headers_of_interest"))
            for hdr in ("strict-transport-security", "content-security-policy", "x-frame-options"):
                if hdr not in headers:
                    missing_headers.append(hdr)
        if missing_headers:
            pts += 3
            highlights.append(f"Missing security headers: {', '.join(set(missing_headers[:3]))}")

        tls_entries = _safe_list(asset.get("tls"))
        tls_issues = []
        for t in tls_entries:
            if not isinstance(t, dict):
                continue
            if t.get("expired"):
                tls_issues.append("expired cert")
            if t.get("self_signed"):
                tls_issues.append("self-signed cert")
            if t.get("mismatched"):
                tls_issues.append("mismatched cert")
        if tls_issues:
            pts += 3
            highlights.append(f"TLS issues: {', '.join(set(tls_issues))}")

        default_creds = [f for f in findings if isinstance(f, dict)
                         and "default-logins" in _safe_str(str(f.get("tags", [])))]
        if default_creds:
            pts += 5
            highlights.append("Default credentials detected")

        exposed_panels = [f for f in findings if isinstance(f, dict)
                          and any(kw in _safe_str(f.get("template_id") or "")
                                  for kw in ("panel", "exposed", "debug", "phpmyadmin"))]
        if exposed_panels:
            pts += 3
            highlights.append(f"Exposed panel/debug endpoint: {exposed_panels[0].get('template_id', '')}")

        return min(pts, 25), highlights

    def _score_criticality(self, asset: dict) -> tuple:
        pts = 0
        highlights = []

        if self._has_auth(asset):
            pts += 6
            highlights.append("Authentication mechanism present (login/OAuth/SSO)")

        findings = _safe_list(asset.get("findings"))
        upload_finding = any(
            isinstance(f, dict) and "file-upload" in _safe_str(str(f.get("tags", [])))
            for f in findings
        )
        web = _safe_list(asset.get("web"))
        upload_title = any(
            UPLOAD_TITLE_RE.search(_safe_str(w.get("title", "")))
            for w in web if isinstance(w, dict)
        )
        if upload_finding or upload_title:
            pts += 4
            highlights.append("File upload functionality detected")

        network = asset.get("network") or {}
        if not isinstance(network, dict):
            network = {}
        cdn = network.get("cdn")
        if not cdn:
            pts += 3
            highlights.append("Not behind CDN — direct origin exposure")

        shared = network.get("shared_hosting") or {}
        if isinstance(shared, dict) and not shared.get("detected"):
            pts += 2

        fqdn = _safe_str(asset.get("fqdn", ""))
        labels = fqdn.split(".")
        matched = [lbl for lbl in labels
                   if any(pat in lbl for pat in SENSITIVE_SUBDOMAIN_PATTERNS)]
        if matched:
            pts += 5
            highlights.append(f"Sensitive subdomain naming: {matched[0]}")

        takeover = any(
            isinstance(f, dict) and "takeover" in _safe_str(f.get("template_id") or "")
            for f in findings
        )
        if takeover:
            pts += 5
            highlights.append("Subdomain takeover candidate detected")

        return min(pts, 25), highlights

    def _has_auth(self, asset: dict) -> bool:
        web = _safe_list(asset.get("web"))
        for w in web:
            if not isinstance(w, dict):
                continue
            if AUTH_TITLE_RE.search(_safe_str(w.get("title", ""))):
                return True
            headers = _safe_str(w.get("headers_of_interest", ""))
            if "set-cookie" in headers or "www-authenticate" in headers:
                return True
        findings = _safe_list(asset.get("findings"))
        return any(
            isinstance(f, dict) and "login-panel" in _safe_str(str(f.get("tags", [])))
            for f in findings
        )

    def _build_recommendations(self, asset: dict, highlights: list) -> list:
        recs = []
        findings = _safe_list(asset.get("findings"))
        web = _safe_list(asset.get("web"))
        services = _safe_list(asset.get("services"))
        network = asset.get("network") or {}
        if not isinstance(network, dict):
            network = {}

        cve_findings = [f for f in findings if isinstance(f, dict)
                        and "cve" in _safe_str(str(f.get("tags", [])))]
        for f in cve_findings[:2]:
            tid = f.get("template_id") or ""
            name = f.get("name") or tid
            recs.append(f"Verify CVE finding: {name}")

        admin_techs = set()
        for w in web:
            if not isinstance(w, dict):
                continue
            for t in _safe_list(w.get("tech")):
                if isinstance(t, dict):
                    n = _safe_str(t.get("name"))
                    if n in ADMIN_PANEL_KEYWORDS:
                        admin_techs.add(n)
        for tech in list(admin_techs)[:1]:
            recs.append(f"Check {tech} for default credentials and known CVEs")

        if any("API endpoints detected" in h for h in highlights):
            recs.append("Test API endpoints for IDOR, broken auth, and mass assignment")

        if self._has_auth(asset):
            recs.append("Test authentication flow for bypass, brute-force, and session issues")

        if any("File upload" in h for h in highlights):
            recs.append("Test file upload for unrestricted types, path traversal, stored XSS")

        for s in services:
            if not isinstance(s, dict):
                continue
            fp = s.get("fingerprint") or {}
            if isinstance(fp, dict) and fp.get("product") and fp.get("version"):
                recs.append(
                    f"Check {fp['product']} {fp['version']} against known CVEs — verify patch status"
                )
                break

        if any("takeover" in h.lower() for h in highlights):
            recs.append("Claim the dangling resource to confirm subdomain takeover")

        tls_entries = _safe_list(asset.get("tls"))
        tls_issues = [t for t in tls_entries if isinstance(t, dict)
                      and (t.get("expired") or t.get("self_signed") or t.get("mismatched"))]
        if tls_issues:
            recs.append("Check for HTTPS downgrade attacks and sensitive data in cleartext")

        return recs[:5]


def load_bounty_results(con: duckdb.DuckDBPyConnection, jsonl_path: str):
    p = Path(jsonl_path)
    if not p.exists() or p.stat().st_size == 0:
        return

    try:
        con.execute("DROP TABLE IF EXISTS bounty_scores")
        con.execute(f"""
            CREATE TABLE bounty_scores AS
            SELECT * FROM read_ndjson_auto('{jsonl_path}',
                maximum_object_size=10485760, ignore_errors=true)
        """)

        con.execute("""
            CREATE OR REPLACE VIEW v_bounty_scores AS
            SELECT
                fqdn,
                bounty_score,
                tier,
                score_breakdown.attack_surface AS score_attack_surface,
                score_breakdown.technology     AS score_technology,
                score_breakdown.security_posture AS score_security_posture,
                score_breakdown.criticality    AS score_criticality,
                attack_surface_summary.open_ports AS open_ports,
                attack_surface_summary.services AS services,
                attack_surface_summary.technologies AS technologies,
                attack_surface_summary.has_auth AS has_auth,
                attack_surface_summary.behind_cdn AS behind_cdn,
                attack_surface_summary.nuclei_findings AS nuclei_findings,
                attack_surface_summary.critical_findings AS critical_findings
            FROM bounty_scores
            ORDER BY bounty_score DESC
        """)

        try:
            con.execute("""
                CREATE OR REPLACE VIEW v_bounty_highlights AS
                WITH expanded AS (
                    SELECT fqdn, bounty_score, tier, UNNEST(highlights) AS highlight
                    FROM bounty_scores
                    WHERE len(highlights) > 0
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

        print("Bounty views created in DuckDB", file=sys.stderr)
    except Exception as e:
        print(f"WARN: Could not load bounty results: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Bug Bounty target scorer")
    parser.add_argument("--db", required=True, help="Path to easm.duckdb")
    parser.add_argument("--output", required=True, help="Output bounty_report.jsonl path")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"ERROR: Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    con = duckdb.connect(str(db_path))
    try:
        try:
            count = con.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        except Exception as e:
            print(f"ERROR: Could not read assets table: {e}", file=sys.stderr)
            sys.exit(1)

        print(f"Scoring {count} assets for bug bounty priority...", file=sys.stderr)

        rows = con.execute("SELECT * FROM assets").fetchall()
        cols = [d[0] for d in con.execute("SELECT * FROM assets LIMIT 0").description]

        scorer = BountyScorer()
        results = []
        for row in rows:
            asset = dict(zip(cols, row))
            try:
                result = scorer.score(asset)
                results.append(result)
            except Exception as e:
                fqdn = asset.get("fqdn", "?")
                print(f"WARN: Scoring failed for {fqdn}: {e}", file=sys.stderr)

        results.sort(key=lambda r: r["bounty_score"], reverse=True)

        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            for r in results:
                f.write(json.dumps(r) + "\n")

        print(f"Bounty report written: {out_path} ({len(results)} records)", file=sys.stderr)

        tier_counts = {}
        for r in results:
            tier_counts[r["tier"]] = tier_counts.get(r["tier"], 0) + 1
        for tier, label in [("S", "Critical"), ("A", "High"), ("B", "Medium"),
                              ("C", "Low"), ("D", "Background")]:
            if tier in tier_counts:
                print(f"  {tier} ({label}): {tier_counts[tier]}", file=sys.stderr)

        load_bounty_results(con, str(out_path))

    finally:
        con.close()


if __name__ == "__main__":
    main()
