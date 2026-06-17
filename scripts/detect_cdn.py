#!/usr/bin/env python3
"""
Multi-signal CDN detection for EASM assets.

Combines CNAME patterns, IP ranges, HTTP headers, and ASN data to identify
CDN-proxied assets with confidence scoring.
"""
import ipaddress
import re

CNAME_PATTERNS: dict[str, str] = {
    ".cloudflare.com": "cloudflare",
    ".cloudflare-dns.com": "cloudflare",
    ".cloudfront.net": "cloudfront",
    ".amazonaws.com": "cloudfront",
    ".akamai.net": "akamai",
    ".akamaiedge.net": "akamai",
    ".akamaized.net": "akamai",
    ".akadns.net": "akamai",
    ".edgesuite.net": "akamai",
    ".edgekey.net": "akamai",
    ".fastly.net": "fastly",
    ".fastlylb.net": "fastly",
    ".azureedge.net": "azure_cdn",
    ".azurefd.net": "azure_cdn",
    ".trafficmanager.net": "azure_cdn",
    ".googleusercontent.com": "google_cdn",
    ".googlevideo.com": "google_cdn",
    ".cdn.google.com": "google_cdn",
    ".stackpathdns.com": "stackpath",
    ".stackpathcdn.com": "stackpath",
    ".hwcdn.net": "stackpath",
    ".incapdns.net": "imperva",
    ".impervadns.net": "imperva",
    ".sucuri.net": "sucuri",
    ".sucuridns.com": "sucuri",
    ".cdn77.org": "cdn77",
    ".netlify.app": "netlify",
    ".netlify.com": "netlify",
    ".vercel-dns.com": "vercel",
    ".fly.dev": "fly",
    ".livefilestore.com": "microsoft",
}

CDN_ASNS: dict[int, str] = {
    13335: "cloudflare",
    209242: "cloudflare",
    16509: "cloudfront",
    14618: "cloudfront",
    20940: "akamai",
    16625: "akamai",
    21342: "akamai",
    54113: "fastly",
    8068: "microsoft",
    15169: "google_cdn",
    396982: "google_cdn",
    33438: "stackpath",
    19551: "incapsula",
}

CDN_HEADERS: list[tuple[str, str, str]] = [
    ("cf-ray", r".", "cloudflare"),
    ("cf-cache-status", r".", "cloudflare"),
    ("server", r"^cloudflare$", "cloudflare"),
    ("x-amz-cf-id", r".", "cloudfront"),
    ("x-amz-cf-pop", r".", "cloudfront"),
    ("x-cache", r"(cloudfront|Hit from cloudfront)", "cloudfront"),
    ("x-akamai-transformed", r".", "akamai"),
    ("x-akamai-request-id", r".", "akamai"),
    ("x-served-by", r"cache-", "fastly"),
    ("x-fastly-request-id", r".", "fastly"),
    ("x-azure-ref", r".", "azure_cdn"),
    ("x-msedge-ref", r".", "azure_cdn"),
    ("x-sucuri-id", r".", "sucuri"),
    ("x-sucuri-cache", r".", "sucuri"),
    ("x-cdn", r"imperva", "imperva"),
    ("x-iinfo", r".", "imperva"),
    ("server", r"^netlify$", "netlify"),
    ("x-nf-request-id", r".", "netlify"),
    ("server", r"^vercel$", "vercel"),
    ("x-vercel-id", r".", "vercel"),
]

CDN_CIDRS: list[tuple[str, str]] = [
    # Cloudflare
    ("173.245.48.0/20", "cloudflare"),
    ("103.21.244.0/22", "cloudflare"),
    ("103.22.200.0/22", "cloudflare"),
    ("103.31.4.0/22", "cloudflare"),
    ("141.101.64.0/18", "cloudflare"),
    ("108.162.192.0/18", "cloudflare"),
    ("190.93.240.0/20", "cloudflare"),
    ("188.114.96.0/20", "cloudflare"),
    ("197.234.240.0/22", "cloudflare"),
    ("198.41.128.0/17", "cloudflare"),
    ("162.158.0.0/15", "cloudflare"),
    ("104.16.0.0/13", "cloudflare"),
    ("104.24.0.0/14", "cloudflare"),
    ("172.64.0.0/13", "cloudflare"),
    ("131.0.72.0/22", "cloudflare"),
    # Fastly
    ("23.235.32.0/20", "fastly"),
    ("43.249.72.0/22", "fastly"),
    ("103.244.50.0/24", "fastly"),
    ("103.245.222.0/23", "fastly"),
    ("103.245.224.0/24", "fastly"),
    ("104.156.80.0/20", "fastly"),
    ("151.101.0.0/16", "fastly"),
    ("157.52.64.0/18", "fastly"),
    ("167.82.0.0/17", "fastly"),
    ("167.82.128.0/20", "fastly"),
    ("167.82.160.0/20", "fastly"),
    ("167.82.224.0/20", "fastly"),
    ("199.27.72.0/21", "fastly"),
]


class CDNDetector:
    def __init__(self):
        self._cidr_nets = [
            (ipaddress.ip_network(cidr, strict=False), name)
            for cidr, name in CDN_CIDRS
        ]

    def detect(self, asset: dict) -> dict | None:
        """Analyze an asset record and return CDN verdict, or None if not CDN."""
        votes: dict[str, list[str]] = {}

        # Signal 1: CNAME chain
        for cname in asset.get("dns", {}).get("cname_chain", []):
            cname_lower = cname.lower().rstrip(".")
            for suffix, provider in CNAME_PATTERNS.items():
                if cname_lower.endswith(suffix):
                    votes.setdefault(provider, []).append(f"cname:{cname_lower}")
                    break

        # Signal 2: IP range
        for ip_str in asset.get("dns", {}).get("a", []):
            try:
                ip = ipaddress.ip_address(ip_str)
                for net, provider in self._cidr_nets:
                    if ip in net:
                        votes.setdefault(provider, []).append(f"ip_range:{net}")
                        break
            except ValueError:
                pass

        # Signal 3: HTTP headers
        for web_entry in asset.get("web", []):
            headers = web_entry.get("headers_of_interest", {})
            server = web_entry.get("server", "")
            all_headers = {**headers}
            if server:
                all_headers["server"] = server
            for header_name, pattern, provider in CDN_HEADERS:
                val = all_headers.get(header_name, "")
                if val and re.search(pattern, val, re.IGNORECASE):
                    votes.setdefault(provider, []).append(f"header:{header_name}")

        # Signal 4: ASN
        asn_num = asset.get("network", {}).get("asn", {}).get("number")
        if asn_num and asn_num in CDN_ASNS:
            votes.setdefault(CDN_ASNS[asn_num], []).append(f"asn:{asn_num}")

        if not votes:
            return None

        best_provider = max(votes, key=lambda p: len(votes[p]))
        signals = votes[best_provider]
        signal_types = {s.split(":")[0] for s in signals}
        confidence = min(1.0, len(signal_types) * 0.35)

        return {
            "provider": best_provider,
            "confidence": round(confidence, 2),
            "signals": signals,
        }
