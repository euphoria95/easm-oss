#!/usr/bin/env python3
"""
EASM Pipeline — Tenable VM / WAS scan-scope routing.

Implements the routing matrix in TENABLE_SCOPE_PIPELINE.MD. Every normalized
asset is classified (direct, CDN, WAF, third-party, PaaS, ...) and routed to:
  * Tenable VM  — network scanning, deduplicated by IP (one decision per IP)
  * Tenable WAS — DAST per web origin, under one of three scan profiles:
      standard  unprotected dynamic application
      waf       WAF-fronted application; scanner egress must be allow-listed
      api       pure API / AI endpoint; needs an OpenAPI / Postman definition

Exclusion always wins for VM: an IP stays out if any asset resolving to it
marks it as CDN edge, WAF or third-party / managed-platform infrastructure.
Infrastructure reasons (CDN, third-party, PaaS) are lifted for IPs inside the
operator-declared owned CIDRs / ASNs; WAF is not.

Pure functions over asset dicts (assets.jsonl records, or rows read back from
DuckDB) — no I/O. cmdb_scope_export.py does the reading and writing.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import orjson


# Matrix categories in reporting precedence: an asset's primary category is the
# first one it matches. Numbers are the rows of the routing matrix.
CATEGORIES = (
    "cloud_paas",      # 6  cloud PaaS / serverless / storage / managed platform
    "cdn",             # 2  behind a CDN (or on a CDN-edge ASN)
    "waf",             # 3  behind a WAF
    "third_party",     # 4  third-party SaaS or shared hosting
    "static_or_dead",  # 8  redirect-only, parked, dead
    "non_http",        # 7  non-HTTP services only
    "api",             # 9  pure API / AI endpoint
    "owned_shared",    # 5  owned IP serving several FQDNs (LB / ingress)
    "direct",          # 1  direct / dedicated IP
)

# cloud_enum.py service → platform class.
#   storage / static / managed — provider-operated, never a VM or WAS target
#   paas_web / paas_api        — customer code on managed infra: WAS only
#   cdn                        — CDN front door: WAS only
# Unlisted services (cloud_service, container_instance, traffic_manager,
# generic) are customer-operated IaaS or DNS-only and do not affect routing.
CLOUD_SERVICE_CLASS: dict[str, str] = {
    "blob_storage": "storage", "file_storage": "storage", "queue_storage": "storage",
    "table_storage": "storage", "data_lake": "storage", "s3": "storage",
    "cloud_storage": "storage",
    "s3_website": "static", "static_web_app": "static", "firebase_hosting": "static",
    "app_service": "paas_web", "app_service_scm": "paas_web",
    "elastic_beanstalk": "paas_web", "app_runner": "paas_web", "elb": "paas_web",
    "app_engine": "paas_web", "cloud_run": "paas_web", "cloud_functions": "paas_web",
    "lambda": "paas_web", "firebase": "paas_web",
    "api_gateway": "paas_api", "api_management": "paas_api",
    "sql_database": "managed", "cosmosdb": "managed", "cosmosdb_mongo": "managed",
    "redis_cache": "managed", "rds": "managed", "service_bus": "managed",
    "container_registry": "managed", "key_vault": "managed",
    "cognitive_search": "managed", "cognitive_services": "managed",
    "openai": "managed", "ad_b2c": "managed", "azure_ad": "managed",
    "cdn": "cdn", "front_door": "cdn", "cloudfront": "cdn",
}

# Hostname / CNAME suffix → (platform, class). "saas" is a vendor-operated
# application (you configure content, the vendor owns the code): DAST against
# it typically breaches the vendor's terms, so it is kept out of WAS by default.
PLATFORM_SUFFIXES: dict[str, tuple[str, str]] = {
    "github.io": ("github_pages", "static"),
    "bitbucket.io": ("bitbucket", "static"),
    "surge.sh": ("surge", "static"),
    "pages.dev": ("cloudflare_pages", "static"),
    "readthedocs.io": ("readthedocs", "static"),
    "herokuapp.com": ("heroku", "paas_web"),
    "herokudns.com": ("heroku", "paas_web"),
    "herokussl.com": ("heroku", "paas_web"),
    "netlify.app": ("netlify", "paas_web"),
    "netlify.com": ("netlify", "paas_web"),
    "netlifyglobalcdn.com": ("netlify", "paas_web"),
    "vercel.app": ("vercel", "paas_web"),
    "vercel-dns.com": ("vercel", "paas_web"),
    "now.sh": ("vercel", "paas_web"),
    "wpengine.com": ("wpengine", "paas_web"),
    "wpenginepowered.com": ("wpengine", "paas_web"),
    "pantheonsite.io": ("pantheon", "paas_web"),
    "kinsta.cloud": ("kinsta", "paas_web"),
    "fly.dev": ("fly", "paas_web"),
    "onrender.com": ("render", "paas_web"),
    "myshopify.com": ("shopify", "saas"),
    "shopify.com": ("shopify", "saas"),
    "squarespace.com": ("squarespace", "saas"),
    "wixdns.net": ("wix", "saas"),
    "wordpress.com": ("wordpress_com", "saas"),
    "ghost.io": ("ghost", "saas"),
    "webflow.io": ("webflow", "saas"),
    "webflow.com": ("webflow", "saas"),
    "zendesk.com": ("zendesk", "saas"),
    "freshdesk.com": ("freshdesk", "saas"),
    "helpscoutdocs.com": ("helpscout", "saas"),
    "intercom.help": ("intercom", "saas"),
    "hubspot.net": ("hubspot", "saas"),
    "hs-sites.com": ("hubspot", "saas"),
    "statuspage.io": ("statuspage", "saas"),
    "unbounce.com": ("unbounce", "saas"),
    "gitbook.io": ("gitbook", "saas"),
    "force.com": ("salesforce", "saas"),
    "atlassian.net": ("atlassian", "saas"),
    "service-now.com": ("servicenow", "saas"),
    "okta.com": ("okta", "saas"),
    "auth0.com": ("auth0", "saas"),
    "sendgrid.net": ("sendgrid", "saas"),
    "mailgun.org": ("mailgun", "saas"),
}

# ASN org (upper-cased) → (platform, class). "edge" = CDN / reverse-proxy
# network: scanning it tests the provider, not the origin. Hyperscaler ASNs
# (AWS, Azure, GCP) are deliberately absent — EC2/VM IPs are customer-operated.
ASN_ORG_RULES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(p), platform, cls) for p, platform, cls in [
        (r"CLOUDFLARE", "cloudflare", "edge"),
        (r"^(?!.*(LINODE|CONNECTED CLOUD)).*AKAMAI", "akamai", "edge"),  # not Linode IaaS
        (r"FASTLY", "fastly", "edge"),
        (r"INCAPSULA|IMPERVA", "imperva", "edge"),
        (r"SUCURI", "sucuri", "edge"),
        (r"EDGECAST|EDGIO", "edgio", "edge"),
        (r"STACKPATH", "stackpath", "edge"),
        (r"GITHUB", "github", "static"),
        (r"HEROKU", "heroku", "paas_web"),
        (r"WPENGINE", "wpengine", "paas_web"),
        (r"NETLIFY", "netlify", "paas_web"),
        (r"VERCEL", "vercel", "paas_web"),
        (r"SHOPIFY", "shopify", "saas"),
        (r"SQUARESPACE", "squarespace", "saas"),
        (r"AUTOMATTIC", "wordpress_com", "saas"),
        (r"\bWIX", "wix", "saas"),
        (r"ZENDESK", "zendesk", "saas"),
        (r"HUBSPOT", "hubspot", "saas"),
    ]
]

PAAS_CLASSES = {"storage", "static", "paas_web", "paas_api", "managed"}

# Matching shared_hosting signals that name a hosting provider or panel (rather
# than IP density / shared certs, which also fire for an owned load balancer)
THIRD_PARTY_HOSTING_SIGNALS = ("asn:", "header:")

# VM exclusion reasons describing the IP's infrastructure that an owned
# CIDR / ASN declaration overrides. waf / non_routable never are.
OWNED_OVERRIDABLE = ("cdn:", "third_party:", "cloud_paas:")

# VM reason prefix → matrix category
REASON_CATEGORY = {
    "cdn": "cdn", "waf": "waf", "third_party": "third_party",
    "cloud_paas": "cloud_paas", "non_routable": "static_or_dead",
}

API_CONTENT_TYPES = re.compile(r"json|graphql|grpc|protobuf|(^|[/+])xml\b", re.I)
PARKED_TITLE = re.compile(
    r"domain (name )?(is |may be )?for sale|buy this domain|parked (free|domain|by)"
    r"|this domain (is|has been) (registered|parked)|hugedomains|sedoparking",
    re.I,
)
DEFAULT_PAGE_TITLE = re.compile(
    r"welcome to nginx|apache2? .*default page|test page for (the )?(apache|nginx)"
    r"|^iis windows server$|^iis\d|^it works!?$|default web site page"
    r"|welcome to (centos|ubuntu|fedora)",
    re.I,
)

DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass
class ScopeConfig:
    cdn_min_confidence: float = 0.35   # detect_cdn scores 0.35 per signal type
    waf_min_confidence: float = 0.5
    cmdb_only: bool = False
    owned_networks: list = field(default_factory=list)
    owned_asns: set = field(default_factory=set)
    require_owned: bool = False
    was_include_saas: bool = False


def parse_owned_networks(spec: str) -> list:
    """'203.0.113.0/24, 198.51.100.7' → [ip_network, ...]"""
    nets = []
    for tok in re.split(r"[,\s]+", spec or ""):
        if tok:
            nets.append(ipaddress.ip_network(tok, strict=False))
    return nets


def parse_owned_asns(spec: str) -> set[int]:
    """'AS64500, 64501' → {64500, 64501}"""
    return {int(tok.upper().removeprefix("AS")) for tok in re.split(r"[,\s]+", spec or "") if tok}


# ---------------------------------------------------------------------------
# Field access — DuckDB hands back all-null / heterogeneous fields as JSON text
# ---------------------------------------------------------------------------

def _obj(v):
    if isinstance(v, str) and v[:1] in ("{", "["):
        try:
            return orjson.loads(v)
        except orjson.JSONDecodeError:
            return None
    return v


def _dict(v) -> dict:
    v = _obj(v)
    return v if isinstance(v, dict) else {}


def _list(v) -> list:
    v = _obj(v)
    return v if isinstance(v, list) else []


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _ip(v):
    try:
        return ipaddress.ip_address(str(v).strip())
    except ValueError:
        return None


def ip_sort_key(ip: str):
    addr = _ip(ip)
    return (addr.version, int(addr)) if addr else (9, 0)


# ---------------------------------------------------------------------------
# Signal extraction
# ---------------------------------------------------------------------------

def _suffix_platform(name: str) -> tuple[str, str] | None:
    name = (name or "").lower().rstrip(".")
    for suffix, platform in PLATFORM_SUFFIXES.items():
        if name == suffix or name.endswith("." + suffix):
            return platform
    return None


def _platforms(asset: dict) -> list[tuple[str, str, str]]:
    """Managed platforms the asset sits on: [(platform, class, evidence), ...]."""
    found: dict[tuple[str, str], str] = {}

    for ep in _list(_dict(asset.get("cloud")).get("endpoints")):
        ep = _dict(ep)
        cls = CLOUD_SERVICE_CLASS.get(ep.get("service") or "")
        if cls:
            found.setdefault((ep["service"], cls), "cloud_enum")

    dns = _dict(asset.get("dns"))
    for name in [asset.get("fqdn", ""), *_list(dns.get("cname_chain"))]:
        hit = _suffix_platform(name)
        if hit:
            found.setdefault(hit, f"cname:{name}")

    org = (_dict(_dict(asset.get("network")).get("asn")).get("org") or "").upper()
    for pattern, platform, cls in ASN_ORG_RULES:
        if org and pattern.search(org):
            found.setdefault((platform, cls), "asn_org")
            break

    return [(p, c, ev) for (p, c), ev in found.items()]


def _is_ai_endpoint(asset: dict) -> bool:
    if _list(asset.get("ai_protocols")):
        return True
    return any(_dict(f).get("source") == "aimap" for f in _list(asset.get("findings")))


def _origin(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme not in DEFAULT_PORTS or not parts.hostname:
        return None
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    if port and port != DEFAULT_PORTS[parts.scheme]:
        return f"{parts.scheme}://{host}:{port}"
    return f"{parts.scheme}://{host}"


def _is_live_status(code: int) -> bool:
    return (200 <= code < 300 and code != 204) or code in (401, 403, 500)


def analyze_web(host: str, web_entries: list) -> dict:
    """Decide which httpx results are real application responses.

    Returns {"origins": [...], "api_only": bool, "web_ports": set,
             "reason": why nothing is live (None when something is)}.
    """
    host = host.lower()
    live: dict[str, bool] = {}            # origin → is API response
    seen: set[str] = set()
    web_ports: set[int] = set()

    for w in web_entries:
        w = _dict(w)
        port = _int(w.get("port"))
        if port:
            web_ports.add(port)
        url = w.get("url") or ""
        status = _int(w.get("status_code"))
        if not url or status is None:
            seen.add("no_app_content")
            continue
        final = urljoin(url, w.get("final_url") or "") or url
        final_host = (urlsplit(final).hostname or "").lower()
        title = w.get("title") or ""

        if 300 <= status < 400 or (final_host and final_host != host):
            seen.add("redirect_only")
        elif PARKED_TITLE.search(title):
            seen.add("parked")
        elif DEFAULT_PAGE_TITLE.search(title.strip()):
            seen.add("default_page")
        elif _is_live_status(status) and (origin := _origin(final)):
            is_api = bool(API_CONTENT_TYPES.search(w.get("content_type") or ""))
            live[origin] = live.get(origin, True) and is_api
        else:
            seen.add("no_app_content")

    # One target per app: when https:443 answers, http:80 on the same host is
    # the same application.
    origins = [o for o in live if not (o.startswith("http://") and "https://" + o[7:] in live)]
    reason = None
    if not origins:
        for r in ("parked", "default_page", "redirect_only", "no_app_content"):
            if r in seen:
                reason = r
                break
    return {
        "origins": sorted(origins),
        "api_only": bool(origins) and all(live[o] for o in origins),
        "web_ports": web_ports,
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

def classify_asset(asset: dict, cfg: ScopeConfig) -> dict:
    """Asset-level routing (VM IP decisions are finalized in route_assets)."""
    fqdn = (asset.get("fqdn") or "").lower()
    dns = _dict(asset.get("dns"))
    network = _dict(asset.get("network"))
    cmdb = _dict(asset.get("cmdb"))
    in_cmdb = bool(cmdb.get("in_cmdb"))
    is_ip_asset = _ip(fqdn) is not None

    ips = sorted({str(a) for a in (_ip(v) for v in _list(dns.get("a"))) if a}, key=ip_sort_key)
    ports = sorted({p for p in (_int(_dict(e).get("port")) for e in _list(network.get("open_ports"))) if p})
    asn = _dict(network.get("asn"))

    categories: list[str] = []
    ip_reasons: list[str] = []      # describe the IPs → poison them for every asset
    vm_block: list[str] = []        # this asset alone is not a VM target
    was_block: list[str] = []

    def cat(name: str):
        if name not in categories:
            categories.append(name)

    # Row 6 / 4 / 2 — managed platforms (cloud_enum, hostname suffix, ASN org)
    platforms = _platforms(asset)
    for platform, cls, _ in platforms:
        if cls == "edge" or cls == "cdn":
            cat("cdn")
            ip_reasons.append(f"cdn:{platform}")
        elif cls == "saas":
            cat("third_party")
            ip_reasons.append(f"third_party:{platform}")
            if not cfg.was_include_saas:
                was_block.append("third_party_saas")
        else:
            cat("cloud_paas")
            ip_reasons.append(f"cloud_paas:{cls}:{platform}")
            if cls == "storage":
                was_block.append("cloud_storage")
            elif cls == "static":
                was_block.append("static_hosting")
            elif cls == "managed":
                was_block.append("managed_service")

    # Row 2 — CDN (multi-signal detector)
    cdn_det = _dict(network.get("cdn_detection"))
    cdn_provider = None
    if cdn_det.get("provider") and (cdn_det.get("confidence") or 0) >= cfg.cdn_min_confidence:
        cdn_provider = cdn_det["provider"]
        cat("cdn")
        ip_reasons.append(f"cdn:{cdn_provider}")

    # Row 3 — WAF (cdncheck IP ranges + waf-detector fingerprint)
    waf = _dict(network.get("waf"))
    waf_provider = None
    if waf.get("provider") and (waf.get("confidence") or 0) >= cfg.waf_min_confidence:
        waf_provider = waf["provider"]
        cat("waf")
        ip_reasons.append(f"waf:{waf_provider}")

    # Row 4 — shared hosting on a third-party provider
    shared = _dict(network.get("shared_hosting"))
    for sig in _list(shared.get("signals")):
        if str(sig).startswith(THIRD_PARTY_HOSTING_SIGNALS):
            cat("third_party")
            ip_reasons.append(f"third_party:{str(sig).split(':', 1)[1]}")

    # Web analysis — rows 7, 8, 9
    web = analyze_web(fqdn, _list(asset.get("web")))
    non_web_ports = [p for p in ports if p not in web["web_ports"]]
    has_web = bool(_list(asset.get("web")))

    if not ips or not (ports or has_web):
        cat("static_or_dead")
        vm_block.append("dead" if not ips else "no_open_ports")
        was_block.append("dead")
    elif not has_web:
        cat("non_http")
        was_block.append("non_http_only")
    elif not web["origins"]:
        was_block.append(web["reason"] or "no_app_content")
        if web["reason"] in ("parked", "redirect_only") and not non_web_ports:
            cat("static_or_dead")
            vm_block.append(web["reason"])

    api = web["api_only"] or _is_ai_endpoint(asset) or any(c == "paas_api" for _, c, _ in platforms)
    if api and web["origins"]:
        cat("api")

    if ips and not any(_ip(ip).is_global for ip in ips):
        was_block.append("non_routable")   # internal IP in public DNS: unreachable for cloud scanners

    if cfg.cmdb_only and not in_cmdb:
        vm_block.append("not_in_cmdb")
        was_block.append("not_in_cmdb")

    if was_block:
        was_action, was_profile, was_urls = "exclude", None, []
    else:
        was_action, was_urls = "include", web["origins"]
        was_profile = "waf" if waf_provider else "api" if api else "standard"

    return {
        "fqdn": fqdn,
        "scan_id": asset.get("scan_id"),
        "in_cmdb": in_cmdb,
        "is_ip_asset": is_ip_asset,
        "ips": ips,
        "ports": ports,
        "asn_number": _int(asn.get("number")),
        "asn_org": asn.get("org") or None,
        "cdn_provider": cdn_provider,
        "waf_provider": waf_provider,
        "platforms": sorted({f"{p}:{c}" for p, c, _ in platforms}),
        "categories": categories,
        "ip_reasons": list(dict.fromkeys(ip_reasons)),
        "vm_block": vm_block,
        "was_action": was_action,
        "was_profile": was_profile,
        "was_reasons": list(dict.fromkeys(was_block)),
        "was_urls": was_urls,
    }


def _is_owned(ip: str, asn_number: int | None, cfg: ScopeConfig) -> bool:
    if asn_number is not None and asn_number in cfg.owned_asns:
        return True
    addr = _ip(ip)
    return bool(addr) and any(addr in net for net in cfg.owned_networks)


def route_assets(assets, cfg: ScopeConfig | None = None) -> tuple[list[dict], list[dict]]:
    """Route every asset. Returns (asset_rows, vm_ip_rows)."""
    cfg = cfg or ScopeConfig()
    rows = [classify_asset(a, cfg) for a in assets if a.get("fqdn")]

    # --- Per-IP aggregation (exclusion wins) ---
    by_ip: dict[str, dict] = {}
    for r in rows:
        for ip in r["ips"]:
            entry = by_ip.setdefault(ip, {
                "assets": [], "reasons": [], "ports": set(), "eligible": False,
                "asn_org": None, "asn_number": None,
            })
            entry["assets"].append(r)
            entry["reasons"].extend(x for x in r["ip_reasons"] if x not in entry["reasons"])
            entry["ports"].update(r["ports"])
            entry["eligible"] |= not r["vm_block"]
            entry["asn_org"] = entry["asn_org"] or r["asn_org"]
            if entry["asn_number"] is None:
                entry["asn_number"] = r["asn_number"]

    ip_rows: list[dict] = []
    ip_action: dict[str, str] = {}
    for ip in sorted(by_ip, key=ip_sort_key):
        entry = by_ip[ip]
        owned = _is_owned(ip, entry["asn_number"], cfg)
        reasons = [x for x in entry["reasons"] if not (owned and x.startswith(OWNED_OVERRIDABLE))]
        if not _ip(ip).is_global:
            reasons.insert(0, "non_routable")

        if reasons:
            action = "exclude"
        elif not entry["eligible"]:
            continue                       # resolves, but nothing to scan
        elif cfg.require_owned and not owned:
            action, reasons = "review", ["ownership_unverified"]
        else:
            action = "include"
        ip_action[ip] = action

        hosts = sorted({r["fqdn"] for r in entry["assets"] if not r["is_ip_asset"]})
        cmdb_hosts = sorted({r["fqdn"] for r in entry["assets"] if not r["is_ip_asset"] and r["in_cmdb"]})
        primary = (cmdb_hosts or sorted(hosts, key=lambda h: (len(h), h)) or [ip])[0]
        ip_rows.append({
            "scan_id": entry["assets"][0]["scan_id"],
            "target_ip": ip,
            "action": action,
            "vm_category": "owned_shared" if len(hosts) > 1 else "direct",
            "primary_fqdn": primary,
            "fqdns": hosts,
            "fqdn_count": len(hosts),
            "ports": sorted(entry["ports"]),
            "asn_org": entry["asn_org"],
            "owned": owned,
            "reasons": reasons,
        })

    shared_ips = {r["target_ip"] for r in ip_rows if r["action"] == "include" and r["vm_category"] == "owned_shared"}
    ip_reasons_by_ip = {r["target_ip"]: r["reasons"] for r in ip_rows}

    # --- Finalize per-asset VM decision ---
    asset_rows = []
    for r in rows:
        included = [ip for ip in r["ips"] if ip_action.get(ip) == "include"]
        if r["vm_block"]:
            vm_action, vm_reasons = "exclude", r["vm_block"]
        elif included:
            vm_action, vm_reasons = "include", []
        elif any(ip_action.get(ip) == "review" for ip in r["ips"]):
            vm_action, vm_reasons = "review", ["ownership_unverified"]
        else:
            vm_action = "exclude"
            vm_reasons = list(dict.fromkeys(x for ip in r["ips"] for x in ip_reasons_by_ip.get(ip, [])))

        categories = list(r["categories"])
        if vm_action == "include":
            categories.append("owned_shared" if any(ip in shared_ips for ip in included) else "direct")
        else:
            # Excluded only via an IP shared with another asset → inherit its category
            for reason in vm_reasons:
                inherited = REASON_CATEGORY.get(reason.split(":", 1)[0])
                if inherited and inherited not in categories:
                    categories.append(inherited)
        categories.sort(key=CATEGORIES.index)
        if not categories:
            categories = ["direct"]

        asset_rows.append({
            "scan_id": r["scan_id"],
            "fqdn": r["fqdn"],
            "in_cmdb": r["in_cmdb"],
            "category": categories[0],
            "categories": categories,
            "ips": r["ips"],
            "ports": r["ports"],
            "asn_org": r["asn_org"],
            "cdn_provider": r["cdn_provider"],
            "waf_provider": r["waf_provider"],
            "platforms": r["platforms"],
            "vm_action": vm_action,
            "vm_ips": included,
            "vm_reasons": vm_reasons,
            "was_action": r["was_action"],
            "was_profile": r["was_profile"],
            "was_reasons": r["was_reasons"],
            "was_urls": r["was_urls"],
        })

    return asset_rows, ip_rows
