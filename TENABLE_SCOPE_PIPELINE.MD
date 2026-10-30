# EASM-OSS to Tenable VM & WAS — Scan Scope Routing Specification

This document defines the architectural rules, asset categorization, and DuckDB filtering logic for exporting discovered external assets from the **EASM-OSS** pipeline into **Tenable Vulnerability Management (VM)** and **Tenable Web Application Scanning (WAS)**.

---

## 1. Fundamental Scanner Constraints & Capabilities

### Tenable Vulnerability Management (Tenable VM / Nessus)
* **Operational Mechanism:** Network-centric (Layer 3 / Layer 4) with service banner grabbing and unauthenticated/authenticated checks. When given an FQDN, Tenable VM resolves it to an IP address and scans the underlying host across all configured ports.
* **Key Limitations:**
  * **CDN / Reverse Proxy Blindness:** Scanning a Cloudflare, Akamai, or CloudFront IP tests the provider's edge infrastructure, not the origin server. It burns Tenable licenses on third-party IPs and generates false positives (e.g., ports 8080/8443 open on the Cloudflare edge).
  * **WAF Interference:** Network-level plugin payloads trigger WAF rate-limiting or IP blocks, resulting in incomplete scans, false negatives, or dropped connections.
  * **Shared IP / Multi-tenant Multiplication:** If 50 FQDNs resolve to a single ingress controller, load balancer, or shared hosting IP, feeding all 50 FQDNs into Tenable VM results in redundant network scans of the exact same IP or unauthorized scanning of third-party co-hosted tenants.
  * **PaaS / Serverless Incompatibility:** Cloud-native endpoints (e.g., AWS S3, Azure App Services, GitHub Pages) have underlying infrastructure managed entirely by the cloud provider; OS/network-level scanning adds zero value.

### Tenable Web Application Scanning (Tenable WAS)
* **Operational Mechanism:** Application-centric (Layer 7 / HTTP/HTTPS). Evaluates specific FQDNs/URLs, respects `Host` headers and SNI, crawls the DOM, and executes active DAST payloads (SQLi, XSS, SSRF).
* **Key Limitations:**
  * **WAF Blocking:** Active DAST payloads will almost certainly trigger WAF rules (`403 Forbidden`, `429 Too Many Requests`, CAPTCHA) unless Tenable scanner IPs or custom headers (`USER_AGENT`) are explicitly allow-listed on the WAF.
  * **Static Content Waste:** Running a heavy headless browser crawl and DAST injection engine against static marketing pages, raw S3 buckets, or simple redirectors wastes scan time and WAS licenses.
  * **Pure APIs without Schemas:** Scanning REST/GraphQL endpoints without providing OpenAPI/Swagger/Postman definitions yields poor coverage (the crawler cannot guess complex JSON bodies).

---

## 2. EASM-OSS Pipeline Routing Matrix

This matrix defines how each discovered asset category in the EASM-OSS pipeline (enriched via `subfinder`, `dnsx`, `pyasn`, `cdndetect`, `wafdetector`, `httpx`, `nerva`, and `cloud_enum`) should be routed:

| Asset Category / Characteristic | Tenable VM (Network/Infra) | Tenable WAS (App/DAST) | Routing Rationale & Action Required |
| :--- | :--- | :--- | :--- |
| **1. Direct / Dedicated IP (Non-CDN, Non-WAF, Owned ASN/Cloud)** | **INCLUDE** (Deduplicated by IP) | **INCLUDE** (If Web Service Active) | **Ideal VM target.** Direct visibility to origin OS and services (`nerva` ports). Export unique IP (or 1 representative FQDN per IP) to VM; export all web FQDNs to WAS. |
| **2. Behind CDN (`cdndetect` == true)** | **EXCLUDE** | **INCLUDE** (Conditional) | **Never scan CDN edge IPs in VM.** Route FQDN to WAS *only* if it hosts a dynamic application. Origin IPs must be found separately via historical DNS/cert leaks if VM scanning is needed. |
| **3. Behind WAF (`wafdetector` == true)** | **EXCLUDE** | **CONDITIONAL** (Tag: `WAF_Protected`) | **Exclude from VM** to prevent IP blackholing. Route to WAS *only* under a dedicated scan policy using allow-listed scanner egress IPs/headers, or low-rate passive profiles. |
| **4. Shared Hosting / 3rd-Party SaaS (`v_shared_hosting` / 3rd-Party ASN)** | **EXCLUDE** | **INCLUDE** (FQDN only) | **Critical VM Exclusion.** Tenable VM resolves the FQDN and scans the shared underlying IP (violating provider ToS and wasting licenses). WAS safely scopes strictly to the `Host` header. |
| **5. Owned Shared IP (K8s Ingress / Reverse Proxy / Load Balancer)** | **INCLUDE** (1x per unique IP) | **INCLUDE** (All unique FQDNs) | If 100 FQDNs point to 1 company-owned Nginx/ALB IP: scan the **IP once** in Tenable VM (infrastructure check), and scan **each unique FQDN** in Tenable WAS (virtual host routing). |
| **6. Cloud PaaS / Serverless (`cloud_enum` == AppService, CloudRun, S3, etc.)** | **EXCLUDE** | **INCLUDE** (If Web App) / **EXCLUDE** (If Storage) | Underlying OS/Network is managed by AWS/GCP/Azure (Shared Responsibility Model). Keep out of VM. Scan web apps in WAS; handle storage buckets via `nuclei`/`cloud_enum`. |
| **7. Non-HTTP Services Only (`nerva` == SSH, VPN, DB, SMTP; `httpx` == null)** | **INCLUDE** | **EXCLUDE** | WAS cannot evaluate non-HTTP protocols. Route directly to Tenable VM to audit TLS (`tlsx`), SSH configurations, VPN concentrators, and exposed databases. |
| **8. Static Sites, Redirects (301/302), Parked Domains, Dead Hosts** | **EXCLUDE** | **EXCLUDE** | Zero infrastructure control and zero dynamic application attack surface. Keep strictly in EASM (`nuclei` / `livecheck`) to monitor for drift or subdomain takeovers. |
| **9. Dangling DNS / Takeover Candidates (`verify_takeovers.py` == true)** | **EXCLUDE** | **EXCLUDE** | Pointing to unclaimed third-party resources. Scanning causes legal/ToS issues. Trigger immediate remediation alert from EASM instead. |
| **10. Pure APIs / AI Endpoints (`aimap` / `httpx` content-type: JSON)** | **INCLUDE** (If Direct IP) | **CONDITIONAL** (API Profile) | Standard WAS DOM-crawlers fail on pure APIs. Tag for specialized WAS API scanning (requires Swagger/OpenAPI spec) or keep in `nuclei` + `aimap`. |

---

## 3. Pipeline Integration & Filtering Logic (`cmdb_scope_export.py`)

To automate this in the EASM-OSS pipeline after adding `subfinder`, `cdndetect`, and `wafdetector`, update `normalize.py` and `load_duckdb.py` to include a `network.waf` object alongside `network.cdn`.

### Proposed Data Model Addition (`assets.jsonl`)

```json
{
  "fqdn": "app.example.com",
  "network": {
    "asn": {
      "number": 13335,
      "prefix": "104.16.0.0/12",
      "org": "CLOUDFLARENET"
    },
    "cdn": {
      "detected": true,
      "provider": "cloudflare",
      "confidence": 0.99,
      "signals": ["cname_pattern", "asn_membership", "ip_range"]
    },
    "waf": {
      "detected": true,
      "provider": "cloudflare",
      "confidence": 0.95
    },
    "is_shared_third_party": false,
    "is_cloud_paas": false,
    "open_ports": [80, 443]
  }
}
```

### DuckDB Scope Export Queries

Implement the routing rules directly as DuckDB SQL views inside `load_duckdb.py` and export them via `cmdb_scope_export.py`:

#### A. `v_tenable_vm_scope` (Infrastructure / Network Targets)
*Goal: Export deduplicated, direct origin IPs (or 1 primary FQDN per IP) that are NOT behind a CDN/WAF, NOT on third-party shared hosting, and NOT serverless PaaS.*

```sql
CREATE OR REPLACE VIEW v_tenable_vm_scope AS
SELECT 
    UNNEST(dns.a) AS target_ip,
    FIRST(fqdn) AS primary_fqdn,
    network.asn.org AS asn_org,
    network.open_ports AS ports
FROM assets
WHERE 
    -- 1. Must be alive and have open ports
    ARRAY_LENGTH(dns.a) > 0 
    AND ARRAY_LENGTH(network.open_ports) > 0
    -- 2. Exclude CDN and WAF fronted assets
    AND COALESCE(network.cdn.confidence, 0) < 0.5
    AND COALESCE(network.waf.detected, false) = false
    -- 3. Exclude Cloud PaaS / Serverless (managed infra)
    AND NOT EXISTS (
        SELECT 1 FROM UNNEST(findings) AS f 
        WHERE f.source = 'cloud_enum' AND f.type IN ('paas', 'serverless', 'storage')
    )
    -- 4. Exclude 3rd-party shared hosting / SaaS ASNs
    AND network.asn.org NOT ILIKE ALL (ARRAY[
        '%CLOUDFLARE%', '%AKAMAI%', '%FASTLY%', '%INCAPSULA%', 
        '%GITHUB%', '%HEROKU%', '%SHOPIFY%', '%SQUARESPACE%', '%WPENGINE%'
    ])
GROUP BY target_ip, network.asn.org, network.open_ports;
```

#### B. `v_tenable_was_scope_standard` (Unprotected Dynamic Web Apps)
*Goal: Export live HTTP/HTTPS FQDNs that return real application content (no pure redirects/default pages) and do NOT have an active WAF blocking payloads.*

```sql
CREATE OR REPLACE VIEW v_tenable_was_scope_standard AS
SELECT DISTINCT
    w.url AS target_url,
    a.fqdn,
    w.status_code,
    w.title,
    w.tech
FROM assets a, UNNEST(a.web) AS w
WHERE 
    -- 1. Live web application returning meaningful status
    w.status_code IN (200, 401, 403, 500)
    -- 2. Exclude WAF-protected targets from standard aggressive DAST
    AND COALESCE(a.network.waf.detected, false) = false
    -- 3. Exclude confirmed subdomain takeover candidates
    AND NOT EXISTS (
        SELECT 1 FROM UNNEST(a.findings) AS f 
        WHERE 'takeover' IN f.tags
    )
    -- 4. Exclude static storage buckets
    AND NOT EXISTS (
        SELECT 1 FROM UNNEST(a.findings) AS f 
        WHERE f.source = 'cloud_enum' AND f.type = 'storage'
    );
```

#### C. `v_tenable_was_scope_waf` (WAF-Fronted Web Apps — Whitelist Required)
*Goal: Export web apps behind a WAF into a separate file (`tenable_was_waf_targets.txt`) so the security team can verify WAF bypass/allow-list rules before scanning.*

```sql
CREATE OR REPLACE VIEW v_tenable_was_scope_waf AS
SELECT DISTINCT
    w.url AS target_url,
    a.fqdn,
    a.network.waf.provider AS waf_provider,
    a.network.cdn.provider AS cdn_provider,
    w.tech
FROM assets a, UNNEST(a.web) AS w
WHERE 
    w.status_code IN (200, 401, 403)
    AND a.network.waf.detected = true;
```

---

## 4. Architectural Recommendations for `subfinder`, `cdndetect`, and `wafdetector`

1. **Placement in Pipeline Stage Order:**
   * **`subfinder`**: Place at **Stage 0** alongside `ct_enrich.py` (`crt.sh`). Merge outputs and deduplicate into `targets.txt` before `dnsx` runs. Tag records with `source: ["subfinder"]` to maintain CMDB gap attribution (`v_cmdb_gaps`).
   * **`cdndetect` (or ProjectDiscovery `cdncheck`)**: Run right after `dnsx` (Stage 1) and before `naabu` (Stage 4). If an IP/FQDN is flagged as CDN/Cloud/WAF at the IP/CNAME level, instruct `naabu` to skip full port scans (only check 80/443) and immediately flag it for `tenable_vm_exclude.txt`.
   * **`wafdetector` (e.g., `wafw00f` or `httpx -cdn` / Nuclei WAF templates)**: Run after `httpx` (Stage 5) only on live HTTP/HTTPS endpoints. Keep request noise low (1–2 benign + 1 light probe request per host) to avoid burning the EASM scanner IP during recon.
2. **Handling the "Shared IP" Trap in Tenable VM:**
   * In `v_shared_hosting`, distinguish between **Internal Load Balancers** (where 20 of your own FQDNs resolve to 1 IP you own) and **External Shared Hosting** (where your FQDN shares an IP with other customers on GoDaddy/Cloudflare/Vercel).
   * For **Internal Load Balancers**, export the **raw IP address** (not the 20 FQDNs) to `tenable_vm_include.txt`. This prevents Tenable VM from running 20 identical network scans against the same load balancer while Tenable WAS still receives all 20 FQDNs to test each individual web application via the `Host` header.
