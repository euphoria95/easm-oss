# PoC architecture for open-source CMDB and EASM discovery

**Bottom line: a lean pipeline anchored on the ProjectDiscovery suite — `dnsx → naabu → httpx → tlsx → nuclei` — can fingerprint thousands of subdomains in a single JSONL stream with roughly 3–6 HTTP requests per live asset, and feed both a CMDB reconciliation process and an EASM triage dashboard.** This is the cheapest, fastest, most maintained way to build the PoC today. It matters because it replaces ad-hoc spreadsheets with a reproducible, diff-able inventory, exposes shadow IT as the delta against the CMDB, and establishes the data contract needed for future continuous EASM. The input for the PoC is a manually exported list of subdomains from Microsoft Defender TI for two root domains; the output is a normalized asset record per FQDN plus screenshots, ready for visualization. Downstream this plugs into ticketing, SOC alerting and — when management approves — a continuous, scheduled EASM service.

The brief below is opinionated. Where tools overlap we pick one. Where a tool is unmaintained (notably `aquatone`), we say so. Where paid services would normally appear (Shodan, Censys, SecurityTrails, Runzero), we note them only as optional future enhancements.

## 1. Reference architecture

The pipeline is a **funnel**: each stage reduces the candidate set so the next stage only spends requests on live, relevant targets. Stages chain over stdin/stdout JSONL, which is the ProjectDiscovery design idiom and removes glue code.

**End-to-end data flow.** (1) Ingestion reads `subdomains.txt` exported from Defender TI plus, optionally, passive enrichment from crt.sh / CT logs. (2) DNS resolution with `dnsx` validates live names and captures A/AAAA, CNAME chain, NS, MX, TXT. (3) Port discovery with `naabu` runs a top-100 or top-1000 TCP sweep with CDN-aware suppression. (4) HTTP(S) probing with `httpx` issues a single multi-signal request per live web port that captures status, title, headers, TLS summary, favicon mmh3 hash, JARM, tech-detect, CNAME, ASN, CDN, redirect chain, and optional screenshot. (5) TLS deep-grab with `tlsx` runs in parallel on 443/8443/other TLS ports to harvest full cert details, SANs, JA3, JARM, misconfigurations (expired/self-signed/mismatched/revoked/untrusted). (6) Non-HTTP banner grabs with `zgrab2` target SSH/FTP/SMTP/IMAP/POP3/MySQL/Postgres/Redis/MongoDB/MSSQL/SMB found open by naabu. (7) Lightweight exposure scanning with `nuclei` runs a *low-noise* profile: `technologies`, `takeovers`, `exposures`, `misconfiguration` tags only. (8) Normalization merges all JSONL streams into a single asset record keyed on FQDN. (9) Storage is DuckDB (+ parquet) for the PoC; screenshots live on disk, referenced by path. (10) Visualization is a gowitness v3 SPA supplemented by a lightweight Metabase/Grafana dashboard against DuckDB.

**Deployment model for a PoC.** A **single containerized host** with Docker Compose is the right answer. The stack is Go-based static binaries plus a headless Chromium for screenshots; everything fits on one VM (4–8 vCPU, 16 GB RAM, 100 GB SSD). Shell pipelines are sequential but massively concurrent inside each tool (httpx default 50 threads / 150 rps; naabu 1000 pps). **Do not** introduce Kafka/RabbitMQ/Temporal at PoC — the orchestration cost exceeds the scanning cost for two root domains and a few thousand subs. Graduate to a queue only when you operationalize continuous discovery across many business units.

**Data flow description (textual).** `subdomains.txt` → `dnsx -json` → `live_dns.jsonl` → extract hostnames → `naabu -json -top-ports 100 -exclude-cdn` → `ports.jsonl` → build `host:port` list → split into `web_targets` (80/443/8080/8443/etc.) and `service_targets` (22/21/25/3306/…) → `httpx -json` fans out the former, `zgrab2` + `tlsx` fan out the latter → outputs converge into a normalizer (Python or `jq` + DuckDB) that emits one record per FQDN → `nuclei -json` runs a low-noise pass on live URLs → findings joined back onto asset records → DuckDB database + screenshots directory → dashboard.

## 2. Opinionated tooling stack

The recommendation, per stage, with versions and justifications grounded in current upstream behavior.

**DNS resolution — pick `dnsx`.** It is actively maintained by ProjectDiscovery, outputs JSONL natively, handles A/AAAA/CNAME/MX/NS/TXT/SOA/PTR, detects wildcards, accepts custom resolvers (DoH/UDP/TCP), and pipes cleanly into `naabu` and `httpx`. `massdns` is faster at extreme scale (millions of queries) but produces plain text needing postprocessing, and `puredns` (which wraps massdns) shines for brute-force wildcard-heavy enumeration — not our use case because subdomains are already provided. `zdns` (ZMap) is the academic-grade alternative, powerful but with a steeper learning curve. **For a PoC of thousands of names, `dnsx` is the clear choice.**

**Port scanning — pick `naabu` (SYN mode, top-100) with optional Nmap -sV handoff.** naabu v2.3.x supports `-top-ports 100|1000|full`, `-rate 1000` (packets/sec), `-c 25` workers, `-exclude-cdn` (skips full sweep on Cloudflare/Akamai/Fastly/etc., scans only 80/443), native SYN scan when run as root with libpcap, and **built-in Nmap handoff via `-nmap-cli "nmap -sV -sC"`** for verified ports. Against masscan it is slower but friendlier; against rustscan it is more stable and JSON-native. For EASM, **top-100 is the right default** — it catches the >95% of exposed web, mail, remote-access and database ports that matter for attack surface while keeping request budget tight. Reserve `-p -` (all 65535) for a periodic *deep sweep* — not the weekly run.

**HTTP(S) probing — use `httpx` with a single consolidated invocation.** This is the centerpiece tool. In one pass (typically 2–3 HTTP requests per target including redirect follow), httpx returns everything listed in §4's schema. The canonical "full-signal" flag set is: `-sc -cl -ct -location -title -server -td -method -websocket -ip -cname -asn -cdn -probe -favicon -jarm -hash sha256 -rt -lc -wc -tls-grab -http2 -vhost -follow-redirects -include-response-header -json`. Add `-screenshot -system-chrome -srd ./shots` for visual triage. Key knobs: `-threads 50` (default), `-rate-limit 150` rps, `-timeout 10`, `-retries 2`, `-max-host-error 30`, `-probe-all-ips` for multi-IP hosts, `-no-fallback` to record both HTTP and HTTPS separately, `-ports http:80,http:8080,https:443,https:8443` for custom scheme mapping. **Minimum httpx version 1.6.7** (for PDCP dashboard support; current is later and stable). httpx embeds the wappalyzergo library, so tech-detect needs no external dependency.

**TLS certificate analysis — pair `tlsx` with the httpx TLS summary.** `httpx -tls-grab` gives you the quick-look subset (issuer, subject, NotBefore/NotAfter, SANs) already inline; `tlsx` gives you the full record plus misconfiguration flags (`-expired -self-signed -mismatched -revoked -untrusted`), JARM (`-jarm`), JA3 (`-ja3`), serial (`-serial`), wildcard detection (`-wc`), cipher and TLS version details, and has a valuable **pre-handshake early-termination mode** (`-ps -scan-mode ztls`) that cuts handshake cost when you only need cert data. Use `-san -cn -resp-only` to harvest additional subdomains you didn't know about — a free passive enrichment that often surfaces assets Defender TI missed. The `auto` scan mode falls back across ctls → ztls → openssl to cover legacy TLS 1.0/1.1 servers.

**Non-HTTP service fingerprinting — use `zgrab2` from ZMap.** Maintained (commits through late 2025), licensed Apache-2.0/ISC, with modules for `ssh`, `ftp`, `smtp`, `imap`, `pop3`, `telnet`, `mysql`, `mssql`, `postgres`, `mongodb`, `redis`, `oracle`, `smb`, `modbus`, `siemens` (S7), `bacnet`, `dnp3`, `ntp`, `fox`, `ipp`, plus `http`. TOML multi-module config triggers specific scanners per host tag. Its JSON schemas are published (`zgrab2_schemas`) and standard. For a PoC, run: `ssh` (port 22), `ftp --authtls` (21), `smtp --send-ehlo --starttls` (25/587), `imap --starttls` (143/993), `pop3 --starttls` (110/995), `mysql` (3306), `postgres` (5432), `redis` (6379), `mongodb` (27017), `mssql` (1433), `smb` (445). **Skip Nmap NSE for the PoC** — naabu→zgrab2 covers the signal at lower operational risk and with cleaner JSON. Nmap's role is ad-hoc deep investigation, not the pipeline itself.

**Technology stack detection — trust `httpx -td` plus `nuclei` technologies templates; avoid depending on dead Wappalyzer CLIs.** The original Wappalyzer project went closed-source / paid in 2023. Viable open-source replacements in 2026: **(a)** `wappalyzergo` (Go library embedded in httpx and gowitness) — maintained, uses Wappalyzer-style fingerprints and is what the ProjectDiscovery suite already ships; **(b)** `s0md3v/wappalyzer-next` — Python wrapper that drives the actual (still-open) Firefox browser extension in headless mode; accurate but heavy; useful as a deep second pass on interesting assets; **(c)** `rverton/webanalyze` — original Go port, fingerprints lag; serviceable but not best-in-class; **(d)** nuclei `technologies` templates — complementary; catches things the fingerprint set misses (specific admin panels, CI systems, niche CMS). **Recommendation: primary is `httpx -td`; secondary deep-pass is `nuclei -tags tech` on top-value assets only.**

**Screenshot capture — use `gowitness` v3 (SensePost), or `httpx -screenshot` if you want zero extra tooling.** gowitness v3 was a major refactor: it fixed the accuracy problem by spawning one Chromium process per screenshot (accepting the overhead in exchange for reliability), supports chromedp (default) and go-rod (`--driver gorod`) drivers, writes SQLite/JSONL/CSV/Postgres/MySQL, and ships a **React SPA report viewer with a full Swagger-documented API at `/swagger/index.html`** that is demo-ready out of the box. `httpx -screenshot` is adequate when you want one tool — its output includes a rendered DOM body in JSONL. **Do not use aquatone** (`michenriksen/aquatone`): the upstream is effectively abandoned (no meaningful maintenance since ~2019–2020), and community forks like `shelld3v/aquatone` are themselves stale. `EyeWitness` still works but is Python+Selenium heavy and less clean to pipe. **Pick gowitness v3 for the PoC** — the SPA is the single most impressive artifact you can hand to management with the least build effort.

**Favicon hashing — built into `httpx -favicon` (mmh3/MurmurHash3, Shodan-compatible int32).** No extra tool needed. The resulting hash is pivot gold: cluster identical hashes across your attack surface and across public datasets to find forgotten clones, staging copies, and phishing look-alikes.

**Lightweight exposure scanning — `nuclei` in a deliberately low-noise profile.** Against your own assets, running the whole `nuclei-templates` corpus is counterproductive — many templates are fuzzing-heavy and will trip your WAFs. For the PoC, restrict to safe, signal-rich tags: `-tags technologies,takeovers,exposures,misconfiguration,default-logins,exposed-panels -severity info,low,medium,high,critical -rate-limit 50 -bulk-size 25 -concurrency 25 -timeout 10 -retries 1 -json`. This keeps you under ~50 rps total and still surfaces default credentials, exposed .git / .env / .DS_Store, backup files, admin panels, takeover candidates, and version-disclosing banners. Exclude `-etags intrusive,dos,fuzz`.

**Subdomain takeover — use nuclei's `takeovers/` template family as the primary, `subzy` (PentestPad) as secondary verification.** Nuclei's templates track the `can-i-take-over-xyz` fingerprint database and are the best-maintained option. `subzy` (github.com/PentestPad/subzy) is actively maintained and complements nuclei by focusing narrowly on takeover fingerprints; invoke as `subzy run --targets subs.txt --hide_fails`. `subjack` (haccer) is legacy but still occasionally useful for niche providers; skip it for the PoC.

**Passive enrichment — add crt.sh and CT streaming for free.** Query `https://crt.sh/?q=%25.example.com&output=json` once per root domain to pull all CT-logged certs; extract SANs; union with your Defender TI list before DNS resolution. This is free, non-intrusive, and consistently finds 10–30% more subdomains. `certstream` or `certspotter` can be layered in later for continuous discovery.

## 3. Request economy and efficiency

The PoC's competitive advantage over naïve scanning is **ruthless funneling**. Every stage is allowed to touch a target only after the previous stage confirmed the target is real.

**Concrete request budget per live asset** (two-root-domain, web-heavy corpus):
- DNS: 1–3 queries (A/AAAA/CNAME, possibly TXT and NS if enabled).
- Port scan: top-100 SYN on each resolved IP; zero TCP handshakes, only SYN+RST cost. Behind a CDN, `-exclude-cdn` collapses this to 2 ports (80/443).
- HTTP probe: 1 request for HTTPS with fallback to HTTP; +1 if redirected; +1 for `/favicon.ico`. Total **typically 2–3 HTTP requests** for the full multi-signal grab. Add ~1 for screenshot (rendered by headless Chromium, which itself pulls sub-resources, so this is the dominant real-world cost).
- TLS: 1 connection per TLS port. Pre-handshake mode cuts handshake cost for cert-only metadata.
- zgrab2: 1 TCP connection per open non-web port.
- Nuclei low-noise: ~5–20 requests per asset spread across templates, depending on what matches. Cap with `-rate-limit 50`.

**Concurrency defaults that are safe on owned infra**: httpx `-threads 50 -rate-limit 150`; naabu `-rate 1000 -c 25`; nuclei `-rate-limit 50 -concurrency 25`; tlsx `-c 25`; zgrab2 `--senders 100`. These are global per-tool limits; the pipeline serializes stages so they do not compound. Retry once, time out at 10 s. Increase only after a dry run shows no WAF/IDS alarms.

**Caching strategy.** Persist each stage's JSONL with a content hash; re-running the pipeline should short-circuit DNS and cert results if younger than 24 h. A simple on-disk JSON cache keyed on `{tool, target, args_hash}` with TTL is enough for the PoC. For continuous mode, move to Redis with LRU eviction.

**Passive-first rule.** Before any active probe, run `dnsx -silent -resp-only` over the Defender TI list and union with SANs from crt.sh. Only then open the SYN scanner. This cuts discovered-but-dead names from the active path and materially reduces request volume.

## 4. Data model

The goal is one record per unique FQDN with nested service/TLS/web/finding objects. Field names borrow from STIX 2.1 (`domain-name`, `ipv4-addr`, `x509-certificate`, `network-traffic`) where natural, but we do not impose the full STIX envelope at PoC.

**Example JSON record (truncated for readability):**

```json
{
  "fqdn": "portal.example.com",
  "first_seen": "2026-03-01T09:12:44Z",
  "last_seen": "2026-04-19T02:15:09Z",
  "source": ["defender_ti", "crt.sh", "tls_san"],
  "confidence": 0.93,
  "tags": ["external", "web", "prod-guess"],
  "owner": null,
  "dns": {
    "a": ["203.0.113.12", "203.0.113.13"],
    "aaaa": [],
    "cname_chain": ["portal.example.com", "edge.cdnprovider.net"],
    "ns": ["ns1.example.com", "ns2.example.com"],
    "mx": [],
    "wildcard": false
  },
  "network": {
    "asn": {"number": 13335, "org": "CLOUDFLARENET", "country": "US"},
    "geo": {"country": "US", "city": "San Francisco"},
    "cdn": "cloudflare",
    "open_ports": [
      {"port": 443, "protocol": "tcp", "service": "https"},
      {"port": 80,  "protocol": "tcp", "service": "http"},
      {"port": 22,  "protocol": "tcp", "service": "ssh",
       "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"}
    ]
  },
  "web": [{
    "port": 443, "scheme": "https",
    "url": "https://portal.example.com/",
    "final_url": "https://portal.example.com/login",
    "status_code": 200,
    "title": "Acme Portal – Sign in",
    "server": "cloudflare",
    "content_type": "text/html; charset=utf-8",
    "content_length": 18422,
    "response_time_ms": 184,
    "tech": [
      {"name": "Nginx", "version": null, "categories": ["Web servers"]},
      {"name": "React", "version": "18.2.0", "categories": ["JavaScript frameworks"]},
      {"name": "Cloudflare", "version": null, "categories": ["CDN"]}
    ],
    "favicon_mmh3": -1340235546,
    "body_sha256": "8e9c2b…",
    "headers_of_interest": {
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "content-security-policy": "default-src 'self' …",
      "x-powered-by": null,
      "set-cookie_flags": {"httpOnly": true, "secure": true, "sameSite": "Lax"}
    },
    "redirect_chain": ["https://portal.example.com/", "https://portal.example.com/login"],
    "screenshot_path": "shots/portal.example.com_443.png"
  }],
  "tls": [{
    "port": 443,
    "version": "TLS1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "jarm": "29d3fd00029d29d00042d43d0000006a2f6f7c1b96e0c5d6c18b5d9b6c5a7b8c",
    "ja3s": "475c9302dc42b2751db9edcac3b74891",
    "issuer": "CN=Cloudflare Inc ECC CA-3, O=Cloudflare, Inc., C=US",
    "subject": "CN=portal.example.com",
    "sans": ["portal.example.com", "*.example.com"],
    "not_before": "2026-01-10T00:00:00Z",
    "not_after":  "2026-07-09T23:59:59Z",
    "days_to_expiry": 81,
    "key_algo": "ECDSA", "key_size": 256,
    "self_signed": false, "expired": false,
    "mismatched": false, "revoked": false, "untrusted": false,
    "serial": "0a1b2c…"
  }],
  "findings": [
    {"source": "nuclei", "template": "exposed-panels/grafana-login",
     "severity": "low", "matched_at": "https://portal.example.com/grafana/"},
    {"source": "nuclei", "template": "takeovers/s3-takeover",
     "severity": "high", "matched_at": "https://portal.example.com/assets/"}
  ],
  "cmdb": {
    "matched_ci": "CI0087721",
    "match_basis": ["fqdn", "cert_san"],
    "in_cmdb": true,
    "gap_type": null
  }
}
```

The identifiers layer (`fqdn`, `dns.a`, `tls.sans`, `favicon_mmh3`, `network.asn.number`) is what the CMDB reconciler joins on. The `cmdb.gap_type` enum is `null | "shadow_it" | "unmanaged" | "stale_ci" | "orphan_cert"`.

## 5. Storage and querying

**For the PoC, use DuckDB on the JSONL output, with screenshots on disk.** DuckDB reads JSONL natively (`SELECT * FROM read_ndjson_auto('assets.jsonl')`), handles nested structures via `UNNEST`, supports columnar analytics at dashboard speed over tens of millions of rows, and needs no server. Back it with Parquet exports for archival. SQLite works but DuckDB wins on aggregations (tech-stack distributions, port heatmaps). Flat JSONL + `jq` is fine for engineers but not demo-able. Elasticsearch/OpenSearch is overkill for two root domains — save it for when you scale. Postgres with JSONB is the right next step when the PoC graduates to a service with multi-user access.

**Scaling considerations.** Beyond ~100k assets and continuous discovery, move to OpenSearch (free Apache-2.0 fork; Kibana/OpenSearch Dashboards included) for full-text over banners, titles, and cert subjects, and add Postgres as system-of-record. For graph analytics (CNAME chains, shared-cert clusters, favicon pivots), Neo4j Community (GPLv3) or the Apache-2.0 `memgraph` work well; both are open-source. Neo4j Bloom is **not** open-source — avoid committing to it as a required dependency.

## 6. Visualization and frontend

**Primary recommendation for the management demo: the `gowitness` v3 SPA as the hero artifact, combined with a Metabase dashboard over DuckDB for aggregations.** This combination maximizes polish-per-hour: gowitness v3 ships a React SPA with screenshot gallery, filters, and an HTTP/JSON API, and Metabase auto-generates charts over DuckDB with point-and-click — set-up time is measured in hours, not days. Both are fully open-source.

**If the team prefers a single-pane approach, use OpenSearch + OpenSearch Dashboards.** Ingest the normalized JSONL, define an index template matching the schema above, and build a dashboard with: (1) Discover-style asset table with rich filters (tech, status, CDN, ASN, cert expiry); (2) tech-stack treemap via aggregation on `web.tech.name`; (3) port/service heatmap on `network.open_ports.port` × FQDN; (4) TLS expiry timeline as a line chart on `tls.days_to_expiry`; (5) severity-bucketed findings table; (6) graph relationships require an add-on plugin or a separate Cytoscape.js view.

**If you must impress with a bespoke build**, use a React app with AG Grid for the asset table, Apache ECharts for charts (treemap, heatmap, timeline, bar), and **Cytoscape.js** for the CNAME/ASN/cert-SAN relationship graph. This is the highest-ceiling, highest-effort path. For a two-week PoC I would not start here.

**Visualizations that land with management.** Lead with the **screenshots gallery clustered by perceptual similarity** — it's the most intuitive demonstration of "this is what attackers see." Follow with the **CMDB gap bar** (assets in EASM but not CMDB, as a red count), the **TLS expiry timeline** (immediate operational hook), and the **takeover candidates highlight** (immediate risk hook). Keep the tech-stack treemap as a secondary "we now know our stack" artifact. The graph view is compelling but budget for it only if you use gowitness/Metabase and have leftover time.

## 7. CMDB and EASM integration

**Reconciliation keys**, in priority order: (1) exact FQDN match; (2) cert-SAN match, which often catches CIs that the CMDB recorded under a primary name while the asset also serves secondary names; (3) resolved IP with ownership confirmation via ASN/RIR WHOIS; (4) owner tag / cost center match from DNS TXT records or internal IPAM if available; (5) favicon mmh3 + title similarity as a weak last-resort heuristic to cluster clones of the same application.

**Gap analysis is the punchline slide.** For each asset record, compute a `cmdb.match_basis` and `cmdb.in_cmdb` boolean against a CMDB export (CSV or ServiceNow REST pull). Three categories light up: **shadow IT** (live asset, no CI), **stale CI** (CI exists, asset dead or redirected elsewhere), and **orphan cert** (certificate SAN references a hostname with no live service and no CI — a classic takeover precursor). Report these counts as percentages of the discovered surface; expect 10–30% shadow IT in a first pass at a large global org — this number is what justifies continuing investment.

**Evolution to production.** The PoC is a batch script. Production is (1) scheduled runs (nightly for discovery, weekly for deep port sweep, monthly for full nuclei catalog); (2) state-diffing between runs, emitting events for new/changed/dead assets; (3) alerting on deltas (new open port on prod asset, new high-severity nuclei finding, cert expiring in <30 days, new takeover candidate); (4) ticketing integration (Jira/ServiceNow) for finding assignment; (5) owner-derivation enrichment from internal sources (AD group ownership of the IP range, IPAM tags, Git repo ownership for apps behind the FQDN); (6) graduated orchestration to a queue-based runner (Temporal or a Celery/RQ cluster) only when scan volume justifies it.

## 8. Operational and legal considerations

Run everything from a **dedicated egress IP pair** that the SOC has pre-authorized and that appears on an internal allow-list. Set a custom User-Agent on every tool that identifies the program and includes a contact mailbox: `-H "User-Agent: AcmeEASM-PoC/0.1 (+security-recon@acme.example)"` in httpx. Document the scope-of-authorization (the two root domains and their subdomains) in a one-page memo co-signed by the CTI and AppSec leads before the first scan. Brief the SOC 24 h before each run; share the egress IPs and the expected traffic profile so your own WAFs, IDS/IPS, and rate-limiters do not misclassify you and pollute the signal for real attackers. For cloud assets, verify that cloud provider terms permit self-scanning — AWS, Azure, and GCP all allow scanning of your own tenancy without pre-authorization, but some managed services (e.g., specific PaaS offerings) still carry constraints.

**Keep data-handling disciplined.** Screenshots and banners routinely leak secrets — embedded credentials in admin panels, tokens in JavaScript bundles, PII in error pages. Treat the PoC output store at the same classification level as production customer data, restrict access, and set a 90-day retention for raw artifacts. Produce a redacted, long-retained derivative (metrics, counts, CI matches) for management and historical comparison.

## 9. PoC plan

**Week 1 — stack up.** Day 1–2: provision the host, install Docker, pull and pin versions of `dnsx`, `naabu`, `httpx`, `tlsx`, `nuclei`, `nuclei-templates`, `zgrab2`, `gowitness`, `subzy`. Use `pdtm` (ProjectDiscovery tool manager) to install and pin the PD suite. Day 3: write the master `run.sh` that chains stages, logs per-stage counts, and writes JSONL artifacts per stage. Day 4: author the DuckDB schema and a Python normalizer that merges stage outputs into the per-FQDN record. Day 5: run a canary scan against ~50 known-good subdomains, validate field coverage, measure requests per asset.

**Week 2 — full pipeline run and enrichment.** Day 1: run the full pipeline against the Defender TI list for both root domains. Day 2–3: build the CMDB reconciler; pull the CMDB export, join on FQDN/SAN/IP, compute gap statistics. Day 4: run the low-noise nuclei profile on live URLs; join findings back to records. Day 5: rerun to validate idempotency, capture first_seen/last_seen behavior, and measure total wall-clock time.

**Week 3 — dashboard and management pitch.** Day 1–2: point gowitness v3 at the screenshots, launch the SPA, wire Metabase (or OpenSearch Dashboards) to DuckDB for aggregations. Day 3: build the management deck: one slide per KPI below, one slide for the gap-analysis punchline, one slide for three concrete findings from the run. Day 4: dry-run the demo with the Principal CTI analyst. Day 5: present to management.

**Success metrics.** (1) **Coverage**: percent of input subdomains successfully resolved and, of those, percent with at least one open port. Target >95% resolution, >60% with open ports. (2) **Request efficiency**: average HTTP requests per live asset for the full fingerprint (target ≤6) and total requests sent per scan (publish the absolute number so the SOC can corroborate). (3) **Findings**: count of nuclei findings by severity; count of takeover candidates; count of expiring/expired/misissued certs. (4) **CMDB gap percentage**: assets discovered but absent from CMDB, as a share of total discovered. (5) **Time-to-complete**: wall-clock for the full pipeline. (6) **Novel subdomains added** via crt.sh and TLS-SAN passive harvest vs. the Defender TI input (demonstrates that open-source passive sources add signal for free).

**Next-step pitch to management.** Continuous EASM service (nightly discovery + weekly deep + monthly catalog), automated ticketing, SOC alerting on deltas, owner-derivation from internal sources, optional paid data uplift (Shodan/Censys/Runzero as *complements*, not replacements — the open-source core is the defensible piece of infrastructure), and a measurable reduction in shadow-IT percentage as the primary KPI for year one.

## 10. Example end-to-end command pipeline

A single, realistic chain that produces enriched JSONL and screenshots from `subs.txt`. Replace paths and egress identity as appropriate. This is copy-paste runnable on a Linux host with the tools installed.

```bash
# 0. passive union: add CT-log SANs to the Defender TI list
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' | tr '\n' '\n' | sed 's/\*\.//' \
  | cat - subs.txt | sort -u > targets.txt

# 1. DNS resolve (JSON), then extract live hostnames
dnsx -l targets.txt -a -aaaa -cname -resp -silent -json \
     -r resolvers.txt -rate-limit 500 -retry 2 \
     -o dns.jsonl
jq -r '.host' dns.jsonl | sort -u > live_hosts.txt

# 2. Port scan top-100 with CDN awareness; JSON output
sudo naabu -l live_hosts.txt -top-ports 100 -exclude-cdn -display-cdn \
           -rate 1000 -c 25 -retries 1 -silent -json \
           -o ports.jsonl

# 3. Build web-target list (ports likely to speak HTTP/S)
jq -r 'select(.port|IN(80,81,443,591,2082,2083,2086,2087,2095,2096,
       3000,3128,4443,5000,5001,5601,7001,7002,8000,8008,8080,8081,
       8090,8443,8888,9000,9001,9090,9200,9443)) | "\(.host):\(.port)"' \
       ports.jsonl | sort -u > web_targets.txt

# 4. Full-signal HTTP probe + screenshot, single invocation
httpx -l web_targets.txt \
  -sc -cl -ct -location -title -server -td -method -websocket \
  -ip -cname -asn -cdn -probe -favicon -jarm -hash sha256 \
  -rt -lc -wc -tls-grab -http2 -follow-redirects \
  -include-response-header -no-fallback \
  -screenshot -system-chrome -srd ./shots \
  -threads 50 -rate-limit 150 -timeout 10 -retries 2 \
  -H "User-Agent: AcmeEASM-PoC/0.1 (+security-recon@acme.example)" \
  -silent -json -o httpx.jsonl

# 5. Deep TLS grab (443/8443/other TLS) with misconfig flags
jq -r 'select(.port|IN(443,465,563,636,853,989,990,992,993,994,995,
       4443,5061,5986,6443,8443,9443)) | "\(.host):\(.port)"' \
       ports.jsonl | sort -u \
  | tlsx -ja3 -jarm -san -cn -so -tv -cipher -serial -hash sha256 \
         -expired -self-signed -mismatched -revoked -untrusted -wc \
         -scan-mode auto -silent -json -o tls.jsonl

# 6. Non-HTTP banner grabs (example: SSH on port 22)
jq -r 'select(.port==22) | .host' ports.jsonl | sort -u \
  | zgrab2 ssh --port=22 --timeout=10 > zgrab_ssh.jsonl

# 7. Low-noise nuclei pass on live web URLs
jq -r '.url' httpx.jsonl | sort -u \
  | nuclei -tags technologies,takeovers,exposures,misconfiguration,\
default-logins,exposed-panels \
           -severity info,low,medium,high,critical \
           -etags intrusive,dos,fuzz \
           -rate-limit 50 -bulk-size 25 -concurrency 25 \
           -timeout 10 -retries 1 -silent -jsonl \
           -o nuclei.jsonl

# 8. Takeover second opinion
subzy run --targets live_hosts.txt --hide_fails --output subzy.json

# 9. Normalize and load into DuckDB (sketch)
python3 normalize.py \
  --dns dns.jsonl --ports ports.jsonl --http httpx.jsonl \
  --tls tls.jsonl --zgrab zgrab_ssh.jsonl --nuclei nuclei.jsonl \
  --subzy subzy.json --cmdb cmdb_export.csv \
  --out assets.jsonl
duckdb easm.duckdb \
  "CREATE TABLE assets AS SELECT * FROM read_ndjson_auto('assets.jsonl');"

# 10. Serve the gowitness v3 SPA over the screenshots
gowitness report server --db-uri sqlite://gowitness.sqlite3 --port 7171
```

## Conclusion

The PoC's value is less about the individual tools and more about **the discipline of the funnel and the structured output**. The ProjectDiscovery suite is the right spine because it is cohesive, maintained, JSONL-native, and chains over stdin/stdout without glue code; `zgrab2` extends the same shape to non-HTTP services; `gowitness` v3 solves the hardest UX problem (screenshots at scale) with a dashboard that is itself demo-quality. Aquatone is dead, Wappalyzer is closed, Neo4j Bloom is commercial — recognize each and route around them, which the stack above does.

The **single highest-leverage insight for management** is the CMDB-gap percentage. It converts a technical scan into a governance number, and that number is what funds the continuous EASM service after the PoC. Everything else — screenshots, treemaps, JARM clusters — is supporting evidence. Build the pipeline, harvest the gap number, present it truthfully, and the path from PoC to production writes itself.