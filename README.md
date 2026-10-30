# EASM Pipeline — External Attack Surface Management

Open-source EASM discovery and CMDB reconciliation pipeline built on the ProjectDiscovery suite.

## Architecture

```
ROOT_DOMAINS (opt-in) ──→ subfinder + crt.sh ──┐  passive subdomain discovery
                                               ▼
subdomains.txt / IPs / CIDRs ────────────────────────→ targets.txt
                                                          │
                                                          ▼
                                                    ┌──────────┐
                                                    │   dnsx    │  DNS Resolution
                                                    └────┬─────┘
                                                         │ live_hosts + A/AAAA records
                                                         ▼
                                                    ┌──────────┐
                                                    │  pyasn    │  ASN Enrichment
                                                    └────┬─────┘  (IP → ASN/prefix/org)
                                                         │ asn.jsonl
                                                         ▼
                                                    ┌──────────┐
                                                    │  getdns   │  Reverse DNS
                                                    └────┬─────┘  (IP → PTR records)
                                                         │ rdns.jsonl
                                                         ▼
                                                    ┌──────────┐
                                                    │ cdncheck  │  CDN / cloud / WAF
                                                    └────┬─────┘  (provider IP ranges)
                                                         │ cdncheck.jsonl
                                                         ▼
                                                    ┌──────────┐
                                                    │  naabu    │  Port Scanning
                                                    └────┬─────┘  (top ports, CDN-aware)
                                                         │ ports.jsonl
                                         ┌───────────────┴──────────────┐
                                         ▼                              ▼
                                   ┌──────────┐               ┌──────────────────┐
                                   │  httpx   │               │  nerva           │
                                   │+screen   │               │  + service       │  Fingerprinting
                                   │+CDN test │               │    fingerprints  │  CPE/vendor/version
                                   └────┬─────┘               │  + misconfigs    │  OS hints
                                        │                     └────┬─────────────┘
                                   ┌────┴─────┐                    │
                                   │waf-detect│                    │  Passive WAF/CDN
                                   └────┬─────┘                    │  fingerprinting
                                        │                          │
                                   ┌────┴─────┐                    │
                                   │  tlsx    │                    │
                                   └────┬─────┘                    │
                                        │                          │
                                   ┌────┴──────────┐               │
                                   │ nuclei        │               │
                                   │ (low noise)   │               │
                                   └────┬──────────┘               │
                                        │                          │
                                   ┌────┴──────────┐               │
                                   │ cloud_enum    │               │  Azure/AWS/GCP
                                   │ (CNAME/host)  │               │  endpoint detection
                                   └────┬──────────┘               │
                                        │                          │
                                   ┌────┴──────────┐               │
                                   │ aimap         │               │  Exposed AI agents
                                   │ (AI endpoints)│               │  (MCP/Ollama/...)
                                   └────┬──────────┘               │
                                        │                          │
                                        ▼                          ▼
                            ┌────────────────────────────────────────┐
                            │   normalize.py                         │  Merge all JSONL
                            │   + CMDB reconciliation                │  + CDN/WAF verdicts
                            │   1 record/FQDN                        │
                            └────────────┬─────────────────────────┘
                                         │ assets.jsonl
                                         ▼
                                    ┌──────────┐
                                    │  DuckDB  │  + Parquet archive
                                    │ + views  │  + Dashboard API
                                    └────┬─────┘
                                         │
                                         ▼
                            ┌────────────────────────────────────────┐
                            │  verify_takeovers.py                    │  Live DNS + HTTP
                            │  (mode: recon)                          │  takeover confirmation
                            │  score_bounty.py    (mode: bounty)      │  S/A/B/C/D tiering
                            │  livecheck.py       (mode: livecheck)   │  Tenable scope export
                            └────────────────────────────────────────┘
```

## Quick Start

### 1. Prerequisites

- Docker & Docker Compose
- OR: Go 1.22+, Python 3.12+, libpcap, Chromium (for native install)

### 2. Setup

```bash
git clone <repo-url> && cd easm-oss

# Edit your configuration
cp config/pipeline.env config/pipeline.env.local
vim config/pipeline.env.local

# Add your subdomains
vim data/input/subdomains.txt

# Add your CMDB export (optional)
vim data/input/cmdb_export.csv

# Optional: enrich targets via subfinder (passive sources) and Certificate
# Transparency logs (crt.sh). Set the root domains per scan in the dashboard
# ("Root domains"), or via env:
#   ROOT_DOMAINS=example.com,example.org ./run.sh

# Optional: subfinder API keys (more sources → more subdomains)
cp config/subfinder-provider-config.example.yaml config/subfinder-provider-config.yaml
```

### 3. Run with Docker (one-click)

```bash
# Build & start the dashboard
docker compose up -d --build

# Open the dashboard — configure stages, enter targets, click Start Scan
open http://127.0.0.1:9990

# Stop everything
docker compose down
```

The dashboard runs the full pipeline inside its container. Select which stages
to run from the scan form (defaults to full pipeline).

<details>
<summary>Optional: CLI usage & advanced build options</summary>

```bash
# Build with Ubuntu 24.04 runtime base (uses Google Chrome instead of Chromium)
RUNTIME_BASE=ubuntu:24.04 docker compose build

# Pin the tools compiled from their upstream repos (defaults: latest / pinned sha)
SUBFINDER_VERSION=<tag> CDNCHECK_VERSION=<tag> WAF_DETECTOR_REF=<git-sha> docker compose build

# Run pipeline from CLI (without the dashboard)
docker compose --profile cli run --rm easm-pipeline
docker compose --profile cli run --rm easm-pipeline --stage dns,ports,http
docker compose --profile cli run --rm easm-pipeline --from tls
docker compose --profile cli run --rm easm-pipeline --dry-run
```

</details>

Notes:
- Default runtime base is `debian:bookworm-slim` (works on both x86_64 and arm64).
- subfinder and cdncheck are compiled with `go install` and waf-detector with `cargo build` from their upstream repositories inside the image build — no local checkout is needed. Local clones in `subfinder/`, `cdncheck/` or `waf-detector/` are git- and docker-ignored.
- `ubuntu:24.04` is supported via `RUNTIME_BASE=ubuntu:24.04`; the image installs Google Chrome instead of snap-based Chromium.

### 4. Run Natively

```bash
# Install Python deps
pip install -r requirements.txt

# Install Go tools (via pdtm or go install)
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/sensepost/gowitness/v3@latest
go install github.com/praetorian-inc/nerva/cmd/nerva@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
# waf-detector (Rust)
cargo install --locked --git https://github.com/ammarion/waf-detector --bin waf-detect
# optional: zgrab2 fallback (set FINGERPRINT_BACKEND=zgrab2 in pipeline.env to use)
# go install github.com/zmap/zgrab2/cmd/zgrab2@latest
# optional: aimap (exposed-AI-agent discovery stage) — vendored separately into aimap/

# Run
chmod +x run.sh scripts/*.sh
./run.sh                     # full recon pipeline
./run.sh --from tls          # resume from TLS onwards
./run.sh --stage normalize   # re-run normalization only
./run.sh --mode bounty       # expanded bug-bounty scan + scoring
./run.sh --mode livecheck    # DNS-only CMDB scope governance
```

### 5. Test with Synthetic Data

```bash
# Generate fake scan data and run normalizer + DuckDB loader
python3 scripts/test_pipeline.py --assets 50

# Normalize
python3 scripts/normalize.py \
    --dns data/output/dns.jsonl \
    --ports data/output/ports.jsonl \
    --http data/output/httpx.jsonl \
    --tls data/output/tls.jsonl \
    --nerva data/output/nerva.jsonl \
    --nuclei data/output/nuclei.jsonl \
    --cmdb data/input/cmdb_export.csv \
    --output data/output/assets.jsonl

# Load into DuckDB
python3 scripts/load_duckdb.py \
    --input data/output/assets.jsonl \
    --db data/output/easm.duckdb \
    --scan-id test_run
```

## Pipeline Stages

Stage order: `subfinder,ct,dns,asn,rdns,cdn,ports,http,waf,tls,fingerprint,nuclei,cloud_enum,aimap,normalize,load,verify,scope`

| Stage | Name | Tool | Purpose |
|-------|------|------|---------|
| 0 | `subfinder` | subfinder | Passive subdomain enumeration across many sources for the configured root domains; adds in-scope hostnames to the targets. Opt-in — skipped unless `ROOT_DOMAINS` is set |
| 1 | `ct` | ct_enrich.py (crt.sh) | Passive Certificate Transparency lookup for the configured root domains; adds new in-scope hostnames to the targets. Opt-in — skipped unless `ROOT_DOMAINS` is set |
| 2 | `dns` | dnsx | Resolve A/AAAA/CNAME/NS/MX/TXT, filter to live hosts |
| 3 | `asn` | pyasn | Enrich IPs with ASN, prefix, organization (offline BGP RIB) |
| 4 | `rdns` | getdns | Reverse DNS lookup on IP addresses → PTR records |
| 5 | `cdn` | cdncheck | Classify live hosts/IPs as CDN / cloud / WAF using provider IP ranges |
| 6 | `ports` | naabu | TCP SYN scan top-100 ports, CDN-aware |
| 7 | `http` | httpx | Full-signal probe: status, title, tech, headers, JARM, screenshot |
| 8 | `waf` | waf-detect | Passive WAF/CDN fingerprinting of every HTTP origin (no attack payloads) |
| 9 | `tls` | tlsx | Deep cert analysis: SANs, expiry, misconfig flags |
| 10 | `fingerprint` | nerva | Auto-detect all protocols: SSH, FTP, DB, Redis, SMB — CPE/vendor/version/OS fingerprints. Alias: `zgrab` |
| 11 | `nuclei` | nuclei | Low-noise scan: takeovers, exposed panels, misconfigs |
| 12 | `cloud_enum` | cloud_enum.py | Detect Azure/AWS/GCP cloud endpoints (storage, web apps, DBs, CDN) from DNS/HTTP/TLS data |
| 13 | `aimap` | run_aimap.py | Discover exposed AI agent endpoints (MCP, Ollama, LangServe, Gradio, ComfyUI…). Requires vendored `aimap/` tool |
| 14 | `normalize` | normalize.py | Merge all JSONL → unified asset record per FQDN + CDN/WAF verdicts |
| 15 | `load` | load_duckdb.py | Load into DuckDB with analytical views + Parquet archive |
| 16 | `verify` | verify_takeovers.py | Live DNS + HTTP fingerprint verification of takeover candidates |
| 17 | `scope` | cmdb_scope_export.py | Route assets to Tenable VM (unique IPs) / Tenable WAS (URLs, standard / WAF / API profiles). `recon` mode only |

`subfinder`, `ct`, `cdn`, `waf`, `cloud_enum` and `aimap` are best-effort enrichment stages — they are skipped (non-fatal) if they have no inputs or the tool is unavailable.

### CT-log enrichment (`ct` stage)

Queries [crt.sh](https://crt.sh) for every certificate ever logged for your root domains and adds the hostnames found to the scan targets — typically surfacing subdomains missing from your input list. Hosts that came from CT are tagged with source `crt.sh` in the asset record, so you can measure how much CT added.

```bash
ROOT_DOMAINS=example.com,example.org ./run.sh        # CLI / env
ROOT_DOMAINS=example.com ./run.sh --stage ct,dns     # just CT + DNS
python3 scripts/ct_enrich.py --domains example.com --output /tmp/ct.txt   # standalone
```

- **Opt-in and scoped.** Nothing is queried unless `ROOT_DOMAINS` is set (or the dashboard's *Root domains* field is filled in), and only names equal to or under those domains are kept — third-party SANs on shared certificates are dropped.
- **Passive.** The only network traffic is to crt.sh; nothing touches your targets until the later stages.
- **Best-effort.** crt.sh is often slow or returns 502s, so requests are retried (`CT_RETRIES`, `CT_TIMEOUT` in `config/pipeline.env`); if it stays down the scan continues with your input list.
- Not run in `livecheck` mode, which validates your registered CMDB names only.
- Output: `data/output/ct_subdomains.txt` (everything CT returned, including names already in your input).

### Passive subdomain enumeration (`subfinder` stage)

Runs [subfinder](https://github.com/projectdiscovery/subfinder) against the same `ROOT_DOMAINS` as the `ct` stage and merges the in-scope results into the targets. Matching assets are tagged with source `subfinder`.

- **Same scope rules as CT.** Opt-in via `ROOT_DOMAINS`; only names equal to or under a root domain are kept; not run in `livecheck` mode.
- **No double crt.sh traffic.** subfinder's `crtsh` source is excluded — the `ct` stage owns it.
- **API keys (optional).** Copy `config/subfinder-provider-config.example.yaml` to `config/subfinder-provider-config.yaml` (git-ignored); it is passed with `-pc` only when present.
- Tunables: `SUBFINDER_THREADS`, `SUBFINDER_TIMEOUT`, `SUBFINDER_MAX_TIME`, `SUBFINDER_TOTAL_TIMEOUT`, `SUBFINDER_ALL`.
- Output: `subfinder.jsonl` (raw, with sources) and `subfinder_subdomains.txt` (in-scope names).

### CDN / cloud / WAF classification (`cdn` stage)

Runs [cdncheck](https://github.com/projectdiscovery/cdncheck) over `live_hosts.txt` (resolved FQDNs + direct IPs). Each record is stored as `network.cdncheck { ip, cdn, cloud, waf }` and:

- adds a `cdncheck:<provider>` signal to the multi-signal CDN detector (`detect_cdn.py`) — Cloudflare / Imperva are counted as CDN even though cdncheck files them under WAF;
- seeds a `network.waf` verdict (confidence 0.6, source `cdncheck`) when a WAF IP range matches.

Also runs in `livecheck` mode (cheap, improves CDN-fronting classification). Tunable: `CDNCHECK_THREADS`.

### WAF detection (`waf` stage)

Runs [waf-detector](https://github.com/ammarion/waf-detector) (`waf-detect scan --ndjson`) against one URL per HTTP origin found by httpx.

- **Passive only.** The stage never enables payload analysis, smoke tests, effectiveness, hardening or adversary modes — those send attack payloads and are out of scope for recon.
- **Verdicts.** The highest-confidence detection per host becomes `network.waf { detected, provider, confidence, sources[], url }`; agreement with cdncheck is recorded in `sources`. A waf-detector CDN verdict adds a `wafdetector:<provider>` signal to CDN detection.
- **Throughput.** Origins are processed in chunks (`WAF_BATCH_SIZE`) by parallel workers (`WAF_WORKERS`), each with a timeout (`WAF_BATCH_TIMEOUT`); a hung chunk loses only its own results. Capped at `WAF_MAX_TARGETS` origins.
- Not run in `livecheck` mode. Output: `waf.jsonl`. Query via `v_waf_analysis` or the dashboard's *Network → CDN Providers* tab.

### Partial runs and resuming

Use `--stage` to run one or more specific stages, or `--from` to run from a given stage through the end of the pipeline. Prior stage outputs on disk are reused as inputs — no re-scanning required.

```bash
# Run only DNS
./run.sh --stage dns

# Run DNS and port scan together
./run.sh --stage dns,ports

# Resume from TLS onwards (e.g. after a config fix)
./run.sh --from tls

# Re-run only normalization and DuckDB load
./run.sh --from normalize

# Preview without executing
./run.sh --dry-run --from tls
```

`--stage` and `--from` are mutually exclusive. `--from` resolves to all stages from the named stage to `load` inclusive.

## Pipeline Modes

Select with `--mode` (or `PIPELINE_MODE` in `config/pipeline.env`). Default is `recon`.

| Mode | Flag | Behavior |
|------|------|----------|
| `recon` | _(default)_ | Full pipeline with conservative, low-noise settings. Ends with takeover verification and Tenable VM/WAS scope routing. |
| `bounty` | `--mode bounty` | Expanded attack-surface scan: top-1000 ports, no CDN exclusion, Nerva misconfigs + UDP, broader `nuclei-bounty.yaml` template set. Runs `score_bounty.py` to assign each asset an S/A/B/C/D priority tier. |
| `livecheck` | `--mode livecheck` | Lightweight DNS-only CMDB scope governance (`dns,asn,rdns,normalize,load`). Validates registered FQDNs for liveness, CDN/WAF fronting, CNAME bloat, stale records, and 3rd-party nameservers, then exports Tenable include/exclude scope files. |

```bash
./run.sh --mode bounty          # expanded scan + bounty scoring
./run.sh --mode livecheck       # CMDB scope validation + Tenable export
```

### Bug Bounty Scoring (`bounty` mode)

`score_bounty.py` reads the unified asset table and computes a 0–100 priority score per subdomain from attack-surface breadth, technology stack, security posture, and criticality signals (admin panels, sensitive subdomain names, vulnerable frameworks). Results are tiered **S/A/B/C/D** and surfaced via the dashboard **Bounty** tab and the `v_bounty_*` DuckDB views.

```bash
python3 scripts/score_bounty.py \
    --db data/output/easm.duckdb \
    --output data/output/bounty_report.jsonl
```

### CMDB Livecheck & Tenable Scope Export (`livecheck` mode)

`livecheck.py` validates CMDB-registered FQDNs for DNS liveness, detects CDN/WAF presence, analyzes CNAME-chain bloat, identifies leaf domains, tracks unavailability over time (via `livecheck_state.json`), and classifies 3rd-party nameservers. `cmdb_scope_export.py` then emits `tenable_include.txt` / `tenable_exclude.txt` for scanning-scope governance.

```bash
# Tunables (config/pipeline.env)
LIVECHECK_DEADLINE_DAYS=30           # grace period before stale records are flagged
LIVECHECK_CNAME_DEPTH_THRESHOLD=3    # CNAME hops considered "bloated"
```

### Tenable VM / WAS Scope Routing (`scope` stage)

Turns every discovered asset into scanner-ready scope, following the routing matrix in [`TENABLE_SCOPE_PIPELINE.MD`](TENABLE_SCOPE_PIPELINE.MD). Tenable VM scans infrastructure by IP; Tenable WAS runs DAST against web applications. Feeding both scanners the raw asset list wastes licences and scans infrastructure you don't own. The rules live in `scripts/tenable_scope.py`; `cmdb_scope_export.py --db` applies them after `verify`, so confirmed takeovers stay out of both scanners.

| Category | Tenable VM | Tenable WAS |
|----------|-----------|-------------|
| Direct / dedicated IP | include (by IP) | include (live web apps) |
| Owned shared IP (LB / ingress, ≥2 FQDNs) | include **once** per IP | include every FQDN |
| Behind CDN (detector, CDN-edge ASN, CloudFront / Front Door) | exclude | include |
| Behind WAF (`network.waf`) | exclude | `waf` profile — allow-list scanner egress first |
| Shared hosting (hosting ASN / panel headers) | exclude | include |
| Third-party SaaS (Shopify, Zendesk, HubSpot … by CNAME/ASN) | exclude | exclude (`TENABLE_WAS_INCLUDE_SAAS=true` to override) |
| Cloud PaaS / serverless (App Service, Cloud Run, Lambda, Heroku, Vercel …) | exclude | include |
| Cloud storage / static hosting / managed DBs (S3, Blob, GitHub Pages, RDS …) | exclude | exclude |
| Non-HTTP only (SSH, VPN, DB, SMTP) | include | exclude |
| Redirect-only / parked / dead | exclude | exclude |
| Default server page (nginx/IIS/Apache welcome) | include | exclude |
| Takeover (verified `confirmed`, or scanner finding not cleared as `likely_fp`) | exclude | exclude |
| Pure API / AI endpoint (JSON responses, aimap hit, API gateway) | include if direct | `api` profile — attach an OpenAPI definition |
| Non-routable IP in public DNS (RFC 1918, documentation ranges) | exclude | exclude when every IP is non-routable |

**Exclusion wins per IP.** If any asset resolving to an IP marks it as CDN, WAF, third-party/PaaS or a takeover target, that IP stays out of VM for every asset that shares it. A WAS URL counts as live on `2xx` (not `204`), `401`, `403` or `500`. A redirect to another host counts as redirect-only; that host is routed as its own asset. When `https://host` answers, `http://host` is dropped as the same app.

Outputs (in `data/output/`, then archived with the scan):

| File | Contents |
|------|----------|
| `tenable_vm_include.txt` | Unique IPs to network-scan |
| `tenable_vm_exclude.txt` | IPs that must not be network-scanned (import as a Tenable exclusion) |
| `tenable_vm_review.txt` | VM candidates outside your declared ranges (only with `TENABLE_VM_REQUIRE_OWNED=true`) |
| `tenable_was_targets.txt` | WAS URLs for the standard scan policy |
| `tenable_was_waf_targets.txt` | WAF-fronted URLs. Scan only once the WAF allow-lists Tenable's egress IPs / header |
| `tenable_was_api_targets.txt` | API / AI endpoints. Scan with an API policy and an OpenAPI/Postman definition |
| `tenable_scope.jsonl` | Per-asset decision with category and reasons (audit trail) |
| `tenable_vm_targets.jsonl` | Per-IP VM decision: primary FQDN, all FQDNs, ports, reasons |
| `tenable_scope_meta.json` | Routing settings used for this run (also shown on the dashboard) |
| `tenable_scope.xlsx` | Analyst workbook — see below |

**XLSX workbook.** `tenable_scope.xlsx` (also downloadable from the dashboard's Tenable Scope page) holds:

| Sheet | Contents |
|-------|----------|
| Summary | Routing settings (ownership, thresholds, CMDB-only), totals, category matrix, caveats to check before importing |
| All | Every routed asset: categories, CMDB match, IPs/ports/ASN/CNAME, CDN/WAF/platforms, VM and WAS decision with reasons, HTTP status/title/tech, TLS expiry and issues, sources, first/last seen |
| Tenable VM Candidates | One row per IP to scan (`include`) or confirm (`review`): category, ownership, primary and all FQDNs, ports, CMDB CIs |
| Tenable WAS Candidates | One row per URL with its scan profile and the policy it needs (standard / WAF allow-list / API definition), HTTP and TLS details |
| Columns | Data dictionary: every column, its type and meaning |

Every data sheet is a filterable Excel table with a frozen header. Hover a header to see what the column means. Scanned text such as titles and banners is always stored as plain text, never as a formula. The workbook is built on `scripts/xlsx_workbook.py`, a small declarative writer (sheets of typed `Column` specs) that other exports can reuse. To regenerate it from any routed database, run `python3 scripts/tenable_xlsx.py --db data/output/easm.duckdb --output tenable_scope.xlsx`.

```bash
# Tunables (config/pipeline.env)
TENABLE_CDN_MIN_CONFIDENCE=0.35   # detect_cdn scores 0.35 per signal type → any CDN signal excludes from VM
TENABLE_WAF_MIN_CONFIDENCE=0.5
TENABLE_OWNED_CIDRS=""            # your ranges — override CDN / third-party / PaaS heuristics (never WAF/takeover)
TENABLE_OWNED_ASNS=""
TENABLE_VM_REQUIRE_OWNED=false    # true = IPs outside owned ranges go to review, not include
TENABLE_SCOPE_CMDB_ONLY=false     # true = only CMDB-registered assets enter scan scope
TENABLE_WAS_INCLUDE_SAAS=false

# Re-route the current database without re-scanning
./run.sh --stage scope
python3 scripts/query.py --db data/output/easm.duckdb --query tenable_scope
```

> **Authorization:** routing reduces the risk of scanning third-party infrastructure but cannot prove ownership. For production scan scopes, set `TENABLE_OWNED_CIDRS` / `TENABLE_OWNED_ASNS` and `TENABLE_VM_REQUIRE_OWNED=true` so that IPs outside your declared ranges go to review rather than straight into VM.

## Querying

```bash
# List available queries
python3 scripts/query.py --db data/output/easm.duckdb --query list

# Run a query (keys: stats, gaps, shadow_it, tls_issues, tls_expiring,
#   findings, findings_critical, tech, tech_summary, ports, port_heatmap,
#   cdn_distribution, waf_distribution, asn_distribution, favicon_clusters, takeovers,
#   verified_takeovers)
python3 scripts/query.py --db data/output/easm.duckdb --query stats
python3 scripts/query.py --db data/output/easm.duckdb --query shadow_it
python3 scripts/query.py --db data/output/easm.duckdb --query tls_issues
python3 scripts/query.py --db data/output/easm.duckdb --query findings_critical
python3 scripts/query.py --db data/output/easm.duckdb --query verified_takeovers
python3 scripts/query.py --db data/output/easm.duckdb --query port_heatmap

# Custom SQL
python3 scripts/query.py --db data/output/easm.duckdb \
    --sql "SELECT fqdn, cmdb.gap_type FROM assets WHERE cmdb.gap_type IS NOT NULL"

# Run all queries
python3 scripts/query.py --db data/output/easm.duckdb --query all
```

## CMDB Gap Report

```bash
python3 scripts/cmdb_report.py \
    --db data/output/easm.duckdb \
    --output data/output/cmdb_gap_report.json
```

## Exports

```bash
# Export all views as CSV
bash scripts/export.sh --db data/output/easm.duckdb --format csv --all

# Export specific view as JSON
bash scripts/export.sh --db data/output/easm.duckdb --format json --query v_findings
```

## Scan Diffing

```bash
# Compare two scan results
bash scripts/diff_scans.sh data/output/assets_prev.jsonl data/output/assets.jsonl
```

## DuckDB Views

| View | Description |
|------|-------------|
| `v_asset_summary` | One-row-per-asset overview with service_count, CDN/WAF status, ASN |
| `v_cmdb_gaps` | Assets missing from CMDB |
| `v_tls_issues` | Expired, self-signed, expiring certs |
| `v_findings` | All nuclei/nerva findings by severity |
| `v_tech_stack` | Technology detected per asset |
| `v_open_ports` | All open ports with service info |
| `v_services` | Per-port fingerprints: vendor, product, version, CPE, OS, certainty |
| `v_software_inventory` | Unique software across the estate, grouped by product/version with host count |
| `v_scan_stats` | Aggregate scan statistics including total_services |
| `v_reverse_dns` | Reverse DNS mappings for infrastructure analysis |
| `v_cdn_analysis` | CDN detection results with confidence scoring |
| `v_cdn_exclusions` | Assets behind CDN (candidate scan exclusions) |
| `v_waf_analysis` | WAF verdicts per asset (provider, confidence, cdncheck/waf-detector sources) |
| `v_cloud_endpoints` | Detected Azure/AWS/GCP cloud endpoints |
| `v_cloud_providers` | Cloud provider distribution |
| `v_cloud_risk` | Cloud endpoints ranked by exposure risk |
| `v_cloud_summary` | Aggregate cloud-endpoint statistics |
| `v_bounty_scores` | Per-asset bug-bounty priority score and S/A/B/C/D tier |
| `v_bounty_highlights` | Top-priority bounty targets with score rationale |
| `v_bounty_summary` | Aggregate bounty scoring statistics |
| `v_livecheck_summary` | CMDB livecheck results: liveness, CDN fronting, staleness |
| `v_scope_removals` | Stale/dead FQDNs proposed for scan-scope removal |
| `v_cname_bloat` | FQDNs with excessive CNAME-chain depth |
| `v_leaf_domains` | Leaf (non-delegated) domains |
| `v_third_party_ns` | FQDNs served by 3rd-party nameservers |
| `v_shared_hosting` | IPs hosting multiple distinct FQDNs |
| `v_tenable_vm_scope` | Tenable VM targets — one row per unique IP with primary FQDN, all FQDNs, ports |
| `v_tenable_vm_exclusions` | IPs kept out of Tenable VM, with reasons |
| `v_tenable_vm_review` | VM candidates awaiting ownership confirmation |
| `v_tenable_was_scope_standard` | Tenable WAS URLs for the standard DAST policy |
| `v_tenable_was_scope_waf` | WAF-fronted WAS URLs with WAF/CDN provider (allow-list first) |
| `v_tenable_was_scope_api` | API / AI endpoints for API-profile WAS scans |
| `v_tenable_scope_summary` | Asset counts per routing category and VM/WAS action |

## Data Model

Each asset record (keyed by FQDN) contains:

```
fqdn, scan_id, first_seen, last_seen, source[], tags[]
├── dns: { a[], aaaa[], cname_chain[], ns[], mx[], txt[], wildcard }
├── network: { 
│   asn: { number, prefix, org },
│   cdn: { provider, confidence, signals[] },
│   cdncheck: { ip, cdn, cloud, waf },
│   waf: { detected, provider, confidence, sources[], url },
│   rdns: [{ ip, ptr }],
│   open_ports[]
│ }
├── web[]: { port, url, status_code, title, tech[], screenshot_path, ... }
├── tls[]: { port, version, issuer, sans[], days_to_expiry, expired, ... }
├── services[]: { port, protocol, transport, service, status, banner,
│               fingerprint: { vendor, product, version, cpe23,
│                              os_vendor, os_product, os_version,
│                              certainty, source } }
├── findings[]: { source, template_id, severity, matched_at, ... }   # nuclei, nerva, aimap, cloud_enum
└── cmdb: { matched_ci, match_basis[], in_cmdb, gap_type }
```

`cloud_enum` (Azure/AWS/GCP endpoint detection) and `aimap` (exposed AI agent discovery) emit findings in Nuclei JSONL format, so they merge into `findings[]` alongside nuclei/nerva results.

## Project Structure

```
easm-oss/
├── run.sh                       # Main pipeline orchestrator
├── Dockerfile                   # Multi-stage build with all tools
├── docker-compose.yml           # Docker Compose stack
├── requirements.txt             # Python dependencies
├── config/
│   ├── pipeline.env             # Pipeline configuration (PIPELINE_MODE, NERVA_*, SUBFINDER_*, WAF_*, …)
│   ├── subfinder-provider-config.example.yaml  # subfinder API keys template (real file git-ignored)
│   ├── resolvers.txt            # DNS resolvers
│   ├── nuclei-config.yaml       # Nuclei scanning profile (recon mode)
│   ├── nuclei-bounty.yaml       # Expanded Nuclei profile (bounty mode)
│   ├── nuclei-templates/        # Custom local Nuclei templates (e.g. cloud)
│   └── zgrab2-modules.ini       # zgrab2 module config (deprecated — kept for fallback)
├── scripts/
│   ├── normalize.py             # JSONL merger & asset normalizer + CDN detection
│   ├── load_duckdb.py           # DuckDB loader with views + archive
│   ├── run_nerva.sh             # Nerva service fingerprinting wrapper
│   ├── detect_cdn.py            # Multi-signal CDN detection (CNAME, IP, headers, ASN, cdncheck, waf-detector)
│   ├── enrich_asn.py            # Offline ASN enrichment using pyasn
│   ├── enrich_nuclei.py         # Nuclei finding aggregation and enrichment
│   ├── cloud_enum.py            # Azure/AWS/GCP cloud endpoint enumeration
│   ├── ct_enrich.py             # Certificate Transparency (crt.sh) subdomain enrichment
│   ├── run_aimap.py             # Exposed AI-agent endpoint discovery stage
│   ├── verify_takeovers.py      # Live verification of subdomain takeover candidates
│   ├── score_bounty.py          # Bug-bounty priority scoring engine (S/A/B/C/D)
│   ├── livecheck.py             # CMDB DNS-liveness / scope governance analysis
│   ├── cmdb_scope_export.py     # Tenable scope exporter (VM/WAS routing + livecheck include/exclude)
│   ├── tenable_scope.py         # Tenable VM/WAS routing rules (TENABLE_SCOPE_PIPELINE.MD matrix)
│   ├── archive_scan.py          # Archive scan results to Parquet
│   ├── validate_schema.py       # Schema validation and data integrity checks
│   ├── cmdb_report.py           # CMDB gap analysis report
│   ├── query.py                 # Query runner with pre-built queries
│   ├── test_pipeline.py         # Synthetic data generator
│   ├── test_nerva_ingest.py     # Unit tests for Nerva ingestion
│   ├── test_ct_enrich.py        # CT enrichment tests (offline, crt.sh mocked)
│   ├── test_recon_tools.py      # subfinder / cdncheck / waf-detector stage + ingest tests (fake binaries)
│   ├── test_pipeline_nerva.sh   # Integration test: normalize + DuckDB with mock Nerva data
│   ├── test_ip_implementation.py # IP scanning and enrichment tests
│   ├── test_livecheck.py        # Livecheck unit tests
│   ├── test_verify_takeovers.py # Takeover verification unit tests
│   ├── test_tenable_scope.py    # Tenable VM/WAS routing tests (matrix rows, DuckDB views, run.sh stage)
│   ├── diff_scans.sh            # Scan-to-scan diff
│   ├── cache.sh                 # Cache manager
│   └── export.sh                # Export to CSV/JSON/Parquet
├── dashboard/
│   ├── app.py                   # FastAPI dashboard + scan orchestration API
│   └── static/
│       ├── index.html           # Single-page UI shell
│       ├── app.js               # Frontend: Overview, Assets, Services, Network,
│       │                        #   Cloud, AIMAP, Takeovers, Bounty, Livecheck,
│       │                        #   Scans (history/compare) tabs
│       └── styles.css           # Styles
├── aimap/                       # Vendored AI-agent discovery tool (git-ignored, optional)
├── subfinder/ cdncheck/ waf-detector/  # Optional local upstream clones (git- & docker-ignored; image builds from remote)
├── data/
│   ├── input/
│   │   ├── subdomains.txt       # Your subdomain list
│   │   └── cmdb_export.csv      # CMDB export
│   ├── output/                  # Pipeline outputs (JSONL, DuckDB, Parquet)
│   ├── screenshots/             # httpx screenshots
│   └── cache/                   # Stage output cache
└── logs/                        # Scan logs
```

## Request Budget

Per live asset, the pipeline makes approximately:
- subfinder: queries to third-party passive sources per root domain (only when `ROOT_DOMAINS` is set; no traffic to targets)
- CT: 1 crt.sh request per root domain (only when `ROOT_DOMAINS` is set)
- cdncheck: mostly offline IP-range matching (+1 DNS lookup per FQDN)
- DNS: 1–3 queries
- ASN: 1 lookup (offline — BGP RIB database)
- Reverse DNS: 1 lookup per IP (PTR query)
- Port scan: top-100 SYN packets (2 if behind CDN)
- HTTP: 2–3 requests (+ sub-resources for screenshot)
- WAF detection: a few benign requests per HTTP origin (no attack payloads)
- TLS: 1 connection per TLS port
- Nerva: 1 TCP/UDP connection per open port (concurrent, auto-detects protocol)
- Nuclei: 5–20 requests (rate-limited to 50 rps total)
- Cloud enum: 0 network requests (pattern-matches existing DNS/HTTP/TLS data)
- AIMAP: a handful of HTTP probes per web target (only when the stage runs)

Note: ASN enrichment and cloud enumeration are offline (no network requests). Reverse DNS may be subject to rate limits depending on your resolver.

## IP Address Scanning & Enrichment

Stages 3–4 (ASN and RDNS) enrich discovered IP addresses with network intelligence:
- **ASN Enrichment** (stage 3): Maps IPs to Autonomous System Numbers, prefixes, and organizations using offline BGP RIB data
- **Reverse DNS** (stage 4): Performs PTR lookups on discovered IPs for hostname inference and infrastructure mapping
- **CDN Detection**: Multi-signal detection during normalization (CNAME patterns, IP ranges, HTTP headers, ASN membership, cdncheck and waf-detector verdicts)

### Configuration (`config/pipeline.env`)

```bash
# ASN enrichment (pyasn)
ASN_DB_PATH="data/cache/ipasn.dat"          # pyasn IPASN database
ASN_NAMES_TSV="data/cache/asn-names.tsv"    # Optional: ASN→org name mapping

# Reverse DNS
RDNS_WORKERS=10                              # Concurrent getdns threads
RDNS_TIMEOUT=5                               # Seconds per lookup

# CDN detection (integrated into normalize.py)
CDN_DETECTION_ENABLED=true
```

### Usage

ASN and RDNS stages run automatically as part of the pipeline. To run them individually:

```bash
./run.sh --stage asn              # Run ASN enrichment only
./run.sh --stage rdns             # Run reverse DNS only
./run.sh --stage asn,rdns         # Run both

# Run from ASN onwards
./run.sh --from asn
```

### Data Model (Network Enrichment)

Each asset includes enriched network data:

```json
{
  "fqdn": "example.com",
  "network": {
    "asn": {
      "number": 13335,
      "prefix": "1.2.3.0/24",
      "org": "CLOUDFLARENET"
    },
    "cdn": {
      "provider": "cloudflare",
      "confidence": 0.95,
      "signals": ["cname_pattern", "asn_membership", "ip_range"]
    },
    "rdns": [
      {"ip": "1.2.3.4", "ptr": "server1.cdn.example.com"}
    ],
    "open_ports": [...]
  }
}
```

## Service Fingerprinting (Nerva)

Nerva replaces zgrab2 as the primary fingerprinting engine. It auto-detects protocols on any open port and produces CPE-normalized vendor/product/version/OS fingerprints.

### Configuration (`config/pipeline.env`)

```bash
NERVA_TIMEOUT=10          # seconds per connection
NERVA_THREADS=50          # concurrent workers
NERVA_FAST_MODE=false     # restrict to default ports only
NERVA_UDP=false           # enable UDP protocol detection
NERVA_MISCONFIGS=false    # surface misconfigs (weak SSH KEX, Redis no-auth, etc.)
FINGERPRINT_BACKEND=nerva # set to "zgrab2" to use legacy fallback
ZGRAB2_FALLBACK=false     # set to "true" to run both nerva and zgrab2
```

### Stage alias

`--stage fingerprint` and `--stage zgrab` both run the fingerprint stage (stage 7).

### Testing

```bash
# Unit tests (helpers + ingest_nerva)
python3 scripts/test_nerva_ingest.py

# Integration test (normalize → DuckDB with mock data)
bash scripts/test_pipeline_nerva.sh

# IP scanning and enrichment tests
python3 scripts/test_ip_implementation.py

# CT enrichment (offline), livecheck, takeover verification
python3 scripts/test_ct_enrich.py
python3 scripts/test_livecheck.py
python3 scripts/test_verify_takeovers.py
```

## Takeover Verification

The `verify` stage (stage 13) reads takeover candidates from the DuckDB assets table (nuclei `takeovers`-tagged findings already confirmed live), then performs live DNS CNAME resolution and HTTP fingerprint checks to confirm whether the dangling resource is actually claimable. Confirmed candidates are written to `takeover_verifications.jsonl` and surfaced via the dashboard **Takeovers** tab and the `takeovers` / `verified_takeovers` queries.

```bash
# Run takeover verification (requires an existing DuckDB)
./run.sh --stage verify

# Or automatically at the end of a full recon run
./run.sh

# Standalone
python3 scripts/verify_takeovers.py \
    --db data/output/easm.duckdb \
    --out data/output/takeover_verifications.jsonl
```

### Schema validation (standalone)

`validate_schema.py` checks the normalized asset dataset for required-field presence, type correctness, nested-object consistency, and IP/ASN/CIDR format validity:

```bash
python3 scripts/validate_schema.py --input data/output/assets.jsonl
```

## Dashboard

The FastAPI dashboard provides real-time visualization **and** in-browser scan orchestration — you configure stages, enter targets, pick a mode, and start a scan without touching the CLI.

**Scan input.** Paste targets or upload a `targets.txt` / `.csv` with the button or by drag-and-drop. This works for every mode (Recon, Bug Bounty, CMDB Livecheck). Hostnames, IPs, CIDRs and URLs are accepted. URLs are reduced to their host, `#` starts a comment, and anything else is skipped and reported. You can optionally attach a CMDB export CSV with an `fqdn`, `hostname` or `name` column. It drives CMDB matching, CMDB Livecheck and the CMDB-only Tenable scope for that scan. Without one, the scan falls back to `data/input/cmdb_export.csv`. Uploaded inputs are stored as `data/input/scan_<id>.txt` and `cmdb_<id>.csv`.

```bash
# Docker (recommended) — exposed on host port 9990
docker compose up -d --build
open http://127.0.0.1:9990

# Native — bind to loopback (see security note below)
python3 -m uvicorn dashboard.app:app --host 127.0.0.1 --port 8443
open http://127.0.0.1:8443
```

> **Security — the dashboard exposes destructive endpoints** (launching scans
> against arbitrary targets, deleting archived scans, importing database files),
> so protect the port. Two layers, use at least one:
>
> 1. **Bind to loopback** — the default `docker compose` mapping is `127.0.0.1`
>    only, and the native default is `--host 127.0.0.1`. Keep it there unless you
>    need remote access.
> 2. **Shared-secret token** — set `DASHBOARD_TOKEN` and every `/api/` request
>    must send it in the `X-EASM-Token` header. The UI prompts for the token on
>    load and keeps it in `sessionStorage`. When `DASHBOARD_TOKEN` is unset, auth
>    is off (fine behind a loopback bind).
>
> ```bash
> # Docker: export the token, then bring the stack up
> export DASHBOARD_TOKEN="$(openssl rand -hex 32)"
> docker compose up -d --build
>
> # Native
> DASHBOARD_TOKEN="$(openssl rand -hex 32)" \
>   python3 -m uvicorn dashboard.app:app --host 127.0.0.1 --port 8443
> ```
>
> If you expose the port beyond loopback (e.g. bind `0.0.0.0` or change the
> compose mapping), **always** set `DASHBOARD_TOKEN`, and ideally also front it
> with a TLS-terminating reverse proxy.

### Dashboard Tabs

- **Overview**: Risk scoring, asset count, service inventory, critical findings
- **Assets**: Searchable, sortable list of discovered assets with detailed records
- **Services**: Fingerprinted services with vendor/product/version/CPE, software inventory
- **Network**: ASN distribution, IP ranges, RDNS records, ports, tech, CDN detection
- **Cloud**: Detected Azure/AWS/GCP cloud endpoints with risk ranking
- **AIMAP**: Exposed AI agent endpoints (MCP, Ollama, LangServe, Gradio, …)
- **TLS**: Certificate expiry, self-signed certs, misconfiguration flags
- **Findings**: Searchable vulnerability findings filtered by severity and source
- **Takeovers**: Subdomain takeover candidates and live-verification results
- **Bounty**: S/A/B/C/D-tiered bug-bounty target scores (bounty mode)
- **Livecheck**: CMDB scope governance results (livecheck mode)
- **Tenable Scope**: VM/WAS routing for the current scan. Shows the routing settings used (ownership enforced or not, owned ranges, CMDB-only), the VM-by-IP and WAS-by-URL split, the routing matrix, why assets were excluded, filterable target lists, and downloads of the Tenable import files
- **CMDB Gaps**: Assets missing from your configuration database
- **Scans**: Scan history, restore/import/export archived scans, and diff two scans (Compare)

Live scans stream stage progress and a debug log viewer in the browser.

### Dashboard API

| Endpoint | Description |
|----------|-------------|
| `GET /api/overview` | Asset stats, risk scores, service counts, top software |
| `GET /api/assets` / `GET /api/assets/{fqdn}` | Asset list / detailed asset record |
| `GET /api/services` / `GET /api/services/inventory` | Fingerprinted services / unique software inventory |
| `GET /api/findings` / `GET /api/findings/tags` | Security findings / available finding tags |
| `GET /api/tls` | TLS certificate issues: expiry, misconfigs, self-signed |
| `GET /api/cmdb` | Assets missing from CMDB with gap analysis |
| `GET /api/cloud` | Detected cloud endpoints (Azure/AWS/GCP) |
| `GET /api/aimap` | Exposed AI agent endpoints |
| `GET /api/takeovers` | Takeover candidates and verification status |
| `GET /api/bounty` / `GET /api/bounty/export` | Bounty scores and tiers / export |
| `GET /api/livecheck` | CMDB livecheck / scope governance results |
| `GET /api/tenable-scope` | Tenable routing overview: settings used, VM/WAS totals, category matrix, exclusion reasons |
| `GET /api/tenable-scope/list` | Paginated targets: `kind=vm_include\|vm_exclude\|vm_review\|was_standard\|was_waf\|was_api\|assets`, filters `q`, `category`, `vm`, `was`, `cmdb` |
| `GET /api/tenable-scope/export` | Import file download (`kind` as above → `.txt`), audit CSV (`kind=assets\|vm_targets`) or XLSX workbook (`kind=xlsx`) |
| `GET /api/network/ports\|tech\|cdn\|asn\|rdns` | Network intelligence breakdowns |
| `GET /api/search` | Cross-asset search |
| `POST /api/scans/new` | Launch a new scan. JSON body: `subdomains` (targets text, ≤ 20 MB), `stages`, `mode`, `root_domains`, optional `cmdb_csv` (CMDB export text). The response reports any skipped entries (`rejected_count`, `rejected_sample`) and `cmdb_rows` |
| `GET /api/scans` / `GET /api/scans/active` / `GET /api/scans/logs` | Scan history / running scan / live logs |
| `GET\|POST\|DELETE /api/scans/{scan_id}...` | Inspect, restore, delete archived scans |
| `POST /api/scans/import` / `GET /api/scans/{scan_id}/export` | Import / export scan archives |
| `GET /api/compare/{scan_a}/{scan_b}` | Diff two scans |

## Security Notes

- Set `USER_AGENT` in `config/pipeline.env` to identify your scanner
- Run from a dedicated egress IP that your SOC has allow-listed
- Brief the SOC 24h before scanning
- Treat output data at production-level classification (screenshots leak secrets)
- Set 90-day retention for raw artifacts
