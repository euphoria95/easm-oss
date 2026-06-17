# EASM Pipeline — External Attack Surface Management

Open-source EASM discovery and CMDB reconciliation pipeline built on the ProjectDiscovery suite.

## Architecture

```
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
                            │   + CMDB reconciliation                │  + CDN detection
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

# Set root domains for CT enrichment
# Edit ROOT_DOMAINS in config/pipeline.env
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

# Run pipeline from CLI (without the dashboard)
docker compose --profile cli run --rm easm-pipeline
docker compose --profile cli run --rm easm-pipeline --stage dns,ports,http
docker compose --profile cli run --rm easm-pipeline --from tls
docker compose --profile cli run --rm easm-pipeline --dry-run
```

</details>

Notes:
- Default runtime base is `debian:bookworm-slim` (works on both x86_64 and arm64).
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

Stage order: `dns,asn,rdns,ports,http,tls,fingerprint,nuclei,cloud_enum,aimap,normalize,load,verify`

| Stage | Name | Tool | Purpose |
|-------|------|------|---------|
| 1 | `dns` | dnsx | Resolve A/AAAA/CNAME/NS/MX/TXT, filter to live hosts |
| 2 | `asn` | pyasn | Enrich IPs with ASN, prefix, organization (offline BGP RIB) |
| 3 | `rdns` | getdns | Reverse DNS lookup on IP addresses → PTR records |
| 4 | `ports` | naabu | TCP SYN scan top-100 ports, CDN-aware |
| 5 | `http` | httpx | Full-signal probe: status, title, tech, headers, JARM, screenshot |
| 6 | `tls` | tlsx | Deep cert analysis: SANs, expiry, misconfig flags |
| 7 | `fingerprint` | nerva | Auto-detect all protocols: SSH, FTP, DB, Redis, SMB — CPE/vendor/version/OS fingerprints. Alias: `zgrab` |
| 8 | `nuclei` | nuclei | Low-noise scan: takeovers, exposed panels, misconfigs |
| 9 | `cloud_enum` | cloud_enum.py | Detect Azure/AWS/GCP cloud endpoints (storage, web apps, DBs, CDN) from DNS/HTTP/TLS data |
| 10 | `aimap` | run_aimap.py | Discover exposed AI agent endpoints (MCP, Ollama, LangServe, Gradio, ComfyUI…). Requires vendored `aimap/` tool |
| 11 | `normalize` | normalize.py | Merge all JSONL → unified asset record per FQDN + CDN detection |
| 12 | `load` | load_duckdb.py | Load into DuckDB with analytical views + Parquet archive |
| 13 | `verify` | verify_takeovers.py | Live DNS + HTTP fingerprint verification of takeover candidates |

`cloud_enum` and `aimap` are best-effort enrichment stages — they are skipped (non-fatal) if no inputs or the `aimap` tool is unavailable.

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
| `recon` | _(default)_ | Full pipeline with conservative, low-noise settings. Ends with takeover verification. |
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

## Querying

```bash
# List available queries
python3 scripts/query.py --db data/output/easm.duckdb --query list

# Run a query (keys: stats, gaps, shadow_it, tls_issues, tls_expiring,
#   findings, findings_critical, tech, tech_summary, ports, port_heatmap,
#   cdn_distribution, asn_distribution, favicon_clusters, takeovers,
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
| `v_asset_summary` | One-row-per-asset overview with service_count, CDN status, ASN |
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

## Data Model

Each asset record (keyed by FQDN) contains:

```
fqdn, scan_id, first_seen, last_seen, source[], tags[]
├── dns: { a[], aaaa[], cname_chain[], ns[], mx[], txt[], wildcard }
├── network: { 
│   asn: { number, prefix, org },
│   cdn: { provider, confidence, signals[] },
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
│   ├── pipeline.env             # Pipeline configuration (PIPELINE_MODE, NERVA_*, ASN_*, LIVECHECK_*)
│   ├── resolvers.txt            # DNS resolvers
│   ├── nuclei-config.yaml       # Nuclei scanning profile (recon mode)
│   ├── nuclei-bounty.yaml       # Expanded Nuclei profile (bounty mode)
│   ├── nuclei-templates/        # Custom local Nuclei templates (e.g. cloud)
│   └── zgrab2-modules.ini       # zgrab2 module config (deprecated — kept for fallback)
├── scripts/
│   ├── normalize.py             # JSONL merger & asset normalizer + CDN detection
│   ├── load_duckdb.py           # DuckDB loader with views + archive
│   ├── run_nerva.sh             # Nerva service fingerprinting wrapper
│   ├── detect_cdn.py            # Multi-signal CDN detection (CNAME, IP, headers, ASN)
│   ├── enrich_asn.py            # Offline ASN enrichment using pyasn
│   ├── enrich_nuclei.py         # Nuclei finding aggregation and enrichment
│   ├── cloud_enum.py            # Azure/AWS/GCP cloud endpoint enumeration
│   ├── run_aimap.py             # Exposed AI-agent endpoint discovery stage
│   ├── verify_takeovers.py      # Live verification of subdomain takeover candidates
│   ├── score_bounty.py          # Bug-bounty priority scoring engine (S/A/B/C/D)
│   ├── livecheck.py             # CMDB DNS-liveness / scope governance analysis
│   ├── cmdb_scope_export.py     # Tenable include/exclude scope file exporter
│   ├── archive_scan.py          # Archive scan results to Parquet
│   ├── validate_schema.py       # Schema validation and data integrity checks
│   ├── cmdb_report.py           # CMDB gap analysis report
│   ├── query.py                 # Query runner with pre-built queries
│   ├── test_pipeline.py         # Synthetic data generator
│   ├── test_nerva_ingest.py     # Unit tests for Nerva ingestion
│   ├── test_pipeline_nerva.sh   # Integration test: normalize + DuckDB with mock Nerva data
│   ├── test_ip_implementation.py # IP scanning and enrichment tests
│   ├── test_livecheck.py        # Livecheck unit tests
│   ├── test_verify_takeovers.py # Takeover verification unit tests
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
- DNS: 1–3 queries
- ASN: 1 lookup (offline — BGP RIB database)
- Reverse DNS: 1 lookup per IP (PTR query)
- Port scan: top-100 SYN packets (2 if behind CDN)
- HTTP: 2–3 requests (+ sub-resources for screenshot)
- TLS: 1 connection per TLS port
- Nerva: 1 TCP/UDP connection per open port (concurrent, auto-detects protocol)
- Nuclei: 5–20 requests (rate-limited to 50 rps total)
- Cloud enum: 0 network requests (pattern-matches existing DNS/HTTP/TLS data)
- AIMAP: a handful of HTTP probes per web target (only when the stage runs)

Note: ASN enrichment and cloud enumeration are offline (no network requests). Reverse DNS may be subject to rate limits depending on your resolver.

## IP Address Scanning & Enrichment

Stages 2–3 (ASN and RDNS) enrich discovered IP addresses with network intelligence:
- **ASN Enrichment** (stage 2): Maps IPs to Autonomous System Numbers, prefixes, and organizations using offline BGP RIB data
- **Reverse DNS** (stage 3): Performs PTR lookups on discovered IPs for hostname inference and infrastructure mapping
- **CDN Detection**: Multi-signal detection during normalization (CNAME patterns, IP ranges, HTTP headers, ASN membership)

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

```bash
# Docker (recommended) — exposed on host port 9990
docker compose up -d --build
open http://127.0.0.1:9990

# Native — served on port 8443
python3 -m uvicorn dashboard.app:app --host 0.0.0.0 --port 8443
open http://127.0.0.1:8443
```

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
| `GET /api/network/ports\|tech\|cdn\|asn\|rdns` | Network intelligence breakdowns |
| `GET /api/search` | Cross-asset search |
| `POST /api/scans/new` | Launch a new scan (targets, stages, mode) |
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
