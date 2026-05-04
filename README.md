# EASM Pipeline — External Attack Surface Management

Open-source EASM discovery and CMDB reconciliation pipeline built on the ProjectDiscovery suite.

## Architecture

```
subdomains.txt ──→ crt.sh enrichment ──→ targets.txt
                                            │
                                            ▼
                                      ┌──────────┐
                                      │   dnsx    │  DNS Resolution
                                      └────┬─────┘
                                           │ live_hosts.txt
                                           ▼
                                      ┌──────────┐
                                      │  naabu    │  Port Scanning (top-100)
                                      └────┬─────┘
                                           │ ports.jsonl
                                   ┌───────┴────────┐
                                   ▼                 ▼
                            ┌──────────┐      ┌──────────┐
                            │  httpx   │      │  nerva    │  Service Fingerprinting
                            │ +screen  │      │  (auto-   │  CPE · vendor · version
                            └────┬─────┘      │  detect)  │  OS hints · misconfigs
                                 │            └────┬─────┘
                            ┌────┴─────┐           │
                            │  tlsx    │           │
                            └────┬─────┘           │
                                 │                 │
                            ┌────┴─────┐           │
                            │ nuclei   │           │
                            │ (low     │           │
                            │  noise)  │           │
                            └────┬─────┘           │
                                 │                 │
                                 ▼                 ▼
                            ┌──────────────────────────┐
                            │   normalize.py            │  Merge all JSONL → 1 record/FQDN
                            │   + CMDB reconciliation   │
                            └────────────┬─────────────┘
                                         │ assets.jsonl
                                         ▼
                                    ┌──────────┐
                                    │  DuckDB  │  + Parquet archival
                                    └──────────┘
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

### 3. Run with Docker

```bash
# Build (recommended runtime: Debian Bookworm Slim)
docker compose build

# Optional: build on Ubuntu 24.04 runtime base
RUNTIME_BASE=ubuntu:24.04 docker compose build

# Full pipeline
docker compose run --rm --profile pipeline easm-pipeline

# Single stage
docker compose run --rm --profile pipeline easm-pipeline --stage dns

# Multiple stages
docker compose run --rm --profile pipeline easm-pipeline --stage dns,ports,http

# Resume from a specific stage (runs that stage and all stages after it)
docker compose run --rm --profile pipeline easm-pipeline --from tls

# Dry run (preview what would execute)
docker compose run --rm --profile pipeline easm-pipeline --dry-run
docker compose run --rm --profile pipeline easm-pipeline --dry-run --from tls
```

Notes:
- Default runtime base is `debian:bookworm-slim` (more predictable Chromium packaging in containers).
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
go install github.com/PentestPad/subzy@latest
go install github.com/praetorian-inc/nerva/cmd/nerva@latest
# optional: zgrab2 fallback (set FINGERPRINT_BACKEND=zgrab2 in pipeline.env to use)
# go install github.com/zmap/zgrab2/cmd/zgrab2@latest

# Run
chmod +x run.sh scripts/*.sh
./run.sh
./run.sh --from tls        # resume from TLS onwards
./run.sh --stage normalize # re-run normalization only
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

| Stage | Name | Tool | Purpose |
|-------|------|------|---------|
| 0 | `passive` | crt.sh | CT log enrichment — find subdomains from certificate transparency |
| 1 | `dns` | dnsx | Resolve A/AAAA/CNAME/NS/MX, filter to live hosts |
| 2 | `ports` | naabu | TCP SYN scan top-100 ports, CDN-aware |
| 3 | `http` | httpx | Full-signal probe: status, title, tech, headers, JARM, screenshot |
| 4 | `tls` | tlsx | Deep cert analysis: SANs, expiry, misconfig flags |
| 5 | `fingerprint` | nerva | Auto-detect all protocols: SSH, FTP, DB, Redis, SMB — CPE/vendor/version/OS fingerprints. Alias: `zgrab` |
| 6 | `nuclei` | nuclei | Low-noise scan: takeovers, exposed panels, misconfigs |
| 7 | `takeover` | subzy | Subdomain takeover verification |
| 8 | `normalize` | normalize.py | Merge all JSONL → unified asset record per FQDN |
| 9 | `load` | load_duckdb.py | Load into DuckDB with analytical views |

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

## Querying

```bash
# List available queries
python3 scripts/query.py --db data/output/easm.duckdb --query list

# Run a query
python3 scripts/query.py --db data/output/easm.duckdb --query stats
python3 scripts/query.py --db data/output/easm.duckdb --query shadow_it
python3 scripts/query.py --db data/output/easm.duckdb --query tls_issues
python3 scripts/query.py --db data/output/easm.duckdb --query findings_critical
python3 scripts/query.py --db data/output/easm.duckdb --query tech_summary
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
| `v_asset_summary` | One-row-per-asset overview with service_count |
| `v_cmdb_gaps` | Assets missing from CMDB |
| `v_tls_issues` | Expired, self-signed, expiring certs |
| `v_findings` | All nuclei/subzy/nerva findings by severity |
| `v_tech_stack` | Technology detected per asset |
| `v_open_ports` | All open ports with service info |
| `v_services` | Per-port fingerprints: vendor, product, version, CPE, OS, certainty |
| `v_software_inventory` | Unique software across the estate, grouped by product/version with host count |
| `v_scan_stats` | Aggregate scan statistics including total_services |

## Data Model

Each asset record (keyed by FQDN) contains:

```
fqdn, scan_id, first_seen, last_seen, source[], tags[]
├── dns: { a[], aaaa[], cname_chain[], ns[], mx[], txt[], wildcard }
├── network: { asn: {number, org, country}, cdn, open_ports[] }
├── web[]: { port, url, status_code, title, tech[], screenshot_path, ... }
├── tls[]: { port, version, issuer, sans[], days_to_expiry, expired, ... }
├── services[]: { port, protocol, transport, service, status, banner,
│               fingerprint: { vendor, product, version, cpe23,
│                              os_vendor, os_product, os_version,
│                              certainty, source } }
├── findings[]: { source, template_id, severity, matched_at, ... }
└── cmdb: { matched_ci, match_basis[], in_cmdb, gap_type }
```

## Project Structure

```
easm-oss/
├── run.sh                    # Main pipeline orchestrator
├── Dockerfile                # Multi-stage build with all tools
├── docker-compose.yml        # Docker Compose stack
├── requirements.txt          # Python dependencies
├── config/
│   ├── pipeline.env          # Pipeline configuration (NERVA_* and FINGERPRINT_BACKEND)
│   ├── resolvers.txt         # DNS resolvers
│   ├── nuclei-config.yaml    # Nuclei scanning profile
│   └── zgrab2-modules.ini    # zgrab2 module config (deprecated — kept for fallback)
├── scripts/
│   ├── normalize.py          # JSONL merger & asset normalizer
│   ├── load_duckdb.py        # DuckDB loader with views
│   ├── run_nerva.sh          # Nerva service fingerprinting wrapper
│   ├── cmdb_report.py        # CMDB gap analysis report
│   ├── query.py              # Query runner with pre-built queries
│   ├── test_pipeline.py      # Synthetic data generator
│   ├── test_nerva_ingest.py  # Unit tests for Nerva ingestion
│   ├── test_pipeline_nerva.sh # Integration test: normalize + DuckDB with mock Nerva data
│   ├── ct_enrich.sh          # Standalone CT log enrichment
│   ├── diff_scans.sh         # Scan-to-scan diff
│   ├── cache.sh              # Cache manager
│   └── export.sh             # Export to CSV/JSON/Parquet
├── data/
│   ├── input/
│   │   ├── subdomains.txt    # Your subdomain list
│   │   └── cmdb_export.csv   # CMDB export
│   ├── output/               # Pipeline outputs (JSONL, DuckDB)
│   ├── screenshots/          # httpx screenshots
│   └── cache/                # Stage output cache
└── logs/                     # Scan logs
```

## Request Budget

Per live asset, the pipeline makes approximately:
- DNS: 1–3 queries
- Port scan: top-100 SYN packets (2 if behind CDN)
- HTTP: 2–3 requests (+ sub-resources for screenshot)
- TLS: 1 connection per TLS port
- Nerva: 1 TCP/UDP connection per open port (concurrent, auto-detects protocol)
- Nuclei: 5–20 requests (rate-limited to 50 rps total)

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

`--stage fingerprint` and `--stage zgrab` both run Stage 5.

### Testing

```bash
# Unit tests (helpers + ingest_nerva)
python3 scripts/test_nerva_ingest.py

# Integration test (normalize → DuckDB with mock data)
bash scripts/test_pipeline_nerva.sh
```

### Dashboard API

| Endpoint | Description |
|----------|-------------|
| `GET /api/services` | Fingerprinted services. Params: `service=`, `search=`, `limit=` |
| `GET /api/services/inventory` | Unique software across the estate (product/vendor/version/CPE, host count) |
| `GET /api/overview` | Now includes `total_services`, `assets_with_services`, `top_software` |

The dashboard **Services** tab surfaces these endpoints with filter pills, search, and a software inventory table.

## Security Notes

- Set `USER_AGENT` in `config/pipeline.env` to identify your scanner
- Run from a dedicated egress IP that your SOC has allow-listed
- Brief the SOC 24h before scanning
- Treat output data at production-level classification (screenshots leak secrets)
- Set 90-day retention for raw artifacts
