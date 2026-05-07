# EASM Pipeline — External Attack Surface Management

Open-source EASM discovery and CMDB reconciliation pipeline built on the ProjectDiscovery suite.

## Architecture

```
subdomains.txt ──────────────────────────────────────→ targets.txt
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
                                                    └────┬─────┘  (top ports)
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
                                        ▼                          ▼
                            ┌────────────────────────────────────────┐
                            │   normalize.py                         │  Merge all JSONL
                            │   + CMDB reconciliation                │  + CDN detection
                            │   + schema validation                  │  1 record/FQDN
                            └────────────┬─────────────────────────┘
                                         │ assets.jsonl
                                         ▼
                                    ┌──────────┐
                                    │  DuckDB  │  + Parquet archive
                                    │ + views  │  + Dashboard API
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
| 1 | `dns` | dnsx | Resolve A/AAAA/CNAME/NS/MX, filter to live hosts |
| 2 | `asn` | pyasn | Enrich IPs with ASN, prefix, organization (offline BGP RIB) |
| 3 | `rdns` | getdns | Reverse DNS lookup on IP addresses → PTR records |
| 4 | `ports` | naabu | TCP SYN scan top-100 ports, CDN-aware |
| 5 | `http` | httpx | Full-signal probe: status, title, tech, headers, JARM, screenshot |
| 6 | `tls` | tlsx | Deep cert analysis: SANs, expiry, misconfig flags |
| 7 | `fingerprint` | nerva | Auto-detect all protocols: SSH, FTP, DB, Redis, SMB — CPE/vendor/version/OS fingerprints. Alias: `zgrab` |
| 8 | `nuclei` | nuclei | Low-noise scan: takeovers, exposed panels, misconfigs |
| 9 | `takeover` | subzy | Subdomain takeover verification |
| 10 | `normalize` | normalize.py | Merge all JSONL → unified asset record per FQDN + CDN detection |
| 11 | `load` | load_duckdb.py | Load into DuckDB with analytical views |
| 12 | `verify` | validate_schema.py | Schema validation and data integrity checks |

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
| `v_asset_summary` | One-row-per-asset overview with service_count, CDN status, ASN |
| `v_cmdb_gaps` | Assets missing from CMDB |
| `v_tls_issues` | Expired, self-signed, expiring certs |
| `v_findings` | All nuclei/subzy/nerva findings by severity |
| `v_tech_stack` | Technology detected per asset |
| `v_open_ports` | All open ports with service info |
| `v_services` | Per-port fingerprints: vendor, product, version, CPE, OS, certainty |
| `v_software_inventory` | Unique software across the estate, grouped by product/version with host count |
| `v_scan_stats` | Aggregate scan statistics including total_services |
| `v_network_overview` | IP ranges, CDN distribution, ASN summary |
| `v_asn_distribution` | Unique ASNs with organization and host count |
| `v_cdn_providers` | CDN detection results with confidence scoring |
| `v_rdns_records` | Reverse DNS mappings for infrastructure analysis |

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
├── findings[]: { source, template_id, severity, matched_at, ... }
└── cmdb: { matched_ci, match_basis[], in_cmdb, gap_type }
```

## Project Structure

```
easm-oss/
├── run.sh                       # Main pipeline orchestrator
├── Dockerfile                   # Multi-stage build with all tools
├── docker-compose.yml           # Docker Compose stack
├── requirements.txt             # Python dependencies
├── config/
│   ├── pipeline.env             # Pipeline configuration (NERVA_*, ASN_*, FINGERPRINT_BACKEND)
│   ├── resolvers.txt            # DNS resolvers
│   ├── nuclei-config.yaml       # Nuclei scanning profile
│   └── zgrab2-modules.ini       # zgrab2 module config (deprecated — kept for fallback)
├── scripts/
│   ├── normalize.py             # JSONL merger & asset normalizer + CDN detection
│   ├── load_duckdb.py           # DuckDB loader with views + archive
│   ├── run_nerva.sh             # Nerva service fingerprinting wrapper
│   ├── detect_cdn.py            # Multi-signal CDN detection (CNAME, IP, headers, ASN)
│   ├── enrich_asn.py            # Offline ASN enrichment using pyasn
│   ├── enrich_nuclei.py         # Nuclei finding aggregation and enrichment
│   ├── archive_scan.py          # Archive scan results to Parquet
│   ├── validate_schema.py       # Schema validation and data integrity checks
│   ├── cmdb_report.py           # CMDB gap analysis report
│   ├── query.py                 # Query runner with pre-built queries
│   ├── test_pipeline.py         # Synthetic data generator
│   ├── test_nerva_ingest.py     # Unit tests for Nerva ingestion
│   ├── test_pipeline_nerva.sh   # Integration test: normalize + DuckDB with mock Nerva data
│   ├── test_ip_implementation.py # IP scanning and enrichment tests
│   ├── diff_scans.sh            # Scan-to-scan diff
│   ├── cache.sh                 # Cache manager
│   └── export.sh                # Export to CSV/JSON/Parquet
├── dashboard/
│   ├── app.py                   # FastAPI dashboard with IP/ASN/RDNS endpoints
│   └── static/
│       ├── app.js               # Frontend: Services, Network Intel, CDN Detection tabs
│       └── ...                  # CSS and templates
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

Note: ASN enrichment is offline (no network requests). Reverse DNS may be subject to rate limits depending on your resolver.

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

`--stage fingerprint` and `--stage zgrab` both run Stage 5.

### Testing

```bash
# Unit tests (helpers + ingest_nerva)
python3 scripts/test_nerva_ingest.py

# Integration test (normalize → DuckDB with mock data)
bash scripts/test_pipeline_nerva.sh

# IP scanning and enrichment tests
python3 scripts/test_ip_implementation.py
```

## Schema Validation & Integrity Checks

The `verify` stage (stage 12) validates the final asset dataset against the expected schema and performs data integrity checks:

```bash
# Run schema validation
./run.sh --stage verify

# Or automatically after a full pipeline run
./run.sh
```

The validator checks:
- Required fields presence and type correctness
- Nested object structure consistency
- IP address format validity
- ASN/CIDR notation compliance
- Data completeness and mutually-dependent field validation

Validation results are logged and summarized in `logs/verify.log`.

## Dashboard

A web-based dashboard provides real-time visualization of scan results:

```bash
# Launch dashboard
python3 dashboard/app.py

# Navigate to http://localhost:8000
```

### Dashboard Features

- **Overview**: Risk scoring, asset count, service inventory, critical findings
- **Assets**: Searchable, sortable list of discovered assets with detailed records
- **Services**: Fingerprinted services with vendor/product/version/CPE, software inventory
- **Network Intelligence**: ASN distribution, IP ranges, RDNS records, infrastructure mapping
- **CDN Detection**: Provider detection with confidence scoring and signal breakdown
- **TLS Issues**: Certificate expiry, self-signed certs, misconfiguration flags
- **Findings**: Searchable vulnerability findings filtered by severity and source
- **CMDB Gaps**: Assets missing from your configuration database

### Dashboard API

| Endpoint | Description |
|----------|-------------|
| `GET /api/overview` | Asset stats, risk scores, service counts, top software |
| `GET /api/assets` | Paginated asset list with filtering and sorting |
| `GET /api/assets/{fqdn}` | Detailed asset record: DNS, network, services, TLS, findings, CMDB |
| `GET /api/services` | Fingerprinted services. Params: `service=`, `search=`, `limit=` |
| `GET /api/services/inventory` | Unique software across the estate (product/vendor/version/CPE, host count) |
| `GET /api/findings` | Security findings with severity filtering and tagging |
| `GET /api/findings/tags` | Available finding tags and summary stats |
| `GET /api/tls` | TLS certificate issues: expiry, misconfigs, self-signed |
| `GET /api/cmdb-gaps` | Assets missing from CMDB with gap analysis |
| `GET /api/network/ports` | Port distribution and open port summary |
| `GET /api/network/tech` | Technology stack distribution across assets |
| `GET /api/network/cdn` | CDN provider distribution and detection results |
| `GET /api/network/asn` | ASN distribution with organization details and IP ranges |
| `GET /api/network/rdns` | Reverse DNS records and PTR mappings |

The dashboard now features separate tabs for **Services**, **Network Intelligence** (IP/ASN/RDNS), and **CDN Detection**.

## Security Notes

- Set `USER_AGENT` in `config/pipeline.env` to identify your scanner
- Run from a dedicated egress IP that your SOC has allow-listed
- Brief the SOC 24h before scanning
- Treat output data at production-level classification (screenshots leak secrets)
- Set 90-day retention for raw artifacts
