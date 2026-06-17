#!/usr/bin/env python3
"""
EASM Pipeline — AIMAP AI Agent Discovery Stage

Detects exposed AI agent endpoints (MCP, Ollama, OpenAI-compatible,
LangServe, Gradio, Streamlit, ComfyUI, etc.) by:

  1. Running Nuclei with AIMAP's custom templates against discovered URLs.
  2. Performing lightweight HTTP probes for known AI endpoint paths
     (e.g. /v1/models, /api/tags, /mcp/sse) that Nuclei might miss.

Input:  httpx JSONL + web_targets.txt from the EASM pipeline
Output: aimap.jsonl in Nuclei JSONL format (consumed by normalize.py)

Usage:
    python3 scripts/run_aimap.py \
        --httpx data/output/httpx.jsonl \
        --web-targets data/output/web_targets.txt \
        --templates-dir aimap/templates \
        --output data/output/aimap.jsonl \
        --scan-id 20260520_122636
"""

import argparse
import json
import logging
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("run_aimap")

# ── Known AI endpoint paths to probe ────────────────────────────────────────
# Each entry: (path, method, match_words, protocol, description)
AI_PROBES = [
    # Ollama
    ("/api/tags", "GET", ["models", "name"], "ollama",
     "Ollama model listing"),
    ("/api/generate", "POST", ["model"], "ollama",
     "Ollama generate endpoint"),

    # OpenAI-compatible
    ("/v1/models", "GET", ['"object"', '"data"'], "openai_compat",
     "OpenAI-compatible model listing"),
    ("/v1/chat/completions", "POST", ["choices", "message"], "openai_compat",
     "OpenAI-compatible chat endpoint"),

    # MCP
    ("/mcp/sse", "GET", ["event:", "data:"], "mcp",
     "MCP Server-Sent Events transport"),

    # LangServe
    ("/docs", "GET", ["swagger", "FastAPI", "langserve"], "langserve",
     "LangServe/FastAPI docs endpoint"),
    ("/openapi.json", "GET", ["openapi", "paths"], "langserve",
     "OpenAPI schema (LangServe)"),

    # Gradio
    ("/info", "GET", ["gradio", "version"], "gradio",
     "Gradio app info endpoint"),
    ("/api/predict", "POST", ["data"], "gradio",
     "Gradio prediction endpoint"),

    # ComfyUI
    ("/system_stats", "GET", ["comfyui", "system"], "comfyui",
     "ComfyUI system stats"),
    ("/object_info", "GET", ["KSampler", "CheckpointLoader"], "comfyui",
     "ComfyUI object info"),

    # Text Generation WebUI (oobabooga)
    ("/api/v1/model", "GET", ["model_name", "result"], "textgen_webui",
     "oobabooga model info"),

    # Open WebUI
    ("/api/config", "GET", ["name", "version"], "open_webui",
     "Open WebUI config"),

    # LiteLLM
    ("/health", "GET", ["healthy", "litellm"], "openai_compat",
     "LiteLLM health check"),
]

# SSL context that skips verification (same as httpx/nuclei behavior)
_TLS_CTX = ssl.create_default_context()
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode = ssl.CERT_NONE


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl_urls(httpx_path: str) -> list[str]:
    """Extract unique base URLs from httpx JSONL output."""
    urls: set[str] = set()
    p = Path(httpx_path)
    if not p.exists():
        return []
    with open(p, "rb") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                url = rec.get("url", "")
                if url:
                    # Strip trailing path, keep scheme://host:port
                    parts = url.split("/")
                    base = "/".join(parts[:3])
                    urls.add(base)
            except (json.JSONDecodeError, ValueError):
                pass
    return sorted(urls)


def read_web_targets(targets_path: str) -> list[str]:
    """Read web_targets.txt (host:port per line) and build base URLs."""
    urls: set[str] = set()
    p = Path(targets_path)
    if not p.exists():
        return []
    with open(p) as f:
        for line in f:
            target = line.strip()
            if not target:
                continue
            # If it already has a scheme, use as-is
            if "://" in target:
                parts = target.split("/")
                urls.add("/".join(parts[:3]))
            else:
                # host:port → try both http and https
                if ":" in target:
                    host, port = target.rsplit(":", 1)
                    if port in ("443", "8443"):
                        urls.add(f"https://{target}")
                    elif port in ("80",):
                        urls.add(f"http://{target}")
                    else:
                        urls.add(f"http://{target}")
                        urls.add(f"https://{target}")
                else:
                    urls.add(f"http://{target}")
                    urls.add(f"https://{target}")
    return sorted(urls)


# ── Nuclei-based scanning ──────────────────────────────────────────────────


def run_nuclei_aimap(
    targets: list[str],
    templates_dir: str,
    output_file: str,
    timeout: int = 600,
    rate_limit: int = 100,
) -> list[dict]:
    """Run nuclei with AIMAP templates against discovered targets."""
    nuclei_bin = shutil.which("nuclei")
    if not nuclei_bin:
        # Check common Go bin paths
        for candidate in [
            Path.home() / "go" / "bin" / "nuclei",
            Path("/usr/local/go/bin/nuclei"),
        ]:
            if candidate.is_file():
                nuclei_bin = str(candidate)
                break

    if not nuclei_bin:
        logger.warning("nuclei binary not found — skipping template-based scan")
        return []

    templates_path = Path(templates_dir)
    if not templates_path.is_dir():
        logger.warning("AIMAP templates dir not found: %s", templates_dir)
        return []

    template_count = len(list(templates_path.glob("*.yaml")))
    if template_count == 0:
        logger.warning("No YAML templates found in %s", templates_dir)
        return []

    # Write targets to temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="aimap_targets_"
    ) as tf:
        for url in targets:
            tf.write(url + "\n")
        targets_file = tf.name

    cmd = [
        nuclei_bin,
        "-l", targets_file,
        "-t", str(templates_path),
        "-jsonl",
        "-o", output_file,
        "-silent",
        "-rate-limit", str(rate_limit),
        "-timeout", "10",
        "-retries", "1",
        "-no-update-templates",
    ]

    logger.info(
        "Running nuclei with %d AIMAP templates against %d targets",
        template_count, len(targets),
    )

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            logger.warning("nuclei exited with code %d: %s",
                           result.returncode, result.stderr[:500])
    except subprocess.TimeoutExpired:
        logger.warning("nuclei timed out after %ds", timeout)
    except FileNotFoundError:
        logger.warning("nuclei binary not executable")
    finally:
        Path(targets_file).unlink(missing_ok=True)

    return _parse_jsonl(output_file)


# ── Python HTTP probing ────────────────────────────────────────────────────


def probe_url(base_url: str, path: str, method: str, timeout: int = 5) -> tuple[int, str]:
    """Send a single HTTP request and return (status_code, body)."""
    url = base_url.rstrip("/") + path
    try:
        if method == "POST":
            data = b'{"input":{}}'
            req = urllib.request.Request(
                url, data=data, method="POST",
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "aimap-easm-scanner/1.0",
                },
            )
        else:
            req = urllib.request.Request(
                url, method="GET",
                headers={"User-Agent": "aimap-easm-scanner/1.0"},
            )
        with urllib.request.urlopen(req, timeout=timeout, context=_TLS_CTX) as resp:
            body = resp.read(8192).decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(4096).decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, body
    except Exception:
        return 0, ""


def probe_target(base_url: str, scan_id: str, timeout: int = 5) -> list[dict]:
    """Probe a single base URL for all known AI endpoint paths."""
    findings = []

    for path, method, match_words, protocol, description in AI_PROBES:
        status, body = probe_url(base_url, path, method, timeout)

        if status == 0:
            continue

        body_lower = body.lower()
        matched = sum(1 for w in match_words if w.lower() in body_lower)

        # Require at least half the match words to hit
        if matched < max(1, len(match_words) // 2):
            continue

        if status >= 400 and status != 403:
            continue

        # Build host/ip from URL
        no_scheme = base_url.split("://", 1)[-1]
        host_part = no_scheme.split("/")[0]
        ip = host_part.split(":")[0]
        port_str = ""
        if ":" in host_part:
            port_str = host_part.split(":")[-1]
        elif base_url.startswith("https"):
            port_str = "443"
        else:
            port_str = "80"

        finding = {
            "template-id": f"aimap-probe-{protocol}",
            "info": {
                "name": f"AIMAP: {description}",
                "author": ["aimap-easm"],
                "severity": "info" if status != 403 else "low",
                "description": description,
                "tags": [protocol, "agent", "discovery", "aimap"],
            },
            "type": "http",
            "host": base_url,
            "matched-at": base_url + path,
            "ip": ip,
            "port": port_str,
            "timestamp": now_iso(),
            "matcher-status": True,
            "matched-words": [w for w in match_words if w.lower() in body_lower],
            "curl-command": f"curl -sk {base_url}{path}",
            "scan_id": scan_id,
        }

        # Extract useful data from response
        if status == 200:
            try:
                data = json.loads(body)
                # Extract model names for OpenAI/Ollama
                if protocol in ("openai_compat", "ollama"):
                    models = []
                    if isinstance(data, dict):
                        for item in data.get("data", data.get("models", [])):
                            if isinstance(item, dict):
                                name = item.get("id") or item.get("name", "")
                                if name:
                                    models.append(name)
                    if models:
                        finding["extracted-results"] = models
            except (json.JSONDecodeError, ValueError):
                pass

        findings.append(finding)
        logger.info("  HIT %s %s → %s (%d)", method, base_url + path, protocol, status)

    return findings


def run_http_probes(
    targets: list[str],
    scan_id: str,
    workers: int = 20,
    timeout: int = 5,
) -> list[dict]:
    """Probe all targets for AI endpoints using Python HTTP requests."""
    all_findings = []

    logger.info("HTTP probing %d targets for AI endpoints (%d workers)", len(targets), workers)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(probe_target, url, scan_id, timeout): url
            for url in targets
        }
        for future in as_completed(futures):
            try:
                findings = future.result()
                all_findings.extend(findings)
            except Exception as e:
                logger.debug("Probe error for %s: %s", futures[future], e)

    return all_findings


# ── Output ──────────────────────────────────────────────────────────────────


def _parse_jsonl(path: str) -> list[dict]:
    """Parse a JSONL file."""
    findings = []
    p = Path(path)
    if not p.is_file():
        return findings
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return findings


def write_jsonl(findings: list[dict], output_path: str):
    """Write findings as JSONL."""
    with open(output_path, "w") as f:
        for finding in findings:
            f.write(json.dumps(finding, default=str) + "\n")


# ── Main ────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="AIMAP AI Agent Discovery — EASM pipeline stage"
    )
    parser.add_argument("--httpx", help="httpx JSONL output from pipeline")
    parser.add_argument("--web-targets", help="web_targets.txt from pipeline")
    parser.add_argument(
        "--templates-dir",
        default="aimap/templates",
        help="Path to AIMAP Nuclei templates (default: aimap/templates)",
    )
    parser.add_argument("--output", required=True, help="Output JSONL path")
    parser.add_argument("--scan-id", default=now_iso(), help="Scan identifier")
    parser.add_argument(
        "--workers", type=int, default=20,
        help="HTTP probe concurrency (default: 20)",
    )
    parser.add_argument(
        "--probe-timeout", type=int, default=5,
        help="Per-request timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--nuclei-timeout", type=int, default=600,
        help="Nuclei scan timeout in seconds (default: 600)",
    )
    parser.add_argument(
        "--nuclei-rate-limit", type=int, default=100,
        help="Nuclei requests per second (default: 100)",
    )
    parser.add_argument(
        "--skip-nuclei", action="store_true",
        help="Skip Nuclei template scan (Python probes only)",
    )
    parser.add_argument(
        "--skip-probes", action="store_true",
        help="Skip Python HTTP probes (Nuclei templates only)",
    )
    args = parser.parse_args()

    # Collect target URLs from all sources
    urls: set[str] = set()

    if args.httpx:
        httpx_urls = read_jsonl_urls(args.httpx)
        urls.update(httpx_urls)
        logger.info("Loaded %d base URLs from httpx", len(httpx_urls))

    if args.web_targets:
        wt_urls = read_web_targets(args.web_targets)
        urls.update(wt_urls)
        logger.info("Loaded %d base URLs from web_targets", len(wt_urls))

    targets = sorted(urls)

    if not targets:
        logger.warning("No targets — nothing to scan")
        write_jsonl([], args.output)
        return

    logger.info("Total unique targets: %d", len(targets))

    all_findings: list[dict] = []

    # Pass 1: Nuclei with AIMAP templates
    if not args.skip_nuclei:
        nuclei_output = args.output + ".nuclei_tmp"
        nuclei_findings = run_nuclei_aimap(
            targets,
            args.templates_dir,
            nuclei_output,
            timeout=args.nuclei_timeout,
            rate_limit=args.nuclei_rate_limit,
        )
        all_findings.extend(nuclei_findings)
        logger.info("Nuclei AIMAP: %d findings", len(nuclei_findings))
        Path(nuclei_output).unlink(missing_ok=True)

    # Pass 2: Python HTTP probes
    if not args.skip_probes:
        probe_findings = run_http_probes(
            targets,
            scan_id=args.scan_id,
            workers=args.workers,
            timeout=args.probe_timeout,
        )
        all_findings.extend(probe_findings)
        logger.info("HTTP probes: %d findings", len(probe_findings))

    # Deduplicate: same (host, port, protocol) keeps first occurrence
    seen: set[tuple[str, str, str]] = set()
    deduped: list[dict] = []
    for f in all_findings:
        key = (
            f.get("ip", ""),
            str(f.get("port", "")),
            f.get("template-id", ""),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    write_jsonl(deduped, args.output)
    logger.info(
        "AIMAP scan complete: %d findings written to %s (nuclei=%d, probes=%d, deduped from %d)",
        len(deduped),
        args.output,
        sum(1 for f in deduped if not f.get("template-id", "").startswith("aimap-probe-")),
        sum(1 for f in deduped if f.get("template-id", "").startswith("aimap-probe-")),
        len(all_findings),
    )


if __name__ == "__main__":
    main()
