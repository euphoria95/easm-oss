#!/usr/bin/env python3
"""
Integration test for the subdomain takeover fix + verify_takeovers pipeline.

What this tests:
  1. normalize.py filters out subzy records where vulnerable=false
  2. load_duckdb.py's v_findings view excludes non-vulnerable subzy entries
  3. verify_takeovers.py runs against the DuckDB and produces JSONL output
     (DNS/HTTP calls are made live; synthetic domains return 'likely_fp' because
      they have no real CNAME — that is the expected result)

Usage:
    cd /path/to/easm-oss
    python3 scripts/test_verify_takeovers.py

Exit 0 = all assertions passed.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).parent.parent
SCRIPTS = REPO / "scripts"

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"

failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  [{PASS}] {label}")
    else:
        msg = f"{label}" + (f" — {detail}" if detail else "")
        print(f"  [{FAIL}] {msg}")
        failures.append(msg)


def run(cmd: list[str], cwd: Path = REPO) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="easm_test_") as tmp:
        tmp = Path(tmp)
        out = tmp / "output"
        out.mkdir()
        (tmp / "output" / "zgrab").mkdir()
        (tmp / "screenshots").mkdir()

        # ------------------------------------------------------------------ #
        # Step 1 — Generate synthetic scan data (including subzy)
        # ------------------------------------------------------------------ #
        print("\n=== Step 1: Generate synthetic data ===")
        result = run([
            sys.executable, str(SCRIPTS / "test_pipeline.py"),
            "--assets", "20",
            "--output-dir", str(out),
        ])
        print(result.stderr.strip())
        check("test_pipeline.py exited 0", result.returncode == 0, result.stderr[-300:])

        manifest_path = out / "test_manifest.json"
        check("test_manifest.json created", manifest_path.exists())
        manifest = json.loads(manifest_path.read_text())
        vulnerable_fqdns: list[str] = manifest["vulnerable_fqdns"]
        non_vulnerable_fqdns: list[str] = manifest["non_vulnerable_fqdns"]
        check("4 vulnerable FQDNs generated", len(vulnerable_fqdns) == 4,
              f"got {len(vulnerable_fqdns)}")
        check("non-vulnerable FQDNs generated", len(non_vulnerable_fqdns) > 0,
              f"got {len(non_vulnerable_fqdns)}")
        print(f"  Vulnerable:     {vulnerable_fqdns}")
        print(f"  Non-vulnerable: {non_vulnerable_fqdns}")

        # ------------------------------------------------------------------ #
        # Step 2 — Run normalizer
        # ------------------------------------------------------------------ #
        print("\n=== Step 2: Normalize ===")
        normalize_cmd = [
            sys.executable, str(SCRIPTS / "normalize.py"),
            "--dns",    str(out / "dns.jsonl"),
            "--ports",  str(out / "ports.jsonl"),
            "--http",   str(out / "httpx.jsonl"),
            "--tls",    str(out / "tls.jsonl"),
            "--nuclei", str(out / "nuclei.jsonl"),
            "--subzy",  str(out / "subzy.json"),
            "--zgrab",  str(out / "zgrab" / "zgrab_ssh.jsonl"),
            "--output", str(out / "assets.jsonl"),
            "--scan-id", "test_001",
        ]
        result = run(normalize_cmd)
        print(result.stderr.strip() or result.stdout.strip())
        check("normalize.py exited 0", result.returncode == 0, result.stderr[-300:])

        assets_path = out / "assets.jsonl"
        check("assets.jsonl created", assets_path.exists())

        # Parse assets and check subzy findings
        assets: dict[str, dict] = {}
        for line in assets_path.read_bytes().splitlines():
            rec = json.loads(line)
            assets[rec["fqdn"]] = rec

        # Vulnerable FQDNs must have a subzy finding
        for fqdn in vulnerable_fqdns:
            if fqdn not in assets:
                check(f"{fqdn} in assets", False, "asset missing")
                continue
            subzy_findings = [
                f for f in assets[fqdn].get("findings", [])
                if f.get("source") == "subzy"
            ]
            check(f"{fqdn}: has subzy finding", len(subzy_findings) == 1,
                  f"found {len(subzy_findings)}")
            if subzy_findings:
                check(f"{fqdn}: finding.vulnerable=True",
                      subzy_findings[0].get("vulnerable") is True)

        # Non-vulnerable FQDNs must NOT have any subzy finding
        for fqdn in non_vulnerable_fqdns:
            if fqdn not in assets:
                continue  # domain may not have resolved in DNS — skip
            subzy_findings = [
                f for f in assets[fqdn].get("findings", [])
                if f.get("source") == "subzy"
            ]
            check(f"{fqdn}: no subzy finding (vulnerable=False filtered)",
                  len(subzy_findings) == 0,
                  f"found {len(subzy_findings)} — FP leak!")

        # ------------------------------------------------------------------ #
        # Step 3 — Load into DuckDB
        # ------------------------------------------------------------------ #
        print("\n=== Step 3: DuckDB load ===")
        db_path = tmp / "easm.duckdb"
        result = run([
            sys.executable, str(SCRIPTS / "load_duckdb.py"),
            "--input",   str(assets_path),
            "--db",      str(db_path),
            "--scan-id", "test_001",
        ])
        print(result.stderr.strip() or result.stdout.strip())
        check("load_duckdb.py exited 0", result.returncode == 0, result.stderr[-300:])
        check("easm.duckdb created", db_path.exists())

        # Query v_findings directly
        import duckdb
        con = duckdb.connect(str(db_path), read_only=True)

        rows = con.execute("""
            SELECT fqdn, finding_source FROM v_findings
            WHERE finding_source = 'subzy'
        """).fetchall()
        found_fqdns = {r[0] for r in rows}

        for fqdn in vulnerable_fqdns:
            check(f"v_findings: {fqdn} present (vulnerable=True)",
                  fqdn in found_fqdns)

        for fqdn in non_vulnerable_fqdns:
            check(f"v_findings: {fqdn} absent (vulnerable=False)",
                  fqdn not in found_fqdns,
                  "FP leak into v_findings!")

        con.close()

        # ------------------------------------------------------------------ #
        # Step 4 — verify_takeovers.py (live DNS/HTTP against synthetic domains)
        # ------------------------------------------------------------------ #
        print("\n=== Step 4: Verify takeovers ===")
        verify_out = tmp / "takeover_verifications.jsonl"
        result = run([
            sys.executable, str(SCRIPTS / "verify_takeovers.py"),
            "--db",    str(db_path),
            "--out",   str(verify_out),
            "--delay", "0.1",
        ])
        print(result.stdout.strip())
        check("verify_takeovers.py exited 0", result.returncode == 0, result.stderr[-300:])
        check("takeover_verifications.jsonl created", verify_out.exists())

        if verify_out.exists():
            results = [json.loads(l) for l in verify_out.read_bytes().splitlines()]
            # Nuclei takeover/* findings also feed into verify — total >= vulnerable subzy count
            check(f"at least {len(vulnerable_fqdns)} verification records written",
                  len(results) >= len(vulnerable_fqdns),
                  f"expected >={len(vulnerable_fqdns)}, got {len(results)}")

            valid_statuses = {"confirmed", "likely_fp", "unverified"}
            for r in results:
                check(f"{r['fqdn']}: status is valid ({r['status']})",
                      r["status"] in valid_statuses)
                check(f"{r['fqdn']}: evidence list present",
                      len(r.get("evidence", [])) > 0)

            check("All synthetic candidates classified (confirmed or likely_fp or unverified)",
                  all(r["status"] in valid_statuses for r in results))

            print(f"\n  Status breakdown:")
            for status in sorted(valid_statuses):
                count = sum(1 for r in results if r["status"] == status)
                print(f"    {status}: {count}")

            # Check that verify_takeovers wrote back into the assets table
            con2 = duckdb.connect(str(db_path), read_only=True)
            columns = {row[0] for row in con2.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_name = 'assets'"
            ).fetchall()}
            check("assets.takeover_status column added", "takeover_status" in columns)
            check("assets.takeover_confidence column added", "takeover_confidence" in columns)
            check("assets.takeover_verified_at column added", "takeover_verified_at" in columns)

            if "takeover_status" in columns:
                updated = con2.execute("""
                    SELECT fqdn, takeover_status FROM assets
                    WHERE takeover_status IS NOT NULL
                """).fetchall()
                updated_fqdns = {r[0] for r in updated}
                for fqdn in vulnerable_fqdns:
                    check(f"assets: {fqdn} takeover_status set",
                          fqdn in updated_fqdns,
                          "status not written back to assets table")
            con2.close()

        # ------------------------------------------------------------------ #
        # Summary
        # ------------------------------------------------------------------ #
        print(f"\n{'='*50}")
        if failures:
            print(f"FAILED — {len(failures)} assertion(s):")
            for f in failures:
                print(f"  • {f}")
            sys.exit(1)
        else:
            print("ALL ASSERTIONS PASSED")
            sys.exit(0)


if __name__ == "__main__":
    main()
