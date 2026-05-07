#!/usr/bin/env python3
"""
EASM Pipeline — Scan Archive Manager

Archives DuckDB + Parquet snapshots with metadata for historical scan tracking.
Each archive lives under data/archives/{scan_id}/ with a metadata.json describing
the scan results at that point in time.

Usage:
    python3 archive_scan.py --db data/output/easm.duckdb --scan-id 20260429_152447
    python3 archive_scan.py --list --archive-dir data/archives
    python3 archive_scan.py --delete 20260429_152447 --archive-dir data/archives
"""

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import duckdb


ARCHIVE_DIR_DEFAULT = "data/archives"

INTERMEDIATE_FILES = [
    "targets.txt",
    "dns.jsonl",
    "live_hosts.txt",
    "ports.jsonl",
    "web_targets.txt",
    "httpx.jsonl",
    "tls.jsonl",
    "nerva.jsonl",
    "service_detection.jsonl",
    "nuclei.jsonl",
    "assets.jsonl",
    "takeover_verifications.jsonl",
    "bounty_report.jsonl",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def extract_metadata_from_db(db_path: str, scan_id: str) -> dict:
    """Read the current DuckDB and extract scan statistics for the metadata envelope."""
    con = duckdb.connect(db_path, read_only=True)
    meta = {
        "scan_id": scan_id,
        "archived_at": now_iso(),
        "status": "completed",
        "results": {},
    }

    try:
        row = con.execute("SELECT * FROM v_scan_stats LIMIT 1").fetchone()
        if row:
            cols = [d[0] for d in con.execute("SELECT * FROM v_scan_stats LIMIT 0").description]
            stats = dict(zip(cols, row))
            meta["results"] = {
                "total_assets": stats.get("total_assets", 0),
                "web_assets": stats.get("web_assets", 0),
                "tls_assets": stats.get("tls_assets", 0),
                "assets_with_findings": stats.get("assets_with_findings", 0),
                "total_findings": stats.get("total_findings", 0),
                "in_cmdb": stats.get("in_cmdb", 0),
                "not_in_cmdb": stats.get("not_in_cmdb", 0),
                "shadow_it": stats.get("shadow_it", 0),
                "stale_ci": stats.get("stale_ci", 0),
            }

        try:
            sev_rows = con.execute("""
                SELECT severity, COUNT(*) AS cnt
                FROM v_findings
                GROUP BY severity
            """).fetchall()
            meta["results"]["findings_by_severity"] = {
                sev: cnt for sev, cnt in sev_rows
            }
        except Exception:
            meta["results"]["findings_by_severity"] = {}

        try:
            tls_count = con.execute("SELECT COUNT(*) FROM v_tls_issues").fetchone()[0]
            meta["results"]["tls_issues"] = tls_count
        except Exception:
            meta["results"]["tls_issues"] = 0

    except Exception as e:
        print(f"WARN: Could not extract full stats: {e}", file=sys.stderr)
    finally:
        con.close()

    return meta


def archive_raw_files(
    output_dir: str,
    screenshot_dir: str,
    log_file: str,
    scan_id: str,
    archive_dir: str,
    status: str = "completed",
) -> None:
    """Move intermediate scan files into archives/{scan_id}/raw/ and screenshots/."""
    out = Path(output_dir)
    arch = Path(archive_dir) / scan_id
    arch.mkdir(parents=True, exist_ok=True)

    raw_dir = arch / "raw"
    raw_dir.mkdir(exist_ok=True)

    for fname in INTERMEDIATE_FILES:
        src = out / fname
        dest = raw_dir / fname
        if src.exists() and not dest.exists():
            shutil.move(str(src), str(dest))

    zgrab_src = out / "zgrab"
    if zgrab_src.exists() and any(zgrab_src.iterdir()):
        zgrab_dest = raw_dir / "zgrab"
        if not zgrab_dest.exists():
            shutil.move(str(zgrab_src), str(zgrab_dest))
    zgrab_src.mkdir(exist_ok=True)

    shots_src = Path(screenshot_dir)
    if shots_src.exists() and any(shots_src.rglob("*")):
        arch_shots = arch / "screenshots"
        if arch_shots.exists():
            shutil.rmtree(str(arch_shots))
        shutil.move(str(shots_src), str(arch_shots))
    shots_src.mkdir(parents=True, exist_ok=True)

    if log_file:
        log_src = Path(log_file)
        if log_src.exists():
            shutil.copy2(str(log_src), str(arch / "scan.log"))

    meta_path = arch / "metadata.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            meta = {"scan_id": scan_id, "results": {}}
    else:
        meta = {
            "scan_id": scan_id,
            "archived_at": now_iso(),
            "status": status,
            "results": {},
        }
    meta["raw_archived"] = True
    meta["raw_archived_at"] = now_iso()
    meta["status"] = status
    meta_path.write_text(json.dumps(meta, indent=2, default=str))

    print(f"Raw files archived: {scan_id} → {arch}", file=sys.stderr)


def archive_scan(db_path: str, scan_id: str, archive_dir: str,
                 input_file: str | None = None, notes: str = "") -> dict:
    """Archive the current scan's DuckDB + Parquet into archive_dir/{scan_id}/."""
    db = Path(db_path)
    if not db.exists():
        print("No DuckDB found — nothing to archive.", file=sys.stderr)
        return {}

    archive_root = Path(archive_dir)
    scan_dir = archive_root / scan_id
    if scan_dir.exists():
        print(f"Archive already exists: {scan_dir}", file=sys.stderr)
        return _read_metadata(scan_dir)

    scan_dir.mkdir(parents=True, exist_ok=True)

    meta = extract_metadata_from_db(str(db), scan_id)

    shutil.copy2(str(db), str(scan_dir / "easm.duckdb"))

    parquet_dir = db.parent / "parquet"
    parquet_file = parquet_dir / f"assets_{scan_id}.parquet"
    if parquet_file.exists():
        shutil.copy2(str(parquet_file), str(scan_dir / f"assets_{scan_id}.parquet"))
        meta["parquet_file"] = f"assets_{scan_id}.parquet"

    if input_file:
        inp = Path(input_file)
        if inp.exists():
            shutil.copy2(str(inp), str(scan_dir / "subdomains.txt"))
            meta["input"] = {
                "subdomain_count": sum(1 for line in open(inp) if line.strip()),
                "source_file": inp.name,
            }

    meta["notes"] = notes
    meta["db_size_bytes"] = (scan_dir / "easm.duckdb").stat().st_size

    meta_path = scan_dir / "metadata.json"
    meta_path.write_text(json.dumps(meta, indent=2, default=str))

    print(f"Archived scan {scan_id} → {scan_dir}", file=sys.stderr)
    return meta


def list_archives(archive_dir: str) -> list[dict]:
    """List all archived scans with metadata, sorted newest first."""
    archive_root = Path(archive_dir)
    if not archive_root.exists():
        return []

    archives = []
    for scan_dir in sorted(archive_root.iterdir(), reverse=True):
        if not scan_dir.is_dir():
            continue
        meta = _read_metadata(scan_dir)
        if meta:
            archives.append(meta)

    return archives


def get_archive(archive_dir: str, scan_id: str) -> dict | None:
    """Get metadata for a specific archived scan."""
    scan_dir = Path(archive_dir) / scan_id
    if not scan_dir.exists():
        return None
    return _read_metadata(scan_dir)


def delete_archive(archive_dir: str, scan_id: str) -> bool:
    """Delete an archived scan."""
    scan_dir = Path(archive_dir) / scan_id
    if not scan_dir.exists():
        return False
    shutil.rmtree(str(scan_dir))
    print(f"Deleted archive: {scan_id}", file=sys.stderr)
    return True


def restore_archive(archive_dir: str, scan_id: str, db_path: str) -> bool:
    """Restore an archived scan's DuckDB as the active database."""
    scan_dir = Path(archive_dir) / scan_id
    archived_db = scan_dir / "easm.duckdb"
    if not archived_db.exists():
        return False
    target = Path(db_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(archived_db), str(target))
    print(f"Restored scan {scan_id} → {target}", file=sys.stderr)
    return True


def _read_metadata(scan_dir: Path) -> dict | None:
    meta_path = scan_dir / "metadata.json"
    if not meta_path.exists():
        return {
            "scan_id": scan_dir.name,
            "archived_at": datetime.fromtimestamp(
                scan_dir.stat().st_mtime, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": "completed",
            "results": {},
        }
    try:
        return json.loads(meta_path.read_text())
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description="EASM Scan Archive Manager")
    parser.add_argument("--db", default="data/output/easm.duckdb", help="DuckDB path")
    parser.add_argument("--scan-id", help="Scan ID to archive")
    parser.add_argument("--archive-dir", default=ARCHIVE_DIR_DEFAULT, help="Archive root directory")
    parser.add_argument("--input-file", help="Input subdomains file to include")
    parser.add_argument("--notes", default="", help="Optional notes about this scan")
    parser.add_argument("--list", action="store_true", help="List all archived scans")
    parser.add_argument("--get", help="Get metadata for a specific scan ID")
    parser.add_argument("--delete", help="Delete a specific archived scan")
    parser.add_argument("--restore", help="Restore archived scan as active DB")
    # Raw file archiving
    parser.add_argument("--archive-raw", action="store_true",
                        help="Move intermediate scan files into the archive folder")
    parser.add_argument("--output-dir", default="data/output", help="Pipeline output directory")
    parser.add_argument("--screenshot-dir", default="data/screenshots", help="Screenshots directory")
    parser.add_argument("--log-file", default="", help="Path to scan log to copy into archive")
    parser.add_argument("--status", default="completed", choices=["completed", "partial"],
                        help="Scan status written to metadata.json")
    args = parser.parse_args()

    if args.archive_raw:
        if not args.scan_id:
            print("ERROR: --scan-id required for --archive-raw", file=sys.stderr)
            sys.exit(1)
        archive_raw_files(
            output_dir=args.output_dir,
            screenshot_dir=args.screenshot_dir,
            log_file=args.log_file,
            scan_id=args.scan_id,
            archive_dir=args.archive_dir,
            status=args.status,
        )
        return

    if args.list:
        archives = list_archives(args.archive_dir)
        if not archives:
            print("No archived scans found.")
            return
        print(f"{'Scan ID':<22} {'Archived At':<22} {'Assets':>8} {'Findings':>10} {'Status':<12}")
        print("-" * 80)
        for a in archives:
            r = a.get("results", {})
            print(
                f"{a.get('scan_id', '?'):<22} "
                f"{a.get('archived_at', '?'):<22} "
                f"{r.get('total_assets', 0):>8} "
                f"{r.get('total_findings', 0):>10} "
                f"{a.get('status', '?'):<12}"
            )
        return

    if args.get:
        meta = get_archive(args.archive_dir, args.get)
        if meta:
            print(json.dumps(meta, indent=2, default=str))
        else:
            print(f"Archive not found: {args.get}", file=sys.stderr)
            sys.exit(1)
        return

    if args.delete:
        if delete_archive(args.archive_dir, args.delete):
            print(f"Deleted: {args.delete}")
        else:
            print(f"Not found: {args.delete}", file=sys.stderr)
            sys.exit(1)
        return

    if args.restore:
        if restore_archive(args.archive_dir, args.restore, args.db):
            print(f"Restored: {args.restore}")
        else:
            print(f"Archive DB not found: {args.restore}", file=sys.stderr)
            sys.exit(1)
        return

    if not args.scan_id:
        print("ERROR: --scan-id required for archiving", file=sys.stderr)
        sys.exit(1)

    archive_scan(args.db, args.scan_id, args.archive_dir,
                 input_file=args.input_file, notes=args.notes)


if __name__ == "__main__":
    main()
