#!/usr/bin/env python3
"""
EASM Pipeline — Asset Schema Validator

Validates that a DuckDB connection or Parquet file contains the
minimum required columns for the EASM dashboard to function.

Usage (standalone):
    python3 validate_schema.py --db path/to/easm.duckdb
    python3 validate_schema.py --parquet path/to/assets.parquet
"""

import argparse
import sys

REQUIRED_COLUMNS = {
    "fqdn",
    "scan_id",
    "dns",
    "network",
    "tls",
    "findings",
    "services",
    "web",
    "cmdb",
}

PARQUET_MAGIC = b"PAR1"


def is_parquet(data: bytes) -> bool:
    """Return True if the first 4 bytes are the Parquet magic number."""
    return data[:4] == PARQUET_MAGIC


def validate_assets_schema(con) -> list[str]:
    """Return a list of missing required columns (empty list = valid)."""
    try:
        result = con.execute("DESCRIBE assets").fetchall()
        present = {row[0].lower() for row in result}
    except Exception as exc:
        return [f"Could not describe assets table: {exc}"]

    return [col for col in REQUIRED_COLUMNS if col not in present]


def main():
    parser = argparse.ArgumentParser(description="Validate EASM asset schema")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--db", help="DuckDB database path")
    group.add_argument("--parquet", help="Parquet file path")
    args = parser.parse_args()

    import duckdb

    if args.db:
        con = duckdb.connect(args.db, read_only=True)
        missing = validate_assets_schema(con)
        con.close()
    else:
        con = duckdb.connect(":memory:")
        con.execute(f"CREATE TABLE assets AS SELECT * FROM read_parquet('{args.parquet}')")
        missing = validate_assets_schema(con)
        con.close()

    if missing:
        print(f"INVALID — missing columns: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    print("OK — schema valid", file=sys.stderr)


if __name__ == "__main__":
    main()
