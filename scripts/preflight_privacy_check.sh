#!/usr/bin/env bash
set -euo pipefail

# Scan repository source files (excluding generated outputs) for potentially profiling strings.
# Usage: bash scripts/preflight_privacy_check.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if ! command -v grep >/dev/null 2>&1; then
  echo "ERROR: grep is required"
  exit 1
fi

# Patterns that often indicate private/profiling metadata.
# Intentionally focused on high-signal markers to avoid noisy false positives.
PATTERN='(/Users/|@[A-Za-z0-9._%+-]+\.[A-Za-z]{2,}|heineken|workspaceStorage)'

EXCLUDES=(
  --exclude-dir=.git
  --exclude-dir=.venv
  --exclude-dir=venv
  --exclude-dir=.tools
  --exclude-dir=data
  --exclude-dir=oss_data
  --exclude-dir=logs
)

EXCLUDE_FILES=(
  ./scripts/preflight_privacy_check.sh
  ./easm_plan.md
)

echo "Running privacy preflight scan in ${ROOT_DIR}"

set +e
RAW_MATCHES="$(grep -RInE "${PATTERN}" . "${EXCLUDES[@]}")"
RC=$?
set -e

if [[ ${RC} -eq 0 ]]; then
  FILTERED_MATCHES="${RAW_MATCHES}"
  for file in "${EXCLUDE_FILES[@]}"; do
    FILTERED_MATCHES="$(printf '%s\n' "${FILTERED_MATCHES}" | grep -v "^${file}:" || true)"
  done

  # Allow explicit placeholder domains used in docs/examples.
  FILTERED_MATCHES="$(printf '%s\n' "${FILTERED_MATCHES}" | grep -vE '(@example\.com|@acme\.example)' || true)"

  if [[ -n "${FILTERED_MATCHES}" ]]; then
    printf '%s\n' "${FILTERED_MATCHES}"
    echo
    echo "Privacy check FAILED: potential profiling markers found."
    echo "Review the lines above and replace with neutral placeholders before publish."
    exit 2
  fi

  echo "Privacy check PASSED: only allowed placeholder matches found."
  exit 0
fi

if [[ ${RC} -eq 1 ]]; then
  echo "Privacy check PASSED: no obvious profiling markers found in source files."
  exit 0
fi

echo "Privacy check ERROR: grep returned unexpected code ${RC}."
exit ${RC}
