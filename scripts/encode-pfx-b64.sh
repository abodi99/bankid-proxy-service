#!/usr/bin/env bash
# Output a single-line base64 string for BANKID_PFX_PROD / BANKID_PFX (paste into .env).
set -euo pipefail
if [ "${1:-}" = "" ]; then
  echo "Usage: $0 path/to/bankid.pfx" >&2
  echo "Then set in .env: BANKID_PFX_PROD=<paste the single line below>" >&2
  exit 1
fi
base64 -i "$1" | tr -d '\n'
echo
