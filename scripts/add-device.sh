#!/usr/bin/env bash
# Backup method: enrol a second certificate (another device) for the same account.
# Authenticates with an existing certificate, then submits the CSR of the new device.
#
#   ./scripts/add-device.sh --from clients/alice --out clients/alice-phone --label alice-phone
set -euo pipefail
source "$(dirname "$0")/lib.sh"

FROM="" OUT="" LABEL="second-device"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from) FROM="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[[ -f "$FROM/cert.pem" && -n "$OUT" ]] || die "usage: add-device.sh --from DIR --out DIR [--label L]"
[[ -f "$OUT/cert.pem" ]] && die "$OUT already contains a certificate"

# On the real second device only key.pem/csr.pem would be generated there and the CSR copied over.
new_key_and_csr "$OUT"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT
MTLS=(--cert "$FROM/cert.pem" --key "$FROM/key.pem" -c "$JAR" -b "$JAR")

api "${MTLS[@]}" -X POST "$APP_URL/api/login" -H 'Content-Type: application/json' --data '{}' >/dev/null
api "${MTLS[@]}" -X POST "$APP_URL/api/me/certificates" -H 'Content-Type: application/json' \
  --data "$(json_body csr "@$OUT/csr.pem" label "$LABEL")" -o "$OUT/response.json"
save_issued "$OUT/response.json" "$OUT"
rm -f "$OUT/response.json"
make_p12 "$OUT" "$LABEL"
