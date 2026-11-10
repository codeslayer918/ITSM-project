#!/usr/bin/env bash
# Certificate reset after losing every certificate. New key pair generated locally.
#
#   ./scripts/recover.sh --username alice --code ABCDE-FGHJK --out clients/alice-new
#   ./scripts/recover.sh --request-link alice@example.test       (then read Mailpit)
#   ./scripts/recover.sh --magic-token <token> --out clients/alice-new
set -euo pipefail
source "$(dirname "$0")/lib.sh"

USERNAME="" CODE="" MAGIC="" EMAIL="" OUT="" LABEL="recovered-device"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --username) USERNAME="$2"; shift 2 ;;
    --code) CODE="$2"; shift 2 ;;
    --magic-token) MAGIC="$2"; shift 2 ;;
    --request-link) EMAIL="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done

if [[ -n "$EMAIL" ]]; then
  api -X POST "$PUBLIC_URL/api/recovery/magic-link" -H 'Content-Type: application/json' \
    --data "$(json_body email "$EMAIL")"
  echo
  exit 0
fi

[[ -n "$OUT" ]] || die "--out DIR is required"
[[ -f "$OUT/cert.pem" ]] && die "$OUT already contains a certificate"
new_key_and_csr "$OUT"

if [[ -n "$MAGIC" ]]; then
  api -X POST "$PUBLIC_URL/api/recovery/magic-link/complete" -H 'Content-Type: application/json' \
    --data "$(json_body token "$MAGIC" csr "@$OUT/csr.pem" label "$LABEL")" -o "$OUT/response.json"
else
  [[ -n "$USERNAME" && -n "$CODE" ]] || die "use --username U --code C, or --magic-token T"
  api -X POST "$PUBLIC_URL/api/recovery/backup-code" -H 'Content-Type: application/json' \
    --data "$(json_body username "$USERNAME" backupCode "$CODE" csr "@$OUT/csr.pem" label "$LABEL")" \
    -o "$OUT/response.json"
fi
save_issued "$OUT/response.json" "$OUT"
rm -f "$OUT/response.json"
make_p12 "$OUT" "$LABEL"
