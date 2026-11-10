#!/usr/bin/env bash
# First enrolment with an invitation token (from the admin page, the e-mail, or .env for
# the bootstrap admin). Generates the key pair locally, sends only the CSR.
#
#   ./scripts/enroll.sh --bootstrap-admin
#   ./scripts/enroll.sh --token <token> --out clients/alice --label alice-laptop
set -euo pipefail
source "$(dirname "$0")/lib.sh"

TOKEN="" OUT="" LABEL="laptop"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bootstrap-admin)
      TOKEN="$(grep '^BOOTSTRAP_ADMIN_TOKEN=' "$ROOT/.env" | cut -d= -f2-)"
      OUT="${OUT:-$ROOT/clients/admin}"; LABEL="admin-laptop"; shift ;;
    --token) TOKEN="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[[ -n "$TOKEN" && -n "$OUT" ]] || die "usage: enroll.sh (--bootstrap-admin | --token T --out DIR) [--label L]"
[[ -f "$OUT/cert.pem" ]] && die "$OUT already contains a certificate"

new_key_and_csr "$OUT"
api -X POST "$PUBLIC_URL/api/enroll" -H 'Content-Type: application/json' \
  --data "$(json_body token "$TOKEN" csr "@$OUT/csr.pem" label "$LABEL")" -o "$OUT/response.json"
save_issued "$OUT/response.json" "$OUT"
rm -f "$OUT/response.json"
make_p12 "$OUT" "$LABEL"
