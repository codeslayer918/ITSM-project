#!/usr/bin/env bash
# Offline ceremony: re-signs the Root CA CRL (it covers the intermediate CAs).
# nginx checks CRLs for the whole chain, so an expired root CRL makes every
# client certificate fail ("CRL has expired") -> fail-closed.
#
# Optional: pass "users" or "servers" to revoke that intermediate CA first
# (the "revoke a whole CA" variant of group revocation).
set -euo pipefail

cd "$(dirname "$0")"
OUT="$PWD/out"
CONF="$PWD/conf/ca.cnf"
ROOT="$OUT/root-ca"

if [[ "${1:-}" == "users" || "${1:-}" == "servers" ]]; then
  if [[ "$1" == "users" ]]; then ca_dir="$OUT/users-ca"; else ca_dir="$OUT/server-ca"; fi
  echo "[pki] Revoking intermediate CA $ca_dir/ca.crt"
  CA_DIR="$ROOT" openssl ca -config "$CONF" -revoke "$ca_dir/ca.crt" \
    -crl_reason cACompromise -passin "file:$ROOT/private/ca.pass"
fi

CA_DIR="$ROOT" openssl ca -config "$CONF" -gencrl -crldays 365 \
  -passin "file:$ROOT/private/ca.pass" -out "$ROOT/ca.crl.pem"
chmod 644 "$ROOT/ca.crl.pem"
openssl crl -in "$ROOT/ca.crl.pem" -noout -text | sed -n '1,20p'
echo "[pki] Root CRL renewed. Restart the backend so it republishes the CRL bundle:"
echo "      docker compose restart backend"
