#!/usr/bin/env bash
# Builds the lab PKI with OpenSSL:
#   - an offline Root CA (EC P-384, key encrypted with AES-256)
#   - a "Users" intermediate CA that signs client certificates (used by the backend)
#   - a "Servers" intermediate CA that signs the nginx TLS certificate
#   - the root CRL (needed because nginx checks CRLs for the whole chain)
#   - the trust bundles mounted into nginx and the backend
#
# Idempotent: does nothing if pki/out/root-ca already exists.
set -euo pipefail

cd "$(dirname "$0")"
OUT="$PWD/out"
CONF="$PWD/conf/ca.cnf"
ORG="ITSM mTLS Lab"

if [[ -f "$OUT/root-ca/ca.crt" ]]; then
  echo "[pki] PKI already initialised in pki/out (delete pki/out to start over)."
  exit 0
fi

umask 077

new_ca_dir() {
  local dir="$1"
  mkdir -p "$dir/private" "$dir/newcerts"
  : > "$dir/index.txt"
  openssl rand -hex 16 > "$dir/serial"
  echo 1000 > "$dir/crlnumber"
  # Random passphrase protecting the CA private key at rest.
  openssl rand -hex 32 > "$dir/private/ca.pass"
  openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve \
    -aes-256-cbc -pass "file:$dir/private/ca.pass" \
    -out "$dir/private/ca.key.pem"
}

issue_intermediate() {
  local dir="$1" subject="$2"
  CA_DIR="$dir" openssl req -config "$CONF" -new -sha384 \
    -key "$dir/private/ca.key.pem" -passin "file:$dir/private/ca.pass" \
    -subj "$subject" -out "$dir/ca.csr"
  CA_DIR="$OUT/root-ca" openssl ca -batch -config "$CONF" \
    -extensions v3_intermediate_ca -days 1825 -notext \
    -passin "file:$OUT/root-ca/private/ca.pass" \
    -in "$dir/ca.csr" -out "$dir/ca.crt"
}

echo "[pki] Root CA"
new_ca_dir "$OUT/root-ca"
CA_DIR="$OUT/root-ca" openssl req -config "$CONF" -new -x509 -sha384 -days 3650 \
  -key "$OUT/root-ca/private/ca.key.pem" -passin "file:$OUT/root-ca/private/ca.pass" \
  -subj "/O=$ORG/CN=ITSM mTLS Root CA" -extensions v3_root_ca \
  -out "$OUT/root-ca/ca.crt"

echo "[pki] Users CA (signs client certificates)"
new_ca_dir "$OUT/users-ca"
issue_intermediate "$OUT/users-ca" "/O=$ORG/OU=Users/CN=ITSM mTLS Users CA"

echo "[pki] Servers CA (signs the nginx certificate)"
new_ca_dir "$OUT/server-ca"
issue_intermediate "$OUT/server-ca" "/O=$ORG/OU=Servers/CN=ITSM mTLS Servers CA"

echo "[pki] Root CRL (empty, valid 365 days, re-sign with renew-root-crl.sh)"
CA_DIR="$OUT/root-ca" openssl ca -config "$CONF" -gencrl -crldays 365 \
  -passin "file:$OUT/root-ca/private/ca.pass" -out "$OUT/root-ca/ca.crl.pem"

echo "[pki] nginx server certificate for localhost"
mkdir -p "$OUT/server"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OUT/server/server.key"
CA_DIR="$OUT/server-ca" openssl req -config "$CONF" -new -sha256 \
  -key "$OUT/server/server.key" -subj "/O=$ORG/CN=localhost" -out "$OUT/server/server.csr"
CA_DIR="$OUT/server-ca" openssl ca -batch -config "$CONF" \
  -extensions server_cert -days 397 -notext \
  -passin "file:$OUT/server-ca/private/ca.pass" \
  -in "$OUT/server/server.csr" -out "$OUT/server/server.crt"
cat "$OUT/server/server.crt" "$OUT/server-ca/ca.crt" > "$OUT/server/server-fullchain.crt"

echo "[pki] Trust bundles"
mkdir -p "$OUT/nginx"
# CAs nginx accepts for *client* certificates: only the Users CA chain.
cat "$OUT/users-ca/ca.crt" "$OUT/root-ca/ca.crt" > "$OUT/nginx/client-trust.pem"
# Chain handed to users together with their certificate (for the PKCS#12 bundle).
cat "$OUT/users-ca/ca.crt" "$OUT/root-ca/ca.crt" > "$OUT/users-ca/chain.pem"

# Files read by containers must be readable by their (non-root) users.
chmod 644 "$OUT"/*/ca.crt "$OUT/root-ca/ca.crl.pem" "$OUT/server/"*.crt \
  "$OUT/nginx/client-trust.pem" "$OUT/users-ca/chain.pem"
chmod 644 "$OUT/users-ca/private/ca.key.pem" "$OUT/users-ca/private/ca.pass" "$OUT/server/server.key"
chmod 755 "$OUT" "$OUT"/* "$OUT/users-ca/private"

echo
openssl verify -CAfile "$OUT/root-ca/ca.crt" "$OUT/users-ca/ca.crt" "$OUT/server-ca/ca.crt"
openssl verify -CAfile "$OUT/root-ca/ca.crt" -untrusted "$OUT/server-ca/ca.crt" "$OUT/server/server.crt"
echo
echo "[pki] Done. In a real deployment, move pki/out/root-ca/private to offline storage:"
echo "      the Root CA key is never mounted into any container."
