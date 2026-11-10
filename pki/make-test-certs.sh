#!/usr/bin/env bash
# Creates the certificates used by the negative tests. None of them must be
# able to open a session on the mTLS listener:
#   rogue-user   valid-looking client certificate signed by a *different* root CA
#   expired      signed by the Users CA but outside its validity period
#   wrong-eku    signed by the Users CA, EKU = emailProtection (no clientAuth)
#   no-eku       signed by the Users CA, no EKU at all (nginx accepts it,
#                the backend must reject it)
set -euo pipefail

cd "$(dirname "$0")"
OUT="$PWD/out"
CONF="$PWD/conf/ca.cnf"
T="$OUT/test-certs"
USERS_CA="$OUT/users-ca"

[[ -f "$USERS_CA/ca.crt" ]] || { echo "Run pki/init-pki.sh first." >&2; exit 1; }
if [[ -f "$T/no-eku.crt" ]]; then
  echo "[pki] Test certificates already exist in pki/out/test-certs."
  exit 0
fi
mkdir -p "$T"

leaf_key_csr() {
  local name="$1" subject="$2"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$T/$name.key"
  CA_DIR="$USERS_CA" openssl req -config "$CONF" -new -sha256 \
    -key "$T/$name.key" -subj "$subject" -out "$T/$name.csr"
}

sign_with_users_ca() {
  local name="$1" profile="$2"; shift 2
  CA_DIR="$USERS_CA" openssl ca -batch -config "$CONF" -extensions "$profile" -notext \
    -passin "file:$USERS_CA/private/ca.pass" -in "$T/$name.csr" -out "$T/$name.crt" "$@"
}

echo "[pki] Rogue root CA + client certificate (other CA)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -keyout "$T/rogue-ca.key" -out "$T/rogue-ca.crt" \
  -subj "/O=ITSM mTLS Lab/CN=ITSM mTLS Root CA" \
  -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign"
leaf_key_csr rogue-user "/O=ITSM mTLS Lab/OU=admins/CN=admin"
openssl x509 -req -in "$T/rogue-user.csr" -CA "$T/rogue-ca.crt" -CAkey "$T/rogue-ca.key" \
  -CAcreateserial -days 90 -sha256 -out "$T/rogue-user.crt" \
  -extfile <(printf "basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n")

echo "[pki] Expired client certificate"
leaf_key_csr expired "/O=ITSM mTLS Lab/OU=staff/CN=expired-user"
sign_with_users_ca expired client_cert -startdate 20250101000000Z -enddate 20250201000000Z

echo "[pki] Client certificate with the wrong EKU (emailProtection)"
leaf_key_csr wrong-eku "/O=ITSM mTLS Lab/OU=staff/CN=wrong-eku-user"
sign_with_users_ca wrong-eku wrong_eku_cert -days 90

echo "[pki] Client certificate without any EKU"
leaf_key_csr no-eku "/O=ITSM mTLS Lab/OU=staff/CN=no-eku-user"
sign_with_users_ca no-eku no_eku_cert -days 90

rm -f "$T"/*.csr
chmod 644 "$T"/*
echo "[pki] Test certificates written to pki/out/test-certs"
