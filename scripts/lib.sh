#!/usr/bin/env bash
# Shared helpers for the client-side scripts (sourced, not executed).
# Run them from WSL / Linux: they need bash, openssl, curl and python3.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACERT="$ROOT/pki/out/root-ca/ca.crt"
APP_URL="${APP_URL:-https://localhost:8443}"
PUBLIC_URL="${PUBLIC_URL:-https://localhost:9443}"

die() { echo "error: $*" >&2; exit 1; }

[[ -f "$CACERT" ]] || die "Root CA certificate not found ($CACERT). Run scripts/setup.sh first."

# Generates a fresh EC P-256 key pair and a CSR in $1. The private key never leaves this machine;
# the subject of the CSR is ignored by the CA (it uses the account data).
new_key_and_csr() {
  local dir="$1"
  mkdir -p "$dir"
  (umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/key.pem" 2>/dev/null)
  openssl req -new -sha256 -key "$dir/key.pem" -subj "/CN=csr" -out "$dir/csr.pem" 2>/dev/null
}

# json_body key1 value1 key2 @file ... -> JSON object; "@path" reads the value from a file.
json_body() {
  python3 - "$@" <<'PY'
import json, sys
args = sys.argv[1:]
out = {}
for k, v in zip(args[0::2], args[1::2]):
    out[k] = open(v[1:]).read() if v.startswith("@") else v
print(json.dumps(out))
PY
}

# Saves certificatePem / chainPem / backupCodes of an issuance response into $2.
save_issued() {
  local response="$1" dir="$2"
  python3 - "$response" "$dir" <<'PY'
import json, sys, os
resp = json.load(open(sys.argv[1]))
d = sys.argv[2]
if "certificatePem" not in resp:
    print(json.dumps(resp, indent=2)); sys.exit(1)
open(os.path.join(d, "cert.pem"), "w").write(resp["certificatePem"])
open(os.path.join(d, "chain.pem"), "w").write(resp["chainPem"])
if resp.get("backupCodes"):
    with open(os.path.join(d, "backup-codes.txt"), "w") as f:
        f.write("\n".join(resp["backupCodes"]) + "\n")
print("serial  :", resp["serial"])
print("subject :", resp["subject"])
print("expires :", resp["notAfter"])
print("message :", resp["message"])
if resp.get("backupCodes"):
    print("backup codes saved to", os.path.join(d, "backup-codes.txt"))
PY
}

# Bundles key + certificate + chain into a PKCS#12 file for browser import.
make_p12() {
  local dir="$1" name="$2" pass="${P12_PASSWORD:-}"
  if [[ -z "$pass" ]]; then
    pass="$(openssl rand -hex 8)"
    (umask 077; echo "$pass" > "$dir/p12-password.txt")
  fi
  openssl pkcs12 -export -inkey "$dir/key.pem" -in "$dir/cert.pem" -certfile "$dir/chain.pem" \
    -name "$name" -out "$dir/client.p12" -passout "pass:$pass"
  if [[ -n "${P12_PASSWORD:-}" ]]; then
    echo "PKCS#12 : $dir/client.p12 (password from \$P12_PASSWORD)"
  else
    echo "PKCS#12 : $dir/client.p12 (password in $dir/p12-password.txt)"
  fi
}

# curl wrapper with the lab trust anchor; extra arguments are passed through.
api() {
  curl -sS --cacert "$CACERT" "$@"
}
