#!/usr/bin/env bash
# Security test harness: runs every negative / positive case against the running stack and
# writes the raw curl / openssl s_client output to tests/logs/ (material for the test log).
#
# Prerequisites: scripts/setup.sh, docker compose up -d, scripts/enroll.sh --bootstrap-admin
# Usage:         ./tests/security-tests.sh            (run from WSL / Linux)
#
# The backend is restarted first: rate-limit counters and sessions live in memory, so every
# run starts from the same state.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
CA=pki/out/root-ca/ca.crt
TC=pki/out/test-certs
ADMIN=clients/admin
APP=https://localhost:8443
PUB=https://localhost:9443
MAILPIT=http://localhost:8025
RUN="$(date +%H%M%S)"
WORK="clients/test-$RUN"
LOG_DIR=tests/logs
LOG="$LOG_DIR/security-test-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$LOG_DIR" "$WORK"
exec > >(tee "$LOG") 2>&1

PASS=0 FAIL=0
RESULTS=()

[[ -f "$ADMIN/cert.pem" ]] || { echo "Enrol the admin first: ./scripts/enroll.sh --bootstrap-admin"; exit 1; }

section() { printf '\n==================================================================\n%s\n==================================================================\n' "$*"; }
show()    { printf '$ %s\n' "$*"; "$@"; local rc=$?; echo; return $rc; }
pass() { PASS=$((PASS + 1)); RESULTS+=("PASS  $1"); echo ">>> PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); RESULTS+=("FAIL  $1"); echo ">>> FAIL: $1 ($2)"; }
check()     { if grep -qF -- "$3" <<<"$2"; then pass "$1"; else fail "$1" "expected '$3'"; fi; }     # name haystack needle
check_not() { if grep -qF -- "$3" <<<"$2"; then fail "$1" "unexpected '$3'"; else pass "$1"; fi; }
# curl that prints status line, the interesting headers and the JSON body.
req() { curl -sS -i --cacert "$CA" "$@" | tr -d '\r' | grep -iE '^(HTTP/|set-cookie:|retry-after:|location:)|^[{[]'; }
mtls() { local dir="$1"; shift; req --cert "$dir/cert.pem" --key "$dir/key.pem" "$@"; }
json() { python3 -c "import json,sys; print(json.load(sys.stdin)[sys.argv[1]])" "$1"; }   # json <top-level key>
J='Content-Type: application/json'

wait_crl_reload() { sleep 4; }

admin_jar="$WORK/admin.jar"
admin() { curl -sS --cacert "$CA" --cert "$ADMIN/cert.pem" --key "$ADMIN/key.pem" -b "$admin_jar" -c "$admin_jar" -H "$J" "$@"; }

# Creates a user through the admin API and enrols a certificate for it.
new_user() {   # new_user name group -> clients/test-RUN/name
  local name="$1-$RUN" group="$2"
  local token
  token=$(admin -X POST "$APP/api/admin/users" -d "{\"username\":\"$name\",\"email\":\"$name@example.test\",\"group\":\"$group\"}" | json enrollmentToken)
  P12_PASSWORD=test bash scripts/enroll.sh --token "$token" --out "$WORK/$1" --label "$1-laptop" >/dev/null
  echo "$name"
}

section "0. Preparation"
echo "Restarting the backend (resets in-memory rate limits and sessions)..."
docker compose restart backend >/dev/null 2>&1
for i in $(seq 1 60); do
  [[ "$(docker inspect -f '{{.State.Health.Status}}' itsm-mtls-backend-1 2>/dev/null)" == healthy ]] && break
  sleep 2
done
admin -X POST "$APP/api/login" -d '{}' >/dev/null
ALICE=$(new_user alice staff)
BOB=$(new_user bob interns)
CAROL=$(new_user carol interns)
REV=$(new_user revoked staff)
echo "Test users: $ALICE (staff), $BOB, $CAROL (interns), $REV (staff)"

# ---------------------------------------------------------------- required cases
section "1. No client certificate -> rejected"
out=$(show req -X POST "$APP/api/login" -H "$J" -d '{}'); echo "$out"
check "no certificate is rejected (403 client_certificate_required)" "$out" "client_certificate_required"
out=$(show bash -c "openssl s_client -connect localhost:8443 -CAfile $CA -servername localhost -brief </dev/null 2>&1 | head -12"); echo "$out"

section "2. Certificate signed by another CA (same DN as our root!) -> rejected"
out=$(show bash -c "openssl x509 -in $TC/rogue-user.crt -noout -subject -issuer"); echo "$out"
out=$(show req --cert "$TC/rogue-user.crt" --key "$TC/rogue-user.key" -X POST "$APP/api/login" -H "$J" -d '{}'); echo "$out"
check "foreign CA is rejected by nginx" "$out" "client_certificate_rejected"

section "3. Expired certificate -> rejected"
out=$(show bash -c "openssl x509 -in $TC/expired.crt -noout -subject -dates"); echo "$out"
out=$(show req --cert "$TC/expired.crt" --key "$TC/expired.key" -X POST "$APP/api/login" -H "$J" -d '{}'); echo "$out"
check "expired certificate is rejected" "$out" "certificate has expired"
out=$(show bash -c "printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' | openssl s_client -connect localhost:8443 -CAfile $CA -servername localhost -cert $TC/expired.crt -key $TC/expired.key -quiet 2>&1 | tail -3"); echo "$out"

section "4. Revoked certificate -> rejected (application list immediately, then CRL in nginx)"
out=$(show mtls "$WORK/revoked" -X POST "$APP/api/login" -H "$J" -d '{}'); echo "$out"
check "certificate accepted before revocation" "$out" "HTTP/2 200"
SERIAL=$(openssl x509 -in "$WORK/revoked/cert.pem" -noout -serial | cut -d= -f2)
out=$(show admin -i -X POST "$APP/api/admin/certificates/$SERIAL/revoke" -d '{"reason":"KEY_COMPROMISE"}'); echo "$out" | grep -E 'HTTP/|^\{'
out=$(show mtls "$WORK/revoked" -X POST "$APP/api/login" -H "$J" -d '{}'); echo "$out"
check "revoked certificate rejected by the application (before CRL reload)" "$out" "certificate_revoked"
wait_crl_reload
docker compose logs --since 30s nginx 2>/dev/null | grep crl-watch | tail -2
out=$(show bash -c "curl -sS --cacert $CA $PUB/crl/users-ca.crl | openssl crl -inform DER -noout -text | grep -A2 -E 'Serial Number: $SERIAL|CRL Number' | head -8"); echo "$out"
out=$(show mtls "$WORK/revoked" -X POST "$APP/api/login" -H "$J" -d '{}'); echo "$out"
check "revoked certificate rejected by nginx (CRL)" "$out" "certificate revoked"

section "5. Wrong EKU (emailProtection, no clientAuth) -> rejected"
out=$(show bash -c "openssl x509 -in $TC/wrong-eku.crt -noout -ext extendedKeyUsage"); echo "$out"
out=$(show req --cert "$TC/wrong-eku.crt" --key "$TC/wrong-eku.key" -X POST "$APP/api/login" -H "$J" -d '{}'); echo "$out"
check "wrong EKU rejected by nginx" "$out" "certificate purpose"
echo "--- 5b. No EKU at all: OpenSSL/nginx accept it, the backend must reject it"
out=$(show req --cert "$TC/no-eku.crt" --key "$TC/no-eku.key" -X POST "$APP/api/login" -H "$J" -d '{}'); echo "$out"
check "certificate without EKU rejected by the backend" "$out" "client_certificate_wrong_eku"

section "6. Recovery (reset) with a backup code"
CODE=$(sed -n 1p "$WORK/alice/backup-codes.txt")
mkdir -p "$WORK/alice-new"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/alice-new/key.pem" 2>/dev/null
openssl req -new -key "$WORK/alice-new/key.pem" -subj /CN=csr -out "$WORK/alice-new/csr.pem" 2>/dev/null
mtls "$WORK/alice" -c "$WORK/alice.jar" -X POST "$APP/api/login" -H "$J" -d '{}' >/dev/null
BODY=$(python3 -c "import json,sys; print(json.dumps({'username':sys.argv[1],'backupCode':sys.argv[2],'csr':open(sys.argv[3]).read(),'label':'alice-new'}))" "$ALICE" "$CODE" "$WORK/alice-new/csr.pem")
curl -sS --cacert "$CA" -X POST "$PUB/api/recovery/backup-code" -H "$J" -d "$BODY" -o "$WORK/alice-new/resp.json" -w 'HTTP %{http_code}\n'
python3 -c "import json; d=json.load(open('$WORK/alice-new/resp.json')); open('$WORK/alice-new/cert.pem','w').write(d.get('certificatePem','')); print({k: d.get(k) for k in ('serial','subject','message','error')})"
out=$(show mtls "$WORK/alice-new" -X POST "$APP/api/login" -H "$J" -d '{}'); echo "$out"
check "new certificate works after recovery" "$out" "HTTP/2 200"
out=$(show mtls "$WORK/alice" -b "$WORK/alice.jar" "$APP/api/me"); echo "$out"
check "old session invalidated after recovery" "$out" "revoked"
out=$(show curl -sS --cacert "$CA" -X POST "$PUB/api/recovery/backup-code" -H "$J" -d "$BODY"); echo "$out"
check "a backup code works only once" "$out" "invalid_credentials"
sleep 1
echo "--- notification sent to the user (Mailpit):"
curl -s "$MAILPIT/api/v1/messages?limit=5" | python3 -c "import json,sys; [print(' -', m['To'][0]['Address'], '|', m['Subject']) for m in json.load(sys.stdin)['messages'] if '$ALICE' in m['To'][0]['Address']]"

section "7. Recovery with a magic link (e-mail, single use, 15 min)"
out=$(show curl -sS -i --cacert "$CA" -X POST "$PUB/api/recovery/magic-link" -H "$J" -d "{\"email\":\"$BOB@example.test\"}"); echo "$out" | grep -E 'HTTP/|^\{'
out2=$(show curl -sS -i --cacert "$CA" -X POST "$PUB/api/recovery/magic-link" -H "$J" -d '{"email":"nobody@example.test"}'); echo "$out2" | grep -E 'HTTP/|^\{'
check "same answer whether the e-mail exists or not" "$out2" "If an account exists for this address"
sleep 2
MID=$(curl -s "$MAILPIT/api/v1/messages?limit=20" | python3 -c "import json,sys; print(next(m['ID'] for m in json.load(sys.stdin)['messages'] if m['Subject'].endswith('recovery link') and '$BOB' in m['To'][0]['Address']))")
TOKEN=$(curl -s "$MAILPIT/api/v1/message/$MID" | python3 -c "import json,sys,re; print(re.search(r'#token=([A-Za-z0-9_-]+)', json.load(sys.stdin)['Text']).group(1))")
echo "token read from Mailpit (truncated): ${TOKEN:0:8}..."
mkdir -p "$WORK/bob-new"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/bob-new/key.pem" 2>/dev/null
openssl req -new -key "$WORK/bob-new/key.pem" -subj /CN=csr -out "$WORK/bob-new/csr.pem" 2>/dev/null
BODY=$(python3 -c "import json,sys; print(json.dumps({'token':sys.argv[1],'csr':open(sys.argv[2]).read(),'label':'bob-new'}))" "$TOKEN" "$WORK/bob-new/csr.pem")
out=$(show curl -sS --cacert "$CA" -X POST "$PUB/api/recovery/magic-link/complete" -H "$J" -d "$BODY" -o "$WORK/bob-new/resp.json" -w 'HTTP %{http_code}\n'); echo "$out"
check "magic link completes the reset" "$out" "HTTP 200"
out=$(show curl -sS --cacert "$CA" -X POST "$PUB/api/recovery/magic-link/complete" -H "$J" -d "$BODY"); echo "$out"
check "magic link is single use" "$out" "invalid_token"
out=$(show curl -sS -i --cacert "$CA" -X POST "$PUB/api/recovery/magic-link" -H "$J" -d '{"email":"admin@itsm-mtls.local"}'); echo "$out" | grep -E 'HTTP/|^\{'
echo "(administrators get the same answer but no e-mail: they must use a backup code)"

section "8. Rate limiting on the reset endpoint (5 attempts / 15 min per account, 20 per IP)"
mkdir -p "$WORK/attacker"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/attacker/key.pem" 2>/dev/null
openssl req -new -key "$WORK/attacker/key.pem" -subj /CN=csr -out "$WORK/attacker/csr.pem" 2>/dev/null
BODY=$(python3 -c "import json,sys; print(json.dumps({'username':sys.argv[1],'backupCode':'AAAAA-BBBBB','csr':open(sys.argv[2]).read()}))" "$CAROL" "$WORK/attacker/csr.pem")
out=""
for i in 1 2 3 4 5 6 7; do
  line=$(curl -sS --cacert "$CA" -X POST "$PUB/api/recovery/backup-code" -H "$J" -d "$BODY" -D - -o "$WORK/attacker/body" | tr -d '\r' | grep -iE '^(HTTP/|retry-after:)' | tr '\n' ' ')
  echo "attempt $i: $line $(cat "$WORK/attacker/body")"
  out+="$line"
done
check "brute force on backup codes is throttled (429 + Retry-After)" "$out" "429"

section "9. Session id regenerated at login (session fixation)"
JAR="$WORK/alice-new.jar"
out=$(show mtls "$WORK/alice-new" -c "$JAR" -X POST "$APP/api/login" -H "$J" -d '{}'); echo "$out"
S1=$(awk '/__Host-SID/ {print $7}' "$JAR")
out=$(show mtls "$WORK/alice-new" -b "$JAR" -c "$JAR" -X POST "$APP/api/login" -H "$J" -d '{}'); echo "$out"
S2=$(awk '/__Host-SID/ {print $7}' "$JAR")
echo "session before: ${S1:0:8}...  after: ${S2:0:8}..."
if [[ -n "$S1" && "$S1" != "$S2" ]]; then pass "new session id on every login"; else fail "new session id on every login" "same id"; fi
out=$(show mtls "$WORK/alice-new" -H "Cookie: __Host-SID=$S1" "$APP/api/me"); echo "$out"
check "the previous session id is dead" "$out" "not_authenticated"
out=$(show mtls "$WORK/alice-new" -H "Cookie: __Host-SID=ATTACKERCHOSENSESSIONID0000000000" -X POST "$APP/api/login" -H "$J" -d '{}'); echo "$out"
check "a fresh session id is issued" "$out" "set-cookie: __Host-SID="
check_not "an attacker-chosen session id is not adopted" "$(grep -i '^set-cookie' <<<"$out")" "ATTACKERCHOSEN"

section "10. Cookie flags"
out=$(show bash -c "curl -sS -i --cacert $CA --cert $WORK/alice-new/cert.pem --key $WORK/alice-new/key.pem -X POST $APP/api/login -H '$J' -d '{}' | grep -i set-cookie"); echo "$out"
check "cookie is Secure" "$out" "Secure"
check "cookie is HttpOnly" "$out" "HttpOnly"
check "cookie is SameSite=Strict" "$out" "SameSite=Strict"
check "cookie uses the __Host- prefix (no Domain, Path=/)" "$out" "__Host-SID"

# ---------------------------------------------------------------- extra defences
section "11. Stolen session cookie used with another certificate (session bound to the certificate)"
mtls "$WORK/carol" -c "$WORK/carol.jar" -X POST "$APP/api/login" -H "$J" -d '{}' >/dev/null
STOLEN=$(awk '/__Host-SID/ {print $7}' "$WORK/carol.jar")
out=$(show mtls "$WORK/alice-new" -H "Cookie: __Host-SID=$STOLEN" "$APP/api/me"); echo "$out"
check "stolen cookie is useless without the matching private key" "$out" "session_certificate_mismatch"

echo "(the backend also invalidated carol's session: a cookie seen with a foreign certificate is treated as stolen)"

section "12. Administration requires role ADMIN and a certificate with OU=admins"
mtls "$WORK/carol" -c "$WORK/carol.jar" -X POST "$APP/api/login" -H "$J" -d '{}' >/dev/null
out=$(show mtls "$WORK/carol" -b "$WORK/carol.jar" "$APP/api/admin/users"); echo "$out"
check "non-admin is denied" "$out" "admin_required"

section "13. Group revocation (OU=interns)"
python3 -c "import json; d=json.load(open('$WORK/bob-new/resp.json')); open('$WORK/bob-new/cert.pem','w').write(d['certificatePem'])"
out=$(show admin "$APP/api/admin/groups"); echo "$out"
out=$(show admin -X POST "$APP/api/admin/groups/interns/revoke" -d '{"reason":"AFFILIATION_CHANGED","disableAccount":true}'); echo "$out"
check "group revoked" "$out" "revokedCertificates"
out=$(show mtls "$WORK/carol" -b "$WORK/carol.jar" "$APP/api/me"); echo "$out"
check "member session killed immediately" "$out" "revoked"
wait_crl_reload
out=$(show mtls "$WORK/bob-new" -X POST "$APP/api/login" -H "$J" -d '{}'); echo "$out"
check "member certificate rejected at TLS level" "$out" "certificate revoked"

section "14. Proxy / transport hardening"
out=$(show req -H 'X-Auth-Listener: mtls' -H 'X-SSL-Client-Verify: SUCCESS' -H "X-SSL-Client-Cert: x" "$PUB/api/me"); echo "$out"
check "spoofed certificate headers on the public listener are useless" "$out" "404"
out=$(show bash -c "curl -sS -m 3 http://localhost:8080/ 2>&1 | head -1"); echo "$out"
check "backend port is not published" "$out" "Failed to connect"
out=$(show bash -c "openssl s_client -connect localhost:8443 -tls1_2 -CAfile $CA </dev/null 2>&1 | grep -iE 'alert|error|Cipher' | head -3"); echo "$out"
check "TLS 1.2 is refused" "$out" "alert"
out=$(show bash -c "openssl s_client -connect localhost:8443 -CAfile $CA -cert $ADMIN/cert.pem -key $ADMIN/key.pem </dev/null 2>&1 | grep -E 'Protocol|Cipher is|Verification:|Acceptable client certificate CA names' -A1 | head -8"); echo "$out"
check "TLS 1.3 negotiated" "$out" "TLSv1.3"

section "15. CSRF defences on state-changing requests"
out=$(show mtls "$ADMIN" -b "$admin_jar" -X POST "$APP/api/admin/crl/publish" -H "$J" -H 'Origin: https://evil.example' -d '{}'); echo "$out"
check "foreign Origin rejected" "$out" "bad_origin"
out=$(show mtls "$ADMIN" -b "$admin_jar" -X POST "$APP/api/admin/crl/publish" -H 'Content-Type: text/plain' -d '{}'); echo "$out"
check "non-JSON body (HTML form) rejected" "$out" "unsupported_media_type"

section "16. Second device (backup authentication method)"
P12_PASSWORD=test bash scripts/add-device.sh --from "$WORK/alice-new" --out "$WORK/alice-phone" --label alice-phone
out=$(show mtls "$WORK/alice-phone" -X POST "$APP/api/login" -H "$J" -d '{}'); echo "$out"
check "second certificate logs into the same account" "$out" "\"username\":\"$ALICE\""

section "17. Audit trail (latest events)"
admin "$APP/api/admin/audit" | python3 -c "
import json,sys
for e in json.load(sys.stdin)[:25][::-1]:
    print(e['occurredAt'][:19], e['eventType'].ljust(24), e['outcome'].ljust(8), (e.get('username') or '-').ljust(18), e.get('details') or '')"

section "SUMMARY"
printf '%s\n' "${RESULTS[@]}"
echo "PASS=$PASS FAIL=$FAIL"
echo "Log written to $LOG"
[[ $FAIL -eq 0 ]]
