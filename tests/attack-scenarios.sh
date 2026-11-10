#!/usr/bin/env bash
# Breaker: adversarial scenarios that go beyond the required test cases. Each scenario is an
# attack from the threat model; the expected result is that the attack fails.
#
# Prerequisites: stack running, admin enrolled (./scripts/enroll.sh --bootstrap-admin).
# Usage:         ./tests/attack-scenarios.sh          (run from WSL / Linux)
# Side effects:  restarts the backend twice (in-memory rate limits / sessions, CRL restore).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
CA=pki/out/root-ca/ca.crt
ADMIN=clients/admin
APP=https://localhost:8443
PUB=https://localhost:9443
MAILPIT=http://localhost:8025
RUN="$(date +%H%M%S)"
WORK="clients/attack-$RUN"
LOG_DIR=tests/logs
LOG="$LOG_DIR/attack-scenarios-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$LOG_DIR" "$WORK"
exec > >(tee "$LOG") 2>&1
J='Content-Type: application/json'

PASS=0 FAIL=0
RESULTS=()
pass() { PASS=$((PASS + 1)); RESULTS+=("PASS  $1"); echo ">>> PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); RESULTS+=("FAIL  $1"); echo ">>> FAIL: $1 ($2)"; }
check()     { if grep -qF -- "$3" <<<"$2"; then pass "$1"; else fail "$1" "expected '$3'"; fi; }
check_not() { if grep -qF -- "$3" <<<"$2"; then fail "$1" "unexpected '$3'"; else pass "$1"; fi; }
section() { printf '\n==================================================================\n%s\n==================================================================\n' "$*"; }
show()    { printf '$ %s\n' "$*"; "$@"; echo; }
req()  { curl -sS -i --cacert "$CA" "$@" | tr -d '\r' | grep -iE '^(HTTP/|set-cookie:|retry-after:)|^[{[]'; }
mtls() { local dir="$1"; shift; req --cert "$dir/cert.pem" --key "$dir/key.pem" "$@"; }
admin_jar="$WORK/admin.jar"
admin() { curl -sS --cacert "$CA" --cert "$ADMIN/cert.pem" --key "$ADMIN/key.pem" -b "$admin_jar" -c "$admin_jar" -H "$J" "$@"; }
key_csr() {   # key_csr dir [subject] [extra openssl req args...]
  local dir="$1" subject="${2:-/CN=csr}"; shift 2 2>/dev/null || shift $#
  mkdir -p "$dir"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/key.pem" 2>/dev/null
  openssl req -new -key "$dir/key.pem" -subj "$subject" "$@" -out "$dir/csr.pem" 2>/dev/null
}
body() { python3 -c "import json,sys; a=sys.argv[1:]; print(json.dumps({k:(open(v[1:]).read() if v.startswith('@') else v) for k,v in zip(a[::2],a[1::2])}))" "$@"; }
wait_backend() {
  for _ in $(seq 1 60); do
    [[ "$(docker inspect -f '{{.State.Health.Status}}' itsm-mtls-backend-1 2>/dev/null)" == healthy ]] && return 0
    sleep 2
  done
}
new_user() {  # new_user short group -> enrolled in $WORK/short, token kept in token.txt
  local name="$1-$RUN" token
  token=$(admin -X POST "$APP/api/admin/users" -d "{\"username\":\"$name\",\"email\":\"$name@example.test\",\"group\":\"$2\"}" \
          | python3 -c "import json,sys; print(json.load(sys.stdin)['enrollmentToken'])")
  P12_PASSWORD=test bash scripts/enroll.sh --token "$token" --out "$WORK/$1" --label "$1-laptop" >/dev/null
  echo "$token" > "$WORK/$1/token.txt"
  echo "$name"
}

[[ -f "$ADMIN/cert.pem" ]] || { echo "Enrol the admin first."; exit 1; }

section "0. Preparation"
docker compose restart backend >/dev/null 2>&1; wait_backend
admin -X POST "$APP/api/login" -d '{}' >/dev/null
ERIN=$(new_user erin staff)
FRANK=$(new_user frank staff)
DAVE=$(new_user dave contractors)
echo "Users: $ERIN, $FRANK (staff), $DAVE (contractors)"

# -------------------------------------------------------------------------------------------
section "A1. Elevation: a CSR that asks for CN=admin, OU=admins and CA:true"
SUBJ="/O=ITSM mTLS Lab/OU=admins/CN=admin"
key_csr "$WORK/evil" "$SUBJ" -addext "basicConstraints=critical,CA:true" -addext "keyUsage=keyCertSign"
show bash -c "openssl req -in $WORK/evil/csr.pem -noout -subject -text | grep -E 'subject=|CA:|Certificate Sign'"
TOKEN=$(admin -X POST "$APP/api/admin/users" -d "{\"username\":\"mallory-$RUN\",\"email\":\"mallory-$RUN@example.test\",\"group\":\"staff\"}" \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['enrollmentToken'])")
curl -sS --cacert "$CA" -X POST "$PUB/api/enroll" -H "$J" -d "$(body token "$TOKEN" csr "@$WORK/evil/csr.pem")" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); open('$WORK/evil/cert.pem','w').write(d['certificatePem'])"
out=$(show bash -c "openssl x509 -in $WORK/evil/cert.pem -noout -subject -ext basicConstraints,keyUsage,extendedKeyUsage"); echo "$out"
check "the CA ignores the requested subject (CN/OU come from the account)" "$out" "CN = mallory-$RUN"
check "the CA ignores the requested CA:true" "$out" "CA:FALSE"
mtls "$WORK/evil" -c "$WORK/evil.jar" -X POST "$APP/api/login" -H "$J" -d '{}' >/dev/null
out=$(show mtls "$WORK/evil" -b "$WORK/evil.jar" "$APP/api/admin/users"); echo "$out"
check "no admin access with the forged request" "$out" "admin_required"

# -------------------------------------------------------------------------------------------
section "A2. Spoofing: inject X-SSL-Client-* / X-Proxy-Secret headers on the mTLS listener"
FAKE=$(python3 -c "import urllib.parse; print(urllib.parse.quote(open('$ADMIN/cert.pem').read(), safe=''))")
out=$(show mtls "$WORK/erin" -H "X-SSL-Client-Cert: $FAKE" -H "X-SSL-Client-Verify: SUCCESS" \
      -H "X-SSL-Client-S-DN: CN=admin,OU=admins" -H "X-Proxy-Secret: guess" -H "X-Real-IP: 10.6.6.6" \
      -X POST "$APP/api/login" -H "$J" -d '{}'); echo "${out:0:300}..."; echo "$out" | tail -1
check "nginx overwrites the injected headers: still logged in as erin" "$out" "\"username\":\"$ERIN\""

# -------------------------------------------------------------------------------------------
section "A3. Bypass nginx: talk to the backend directly from inside the Docker network"
out=$(show docker compose exec -T nginx wget -S -O- \
      --header "X-Auth-Listener: mtls" --header "X-SSL-Client-Verify: SUCCESS" http://backend:8080/api/me 2>&1); echo "$out"
check "backend refuses requests without the proxy secret" "$out" "403"
out=$(show bash -c "curl -sS -m 3 http://localhost:8080/ 2>&1; docker compose port backend 8080 2>&1"); echo "$out"
check "backend port not published on the host" "$out" "Failed to connect"

# -------------------------------------------------------------------------------------------
section "A4. Replay an enrolment invitation token"
key_csr "$WORK/replay"
out=$(show curl -sS --cacert "$CA" -X POST "$PUB/api/enroll" -H "$J" \
      -d "$(body token "$(cat "$WORK/erin/token.txt")" csr "@$WORK/replay/csr.pem")"); echo "$out"
check "a used invitation token cannot be replayed" "$out" "invalid_token"

# -------------------------------------------------------------------------------------------
section "A5. Re-certify an already certified key pair (e.g. a key known to be compromised)"
mtls "$WORK/erin" -c "$WORK/erin.jar" -X POST "$APP/api/login" -H "$J" -d '{}' >/dev/null
out=$(show curl -sS --cacert "$CA" --cert "$WORK/erin/cert.pem" --key "$WORK/erin/key.pem" -b "$WORK/erin.jar" \
      -X POST "$APP/api/me/certificates" -H "$J" -d "$(body csr "@$WORK/erin/csr.pem" label reuse)"); echo "$out"
check "key reuse is refused" "$out" "key_reuse"

# -------------------------------------------------------------------------------------------
section "A6. Malformed / weak CSRs"
mkdir -p "$WORK/weak"
openssl req -new -newkey rsa:1024 -nodes -keyout "$WORK/weak/key.pem" -subj /CN=x -out "$WORK/weak/csr.pem" 2>/dev/null
out=$(show curl -sS --cacert "$CA" --cert "$WORK/erin/cert.pem" --key "$WORK/erin/key.pem" -b "$WORK/erin.jar" \
      -X POST "$APP/api/me/certificates" -H "$J" -d "$(body csr "@$WORK/weak/csr.pem")"); echo "$out"
check "RSA-1024 key refused" "$out" "2048"
key_csr "$WORK/pop"
python3 - "$WORK/pop/csr.pem" <<'PY'
import base64, sys
p = sys.argv[1]
lines = open(p).read().strip().splitlines()
der = bytearray(base64.b64decode("".join(lines[1:-1])))
der[-1] ^= 1                      # flip one bit of the signature
b64 = base64.b64encode(bytes(der)).decode()
open(p, "w").write("-----BEGIN CERTIFICATE REQUEST-----\n" + "\n".join(b64[i:i+64] for i in range(0, len(b64), 64)) + "\n-----END CERTIFICATE REQUEST-----\n")
PY
out=$(show curl -sS --cacert "$CA" --cert "$WORK/erin/cert.pem" --key "$WORK/erin/key.pem" -b "$WORK/erin.jar" \
      -X POST "$APP/api/me/certificates" -H "$J" -d "$(body csr "@$WORK/pop/csr.pem")"); echo "$out"
check "CSR without valid proof of possession refused" "$out" "proof of possession"

# -------------------------------------------------------------------------------------------
section "A7. Race condition: the same backup code sent twice in parallel"
CODE=$(sed -n 1p "$WORK/frank/backup-codes.txt")
key_csr "$WORK/race1"; key_csr "$WORK/race2"
PIDS=()
for i in 1 2; do
  curl -sS --cacert "$CA" -X POST "$PUB/api/recovery/backup-code" -H "$J" \
    -d "$(body username "$FRANK" backupCode "$CODE" csr "@$WORK/race$i/csr.pem")" \
    -o "$WORK/race$i/resp.json" -w "request $i -> HTTP %{http_code}\n" &
  PIDS+=($!)
done
wait "${PIDS[@]}"   # not a bare "wait": it would also wait for the tee of the log
out=$(cat "$WORK/race1/resp.json" "$WORK/race2/resp.json"); echo "$out" | cut -c1-160
ok=$(grep -o '"certificatePem"' <<<"$out" | wc -l)
echo "successful recoveries: $ok"
if [[ "$ok" -eq 1 ]]; then pass "a backup code is consumed exactly once under concurrency"; else fail "single-use under concurrency" "$ok successes"; fi

# -------------------------------------------------------------------------------------------
section "A8. A disabled account cannot self-recover, even with a valid backup code"
out=$(show admin -X POST "$APP/api/admin/users/$DAVE/revoke" -d '{"reason":"AFFILIATION_CHANGED","disableAccount":true}'); echo "$out"
key_csr "$WORK/dave-new"
out=$(show curl -sS --cacert "$CA" -X POST "$PUB/api/recovery/backup-code" -H "$J" \
      -d "$(body username "$DAVE" backupCode "$(sed -n 1p "$WORK/dave/backup-codes.txt")" csr "@$WORK/dave-new/csr.pem")"); echo "$out"
check "recovery refused for a disabled account (generic error)" "$out" "invalid_credentials"

# -------------------------------------------------------------------------------------------
# Budget note: all recovery calls share the per-IP limit (20 / 15 min); this script uses 18.
section "A9. Account enumeration: response time, existing vs unknown username"
key_csr "$WORK/enum"
measure() {
  local user="$1" total=0 t
  for _ in 1 2 3; do
    t=$(curl -sS --cacert "$CA" -o /dev/null -w '%{time_total}' -X POST "$PUB/api/recovery/backup-code" -H "$J" \
        -d "$(body username "$user" backupCode WRONG-CODE0 csr "@$WORK/enum/csr.pem")")
    total=$(python3 -c "print($total + $t)")
  done
  python3 -c "print(round($total / 3 * 1000))"
}
T_EXIST=$(measure "$ERIN")
T_UNKNOWN=$(measure "nobody-$RUN")
echo "mean response time: existing user = ${T_EXIST} ms, unknown user = ${T_UNKNOWN} ms"
DIFF=$(python3 -c "a,b=$T_EXIST,$T_UNKNOWN; print(abs(a-b) / max(a,b) * 100)")
echo "relative difference: ${DIFF%.*} %"
if python3 -c "import sys; sys.exit(0 if $DIFF < 25 else 1)"; then pass "no exploitable timing difference (< 25 %)"; else fail "timing difference" "${DIFF}%"; fi
out=$(curl -sS --cacert "$CA" -X POST "$PUB/api/recovery/backup-code" -H "$J" -d "$(body username "nobody2-$RUN" backupCode X csr "@$WORK/enum/csr.pem")")
echo "unknown user answer : $out"
check "same error message for unknown users" "$out" "Invalid username or backup code."
echo "--- A9b. same question on the magic-link endpoint (finding F2, fixed with MagicLinkWorker)"
for i in 1 2 3; do
  admin -X POST "$APP/api/admin/users" -d "{\"username\":\"probe$i-$RUN\",\"email\":\"probe$i-$RUN@example.test\",\"group\":\"staff\"}" >/dev/null
done
curl -sS --cacert "$CA" -o /dev/null -X POST "$PUB/api/recovery/magic-link" -H "$J" -d '{"email":"warmup@example.test"}'
TE=0; TU=0
for i in 1 2 3; do
  e=$(curl -sS --cacert "$CA" -o /dev/null -w '%{time_total}' -X POST "$PUB/api/recovery/magic-link" -H "$J" -d "{\"email\":\"probe$i-$RUN@example.test\"}")
  u=$(curl -sS --cacert "$CA" -o /dev/null -w '%{time_total}' -X POST "$PUB/api/recovery/magic-link" -H "$J" -d "{\"email\":\"ghost$i-$RUN@example.test\"}")
  echo "existing=${e}s unknown=${u}s"
  TE=$(python3 -c "print($TE + $e)"); TU=$(python3 -c "print($TU + $u)")
done
echo "mean: existing=$(python3 -c "print(round($TE/3*1000))") ms unknown=$(python3 -c "print(round($TU/3*1000))") ms"
if python3 -c "import sys; a,b=$TE,$TU; sys.exit(0 if abs(a-b) < 0.02*3 else 1)"; then
  pass "magic-link answers in the same time for existing and unknown e-mails (< 20 ms apart)"
else
  fail "magic-link timing" "difference above 20 ms"
fi

# -------------------------------------------------------------------------------------------
section "A10. IDOR: erin tries to revoke frank's certificate through her own endpoint"
FRANK_SERIAL=$(admin "$APP/api/admin/certificates" | python3 -c "import json,sys; print(next(c['serial'] for c in json.load(sys.stdin) if c['username']=='$FRANK' and c['status']=='ACTIVE'))")
out=$(show mtls "$WORK/erin" -b "$WORK/erin.jar" -X POST "$APP/api/me/certificates/$FRANK_SERIAL/revoke" -H "$J" -d '{}'); echo "$out"
check "cannot revoke another user's certificate" "$out" "not_found"

# -------------------------------------------------------------------------------------------
section "A11. Session termination: logout (ASVS 7.4.1) and account disabled (ASVS 7.4.2)"
JAR="$WORK/erin2.jar"
mtls "$WORK/erin" -c "$JAR" -X POST "$APP/api/login" -H "$J" -d '{}' >/dev/null
SID=$(awk '/__Host-SID/ {print $7}' "$JAR")
show mtls "$WORK/erin" -b "$JAR" -X POST "$APP/api/logout" -H "$J" -d '{}'
out=$(show mtls "$WORK/erin" -H "Cookie: __Host-SID=$SID" "$APP/api/me"); echo "$out"
check "a logged-out session id cannot be reused" "$out" "not_authenticated"
mtls "$WORK/erin" -c "$JAR" -X POST "$APP/api/login" -H "$J" -d '{}' >/dev/null
admin -X POST "$APP/api/admin/users/$ERIN/revoke" -d '{"reason":"AFFILIATION_CHANGED","disableAccount":true}' >/dev/null
out=$(show mtls "$WORK/erin" -b "$JAR" "$APP/api/me"); echo "$out"
check "disabling the account ends its active sessions" "$out" "revoked"

# -------------------------------------------------------------------------------------------
section "A12. Lock-out abuse: revoke the whole admins group"
out=$(show admin -X POST "$APP/api/admin/groups/admins/revoke" -d '{}'); echo "$out"
check "revoking every administrator at once is refused" "$out" "self_lockout"

# -------------------------------------------------------------------------------------------
section "A13. E-mail takeover of an administrator: magic link for the admin address"
BEFORE=$(curl -s "$MAILPIT/api/v1/search?query=to:admin@itsm-mtls.local%20subject:recovery" | python3 -c "import json,sys; print(json.load(sys.stdin)['messages_count'])")
out=$(show curl -sS --cacert "$CA" -X POST "$PUB/api/recovery/magic-link" -H "$J" -d '{"email":"admin@itsm-mtls.local"}'); echo "$out"
sleep 2
AFTER=$(curl -s "$MAILPIT/api/v1/search?query=to:admin@itsm-mtls.local%20subject:recovery" | python3 -c "import json,sys; print(json.load(sys.stdin)['messages_count'])")
echo "recovery e-mails to admin before=$BEFORE after=$AFTER"
if [[ "$BEFORE" == "$AFTER" ]]; then pass "no magic link is ever sent to an administrator"; else fail "admin magic link" "e-mail sent"; fi

# -------------------------------------------------------------------------------------------
section "A14. Stale CRL (DoS / tampering): nginx must fail closed"
docker compose cp backend:/var/lib/mtls/crl/crl-bundle.pem "$WORK/good-bundle.pem" >/dev/null 2>&1
CA_DIR=pki/out/users-ca openssl ca -config pki/conf/ca.cnf -gencrl -crlsec 1 \
  -passin file:pki/out/users-ca/private/ca.pass -out "$WORK/short.crl.pem" 2>/dev/null
cat pki/out/root-ca/ca.crl.pem "$WORK/short.crl.pem" > "$WORK/stale-bundle.pem"
show bash -c "openssl crl -in $WORK/short.crl.pem -noout -lastupdate -nextupdate"
sleep 2
docker compose cp "$WORK/stale-bundle.pem" backend:/var/lib/mtls/crl/crl-bundle.pem >/dev/null 2>&1
sleep 5
docker compose logs --since 20s nginx 2>/dev/null | grep crl-watch | tail -1
out=$(show mtls "$ADMIN" -X POST "$APP/api/login" -H "$J" -d '{}'); echo "$out"
check "expired CRL: every client certificate is rejected (fail closed)" "$out" "CRL has expired"
echo "--- restore: the backend republishes a fresh CRL at start-up"
docker compose restart backend >/dev/null 2>&1; wait_backend; sleep 4
out=$(show mtls "$ADMIN" -X POST "$APP/api/login" -H "$J" -d '{}'); echo "$out"
check "service restored with a fresh CRL" "$out" "HTTP/2 200"

# -------------------------------------------------------------------------------------------
section "A15. Repudiation: every attack above left a trace"
admin -X POST "$APP/api/login" -d '{}' >/dev/null
EVENTS=$(admin "$APP/api/admin/audit" | python3 -c "
import json,sys
for e in json.load(sys.stdin):
    print(e['eventType'], e['outcome'], e.get('username') or '-', e.get('details') or '')")
for ev in "ADMIN_ACCESS_DENIED" "ENROLLMENT_FAILED" "RECOVERY_FAILED" "USER_REVOKED" "BACKUP_CODE_USED" "RECOVERY_LINK_REQUESTED FAILURE admin"; do
  grep -q "$ev" <<<"$EVENTS" && pass "audit contains $ev" || fail "audit contains $ev" "missing"
done
echo "--- no secret in the logs (backup code of frank must not appear):"
if docker compose logs backend 2>/dev/null | grep -qF "$CODE"; then fail "no backup code in logs" "found"; else pass "backup codes never logged"; fi

section "SUMMARY"
printf '%s\n' "${RESULTS[@]}"
echo "PASS=$PASS FAIL=$FAIL"
echo "Log written to $LOG"
[[ $FAIL -eq 0 ]]
