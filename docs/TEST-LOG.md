# Security test log

| | |
| --- | --- |
| Date | 2026-11-09 |
| Environment | Windows 11 + WSL2 (Ubuntu), Docker 29.5 / Compose v5.1, OpenSSL 3.0.2, curl 7.81 |
| Stack | nginx 1.27.5 (TLS 1.3), Spring Boot 3.4.5 / Java 21, PostgreSQL 16, Mailpit 1.21 |
| Harnesses | `tests/security-tests.sh` (required cases, **35/35 PASS**), `tests/attack-scenarios.sh` (adversarial scenarios, **29/29 PASS**) |
| Raw logs | [`tests/logs/security-test-20261109-144514.log`](../tests/logs/security-test-20261109-144514.log), [`tests/logs/attack-scenarios-20261109-144430.log`](../tests/logs/attack-scenarios-20261109-144430.log) |
| First run (before fixing the harness) | [`tests/logs/security-test-20261109-141829.log`](../tests/logs/security-test-20261109-141829.log): 31/35, the 4 failures were mistakes in the test script (see "Findings") |

Reproduce:

```bash
./scripts/setup.sh && docker compose up -d --build && ./scripts/enroll.sh --bootstrap-admin
./tests/security-tests.sh && ./tests/attack-scenarios.sh
```

Helpers used in the commands below: `req` = `curl -sS -i --cacert pki/out/root-ca/ca.crt` (only
the status line, `Set-Cookie`, `Retry-After` and the JSON body are kept); `mtls DIR` = `req` with
`--cert DIR/cert.pem --key DIR/key.pem`. The negative-test certificates come from
`pki/make-test-certs.sh`.

---

## Part 1: required cases

### T1. No client certificate → refused

```text
$ req -X POST https://localhost:8443/api/login -H 'Content-Type: application/json' -d '{}'
HTTP/2 403
{"error":"client_certificate_required","reason":"no client certificate was sent"}

$ openssl s_client -connect localhost:8443 -CAfile pki/out/root-ca/ca.crt -servername localhost -brief
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: O = ITSM mTLS Lab, CN = localhost
Verification: OK
Server Temp Key: X25519, 253 bits
```

nginx completes the handshake, then answers 403 (`error_page 496`): no request reaches the backend.

### T2. Certificate signed by another CA → refused

The rogue root uses **exactly the same DN** as our root, and the leaf claims `OU=admins, CN=admin`.

```text
$ openssl x509 -in pki/out/test-certs/rogue-user.crt -noout -subject -issuer
subject=O = ITSM mTLS Lab, OU = admins, CN = admin
issuer=O = ITSM mTLS Lab, CN = ITSM mTLS Root CA
$ req --cert pki/out/test-certs/rogue-user.crt --key pki/out/test-certs/rogue-user.key -X POST https://localhost:8443/api/login ...
HTTP/2 403
{"error":"client_certificate_rejected","reason":"FAILED:unable to verify the first certificate"}
```

### T3. Expired certificate → refused

```text
$ openssl x509 -in pki/out/test-certs/expired.crt -noout -subject -dates
subject=O = ITSM mTLS Lab, OU = staff, CN = expired-user
notBefore=Jan  1 00:00:00 2025 GMT
notAfter=Feb  1 00:00:00 2025 GMT
$ req --cert pki/out/test-certs/expired.crt --key pki/out/test-certs/expired.key -X POST https://localhost:8443/api/login ...
HTTP/2 403
{"error":"client_certificate_rejected","reason":"FAILED:certificate has expired"}
$ printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' | openssl s_client -connect localhost:8443 -CAfile pki/out/root-ca/ca.crt \
      -cert pki/out/test-certs/expired.crt -key pki/out/test-certs/expired.key -quiet
{"error":"client_certificate_rejected","reason":"FAILED:certificate has expired"}
```

### T4. Revoked certificate → refused (application immediately, then nginx through the CRL)

```text
$ mtls clients/test-144514/revoked -X POST https://localhost:8443/api/login ...
HTTP/2 200                                   <- valid before revocation
$ (admin) POST /api/admin/certificates/2B8565CDFA2AE8768698126BEC2156A1/revoke {"reason":"KEY_COMPROMISE"}
{"message":"Certificate revoked."}
$ mtls clients/test-144514/revoked -X POST https://localhost:8443/api/login ...      <- immediately after
HTTP/2 403
{"error":"certificate_revoked","message":"This certificate has been revoked."}      <- application-level list
nginx-1  | [crl-watch] 2026-11-09T12:45:38Z CRL changed, nginx reloaded
$ curl https://localhost:9443/crl/users-ca.crl | openssl crl -inform DER -noout -text
            X509v3 CRL Number:
                36
    Serial Number: 2B8565CDFA2AE8768698126BEC2156A1
        Revocation Date: Nov  9 12:45:36 2026 GMT
$ mtls clients/test-144514/revoked -X POST https://localhost:8443/api/login ...      <- 4 s later
HTTP/2 403
{"error":"client_certificate_rejected","reason":"FAILED:certificate revoked"}       <- nginx, TLS layer
```

### T5. Wrong EKU (no clientAuth) → refused

```text
$ openssl x509 -in pki/out/test-certs/wrong-eku.crt -noout -ext extendedKeyUsage
X509v3 Extended Key Usage:
    E-mail Protection
$ req --cert pki/out/test-certs/wrong-eku.crt --key pki/out/test-certs/wrong-eku.key -X POST https://localhost:8443/api/login ...
HTTP/2 403
{"error":"client_certificate_rejected","reason":"FAILED:unsuitable certificate purpose"}
```

T5b, a certificate with **no EKU at all**: OpenSSL (and nginx) accept it, the backend rejects it.

```text
$ req --cert pki/out/test-certs/no-eku.crt --key pki/out/test-certs/no-eku.key -X POST https://localhost:8443/api/login ...
HTTP/2 403
{"error":"client_certificate_wrong_eku","message":"The client certificate is not allowed for TLS client authentication (EKU clientAuth missing)."}
```

### T8. Rate limiting on the reset endpoint

Seven wrong backup codes for the same account:

```text
attempt 1: HTTP/2 401   {"error":"invalid_credentials","message":"Invalid username or backup code."}
attempt 2: HTTP/2 401   ...
attempt 5: HTTP/2 401   {"error":"invalid_credentials","message":"Invalid username or backup code."}
attempt 6: HTTP/2 429  retry-after: 896  {"error":"rate_limited","message":"Too many attempts, try again later."}
attempt 7: HTTP/2 429  retry-after: 896  {"error":"rate_limited","message":"Too many attempts, try again later."}
```

Audit: `RECOVERY_FAILED × 5`, then `RATE_LIMITED scope=recovery-account × 2`.

### T9. Session regenerated at login

```text
$ mtls clients/test-144514/alice-new -c jar -X POST https://localhost:8443/api/login ...
set-cookie: __Host-SID=EDAB2F1A704C10CE65AEA18BE9228871; Path=/; Secure; HttpOnly; SameSite=Strict
$ mtls clients/test-144514/alice-new -b jar -c jar -X POST https://localhost:8443/api/login ...   <- sends the old cookie
set-cookie: __Host-SID=C61C30D4516D0E425067E130766D1A96; Path=/; Secure; HttpOnly; SameSite=Strict
$ mtls clients/test-144514/alice-new -H 'Cookie: __Host-SID=EDAB2F1A704C10CE65AEA18BE9228871' https://localhost:8443/api/me
HTTP/2 401
{"error":"not_authenticated","message":"No session: POST /api/login first."}             <- old id is dead
$ mtls clients/test-144514/alice-new -H 'Cookie: __Host-SID=ATTACKERCHOSENSESSIONID0000000000' -X POST .../api/login ...
set-cookie: __Host-SID=CD7CC1D6428126559328163BA95BC848; ...                              <- attacker id not adopted
```

### T10. Cookie flags

```text
$ curl ... -X POST https://localhost:8443/api/login ... | grep -i set-cookie
set-cookie: __Host-SID=0E8459D51BB4BB32A58A11F21753DDDF; Path=/; Secure; HttpOnly; SameSite=Strict
```

`Secure`, `HttpOnly`, `SameSite=Strict`, `__Host-` prefix (so `Path=/` and no `Domain`). The id
has 32 hex characters = 128 bits.

---

## Part 2: other defences (`security-tests.sh`)

| ID | Defence | Expected | Observed | Result |
| --- | --- | --- | --- | --- |
| T6 | Reset with a backup code | new cert works, old session dead, code single use, e-mail sent | `200`; new login `200`; old session `403 certificate_revoked`; reuse `401 invalid_credentials`; Mailpit: "Your certificates were reset" + "New certificate issued" | PASS |
| T7 | Reset with a magic link | same `202` for known / unknown e-mail; link works once; none for admins | `202` identical bodies; complete `200`; replay `401 invalid_token`; admin: `202`, no e-mail | PASS |
| T11 | Stolen cookie with another certificate | refused | `401 session_certificate_mismatch` (the victim's session is also killed) | PASS |
| T12 | Non-admin on `/api/admin/*` | refused | `403 admin_required`, audit `ADMIN_ACCESS_DENIED` | PASS |
| T13 | Group revocation (`OU=interns`) | member sessions dead now, TLS refusal after CRL reload | `revokedCertificates: 2`; session `403 certificate_revoked`; login `403 FAILED:certificate revoked` | PASS |
| T14 | Header spoofing on the public port; backend exposure; TLS version | refused | `404` on 9443 with forged headers; `curl :8080` connection refused; `-tls1_2` → `alert protocol version`; TLS 1.3 + `TLS_AES_256_GCM_SHA384`, server asks only for "ITSM mTLS Users CA" | PASS |
| T15 | CSRF | refused | foreign `Origin` → `403 bad_origin`; `text/plain` → `415` | PASS |
| T16 | Second device | logs into the same account | `200`, same username, different serial | PASS |
| T17 | Audit trail | every event recorded | login, rejected session, rate limit, revocation, recovery events present | PASS |

## Part 3: attack scenarios (`attack-scenarios.sh`)

| ID | Attack (STRIDE) | Observed | Result |
| --- | --- | --- | --- |
| A1 | CSR asking for `CN=admin, OU=admins, CA:true, keyCertSign` (E/T) | issued cert: `CN=mallory-…, OU=staff`, `CA:FALSE`, KU digitalSignature, EKU clientAuth; `/api/admin` → `403 admin_required` | PASS |
| A2 | Inject `X-SSL-Client-Cert` (admin cert), `X-SSL-Client-Verify`, `X-Proxy-Secret`, `X-Real-IP` on 8443 (S) | logged in as **erin** (her real certificate): nginx overwrote every header | PASS |
| A3 | Call the backend directly from inside the Docker network (S) | `HTTP/1.1 403` (no proxy secret); port 8080 not published | PASS |
| A4 | Replay a used enrolment token (E) | `401 invalid_token` | PASS |
| A5 | Re-certify an already certified key (T) | `409 key_reuse` | PASS |
| A6 | RSA-1024 CSR; CSR with a corrupted signature (T) | `400` "RSA keys must be between 2048 and 8192 bits"; `400` "proof of possession failed" | PASS |
| A7 | Same backup code sent twice **in parallel** (E) | one `200`, one `401`: consumed exactly once | PASS |
| A8 | Valid backup code of a **disabled** account (E) | `401 invalid_credentials` (generic) | PASS |
| A9 | Username enumeration by timing on backup-code reset (I) | 384 ms (existing) vs 361 ms (unknown), 5 % (noise); identical message | PASS |
| A9b | E-mail enumeration by timing on magic-link request (I) | 13 ms vs 13 ms (after fix F2; before: ~43 ms vs ~20 ms) | PASS |
| A10 | IDOR: revoke another user's certificate via `/api/me/...` (E) | `404 not_found`, certificate still active | PASS |
| A11 | Reuse a logged-out session id; session of an account being disabled (ASVS 7.4.1/7.4.2) | `401 not_authenticated`; `403 certificate_revoked` | PASS |
| A12 | Revoke the whole `admins` group (D) | `409 self_lockout` | PASS |
| A13 | Magic link for the admin address (S/E) | `202` generic answer, **0** e-mail sent | PASS |
| A14 | Stale CRL (expired 1 s after issue) pushed to nginx (D/T) | every login `403 FAILED:CRL has expired` (fail closed); after backend restart → fresh CRL → `200` | PASS |
| A15 | Repudiation / secrets in logs (R/I) | audit contains every attack; the backup code used in A7 never appears in the backend logs | PASS |

---

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Low | CSP had no `object-src 'none'` (ASVS 3.4.3) | **Fixed** in `nginx/templates/default.conf.template` |
| F2 | Medium | **E-mail enumeration by timing** on `POST /api/recovery/magic-link`: existing account ≈ 43 ms, unknown ≈ 20 ms (token written to the DB synchronously), although the message was identical | **Fixed**: `MagicLinkWorker` does the lookup / token / e-mail asynchronously; re-test A9b: 13 ms vs 13 ms |
| F3 | Info | nginx returns the verification reason (`FAILED:certificate revoked`) in the 403 body | Accepted for the demo (it helps); use a generic message in production |
| F4 | Low | Rate-limit counters and sessions are in memory: a backend restart resets them; single instance only | Accepted (lab); Redis / DB-backed limiter for production |
| F5 | Low | An attacker who keeps sending 5 wrong codes every 15 min blocks the victim's *recovery* (login unaffected) | Accepted, documented (ASVS 6.1.1) |
| F6 | Info | A session cookie shown with a foreign certificate kills the victim's session (theft detection) | By design |
| F7 | High (design) | The Users CA key is online in the backend container: a host compromise lets the attacker mint certificates | Accepted for the lab; HSM / separate signing service in production; the root can revoke the Users CA |
| F8 | n/a | Test-harness bugs on the first run (wrong expected strings, a bare `wait` that also waited for `tee`) | Fixed in the scripts; no application defect |

Not tested automatically (waiting time too long): idle timeout (15 min), absolute timeout (4 h),
expiry of a magic link (15 min) and of an invitation (24 h). They are enforced by configuration and
by `SessionAuthFilter` / `TokenService` and can be shown manually.
