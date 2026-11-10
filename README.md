# Mutual TLS client certificate authentication (Full)

Course project for *Information Technology Security Methods* (VILNIUS TECH, 2026-2027).
A web application where login means presenting an X.509 client certificate during the TLS
handshake. On top of the base mechanism it adds:

1. a **backup method**: a second certificate on another device, plus 10 one-time backup codes,
2. a **certificate reset** for users who lost every certificate (backup code or e-mail magic link),
3. **centralised revocation** of a certificate, a user or a whole group, both in the CRL and
   in the application.

## Architecture

```
                         ┌───────────────────────── docker network "internal" (no egress) ───────────┐
 browser / curl          │                                                                            │
   │  TLS 1.3 + client   │  ┌────────────── nginx ──────────────┐      ┌──── backend (Spring Boot) ───┐│
   ├──── cert ──:8443────┼─►│ ssl_verify_client on              │─────►│ re-checks the cert (CA, EKU, ││
   │                     │  │ ssl_client_certificate (Users CA) │ HTTP │ validity), fingerprint ->    ││
   │                     │  │ ssl_crl (root + Users CA CRL)     │ +hdr │ account, session, revocation ││
   │                     │  │ forwards cert, DN, serial         │      │ list, Users CA (signs CSRs,  ││
   └──── no cert ─:9443──┼─►│ public: enrol / recovery / CRL    │─────►│ generates the CRL)           ││
                         │  └───────────────▲───────────────────┘      └───────┬────────────┬─────────┘│
                         │                  │ CRL file (volume) + auto reload  │            │          │
                         │                  └──────────────────────────────────┘      PostgreSQL  Mailpit│
                         └────────────────────────────────────────────────────────────────────────────┘
```

| Component | Role |
|---|---|
| `pki/` | OpenSSL PKI: offline **Root CA** → **Users CA** (client certificates) and **Servers CA** (nginx). EC P-384 CA keys, encrypted with AES-256. |
| `nginx/` | Terminates TLS 1.3. Port **8443** requires a client certificate (`ssl_verify_client on`, `ssl_crl`), port **9443** is public (enrolment, recovery, CRL only). Reloads itself when the CRL changes. |
| `backend/` | Spring Boot 3 / Java 21. Maps the SHA-256 fingerprint of the certificate to an account, creates the session, holds the application-level revocation list, signs CSRs with the Users CA, publishes the CRL, sends notifications, writes the audit log. |
| `db` | PostgreSQL 16 (accounts, certificates, backup code hashes, token hashes, audit log). |
| `mail` | Mailpit: fake SMTP server, web UI on http://localhost:8025 (magic links, notifications). |

## Quick start (WSL / Linux)

Prerequisites: Docker with Compose v2, `openssl`, `curl`, `python3` (all scripts are bash: run them from WSL).

```bash
./scripts/setup.sh                       # PKI + negative-test certificates + .env (random secrets)
docker compose up -d --build             # db, mail, backend, nginx
./scripts/enroll.sh --bootstrap-admin    # admin key pair + CSR -> clients/admin/{key,cert,chain}.pem, client.p12, backup codes
./tests/security-tests.sh                # full security test run, log in tests/logs/
```

Log in with curl:

```bash
CA=pki/out/root-ca/ca.crt
curl --cacert $CA --cert clients/admin/cert.pem --key clients/admin/key.pem -c jar -b jar \
     -X POST https://localhost:8443/api/login -H 'Content-Type: application/json' -d '{}'
curl --cacert $CA --cert clients/admin/cert.pem --key clients/admin/key.pem -b jar https://localhost:8443/api/me
```

### Browser demo

1. Trust `pki/out/root-ca/ca.crt` as a root authority (Windows: `certmgr.msc` → *Trusted Root
   Certification Authorities*; Firefox: *Settings → Certificates → Authorities*).
2. Import `clients/admin/client.p12` (password in `clients/admin/p12-password.txt`) in the personal
   certificate store (Windows / Chrome / Edge) or in *Your Certificates* (Firefox).
3. Open https://localhost:8443, pick the certificate, click **Sign in** → admin page.
4. Create a user, then open the invitation link (https://localhost:9443/enroll.html#token=...)
   or run the CLI shown on the admin page.

### Client scripts

| Script | Purpose |
|---|---|
| `scripts/enroll.sh --token T --out clients/alice` | First enrolment with an invitation token |
| `scripts/add-device.sh --from clients/alice --out clients/alice-phone` | Second certificate (backup method) |
| `scripts/recover.sh --username alice --code XXXXX-XXXXX --out clients/alice-new` | Reset with a backup code |
| `scripts/recover.sh --request-link alice@example.test` then `--magic-token T --out ...` | Reset with an e-mail link |

All of them generate the key pair **locally** and only send a CSR.

## API

| Listener | Method + path | Auth | Purpose |
|---|---|---|---|
| 8443 | `POST /api/login` | client cert | Maps the certificate to the account, creates a new session |
| 8443 | `POST /api/logout` | cert + session | Ends the session |
| 8443 | `GET /api/me`, `GET /api/me/certificates` | cert + session | Profile, own certificates |
| 8443 | `POST /api/me/certificates` `{csr,label}` | cert + session | Add another device |
| 8443 | `POST /api/me/certificates/{serial}/revoke` | cert + session | Revoke one of my certificates |
| 8443 | `POST /api/me/backup-codes` | cert + session | Regenerate the 10 backup codes |
| 8443 | `GET/POST /api/admin/users`, `.../users/{u}/revoke`, `.../enable`, `.../enrollment-token` | admin | Accounts and invitations |
| 8443 | `GET /api/admin/certificates`, `POST .../certificates/{serial}/revoke` | admin | Certificate revocation |
| 8443 | `GET /api/admin/groups`, `POST .../groups/{g}/revoke` | admin | Group revocation |
| 8443 | `GET /api/admin/audit`, `POST /api/admin/crl/publish` | admin | Audit log, force CRL |
| 9443 | `POST /api/enroll` `{token,csr,label}` | invitation token | First certificate + backup codes |
| 9443 | `POST /api/recovery/backup-code` `{username,backupCode,csr,label}` | backup code | Reset |
| 9443 | `POST /api/recovery/magic-link` `{email}` → `POST .../magic-link/complete` `{token,csr,label}` | e-mail link | Reset |
| 9443 | `GET /crl/users-ca.crl`, `GET /ca/chain.pem` | none | CRL distribution point, CA chain |

"admin" = role ADMIN in the database **and** a certificate with `OU=admins`.

## Security design (input for the threat model and the ASVS checklist)

### Login (base mechanism)
- TLS 1.3 only; no session tickets / session cache, so every connection runs a full handshake
  and the client certificate is checked against the *current* CRL.
- nginx trusts only the Users CA chain for client certificates (`ssl_verify_depth 2`) and checks
  CRLs for the whole chain (root CRL + Users CA CRL). An expired CRL makes every login fail
  (**fail closed**); the backend republishes the CRL every 10 minutes (validity 24 h).
- nginx forwards the certificate in headers that are always overwritten (`proxy_set_header`), so a
  client cannot inject them; the public listener removes them entirely. The backend only accepts
  requests carrying a secret header set by nginx, and its port is not published.
- The backend re-validates the certificate (defence in depth): issued by the Users CA (signature
  check), within its validity period, **EKU clientAuth present** (OpenSSL accepts a certificate
  without any EKU; the backend does not).
- Account mapping uses the SHA-256 fingerprint computed by the backend (not nginx's SHA-1).

### Session
- Cookie `__Host-SID`: `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`; cookie-only
  tracking (no ids in URLs).
- A new session id at every login (any presented session is invalidated first): no session fixation.
- The session is **bound to the certificate**: on each request the backend compares the current TLS
  certificate with the one used at login. A stolen cookie is useless without the private key, and
  the session is killed when such a mismatch is seen.
- Idle timeout 15 min, absolute timeout 4 h.
- CSRF: `SameSite=Strict` + rejection of `Sec-Fetch-Site: cross-site`, foreign `Origin` and non-JSON
  bodies on state-changing requests (browsers send client certificates cross-site, so the
  certificate alone must not authorise a state change).

### Backup method
- Second certificate on another device: only from an authenticated session, max 3 active
  certificates per account, owner notified by e-mail.
- 10 backup codes (~49.5 bits each), stored as **Argon2id** hashes (m=19 MiB, t=2, p=1), single use
  (atomic update), shown once. They can **only** enrol a new certificate, never log in. Verification
  does the same Argon2 work whether the account exists or not.

### Reset
- Proof of identity: a backup code, or a magic link sent to the registered address (256-bit token,
  stored as SHA-256, single use, 15 min, in the URL fragment so it never reaches server logs or
  `Referer`). **E-mail recovery is disabled for administrators** (e-mail takeover ≠ admin takeover).
- The user generates the key pair locally and sends a CSR. The CSR signature proves possession of
  the private key; the CA ignores the requested subject/extensions and builds them from the account;
  a key that was already certified is refused. The server never sees a private key (no server-side
  PKCS#12).
- On success: **every** previous certificate is revoked (reason keyCompromise), every session is
  invalidated (session epoch), the CRL is regenerated, the user is notified by e-mail.
- Rate limiting: per account 5 attempts / 15 min, per IP 20 / 15 min, magic links 3 / h per e-mail,
  plus nginx `limit_req` (30 r/min per IP). `429` with `Retry-After`. Same response whether the
  account / e-mail exists or not; the magic-link lookup, token creation and e-mail run
  asynchronously after the response (`MagicLinkWorker`), so the timing reveals nothing either.

### Revocation
- Application level: certificate status checked on **every** request, effective immediately.
- Infrastructure level: CRL regenerated after each revocation, written atomically, nginx reloads
  within ~2 s (`crl-watch.sh`).
- Revoke one certificate, all certificates of a user (optionally disabling the account, which also
  blocks recovery), or a whole group (all certificates whose `OU` is the group). Revoking the
  `admins` group as a whole is refused (lock-out). Variant "revoke a whole intermediate CA":
  `pki/renew-root-crl.sh users` (offline root ceremony).
- Re-enabling an account deletes its old backup codes and issues a new invitation.

### Traceability
- Audit events (DB + `AUDIT` logger on stdout, SIEM-ready): login success/failure, logout, rejected
  sessions, enrolment, certificate issued/revoked, user/group revocation, backup code used,
  recovery requested/completed/failed, rate limiting, denied admin access, CRL publication.
  Codes, tokens, session ids and keys are never logged.

### Known limitations
- Rate-limit counters and sessions are in memory (single backend instance; reset on restart).
- nginx completes the TLS handshake and then answers 403 when the certificate is missing or
  invalid (`$ssl_client_verify` is reported in the JSON body); it cannot abort the handshake itself.
- The Users CA private key is on the backend host (encrypted at rest, passphrase as a Docker
  secret); an HSM would be needed in production. The Root CA key is never mounted.
- No OCSP responder: revocation relies on the CRL (nginx) and the database (application).
- The lab uses `localhost` and self-generated CAs; Mailpit replaces a real mail server.

## Tests

- `backend`: unit tests (CA issuance and EKU, foreign CA, CRL, CSR proof of possession, weak keys,
  rate limiter, header decoding) run during `docker compose build`.
- `tests/security-tests.sh`: 35 checks against the running stack (no certificate, foreign CA,
  expired, revoked via app and via CRL, wrong EKU, no EKU, backup code reset, magic link, rate limit,
  session regeneration, cookie flags, stolen cookie, admin access, group revocation, header
  spoofing, TLS 1.2 refused, CSRF, second device). Raw output is saved in `tests/logs/`.
- `tests/attack-scenarios.sh`: 29 adversarial checks (forged CSR, header injection, nginx bypass,
  token replay, key reuse, race on a backup code, timing enumeration, IDOR, admin lock-out, expired
  CRL fail-closed, audit completeness).

## Documentation

| File | Content |
|---|---|
| [DEMO.md](DEMO.md) | Step-by-step demo guide: preparation, commands, expected results and explanations |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | STRIDE threat model of the login and recovery flows |
| [docs/ASVS-CHECKLIST.md](docs/ASVS-CHECKLIST.md) | OWASP ASVS 5.0 Level 1 checklist, V6 and V7 |
| [docs/TEST-LOG.md](docs/TEST-LOG.md) | Commented security test log and findings |
| [docs/ITSM-mTLS-Report.pdf](docs/ITSM-mTLS-Report.pdf) | The project report |

## Repository layout

```
pki/        OpenSSL configuration and scripts (output in pki/out/, git-ignored)
nginx/      nginx image: TLS / mTLS configuration template, CRL watcher
backend/    Spring Boot application (Java 21, Maven)
scripts/    setup and client-side scripts (key generation, CSR, PKCS#12)
tests/      security test harness and logs
docs/       threat model, ASVS checklist, test log, report
```
