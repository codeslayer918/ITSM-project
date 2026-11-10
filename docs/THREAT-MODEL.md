# Threat model (STRIDE): login and recovery flows

**System:** mutual-TLS web application (nginx TLS 1.3 + Spring Boot + own PKI). **Assets:** the
accounts (especially admins), the Users CA private key, the client private keys, the session
cookies, the backup codes and magic links, the CRL, the audit log.

**Trust boundaries:** (1) Internet ↔ nginx (TLS), (2) nginx ↔ backend (internal Docker network,
proxy secret), (3) backend ↔ PostgreSQL / mail, (4) offline Root CA ↔ everything else.

**Attackers:** (A) remote attacker without any credential, (B) attacker holding a stolen
credential (certificate + key, session cookie, backup code sheet, mailbox), (C) malicious or
curious regular user, (D) attacker on the backend host (insider / compromised container).

**Evidence column:** ids of the tests in [TEST-LOG.md](TEST-LOG.md) (`T*` = required cases,
`A*` = attack scenarios). **Residual risk:** L = low, M = medium, H = high.

| # | STRIDE | Flow | Threat (what the attacker tries) | How it is blocked | Evidence | Residual |
|---|---|---|---|---|---|---|
| S1 | Spoofing | Login | Use a **stolen certificate + private key** (laptop theft, malware) | Key generated on the device, never sent; owner, admin or recovery revokes it: immediate in the app, at TLS level after ≤ 2 s (CRL); 180-day validity | T4, T13, A11 | **M** until revoked |
| S2 | Spoofing | Login | Certificate from **another CA**, even with an identical DN | nginx trusts only the Users CA chain; backend verifies the signature with the Users CA key | T2 | L |
| S3 | Spoofing | Login | **Inject `X-SSL-Client-*` headers** or reach the backend without nginx | `proxy_set_header` overwrites them (public listener deletes them); shared proxy secret; backend port not published, internal network | T14, A2, A3 | L |
| S4 | Spoofing | Session | Replay a **stolen session cookie** (XSS, malware, logs) | `HttpOnly`, `Secure`, `__Host-`; session **bound to the certificate fingerprint**, and the session is killed when it shows up with another certificate | T11 | L |
| S5 | Spoofing | Session | **Session fixation** | New session id at every login, a presented id is never adopted | T9 | L |
| S6 | Spoofing | Recovery | **E-mail account takeover**, then magic link → new certificate | Link single use, 15 min, 256-bit, sent only to the registered address; every old certificate is revoked and the user notified (takeover is loud); **disabled for admins**; rate limited | T7, A13 | **M** (regular users) |
| T1 | Tampering | Enrolment / recovery | **CSR asking for `CN=admin`, `OU=admins`, `CA:true`** | The CA ignores the CSR subject and extensions and builds them from the account; `CA:FALSE`, EKU clientAuth only | A1 | L |
| T2 | Tampering | Revocation | **Replace or freeze the CRL** to resurrect a revoked certificate | CRL signed by the Users CA (nginx checks the signature); atomic write; expired CRL → fail closed; app-level revocation list checked independently on every request | T4, A14 | L |
| T3 | Tampering | Enrolment | Weak key, CSR without proof of possession, reuse of a compromised key | Only EC P-256/P-384 or RSA ≥ 2048, CSR signature verified, a key certified once can never be certified again | A5, A6 | L |
| T4 | Tampering | Session | **CSRF**: browsers send client certificates cross-site | `SameSite=Strict`; `Sec-Fetch-Site` / `Origin` checks; JSON-only bodies | T15 | L |
| R1 | Repudiation | All | "It was not me who reset / revoked / logged in" | Audit events (time, user, IP, user agent, serial, outcome) in DB + stdout for a SIEM; e-mail notification of every certificate issuance, reset and revocation | T17, A15 | M (no WORM storage) |
| I1 | Info disclosure | Recovery | **Account enumeration** through messages or **response time** | Same message for unknown users; same Argon2 work; magic-link work done asynchronously (finding F2, fixed) | T7, A9, A9b | L |
| I2 | Info disclosure | Recovery | Steal codes or tokens from DB / logs / URLs | Backup codes Argon2id, tokens SHA-256; token in the URL **fragment**; secrets never logged | A15 | L |
| I3 | Info disclosure | Enrolment | Server-side key generation (PKCS#12 built by the server) exposes keys | CSR model: the server never sees a private key | A1, design | L |
| D1 | Denial of service | Recovery | Brute force of backup codes / Argon2 CPU exhaustion | Per account 5 / 15 min, per IP 20 / 15 min, 3 links / h per e-mail, nginx 30 r/min; `429 + Retry-After` | T8 | L (victim can be blocked from *recovery* for 15 min, login unaffected) |
| D2 | Denial of service | Login | **Stale CRL** (backend down, CRL expired) blocks every login | CRL republished every 10 min (valid 24 h) and after every revocation; fail closed is a deliberate choice | A14 | M (needs monitoring) |
| D3 | Denial of service | Revocation | Revoke the `admins` group / lock every admin out | Group revocation of `admins` refused; audit; admins revoked one by one | A12 | L |
| E1 | Elevation | Recovery | **Abuse the reset flow** to take over an account: guess / race a backup code, use a disabled account | ~49.5-bit codes, Argon2id, atomic single use (race tested), rate limited, disabled accounts cannot recover, all old certificates revoked + notification | T6, T8, A7, A8 | L |
| E2 | Elevation | Login | Regular user → administrator | Admin = DB role ADMIN **and** certificate `OU=admins` (set by the CA); admins cannot use e-mail recovery | T12, A1, A13 | L |
| E3 | Elevation | Enrolment | Replay an invitation token; act on another user's certificate (IDOR) | Tokens single use, 24 h; ownership check on `/api/me/...` | A4, A10 | L |
| E4 | Elevation | PKI | **Compromise the backend host** → Users CA key → mint any certificate (even admin) | Key encrypted at rest (AES-256), Root CA offline, backend not exposed; the root can revoke the whole Users CA (`renew-root-crl.sh users`) | design | **H** (an HSM would be needed) |

**Summary.** The highest residual risks are E4 (online issuing CA), S1 (a stolen device until it is
revoked), S6 (e-mail as a recovery factor for non-admin users) and D2 (availability tied to CRL
freshness). They are accepted for the lab and discussed in the report ("Does it increase security?").
