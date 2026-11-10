# OWASP ASVS 5.0.0: Level 1 checklist, chapters V6 and V7

Source: OWASP Application Security Verification Standard 5.0.0 (May 2025),
`0x15-V6-Authentication.md` and `0x16-V7-Session-Management.md`. The requirement texts below
are short paraphrases; the ids are the official ones.

Status: **Met**, **Not met**, **N/A** (with the reason). Evidence = test ids of
[TEST-LOG.md](TEST-LOG.md) or the file that implements the control.

## V6 Authentication (Level 1)

| ID | Requirement (paraphrase) | Status | Why / evidence |
|---|---|---|---|
| 6.1.1 | Documentation explains how rate limiting, anti-automation and adaptive response defend against credential stuffing and brute force, and how they avoid malicious account lockout | **Met** | README "Security design" and report §8 document the limits (per account 5 / 15 min, per IP 20 / 15 min, 3 links / h per e-mail, nginx 30 r/min). They apply only to the recovery / enrolment endpoints; certificate login has no secret to brute force. Lockout is temporary (sliding window) and only blocks *recovery*, never login. Known limit: an attacker can keep a victim's recovery blocked by sending 5 bad codes every 15 min (documented, D1). |
| 6.2.1 – 6.2.8 | Password rules (length ≥ 8, change, current password, breached-password list, no composition rules, masking, paste allowed, no truncation) | **N/A** | The application has **no passwords**: users authenticate with an X.509 certificate. Backup codes are lookup secrets (V6.5), not passwords, and cannot log in. |
| 6.3.1 | Controls against credential stuffing and brute force are implemented as documented | **Met** | `RateLimiter` / `RateLimitGuard`, nginx `limit_req`. Tests T8 (429 + Retry-After after 5 attempts), A7 (race), A9. |
| 6.3.2 | Default accounts ("root", "admin", "sa") are absent or disabled | **Not met** | The bootstrap account is called `admin`. It has **no default credential**: it can only enrol with a random 256-bit, single-use, 24 h token generated in `.env` at setup, and it needs a certificate. Strictly the requirement is still not met. Fix: set `app.bootstrap.admin-username` to a personal name before the first start. |
| 6.4.1 | System-generated activation codes are random, follow policy, expire after a short time or first use, and are not long-term secrets | **Met** | Enrolment tokens: 256 bits from `SecureRandom`, single use (atomic update), valid 24 h, stored as SHA-256. Magic links: same, valid 15 min. Tests T7, A4. |
| 6.4.2 | No password hints or knowledge-based questions | **Met** | No secret questions anywhere. Recovery = backup code or e-mail link. |

## V7 Session Management (Level 1)

| ID | Requirement (paraphrase) | Status | Why / evidence |
|---|---|---|---|
| 7.2.1 | Session token verification is done by a trusted backend service | **Met** | Server-side Tomcat session, checked by `SessionAuthFilter` on every protected request (plus certificate binding, revocation list and epoch). |
| 7.2.2 | Session tokens are dynamically generated, not static API secrets or keys | **Met** | Random session id created at login. The only static secret is the nginx→backend proxy secret, which is not a user session token. |
| 7.2.3 | Reference tokens are unique, from a CSPRNG, with at least 128 bits of entropy | **Met** | Tomcat session ids: 16 bytes from `SecureRandom` = 128 bits (32 hex characters, see T9). |
| 7.2.4 | A new session token is created on authentication (and re-authentication) and the previous one is terminated | **Met** | `LoginController` invalidates any presented session and creates a new one. T9: id changes on every login, the old id is dead, an attacker-chosen id is not adopted. |
| 7.4.1 | After logout or expiry, the session can no longer be used | **Met** | Logout invalidates the server-side session and expires the cookie; idle (15 min) and absolute (4 h) expiry are checked on the server. A11: a logged-out id is rejected. |
| 7.4.2 | All active sessions are terminated when an account is disabled or deleted | **Met** | Disabling bumps the account `session_epoch` and revokes the certificates; every existing session fails on its next request. A11, T13. |

**Result for Level 1: 11 applicable requirements, 10 met, 1 not met (6.3.2); 8 N/A (passwords).**

## Beyond Level 1 (for information)

| ID | Level | Status | Note |
|---|---|---|---|
| 6.3.3 | 2 | Not met | The certificate is a single factor ("something you have"). Real MFA would need e.g. a smart card / TPM key protected by a PIN, or a second factor. |
| 6.4.3 | 2 | Met | Reset never bypasses the certificate: it only issues a new certificate and revokes the old ones. |
| 6.5.1 – 6.5.4 | 2 | Met | Lookup secrets (backup codes): single use, Argon2id with salt, CSPRNG, ~49.5 bits (≥ 20). T6, A7. |
| 7.3.1 / 7.3.2 | 2 | Met (not tested) | Idle timeout 15 min, absolute 4 h (configuration + filter); waiting times too long for the automated run. |
| 7.4.3 | 2 | Met | A reset (change of authentication factor) terminates every session automatically. T6. |
| 7.4.5 | 2 | Partially | Admins end sessions by revoking certificates / disabling the account, not with a separate "kill session" button. |
| 7.5.1 / 7.5.2 | 2 | Not met | No re-authentication step before sensitive actions; no list of active sessions for the user. |

## Related requirements outside V6/V7

| ID | Level | Status | Note |
|---|---|---|---|
| 3.3.1 | 1 | Met | Cookie has `Secure` and the `__Host-` prefix (T10). |
| 3.3.2 / 3.3.3 / 3.3.4 | 2 | Met | `SameSite=Strict`, `__Host-` prefix, `HttpOnly` (T10). |
| 3.4.1 | 1 | Met | HSTS `max-age=31536000` on every response (`always`). |
| 3.4.3 | 2 | Met (after fix F1) | CSP with `object-src 'none'` and `base-uri 'none'`; added after the Breaker review. |
| 12.1.1 | 1 | Met | Only TLS 1.3 is enabled; a TLS 1.2 handshake is refused (T14). |
