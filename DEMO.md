# Live demo guide

The guide we follow during the live demonstration: the preparation, then for each act the commands,
the expected result and the explanation of what happens, and what to do if something goes wrong.

- **Full demo: about 22 minutes**, in 14 acts. A **15-minute** and a **10-minute version** are given
  at the end (§16).
- **The idea of this demo:** every feature is shown **in every way it can be used**. Enrolment is
  done three ways (by hand with OpenSSL + curl, with the script, in the browser), the reset with a
  backup code three ways, the magic link two ways, revocation at its three levels. The audience sees
  that the security does not depend on the client: the script and the browser are only front-ends to
  the same API, and the server checks everything itself.
- Every command comes from [ManualTest.md](ManualTest.md), where each one is explained; this file only
  puts them in the order of a presentation.
- Speakers: **B** = Builder, **K** = Breaker, **W** = Writer. Every member must also be able to
  explain the parts they do not present (the course can ask anyone about anything).

| Feature | ⌨ By hand (OpenSSL + curl) | ⌨ Script | 🖱 Browser |
| --- | --- | --- | --- |
| Create a user (admin) | alice (act 4a), bob (4c) | | dave (4b) |
| Enrolment | alice (4a) | dave (4b) | bob (4c) |
| Login | every check (`mtls ...`) | | admin (act 3) |
| Second device | | alice's phone (7a) | admin's second PC (7b) |
| Reset with a backup code | alice, code 2 (8b) | alice, code 1 (8a) | alice, code 3 (8c) |
| Reset with a magic link | request (9a) | completion (9a) | request + completion (9b) |
| Revocation | one certificate: dave (11a) | | one user: alice (11b), one group: interns (11c) |

---

## 0. Preparation

### 0.1 Two days before: full rehearsal

Run the whole demo once, from WSL, in the project folder:

```bash
cd "/mnt/f/VILNIUS TECH/Information Technology Security Methods/Project"
docker compose down -v; rm -rf pki/out clients .env    # start from zero (deletes PKI, DB, client certs)
./scripts/setup.sh
docker compose up -d --build
./scripts/enroll.sh --bootstrap-admin
./tests/security-tests.sh                               # must end with PASS=35 FAIL=0
./tests/attack-scenarios.sh                             # must end with PASS=29 FAIL=0
```

Then, in the browser that you will use for the demo (Edge or Chrome use the Windows store, Firefox
has its own):

1. Import `pki\out\root-ca\ca.crt` as a **trusted root** (ManualTest.md §5.2).
2. Import `clients\admin\client.p12` (ManualTest.md §5.3; the password is in
   `clients\admin\p12-password.txt`).
3. Restart the browser (`chrome://restart`), open https://localhost:8443, check that it proposes the
   *admin* certificate.
4. Browser settings → *Downloads*: note the download folder, and turn **off** *"Ask where to save
   each file"* (the demo downloads `cert.pem` several times).

Then rehearse every act below with a stopwatch.

### 0.2 The morning of the demo: clean state, same PKI

The rehearsal left users (alice, bob...) in the database. Reset the database **but keep the PKI**,
so the browser still trusts the root CA:

```bash
docker compose down -v                 # deletes the database and the CRL volume, keeps pki/out
rm -rf clients                         # old client certificates are now unknown to the DB
docker compose up -d
./scripts/enroll.sh --bootstrap-admin  # new admin certificate (the bootstrap token works again on a new DB)
```

In the browser, remove the old *admin* certificate (`certmgr.msc` → *Personal* → *Certificates*),
import the **new** `clients\admin\client.p12`, restart the browser, check that the login works.

### 0.3 Ten minutes before: the screen

Open, in this order (switch with Alt+Tab):

| Window | Content |
| --- | --- |
| Browser tab 1 | https://localhost:8443 (not logged in yet) |
| Browser tab 2 | http://localhost:8025 (Mailpit, the fake mailbox) |
| Browser tab 3 | `docs/report/figures/architecture.png` |
| **Terminal A** (WSL) | the commands of the demo, font size 18+ so the room can read |
| **Terminal B** (WSL) | live logs: `docker compose logs -f --since 1s nginx backend \| grep -E "crl-watch\|AUDIT"` |
| Editor | `docs/THREAT-MODEL.md`, `docs/ASVS-CHECKLIST.md`, the report PDF |

In **Terminal A**, paste the helper block (the same as in ManualTest.md §0, plus three helpers for
the browser parts) and restart the backend so the rate-limit counters are empty:

```bash
cd "/mnt/f/VILNIUS TECH/Information Technology Security Methods/Project"
export CA=pki/out/root-ca/ca.crt APP=https://localhost:8443 PUB=https://localhost:9443
J='Content-Type: application/json'
req()  { curl -sS -i --cacert "$CA" "$@" | tr -d '\r' | grep -iE '^(HTTP/|set-cookie:|retry-after:)|^[{[]'; }
mtls() { local d="$1"; shift; req --cert "$d/cert.pem" --key "$d/key.pem" "$@"; }
admin() { curl -sS --cacert "$CA" --cert clients/admin/cert.pem --key clients/admin/key.pem \
               -b /tmp/admin.jar -c /tmp/admin.jar -H "$J" "$@"; echo; }
body() { python3 -c 'import json,sys; a=sys.argv[1:]; print(json.dumps({k:(open(v[1:]).read() if v.startswith("@") else v) for k,v in zip(a[::2],a[1::2])}))' "$@"; }
newkey() { mkdir -p "$1"; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1/key.pem" 2>/dev/null
           openssl req -new -key "$1/key.pem" -subj /CN=csr -out "$1/csr.pem"; }
jget() { python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }

# --- browser helpers ---
DL=/mnt/f/Downloads          # your browser download folder, as seen from WSL (check it in 0.1 step 4)
# copy the CSR of a folder to the Windows clipboard, ready for Ctrl+V in the page
copycsr() { /mnt/c/Windows/System32/clip.exe < "$1/csr.pem" && echo "CSR of $1 copied: paste it with Ctrl+V"; }
# move the files downloaded from the page next to the private key
grab() { mv "$DL/cert.pem" "$DL/chain.pem" "$1/" && { [ -f "$DL/backup-codes.txt" ] && mv "$DL/backup-codes.txt" "$1/"; ls "$1"; }; }

rm -f "$DL"/cert*.pem "$DL"/chain*.pem "$DL"/backup-codes*.txt     # no old downloads ("cert (1).pem")
docker compose restart backend && sleep 20 && docker compose ps
mtls clients/admin -c /tmp/admin.jar -X POST $APP/api/login -H "$J" -d '{}' | head -1   # HTTP/2 200
clear
```

Checklist before starting: `docker compose ps` shows 4 services, backend and db `healthy`; the admin
login answers `HTTP/2 200`; Mailpit is empty (click *Delete all* if needed); `copycsr` and `grab`
are defined (`type grab`).

> **Rate-limit budget.** The backend allows 20 recovery requests per IP per 15 minutes (and 5 per
> account). The acts below use 19, in this order, so **do not repeat** a recovery command during the
> demo. If you must, restart the backend first (§17).

---

## 1. Introduction (W, 1 min)

Our project replaces passwords with **mutual TLS client certificates**. During the TLS handshake
the browser proves it holds a private key, and our own certification authority has certified that
this key belongs to a given user and group. We built the **full option**: a backup method (a second
device and ten one-time backup codes), a reset when every device is lost (backup code or a
15-minute magic link), and centralised revocation of a certificate, a user or a whole group.
We will show every feature **in each way a user can use it**: by hand, with our scripts, and in the
browser. I am the Writer, [name] is the Builder, [name] is the Breaker.

---

## 2. Architecture and PKI (B, 2 min)

On screen: browser tab 3 (`architecture.png`).

Four containers. **nginx** terminates TLS 1.3 and has two ports: **8443** demands a client
certificate, **9443** is public but only exposes enrolment, recovery and the CRL, because someone who
lost their certificate cannot connect to 8443 at all. The **backend**, Spring Boot, is not
reachable from outside; it maps the certificate to an account, manages sessions and acts as our
Users CA. **PostgreSQL** stores accounts and certificates, **Mailpit** is a fake mail server.

```bash
docker compose ps
openssl verify -CAfile pki/out/root-ca/ca.crt -untrusted pki/out/users-ca/ca.crt clients/admin/cert.pem
openssl x509 -in clients/admin/cert.pem -noout -text | grep -E "Issuer:|Subject:|Not After|CA:|TLS Web|URI:"
```

**Result:** `clients/admin/cert.pem: OK`, then
`Subject: O = ITSM mTLS Lab, OU = admins, CN = admin`, `CA:FALSE`, `TLS Web Client Authentication`,
the CRL URL.

Chain of trust: an **offline root** that only signs two intermediates, a **Users CA** for people and
a **Servers CA** for nginx. In a certificate, CN is the username and **OU is the group**: this is what
lets us revoke a whole group, and OU=admins is required for the admin page. The EKU says *client
authentication only*.

---

## 3. Login in the browser and cookie flags (B, 1.5 min)

Browser tab 1 → https://localhost:8443 → the browser asks for a certificate → choose *admin*
→ **Sign in** → the administration page opens.

The browser only proposes certificates issued by our Users CA, because nginx's
CertificateRequest lists only that CA. No password was typed. In the terminal we will log in the
same way with curl: same certificate, same answer.

F12 → *Application* → *Cookies* → `https://localhost:8443`.

The cookie `__Host-SID`: **Secure**, **HttpOnly**, **SameSite Strict**, path `/`, no domain. In the
*Console* tab, type `document.cookie` → `''`.

The cookie only holds a random 128-bit session id. Secure: HTTPS only. HttpOnly: JavaScript cannot
read it, as you see in the console, so XSS cannot steal it. SameSite Strict and our Origin checks
stop CSRF. And the session is **bound to the certificate**: we will show that a stolen cookie is
useless.

---

## 4. Enrolment, three ways (B, 3.5 min)

Enrolment always follows the same protocol: the admin creates the account and a single-use
invitation; the user generates a key pair **on their own machine**, sends only a CSR with the
token, and our CA builds the certificate from the account. We show it three times: by hand, so you
see every step; with our script; and in the browser, as a normal user would do.

### 4a. alice: by hand, step by step (⌨ admin and user on the command line)

```bash
TOKEN=$(admin -X POST $APP/api/admin/users -d '{"username":"alice","email":"alice@example.test","group":"staff"}' | jget enrollmentToken); echo "$TOKEN"
newkey clients/alice                                     # key.pem stays here, csr.pem will be sent
openssl req -in clients/alice/csr.pem -noout -verify     # proof of possession
curl -sS --cacert $CA -X POST $PUB/api/enroll -H "$J" \
     -d "$(body token "$TOKEN" csr @clients/alice/csr.pem label alice-laptop)" > /tmp/alice.json
jget subject < /tmp/alice.json
jget certificatePem < /tmp/alice.json > clients/alice/cert.pem
jget chainPem < /tmp/alice.json > clients/alice/chain.pem
python3 -c 'import json; print("\n".join(json.load(open("/tmp/alice.json"))["backupCodes"]))' > clients/alice/backup-codes.txt
head -3 clients/alice/backup-codes.txt
mtls clients/alice -c /tmp/alice.jar -X POST $APP/api/login -H "$J" -d '{}'
```

**Result:** a 43-character token, `Certificate request self-signature verify OK`,
`CN=alice,OU=staff,O=ITSM mTLS Lab`, three codes like `7KQ2M-XW9PA`, then the login: `HTTP/2 200`,
the `set-cookie` line, `"username":"alice","admin":false`.

The CSR is signed with alice's private key: that is the proof she holds it. She sends it to the
**public** port, since she has no certificate yet. The server signed a certificate with **her
account's** name and group, and returned ten backup codes, **shown once**: it only stores their
Argon2id hashes.

**Replay the invitation:**

```bash
newkey /tmp/replay
curl -sS --cacert $CA -X POST $PUB/api/enroll -H "$J" -d "$(body token "$TOKEN" csr @/tmp/replay/csr.pem)"; echo
```

**Result:** `{"error":"invalid_token","message":"Invalid or expired enrolment token."}`

### 4b. dave: admin in the browser, user with the script (🖱 + ⌨)

Admin page → **Create a user**: `dave`, `dave@example.test`, group `contractors` →
**Create and invite**. The box shows the token and a ready line
`CLI: ./scripts/enroll.sh --token ... --out clients/dave`.

Paste the line from the page, add a label:

```bash
./scripts/enroll.sh --token <TOKEN-FROM-THE-PAGE> --out clients/dave --label dave-laptop
mtls clients/dave -X POST $APP/api/login -H "$J" -d '{}' | head -1
```

**Result:** `subject : CN=dave,OU=contractors,O=ITSM mTLS Lab`, `backup codes saved to
clients/dave/backup-codes.txt`, a `client.p12` ready for a browser, and `HTTP/2 200`.

The script does exactly the steps you just saw, in one command, and also builds the PKCS#12 file
that a browser can import.

### 4c. bob: the normal user, in the browser (⌨ admin, 🖱 user)

Admin, command line; bob is an intern, we will need that group later:

```bash
admin -X POST $APP/api/admin/users -d '{"username":"bob","email":"bob@example.test","group":"interns"}' >/dev/null
newkey clients/bob && copycsr clients/bob        # bob's key is created on his machine
```

1. Mailpit (tab 2) → the e-mail *"Enrol your client certificate"* for bob → click the link. The page
   `https://localhost:9443/enroll.html` opens with the **token already filled**, and the `#token=`
   disappears from the address bar.
2. *Device label*: `bob-laptop`. Click in **CSR (PEM)** → `Ctrl+V`.
3. **Request certificate** → green message and the section *Certificate issued*.
4. Click **Download cert.pem**, **Download chain.pem**, **Download backup codes**.

```bash
grab clients/bob
mtls clients/bob -X POST $APP/api/login -H "$J" -d '{}' | tail -1
```

**Result:** `backup-codes.txt  cert.pem  chain.pem  csr.pem  key.pem`, then
`"username":"bob","group":"interns"`.

The page never asked for the private key: we only pasted the CSR, which contains the public key.
The token was in the link after the `#`: browsers never send that part to the server, so it is not
in any log, and the page removes it from the address bar. Three clients, one API, the same checks.

---

## 5. The four rejected certificates (K, 2 min)

I am the Breaker. The course requires four refusals. Each time nginx refuses during the handshake,
before the application is even reached.

```bash
req -X POST $APP/api/login -H "$J" -d '{}'                                         # 1. no certificate

openssl x509 -in pki/out/test-certs/rogue-user.crt -noout -subject -issuer         # 2. other CA
req --cert pki/out/test-certs/rogue-user.crt --key pki/out/test-certs/rogue-user.key -X POST $APP/api/login -H "$J" -d '{}'

req --cert pki/out/test-certs/expired.crt --key pki/out/test-certs/expired.key -X POST $APP/api/login -H "$J" -d '{}'      # 3. expired

req --cert pki/out/test-certs/wrong-eku.crt --key pki/out/test-certs/wrong-eku.key -X POST $APP/api/login -H "$J" -d '{}'  # 4. wrong EKU
```

**Result:**
1. `403 client_certificate_required`
2. The rogue certificate says `OU = admins, CN = admin` and its issuer has **exactly our root's
   name**, yet: `403 ... FAILED:unable to verify the first certificate`
3. `403 ... FAILED:certificate has expired`
4. `403 ... FAILED:unsuitable certificate purpose`

Case 2 is the interesting one: I forged a root CA with the same name as ours. Trust is based on the
**signature**, not on the name, so it fails. Case 4 is an e-mail signing certificate: it is a real
certificate, but not for client authentication. The fifth required case, a **revoked** certificate,
comes with the revocation in act 11.

**Optional, browser (10 s):** open a private window (`Ctrl+Shift+N`) → https://localhost:8443 →
*Cancel* in the certificate window → the same JSON `client_certificate_required`.

---

## 6. Stolen session cookie (K, 1 min)

```bash
STOLEN=$(awk '/__Host-SID/ {print $7}' /tmp/alice.jar); echo "$STOLEN"
mtls clients/admin -H "Cookie: __Host-SID=$STOLEN" $APP/api/me      # attacker: alice's cookie + another certificate
mtls clients/alice -b /tmp/alice.jar $APP/api/me                    # alice's own session
```

**Result:** `401 session_certificate_mismatch`, then `401 not_authenticated`.

I stole alice's cookie and used it with another valid certificate. The session remembers the
fingerprint of the certificate used at login, so it is refused, and the session is **destroyed**
because a stolen cookie means it is compromised. To use the cookie I would also need alice's private
key. The session id is also regenerated at every login, so session fixation does not work either.

Then alice logs in again (needed for the next act):

```bash
mtls clients/alice -c /tmp/alice.jar -X POST $APP/api/login -H "$J" -d '{}' | head -1
```

---

## 7. Backup method: a second device, two ways (B, 1.5 min)

### 7a. alice's phone, with the script (⌨)

```bash
./scripts/add-device.sh --from clients/alice --out clients/alice-phone --label alice-phone
mtls clients/alice-phone -X POST $APP/api/login -H "$J" -d '{}' | tail -1
mtls clients/alice -b /tmp/alice.jar $APP/api/me/certificates
```

**Result:** the phone logs in as `alice` with another serial; the list shows **two ACTIVE
certificates**, `alice-laptop` marked `"current":true`. Mailpit: *"New certificate issued"*.

### 7b. the admin's second PC, in the browser (🖱)

`newkey clients/admin-pc2 && copycsr clients/admin-pc2`

Admin page → **My account** → section *Add a second device (backup method)* → label
`admin-pc2`, paste the CSR → **Issue certificate**. *My certificates* now lists **two** ACTIVE
certificates. (Optional: download `cert.pem` and `chain.pem`, then `grab clients/admin-pc2`.)

This is the first backup method, like a second passkey. Only someone already logged in with a
valid certificate **and** session can add a device: a stolen cookie alone is not enough, as we saw.
If alice loses her phone, she revokes just that one from her laptop: no recovery needed. The second
backup method is the sheet of ten codes.

---

## 8. Reset with a backup code, three ways (B, 3 min)

Now alice loses **both** devices. She can no longer connect to port 8443. She goes to the public
port, generates a new key, and proves who she is with one backup code. Each successful reset
revokes **all** her previous certificates. We do it three times, with codes 1, 2 and 3 of her sheet.

### 8a. With the script (⌨, code 1)

```bash
CODE=$(sed -n 1p clients/alice/backup-codes.txt); echo "$CODE"
./scripts/recover.sh --username alice --code "$CODE" --out clients/alice-new --label alice-new
mtls clients/alice-new -X POST $APP/api/login -H "$J" -d '{}' | head -1     # new certificate: OK
mtls clients/alice -b /tmp/alice.jar $APP/api/me                            # old laptop + its session
mtls clients/alice-phone -X POST $APP/api/login -H "$J" -d '{}' | tail -1   # old phone
```

**Result:** `message : Certificate issued. 2 previous certificate(s) revoked, all sessions
closed. Backup codes left: 9.`, then `HTTP/2 200` for the new certificate, `403 certificate_revoked`
for the laptop and for the phone. Mailpit: *"Your certificates were reset"*.

**Same code again:**

```bash
./scripts/recover.sh --username alice --code "$CODE" --out /tmp/again-$$
```

**Result:** `"error": "invalid_credentials"`, `"Invalid username or backup code."`

### 8b. By hand (⌨, code 2)

```bash
CODE2=$(sed -n 2p clients/alice/backup-codes.txt)
newkey clients/alice-new2
curl -sS --cacert $CA -X POST $PUB/api/recovery/backup-code -H "$J" \
     -d "$(body username alice backupCode "$CODE2" csr @clients/alice-new2/csr.pem label alice-new2)" > /tmp/rec.json
jget message < /tmp/rec.json
jget certificatePem < /tmp/rec.json > clients/alice-new2/cert.pem
mtls clients/alice-new2 -X POST $APP/api/login -H "$J" -d '{}' | head -1
mtls clients/alice-new -X POST $APP/api/login -H "$J" -d '{}' | tail -1
```

**Result:** `... 1 previous certificate(s) revoked, all sessions closed. Backup codes left: 8.`,
`HTTP/2 200`, then `certificate_revoked` for `alice-new`.

### 8c. In the browser (🖱, code 3)

```bash
sed -n 3p clients/alice/backup-codes.txt                 # read code 3 aloud / copy it
newkey clients/alice-new3 && copycsr clients/alice-new3
```

Open https://localhost:9443/recover.html (no certificate asked: public port).
1. *Device label*: `alice-new3`; **New CSR (PEM)**: `Ctrl+V`.
2. **Option A - backup code**: *Username* `alice`, *Backup code*: code 3 →
   **Recover with backup code**.
3. Green message *"Certificate issued. 1 previous certificate(s) revoked, all sessions closed. Backup
   codes left: 7."* → **Download cert.pem**, **Download chain.pem**.

```bash
grab clients/alice-new3
mtls clients/alice-new3 -c /tmp/alice.jar -X POST $APP/api/login -H "$J" -d '{}' | head -1
mtls clients/alice-new2 -X POST $APP/api/login -H "$J" -d '{}' | tail -1
```

**Result:** `HTTP/2 200`, then `certificate_revoked` for `alice-new2`.

Three clients, the same rules: every old certificate is revoked, because a lost laptop may be in an
attacker's hands; every session is closed; alice receives an e-mail each time, so if she did not do
it herself she knows immediately; and each code works once. 7 codes are left.

---

## 9. Reset with a magic link, two ways (B, 2.5 min)

### 9a. Command line: request, then the script (⌨)

```bash
req -X POST $PUB/api/recovery/magic-link -H "$J" -d '{"email":"bob@example.test"}'
req -X POST $PUB/api/recovery/magic-link -H "$J" -d '{"email":"nobody@example.test"}'
```

**Result:** twice **exactly the same** `HTTP/2 202 "If an account exists for this
address, a recovery link has been sent."`

Mailpit: one e-mail *"Certificate recovery link"* for bob only. The link:
`https://localhost:9443/recover.html#token=...`.

The answer does not tell an attacker whether the address exists, and since our fix F2 it takes the
same time too. The token is after the `#`, so it never reaches server logs. It is valid 15 minutes,
single use.

Read the token from the e-mail, as bob would copy it; then use it twice:

```bash
ID=$(curl -s "http://localhost:8025/api/v1/search?query=to:bob@example.test%20subject:recovery" | python3 -c 'import json,sys; print(json.load(sys.stdin)["messages"][0]["ID"])')
MAGIC=$(curl -s "http://localhost:8025/api/v1/message/$ID" | jget Text | grep -o 'token=[A-Za-z0-9_-]*' | cut -d= -f2); echo "$MAGIC"
./scripts/recover.sh --magic-token "$MAGIC" --out clients/bob-new --label bob-new
./scripts/recover.sh --magic-token "$MAGIC" --out /tmp/replay-$$                        # same link again
req -X POST $PUB/api/recovery/magic-link -H "$J" -d '{"email":"admin@itsm-mtls.local"}'   # an admin
```

**Result:** `Certificate issued. 1 previous certificate(s) revoked, all sessions closed.`,
then `invalid_token` `"Invalid or expired recovery link."` for the replay. For the admin address:
the same `202`, but **no e-mail arrives** in Mailpit.

Administrators cannot use the magic link: otherwise taking over an admin's mailbox would be enough
to obtain an admin certificate.

### 9b. Browser, from start to end (🖱)

Https://localhost:9443/recover.html → **Option B - e-mail link** → `bob@example.test` →
**Send me a recovery link** → green generic message. Mailpit → the **new** e-mail → click the link:
the page now says *"Recovery link detected. Paste your new CSR above"* with the button
**Complete recovery**.

`newkey clients/bob-new2 && copycsr clients/bob-new2`

*Device label* `bob-new2`, **New CSR (PEM)**: `Ctrl+V` → **Complete recovery** →
*"Certificate issued. 1 previous certificate(s) revoked..."* → **Download cert.pem**,
**Download chain.pem**.

```bash
grab clients/bob-new2
mtls clients/bob-new2 -X POST $APP/api/login -H "$J" -d '{}' | tail -1
mtls clients/bob-new -X POST $APP/api/login -H "$J" -d '{}' | tail -1
```

**Result:** `"username":"bob"` for `bob-new2`, `certificate_revoked` for `bob-new`.

---

## 10. Rate limit on the reset (K, 1 min)

The reset is the weakest point of any authentication system, so I attack it: I try wrong backup
codes for dave.

```bash
newkey /tmp/bf
for i in 1 2 3 4 5 6 7; do
  curl -sS --cacert $CA -o /tmp/bf.out -D - -X POST $PUB/api/recovery/backup-code -H "$J" \
       -d "$(body username dave backupCode AAAAA-BBBBB csr @/tmp/bf/csr.pem)" | tr -d '\r' | grep -iE '^(HTTP|retry-after)' | tr '\n' ' '
  cat /tmp/bf.out; echo
done
```

**Result:** five times `HTTP/2 401 invalid_credentials`, then `HTTP/2 429 retry-after: ...
rate_limited`.

Five attempts per account per 15 minutes, twenty per IP, and nginx adds its own limit. A code has
about 49.5 bits of randomness, so guessing is hopeless anyway. The answer is the same for an
unknown username, and the response time too: the server always computes ten Argon2 hashes, so
timing does not reveal which accounts exist. dave's normal login is not affected.

---

## 11. Centralised revocation, three levels (B + K, 3 min)

### 11a. One certificate: dave (⌨)

```bash
SERIAL=$(openssl x509 -in clients/dave/cert.pem -noout -serial | cut -d= -f2); echo "$SERIAL"
mtls clients/dave -c /tmp/dave.jar -X POST $APP/api/login -H "$J" -d '{}' | head -1          # 200
admin -X POST $APP/api/admin/certificates/$SERIAL/revoke -d '{"reason":"KEY_COMPROMISE"}'
mtls clients/dave -b /tmp/dave.jar $APP/api/me                                                # 1. immediately
```

In Terminal B: `[crl-watch] ... CRL changed, nginx reloaded` (about 2 seconds later).

```bash
mtls clients/dave -X POST $APP/api/login -H "$J" -d '{}'                                      # 2. after the reload
curl -sS --cacert $CA $PUB/crl/users-ca.crl | openssl crl -inform DER -noout -text | grep -A1 "$SERIAL"
```

**Result:** first `403 certificate_revoked` (the open session dies at once, application
level), then `403 ... FAILED:certificate revoked` from **nginx**, and dave's serial in the signed CRL.

Two independent layers. The database status is checked on every request, so revocation is
**immediate**. Then the backend signs a new CRL and nginx reloads it: from now on the TLS handshake
itself fails. This is the fifth required negative case, a revoked certificate. The CRL is valid
24 hours and refreshed every 10 minutes; if it ever expired, nginx would refuse everybody: we fail
closed." (The same is one click: button **Revoke** in the *Certificates* table.)

### 11b. One user, with disable: alice leaves the company (🖱)

Reload the admin page → table *Users* → line `alice` → **Revoke + disable** → *"alice revoked
and disabled."*; alice is `DISABLED` with 0 active certificates.

```bash
mtls clients/alice-new3 -b /tmp/alice.jar $APP/api/me                                           # her open session
./scripts/recover.sh --username alice --code "$(sed -n 4p clients/alice/backup-codes.txt)" --out /tmp/alice-back-$$
```

**Result:** `403 certificate_revoked`, then `invalid_credentials` although code 4 is a
**valid, unused** code.

A departing employee must not come back with her code sheet: a disabled account cannot recover.

### 11c. A whole group: the interns (🖱)

Bob keeps a session open:

```bash
mtls clients/bob-new2 -c /tmp/bob.jar -X POST $APP/api/login -H "$J" -d '{}' | head -1
```

Admin page → **Revoke a whole group** → `interns`, reason *affiliationChanged*, leave *Also
disable the accounts* unticked → **Revoke group** (confirm) → *"Group interns: 1 certificate(s)
revoked, 1 account(s) affected."*

```bash
mtls clients/bob-new2 -b /tmp/bob.jar $APP/api/me                    # immediately
sleep 3; mtls clients/bob-new2 -X POST $APP/api/login -H "$J" -d '{}'  # after the CRL reload
```

**Result:** `403 certificate_revoked`, then `FAILED:certificate revoked`.

The group is the OU written in every certificate, so the end of an internship is one click.

**Optional (K), lock-out protection:** *Revoke a whole group* → `admins` → red message *"Revoking the
whole admins group would lock every administrator out. Revoke admins one by one."*

---

## 12. Audit log (B, 30 s)

Reload the admin page, scroll to **Audit log**.

Every login, refusal, enrolment, issuance, revocation, reset, rate limit and admin access is
recorded with time, user, IP and certificate serial. The same lines go to the container output in a
key=value format that a SIEM can collect. Secrets such as backup codes or tokens are never logged.

Optional proof:

```bash
docker compose logs backend | grep AUDIT | tail -3
docker compose logs backend | grep -c "$CODE"        # 0: the backup code never appears
```

---

## 13. Tests and findings (K, 1 min)

```bash
grep -H "PASS=" tests/logs/*.log
```

**Result:** one line per run: `PASS=29 FAIL=0` (attacks), `PASS=31 FAIL=4` (first run of
the security tests) and `PASS=35 FAIL=0` (final run).

The first run had four failures, and all four were mistakes in our test script, not in the
application: for example we expected the wrong OpenSSL message. We fixed the script and kept the
log as evidence.
Two scripts against the real stack: 35 checks for the required cases and the main defences, 29
attack scenarios from the threat model, for example two parallel requests with the same backup code
to test the race condition, or an expired CRL. Everything passes. They also found two real problems:
the Content-Security-Policy lacked `object-src 'none'` (F1), and the magic-link request was about
twice slower for an existing e-mail, 43 versus 20 ms, which reveals which addresses exist (F2). The
Builder moved that work to a background worker; the re-test shows 13 versus 13 ms.

(Do **not** run the scripts live during the main demo: they restart the backend and close every
session. Run them only if the teacher asks, about 1 minute each.)

---

## 14. Threat model, ASVS and conclusion (W, 2 min)

In `docs/THREAT-MODEL.md`, two rows:
- **S4** stolen cookie → session bound to the certificate → test T11 (shown in act 6).
- **E1** abuse of the reset → single-use codes, rate limit, race protection → tests T8, A7 (acts 8 and 10).

The central question of the assignment:
Do the additions make the system stronger or weaker?
- The **second device** slightly enlarges the attack surface but greatly improves availability; it
  can only be added from an authenticated session and is revocable on its own.
- **Backup codes** are neutral to positive: offline, single use, Argon2id, rate limited, and they
  cannot log in, only reset.
- Every **reset** lowers the account to its weakest accepted proof: by code, to the code sheet; by
  magic link, to the mailbox. That is why the reset is rate limited, notified, revokes everything,
  and why admins cannot use the magic link.
- **Revocation** clearly increases security: a stolen certificate dies in seconds instead of
  remaining valid up to 180 days. Its cost is a dependency on CRL freshness, and we fail closed.

Overall security improves, because recovery becomes explicit, limited and visible instead of an
ad-hoc help-desk procedure. And as you saw, the security is in the server: the script and the
browser are only convenient front-ends, and both get exactly the same answers as raw curl.

In `docs/ASVS-CHECKLIST.md`:
ASVS 5.0 Level 1, chapters V6 and V7: 11 applicable requirements, 10 met, one not met: 6.3.2,
because an account named `admin` exists, although without any default password. Eight are not
applicable because there are no passwords.

Accepted residual risks:
The Users CA key is online on the backend host (in production: an HSM; the offline root can still
revoke the whole Users CA), e-mail recovery for regular users, availability tied to CRL freshness,
and rate limits kept in memory on a single instance.

Thank you, we are ready for your questions.

---

## 15. Bonus if asked: expired CRL, fail closed (K, 1 min)

⚠️ Every login fails until the restore command. Run it only if asked.

```bash
CA_DIR=pki/out/users-ca openssl ca -config pki/conf/ca.cnf -gencrl -crlsec 1 \
   -passin file:pki/out/users-ca/private/ca.pass -out /tmp/short.crl.pem 2>/dev/null
cat pki/out/root-ca/ca.crl.pem /tmp/short.crl.pem > /tmp/stale-bundle.pem
sleep 2; docker compose cp /tmp/stale-bundle.pem backend:/var/lib/mtls/crl/crl-bundle.pem
sleep 5; mtls clients/admin -X POST $APP/api/login -H "$J" -d '{}'       # FAILED:CRL has expired

docker compose restart backend; sleep 25                                  # restore: fresh CRL at start-up
mtls clients/admin -X POST $APP/api/login -H "$J" -d '{}' | head -1       # HTTP/2 200
```

Other demos ready in [ManualTest.md](ManualTest.md) if a question needs them: CSRF (§8.5), CSR asking
for `OU=admins` (§9.2), IDOR (§9.3), forged proxy headers and nginx bypass (§16), TLS 1.2 refused (§3),
re-enabling a disabled user (§14.2).

---

## 16. Shorter versions

**15 minutes:** keep one way per feature for the repeated acts, and **name** the others in one
sentence ("the same works with our script and in the browser"):
- act 4: 4a (by hand) and 4c (browser); skip 4b;
- act 7: 7a only;
- act 8: 8a (script) and 8c (browser); skip 8b;
- act 9: 9b (browser) only, plus the two `req` lines of 9a for the generic answer;
- act 11: 11a and 11c; skip 11b.

**10 minutes:** acts **1, 3, 4a, 5, 8a, 10, 11a, 14** and a shorter speech; mention the others.

Removing a sub-act also lowers the rate-limit budget used, so the order stays valid.

---

## 17. If something goes wrong

| Symptom | Cause | Fix |
| --- | --- | --- |
| `429 rate_limited` when you do not expect it | the 20 recovery requests per IP per 15 min are used (a command was repeated), or counters left from a rehearsal | say *"this is the rate limit defending us"*, then `docker compose restart backend`, wait 20 s, `mtls clients/admin -c /tmp/admin.jar -X POST $APP/api/login -H "$J" -d '{}'`, reload the admin page and sign in again |
| `grab` says `cannot stat .../cert.pem` | the browser saved the file elsewhere, or as `cert (1).pem` | check `ls "$DL"`; fix `DL=...`; delete old downloads (`rm "$DL"/cert*.pem "$DL"/chain*.pem`) and download again |
| The page says the CSR is invalid | the paste is incomplete or empty | `copycsr clients/<name>` again, click in the field, `Ctrl+V`: the text must start with `-----BEGIN CERTIFICATE REQUEST-----` |
| The enrolment page shows an empty token field | link opened without its `#token=...` | click the link in Mailpit again |
| *"Invalid or expired recovery link."* in the browser | the link was already used or is older than 15 min | ask for a new link (at most 3 per address per hour) |
| `key_reuse` | the same CSR / key was already certified | `newkey` into a **new** folder |
| The browser does not ask for a certificate, or uses an old one | browser cache of the TLS choice | `chrome://restart` (or `edge://restart`); check `certmgr.msc` → *Personal* |
| Browser `NET::ERR_CERT_AUTHORITY_INVALID` | root CA not trusted (or PKI rebuilt) | import `pki\out\root-ca\ca.crt` again |
| *"This certificate is not registered."* for admin | database reset but old `clients/admin` | `rm -rf clients/admin && ./scripts/enroll.sh --bootstrap-admin`, re-import the `.p12` |
| `invalid_token` at enrolment | invitation already used | `admin -X POST $APP/api/admin/users/<u>/enable` (or the **Invite** button) for a new token |
| `... already contains a certificate` | output folder exists from the rehearsal | use another `--out` folder or `rm -rf clients/<name>` |
| No `crl-watch` line in Terminal B | log command started before nginx restarted | `docker compose logs --since 30s nginx \| grep crl-watch` |
| `curl: (7) Failed to connect` | stack not running | `docker compose ps`; `docker compose up -d`; check `docker compose logs backend` |
| `docker: command not found` / daemon not running | Docker in WSL not started | start Docker in WSL (`sudo service docker start`), then `docker compose up -d` |
| Mailpit shows nothing | e-mails are sent asynchronously | wait 1–2 seconds and refresh |

Golden rule: if an act fails, **say what should happen**, show the matching line in
`tests/logs/` (the evidence already exists), and move on. Do not debug in front of the audience.

---

## 18. After the demo

```bash
docker compose down        # stop (keep data), or down -v to delete the database too
```

Remove the imported *admin* certificate and the root CA from the Windows store when the course is
over.
