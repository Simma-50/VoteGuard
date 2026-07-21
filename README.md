# VoteGuard — PKI-Based Corporate Board of Directors Election System

VoteGuard ensures only verified board directors can cast **encrypted,
tamper-proof votes**, using X.509 digital certificates, RSA/AES cryptography,
and email-based multi-factor authentication. Director accounts are created
exclusively by an Election Official/Admin — there is no public self-service
registration. It's a runnable implementation of the PKI-Based Secure E-Voting
Architecture, built with Node.js — no external database, no cloud services,
no OpenSSL binary required.

The interface is a role-based enterprise console (sidebar navigation, topbar
notifications, operational status widgets) in the style of Azure Portal / AWS
Console / Keycloak Admin Console — not a demo or documentation site.

## What's preserved vs. what changed

**Preserved exactly as before:** the PKI architecture (`pki/ca.js`,
`pki/certService.js`), all cryptography (`pki/cryptoService.js` — AES-256-GCM
ballot encryption, SHA-256 hashing, RSA-PSS signing), JWT issuance/verification
mechanics, the database "schema" (JSON record shapes in `db/store.js`), and
every existing route's contract. `routes/voter.js`'s vote-casting and
receipt-verification logic, `routes/audit.js`, and `utils/logger.js`
(the hash-chained audit log) are untouched.

**Changed, as explicitly required by this revision:**
- **Self-registration removed.** The public `POST /api/auth/register` route
  no longer exists. Directors are onboarded only via
  `POST /api/admin/directors`, callable exclusively by an
  `election_official`.
- **Admin-managed director lifecycle**, added to `routes/admin.js`: create,
  disable/enable, reset password, renew certificate — alongside the
  certificate revocation endpoint that already existed.
- **Forced first-login password change**, added to `routes/auth.js`
  (`POST /api/auth/force-change-password`): a director created by the Admin
  must set their own password before MFA is issued. This uses the same
  bcrypt hashing already in use — no new hashing scheme.
- **Live "disabled" check**, added to `middleware/auth.js`: an Admin
  disabling a director now takes effect immediately, even against an
  already-issued JWT — without changing how the JWT itself is signed or
  verified.
- **A director's own certificate view**, added to `routes/voter.js`
  (`GET /api/voter/certificate`): returns the director's own public
  certificate only — the private signing key is never returned by this or
  any other endpoint after initial issuance; it stays server-side, where it
  already was, and is used only internally to sign that director's ballots.
- **Candidate edits locked while the election is open** — a guard clause in
  the existing `POST /api/admin/candidates` / `DELETE /api/admin/candidates/:id`
  handlers, not a new mechanism.
- **Email OTP delivery** (`utils/mailer.js`, Nodemailer/Gmail SMTP) in place
  of the OTP ever being shown on screen or returned in an API response.
- **Seed content**: the default admin account, board candidate slate, and
  election title reflect the Corporate Board of Directors scenario.

No cryptographic primitive, JWT signing mechanism, or existing route's
behavior for an already-authorized caller was altered.

## Requirements

- Node.js 16+ (18+ recommended)
- No native build tools needed — every backend dependency (`express`,
  `node-forge`, `bcryptjs`, `jsonwebtoken`, `uuid`, `cors`, `nodemailer`,
  `dotenv`) is pure JavaScript.
- The frontend loads Bootstrap 5, Bootstrap Icons, Google Fonts (Inter), and
  Chart.js from public CDNs — an internet connection in the browser is
  needed to see the styling/icons/charts/fonts. No frontend build step.

## Setup

```bash
cd voteguard
npm install
cp .env.example .env   # then fill in GMAIL_USER / GMAIL_APP_PASSWORD (see below)
npm start
```

Then open **http://localhost:4000**.

### Configuring real email delivery (Gmail SMTP)

1. Enable 2-Step Verification on the Gmail account you want to send from.
2. Generate an **App Password** at <https://myaccount.google.com/apppasswords>
   (a 16-character code — not your normal Gmail password).
3. In `.env`:
   ```
   GMAIL_USER=youraddress@gmail.com
   GMAIL_APP_PASSWORD=xxxxxxxxxxxxxxxx
   ```
4. Restart the server. OTP codes, director welcome emails, and password-reset
   emails will now be sent for real.

**If you skip this step**, the app still runs — every email (OTP, welcome
credentials, password reset) is printed to the server console instead, so
you can test the entire flow without a Gmail account. The OTP is never shown
in the browser or returned in any API response either way — only whether an
email was sent.

On first run the server automatically:
- Generates a root Certificate Authority (`data/pki/ca-cert.pem`, `ca-key.pem`)
- Generates the AES-256 ballot encryption key (`data/pki/election-aes.key`)
- Seeds two accounts:
  - **Admin (Election Official)** — `admin` / `Admin@123`
  - **Auditor** — `auditor1` / `Auditor@123`
- Seeds the board candidate slate (below)

There is no self-registration page. Every director account must be created
by the Admin from **Manage Directors**.

## Board candidates (this election)

| Candidate | Position | Department |
|---|---|---|
| Sushma Rai | Board Director | Finance |
| Hari Basnet | Board Director | Operations |
| Jaya Thapa | Board Director | Human Resources |
| Kiran Singh | Board Director | Technology |

Candidates can be added/removed from **Candidates** only while the election
is closed; the UI disables those controls (and the API rejects the request)
once the election is opened.

## The full login flow

1. **Username → Password.** If this account has never signed in
   (`mustChangePassword`), the response stops here and the UI shows a
   "set a new password" step — no OTP is issued yet.
2. **Forced password change** (first login only). Submits the temporary
   password + a new one to `/api/auth/force-change-password`. On success,
   this immediately continues to step 3 (no separate re-login required).
3. **Certificate validation.** The server confirms the director's X.509
   certificate is present, unexpired, and not on the revocation list.
4. **Email OTP.** A 6-digit code is emailed (or console-logged if SMTP isn't
   configured), valid for 60 seconds, with a 20-second resend cooldown.
5. **OTP verification → JWT.** A 20-minute session token is issued, tagged
   with the director's role, and the browser is redirected to the
   role-appropriate dashboard.

## How an Admin onboards a director

From **Manage Directors**:
1. Enter a username and email, click **Create Director**.
2. The server generates a random temporary password, issues an X.509
   certificate via the existing PKI/certificate service, and emails (or
   console-logs) the username + temporary password. **No password,
   certificate, or private key is ever shown in the Admin's browser** at
   this step.
3. The director completes the first-login flow above. Their certificate can
   later be viewed (public cert only) from their own **Certificate** page
   after logging in, behind a collapsible "Advanced Details" panel.
4. From the same **Manage Directors** table, the Admin can at any time:
   **Reset Password** (emails a fresh temporary password, forces another
   change on next login), **Renew Certificate** (issues a new certificate and
   revokes the old one), **Revoke Certificate**, **Disable/Enable Account**,
   or **View Profile**.

## Frontend pages

| Role | Pages |
|---|---|
| Before login | `index.html` (status-only landing page), `login.html` |
| Director | `voter-dashboard.html`, `vote.html`, `receipt.html`, `verify.html`, `certificate.html`, `profile.html` |
| Election Official / Admin | `official-dashboard.html`, `admin.html` (Manage Election), `directors.html` (Manage Directors), `candidates.html`, `certificates.html` (Certificate Repository), `results.html`, `audit.html` |
| Auditor | `auditor-dashboard.html`, `audit.html`, `verify-integrity.html`, `results.html` |

The landing page shows only the VoteGuard name, the election scenario, five
live status widgets (System, Election, Certificate Authority, Certificate
Repository, Audit Log — powered by the new unauthenticated
`GET /api/public/status`, which exposes only safe aggregate booleans/counts,
no PII or log contents), and a single **Sign In** button. There is no
Register button and no cryptographic-algorithm badges on this page.

## Try breaking it (useful for a VAPT report)

```bash
node -e "
const fs = require('fs');
const votes = JSON.parse(fs.readFileSync('data/store/votes.json'));
votes[0].ciphertext = votes[0].ciphertext.slice(0, -4) + 'ffff';
fs.writeFileSync('data/store/votes.json', JSON.stringify(votes, null, 2));
"
```
Then check `/results.html` — the tampered ballot is flagged and excluded from
the tally. Editing `data/store/auditLogs.json` similarly breaks the hash
chain, detected by "Verify Chain" on `/audit.html` or `/verify-integrity.html`.

## Production hardening notes (intentionally out of scope for this demo)

- **TLS/HTTPS** in front of the app (e.g. Nginx) for the Secure Channel.
- **Client-side key generation** (WebCrypto or HSM) instead of server-side
  RSA key pair generation, so private keys never touch the server at all —
  today the server generates and holds them so it can sign each director's
  ballot on their behalf, which is why the private key is never returned to
  any client, including the Admin at account-creation time.
- **A real database** (PostgreSQL/MongoDB) instead of the JSON files here.
- **A transactional email provider** (SES, SendGrid, etc.) instead of Gmail
  SMTP for production-scale delivery.
- **A published OCSP responder / CRL endpoint** and HSM-backed CA.
- **Real backup/DR tooling** — the "Backup" status widget intentionally
  reads "Not Configured" since no backup mechanism exists in this demo.
- Rate limiting, SIEM export, and independent security review before any
  real board election use.

## Project structure

```
voteguard/
  server.js                 # bootstrap: CA, seed admin/auditor/candidates
  config.js                  # OTP TTL/resend cooldown, SMTP env wiring
  .env.example                # copy to .env and fill in Gmail credentials
  pki/
    ca.js                      # Certificate Authority (unchanged)
    certService.js             # issue / verify director certificates (unchanged)
    cryptoService.js           # AES-256-GCM + RSA-PSS + SHA-256 (unchanged)
  db/store.js                # JSON file-based data store (unchanged)
  routes/
    auth.js                    # login, forced password change, OTP, resend, verify
    voter.js                   # candidates, own certificate, cast vote, verify receipt
    admin.js                   # directors CRUD, candidates, election, revocation
    audit.js                   # results tally, audit logs, CRL, certificates (unchanged)
  middleware/auth.js          # JWT auth + role check + live disabled-account check
  utils/
    otp.js                      # OTP generation/verification + resend cooldown
    mailer.js                   # Nodemailer/Gmail SMTP: OTP, welcome, reset emails
    passwordGen.js               # temporary password generator
    logger.js                   # tamper-evident (hash-chained) audit logging (unchanged)
  public/                     # enterprise console frontend (Bootstrap 5)
    css/app.css                  # sidebar/topbar shell, status widgets, stepper
    js/common.js                  # session/API helpers, sidebar nav, notifications
    index.html, login.html        # no register page — admin-managed onboarding only
    voter-dashboard.html, vote.html, receipt.html, verify.html,
    certificate.html, profile.html
    official-dashboard.html, admin.html, directors.html, candidates.html,
    certificates.html, results.html, audit.html
    auditor-dashboard.html, verify-integrity.html
  data/                      # generated at runtime (CA, keys, JSON "database")
```
