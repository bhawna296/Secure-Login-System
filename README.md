[README.md](https://github.com/user-attachments/files/30362536/README.md)
# Secure Login System

A Flask web app demonstrating the core building blocks of secure
authentication: hashed passwords, SQL-injection-proof queries, CSRF
protection, session management, account lockout, rate limiting, and
optional TOTP-based two-factor authentication.

## Project structure

| File | Purpose |
|---|---|
| `app.py` | Main Flask app — routes, session wiring, Flask-Login setup |
| `database.py` | SQLite layer — every query is parameterized (SQL injection defense) |
| `auth.py` | Argon2id password hashing, password/username validation, lockout logic |
| `forms.py` | Flask-WTF forms — CSRF protection + server-side input validation |
| `templates/` | Jinja2 HTML templates |
| `static/style.css` | Styling |
| `requirements.txt` | Exact dependency versions used during development |

## Security features implemented

1. **Password hashing — Argon2id** (`auth.py`). OWASP's current
   recommendation over bcrypt for new projects. Passwords are never
   stored, logged, or transmitted in plaintext after submission —
   only the one-way hash is kept.
2. **SQL injection protection** (`database.py`). Every query uses `?`
   parameterized placeholders; user input is never concatenated or
   f-string-interpolated into SQL. See the comment at the top of
   `database.py` for a vulnerable-vs-safe comparison.
3. **CSRF protection** (`forms.py` + Flask-WTF). Every form includes a
   signed token that's validated on submit, so a malicious site can't
   trick a logged-in user's browser into submitting requests here.
4. **Session management** (`app.py`, via Flask-Login). Signed,
   `HttpOnly`, `SameSite=Lax` session cookies; `@login_required`
   guards protected routes; `/logout` fully clears the session.
5. **Account lockout**: 5 failed password attempts locks the account
   for 15 minutes (brute-force defense).
6. **Rate limiting** (Flask-Limiter): a second layer against
   brute-force / credential-stuffing on `/login` and `/register`.
7. **Optional TOTP 2FA** (`pyotp` + `qrcode`): standard
   Google-Authenticator-compatible flow — scan a QR code, confirm one
   code to enable, then every login requires a fresh 6-digit code.
8. **User-enumeration resistance**: login failures always show the
   same generic "Invalid username or password" message, whether the
   username exists or not.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python3 app.py
```

Open **http://127.0.0.1:5000** in your browser. First visit redirects
to `/login`; click through to `/register` to create an account.

## Password requirements (enforced server-side)

At least 10 characters, containing an uppercase letter, a lowercase
letter, a digit, and a special character. A short list of common
"technically strong" passwords (e.g. `Password123!`) is explicitly
rejected too.

## Setting up 2FA

1. Log in, then click **Enable 2FA** on the dashboard.
2. Scan the QR code with Google Authenticator, Authy, or any TOTP app
   (or type in the secret manually — it's shown below the QR code).
3. Enter the 6-digit code the app shows to confirm setup.
4. From then on, login requires your password **and** a fresh code.

## How I tested this (and a bug I actually found)

I ran the app end-to-end with `curl`, not just by reading the code:

- **Registration** → confirmed the stored value in SQLite is a real
  `$argon2id$...` hash, never the plaintext password.
- **SQL injection**: submitted `admin' OR '1'='1` and a
  `'; DROP TABLE users; --` payload as the username. Both were
  treated as literal (nonexistent) usernames — rejected with the
  generic error, and the `users` table was untouched afterward.
- **CSRF**: submitted a registration POST with no CSRF token. It
  silently failed validation — no account was created.
- **Login/session**: logged in, hit the protected dashboard route,
  logged out, and confirmed the dashboard then redirects to `/login`.
- **2FA**: completed a full enrollment (extracted the TOTP secret from
  the setup page, generated a real code for it in Python, submitted
  it — 2FA turned on in the database). Then confirmed **password
  alone no longer grants dashboard access** — it correctly redirects
  to the 2FA challenge — and that a valid generated code completes
  login while a wrong code is rejected.
- **Account lockout**: exercised `auth.register_failed_attempt`
  directly and confirmed the account locks after exactly 5 failures
  and `is_locked()` returns `True` afterward.

**A real bug this caught**: the first version of `app.py` called
`auth.reset_failed_attempts(...)` after a correct password, but that
function actually lives in `database.py`, not `auth.py` — so every
successful login crashed with a 500 error. This is exactly the kind
of mistake that's invisible from reading the code casually (both
modules are imported as `auth` / `db`, and the function names read
fine in isolation) but shows up immediately once you actually run the
login flow. Fixed by calling `db.reset_failed_attempts(...)` instead
— worth remembering as a reason to actually execute security code, not
just review it.

## Known limitations / what a production app would add

This is a learning project. Before treating any variant of this as
production-ready:

- **HTTPS everywhere.** Cookies are only marked `Secure` when
  `FLASK_ENV=production`; in real deployment you'd terminate TLS and
  enforce HTTPS unconditionally.
- **`SECRET_KEY`** is randomly generated per process start here (so
  sessions don't survive a restart). In production, load a fixed
  secret from an environment variable or secrets manager.
- **Rate limiter storage** is in-memory (fine for one process; use
  Redis or similar for a multi-worker deployment — Flask-Limiter warns
  about this on startup).
- **Email verification** isn't implemented — registration doesn't
  confirm the email address is real/owned by the registrant.
- **Password reset flow** isn't implemented (a real app needs a secure
  "forgot password" email-token flow).
- **`debug=True`** must never be used in production — it exposes an
  interactive debugger that allows arbitrary code execution if
  someone reaches an error page.
- **Backup/recovery codes for 2FA** aren't implemented — if a user
  loses their authenticator device, this demo has no account-recovery
  path (a real app needs one, carefully designed so it doesn't become
  its own bypass vulnerability).
- Consider a Web Application Firewall, structured logging/alerting on
  repeated failures, and a proper security review before any real
  deployment.
