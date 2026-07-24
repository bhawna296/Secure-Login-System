"""
auth.py
========
Password hashing and brute-force protection.

PASSWORD HASHING
-----------------
We use Argon2id (via argon2-cffi), the algorithm currently recommended
by OWASP over bcrypt for new projects, because it's resistant to both
GPU-cracking and side-channel attacks and its cost parameters are
tunable. bcrypt is also a fine choice (see BCRYPT_ALTERNATIVE.md-style
notes in the README) — swap PasswordHasher for `bcrypt.hashpw` if your
assignment specifically requires bcrypt.

We NEVER store or log plaintext passwords, anywhere, ever. The hash is
one-way: it can verify a password without letting us (or an attacker
who steals the database) recover the original.

ACCOUNT LOCKOUT
-----------------
After too many failed attempts, the account is temporarily locked.
This defends against online brute-force / credential-stuffing attacks
where an attacker just tries many passwords rapidly.
"""

import re
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash

import database as db

ph = PasswordHasher()  # sensible default cost parameters (time, memory, parallelism)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")


def hash_password(plain_password):
    return ph.hash(plain_password)


def verify_password(plain_password, password_hash):
    try:
        ph.verify(password_hash, plain_password)
        return True
    except (VerifyMismatchError, InvalidHash):
        return False


def needs_rehash(password_hash):
    """If Argon2 parameters were tightened since this hash was created,
    re-hash on next successful login (standard best practice)."""
    return ph.check_needs_rehash(password_hash)


def validate_username(username):
    if not username or not USERNAME_RE.match(username):
        return "Username must be 3-32 characters: letters, numbers, underscores only."
    return None


def validate_password_strength(password):
    if len(password) < 10:
        return "Password must be at least 10 characters long."
    if not re.search(r"[a-z]", password):
        return "Password must contain a lowercase letter."
    if not re.search(r"[A-Z]", password):
        return "Password must contain an uppercase letter."
    if not re.search(r"\d", password):
        return "Password must contain a digit."
    if not re.search(r"[^\w\s]", password):
        return "Password must contain a special character."
    # Reject a short list of extremely common passwords even if they
    # technically satisfy the rules above (e.g. "Password123!").
    common = {"password123!", "qwerty123!", "letmein123!", "welcome123!"}
    if password.lower() in common:
        return "That password is too common. Please choose another."
    return None


def is_locked(user):
    if not user.get("locked_until"):
        return False
    locked_until = datetime.fromisoformat(user["locked_until"])
    return datetime.now(timezone.utc) < locked_until


def lock_seconds_remaining(user):
    if not user.get("locked_until"):
        return 0
    locked_until = datetime.fromisoformat(user["locked_until"])
    remaining = (locked_until - datetime.now(timezone.utc)).total_seconds()
    return max(0, int(remaining))


def register_failed_attempt(user):
    attempts = db.increment_failed_attempts(user["id"])
    if attempts >= MAX_FAILED_ATTEMPTS:
        locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
        db.set_lock(user["id"], locked_until.isoformat())
        return True  # just got locked
    return False
