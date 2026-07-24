"""
database.py
============
SQLite database layer for the secure login system.

SQL INJECTION PROTECTION
-------------------------
Every query in this file uses parameterized placeholders ('?') with
values passed separately via the `params` tuple, NEVER via string
formatting/concatenation. This is the actual defense against SQL
injection — the database driver treats parameters strictly as data,
never as executable SQL, no matter what characters they contain.

    # VULNERABLE (never do this):
    #   cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    #   An attacker could submit  username = "' OR '1'='1"  and read/alter
    #   arbitrary rows, or worse (e.g. "'; DROP TABLE users; --").
    #
    # SAFE (what this file does):
    #   cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    #   The value is sent to SQLite separately from the query structure,
    #   so it can never change the meaning of the SQL statement.

We use Python's built-in `sqlite3` directly (rather than an ORM) so the
parameterization is explicit and easy to learn from. In a larger app,
an ORM like SQLAlchemy gives you this protection by default.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = "secure_login.db"


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                totp_enabled INTEGER NOT NULL DEFAULT 0,
                failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS login_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username_attempted TEXT,
                success INTEGER NOT NULL,
                ip_address TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                token TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)


def create_user(username, email, password_hash):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, created_at) "
            "VALUES (?, ?, ?, ?)",
            (username, email, password_hash, datetime.now(timezone.utc).isoformat()),
        )


def get_user_by_username(username):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return dict(row) if row else None


def get_user_by_email(email):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return dict(row) if row else None


def set_totp_secret(user_id, secret):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user_id)
        )


def enable_totp(user_id):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET totp_enabled = 1 WHERE id = ?", (user_id,)
        )


def disable_totp(user_id):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?",
            (user_id,),
        )


def record_login_attempt(user_id, username_attempted, success, ip_address):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO login_events (user_id, username_attempted, success, "
            "ip_address, timestamp) VALUES (?, ?, ?, ?, ?)",
            (user_id, username_attempted, int(success), ip_address,
             datetime.now(timezone.utc).isoformat()),
        )


def increment_failed_attempts(user_id):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 "
            "WHERE id = ?", (user_id,)
        )
        row = conn.execute(
            "SELECT failed_login_attempts FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return row["failed_login_attempts"] if row else 0


def reset_failed_attempts(user_id):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL "
            "WHERE id = ?", (user_id,)
        )


def set_lock(user_id, locked_until_iso):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET locked_until = ? WHERE id = ?",
            (locked_until_iso, user_id),
        )


def get_recent_login_events(user_id, limit=10):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM login_events WHERE user_id = ? "
            "ORDER BY timestamp DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


# Password reset functions
def create_password_reset_token(user_id, token, expires_at_iso):
    """Create a password reset token for a user"""
    with get_db() as conn:
        conn.execute(
            "INSERT INTO password_reset_tokens (user_id, token, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (user_id, token, datetime.now(timezone.utc).isoformat(), expires_at_iso),
        )


def get_reset_token(token):
    """Retrieve a password reset token if it's valid (not expired)"""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM password_reset_tokens WHERE token = ?", (token,)
        ).fetchone()
        
        if not row:
            return None
        
        # Check if token has expired
        token_dict = dict(row)
        expires_at = datetime.fromisoformat(token_dict["expires_at"])
        if datetime.now(timezone.utc) > expires_at:
            # Token expired, delete it
            conn.execute(
                "DELETE FROM password_reset_tokens WHERE token = ?", (token,)
            )
            return None
        
        return token_dict


def update_password(user_id, new_password_hash):
    """Update user's password"""
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_password_hash, user_id),
        )


def delete_reset_token(token):
    """Delete a password reset token after it's been used"""
    with get_db() as conn:
        conn.execute(
            "DELETE FROM password_reset_tokens WHERE token = ?", (token,)
        )


def delete_user_reset_tokens(user_id):
    """Delete all reset tokens for a user (when password is reset)"""
    with get_db() as conn:
        conn.execute(
            "DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,)
        )
