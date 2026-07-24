#!/usr/bin/env python3
"""
app.py
=======
Secure Login System — main Flask application.

Run with:
    python3 app.py

Then open http://127.0.0.1:5000 in your browser.

SECURITY FEATURES IMPLEMENTED
-------------------------------
1. Password hashing with Argon2id (auth.py) — passwords are never
   stored or logged in plaintext.
2. SQL injection protection via parameterized queries everywhere
   (database.py) — no query is ever built with string concatenation
   or f-strings containing user input.
3. Input validation & CSRF protection via Flask-WTF forms (forms.py).
4. Session management via Flask-Login: secure, signed session cookies;
   `@login_required` guards protected routes; explicit logout clears
   the session.
5. Account lockout after repeated failed logins (brute-force defense).
6. Rate limiting on the login/register endpoints (Flask-Limiter) as a
   second layer of brute-force / credential-stuffing defense.
7. Optional TOTP-based Two-Factor Authentication (compatible with
   Google Authenticator, Authy, etc.), including a QR-code setup flow.
8. Secure cookie flags (HttpOnly, SameSite) and a generic "invalid
   username or password" error message that doesn't reveal whether
   the username exists (prevents user enumeration).

This is a learning project. Read SECURITY_NOTES in README.md before
considering any variant of this production-ready.
"""

import base64
import io
import os
import secrets

import pyotp
import qrcode
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                          login_required, current_user)

import auth
import database as db
from forms import RegisterForm, LoginForm, TOTPForm

app = Flask(__name__)

# SECRET_KEY signs the session cookie. In production, load this from an
# environment variable / secrets manager — never hardcode it or commit
# it to source control. We generate a random one here for local demo
# purposes only, which means sessions won't survive an app restart.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Cookie hardening:
app.config["SESSION_COOKIE_HTTPONLY"] = True   # JS can't read the cookie (mitigates XSS session theft)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # mitigates CSRF via cross-site requests
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"  # HTTPS-only in prod

db.init_db()

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."

limiter = Limiter(get_remote_address, app=app, default_limits=[])


class User(UserMixin):
    """Thin adapter so Flask-Login can work with our sqlite user rows."""
    def __init__(self, row):
        self.id = str(row["id"])
        self.username = row["username"]
        self.email = row["email"]
        self.totp_enabled = bool(row["totp_enabled"])


@login_manager.user_loader
def load_user(user_id):
    row = db.get_user_by_id(int(user_id))
    return User(row) if row else None


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        password = form.password.data

        username_error = auth.validate_username(username)
        password_error = auth.validate_password_strength(password)

        if username_error:
            flash(username_error, "error")
        elif password_error:
            flash(password_error, "error")
        elif db.get_user_by_username(username):
            flash("That username is already taken.", "error")
        elif db.get_user_by_email(email):
            flash("An account with that email already exists.", "error")
        else:
            password_hash = auth.hash_password(password)
            db.create_user(username, email, password_hash)
            flash("Account created! You can now log in.", "success")
            return redirect(url_for("login"))

    return render_template("register.html", form=form)


# ---------------------------------------------------------------------------
# Login (+ TOTP second factor)
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        user = db.get_user_by_username(username)

        # Generic error message on every failure path below —
        # never reveal whether the username exists (defends against
        # username enumeration).
        generic_error = "Invalid username or password."

        if user is None:
            flash(generic_error, "error")
            db.record_login_attempt(None, username, success=False,
                                     ip_address=request.remote_addr)
            return render_template("login.html", form=form)

        if auth.is_locked(user):
            remaining = auth.lock_seconds_remaining(user)
            flash(f"Account temporarily locked. Try again in "
                  f"{remaining // 60 + 1} minute(s).", "error")
            return render_template("login.html", form=form)
        
        # If lockout has expired, reset the failed attempts counter
        if user.get("failed_login_attempts") > 0 and not auth.is_locked(user):
            db.reset_failed_attempts(user["id"])
            user = db.get_user_by_username(username)  # Refresh user data

        if not auth.verify_password(password, user["password_hash"]):
            just_locked = auth.register_failed_attempt(user)
            db.record_login_attempt(user["id"], username, success=False,
                                     ip_address=request.remote_addr)
            if just_locked:
                flash(f"Too many failed attempts. Account locked for "
                      f"{auth.LOCKOUT_MINUTES} minutes.", "error")
            else:
                flash(generic_error, "error")
            return render_template("login.html", form=form)

        # Password correct.
        db.reset_failed_attempts(user["id"])

        if user["totp_enabled"]:
            # Don't log in yet — stash a pending user id and send them
            # to the 2FA challenge. Nothing session-wise grants access
            # until the TOTP code is also verified.
            session["pending_2fa_user_id"] = user["id"]
            return redirect(url_for("verify_2fa"))

        db.record_login_attempt(user["id"], username, success=True,
                                 ip_address=request.remote_addr)
        login_user(User(user))
        flash("Logged in successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html", form=form)


@app.route("/verify-2fa", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def verify_2fa():
    pending_id = session.get("pending_2fa_user_id")
    if not pending_id:
        return redirect(url_for("login"))

    user = db.get_user_by_id(pending_id)
    if not user:
        session.pop("pending_2fa_user_id", None)
        return redirect(url_for("login"))

    form = TOTPForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(user["totp_secret"])
        if totp.verify(form.token.data, valid_window=1):
            session.pop("pending_2fa_user_id", None)
            db.record_login_attempt(user["id"], user["username"], success=True,
                                     ip_address=request.remote_addr)
            login_user(User(user))
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        else:
            db.record_login_attempt(user["id"], user["username"], success=False,
                                     ip_address=request.remote_addr)
            flash("Invalid authentication code.", "error")

    return render_template("verify_2fa.html", form=form)


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard (protected)
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def dashboard():
    events = db.get_recent_login_events(int(current_user.id), limit=5)
    return render_template("dashboard.html", user=current_user, events=events)


# ---------------------------------------------------------------------------
# 2FA setup / disable
# ---------------------------------------------------------------------------

@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user = db.get_user_by_id(int(current_user.id))
    if user["totp_enabled"]:
        flash("Two-factor authentication is already enabled.", "info")
        return redirect(url_for("dashboard"))

    if "new_totp_secret" not in session:
        session["new_totp_secret"] = pyotp.random_base32()

    secret = session["new_totp_secret"]
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user["email"], issuer_name="SecureLoginDemo")

    # Render QR code as a base64 PNG embedded directly in the page
    qr_img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode()

    form = TOTPForm()
    if form.validate_on_submit():
        totp_check = pyotp.TOTP(secret)
        if totp_check.verify(form.token.data, valid_window=1):
            db.set_totp_secret(int(current_user.id), secret)
            db.enable_totp(int(current_user.id))
            session.pop("new_totp_secret", None)
            flash("Two-factor authentication enabled!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Incorrect code. Scan the QR code and try again.", "error")

    return render_template("setup_2fa.html", form=form, qr_base64=qr_base64, secret=secret)


@app.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    db.disable_totp(int(current_user.id))
    flash("Two-factor authentication disabled.", "info")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# 2FA Regenerate
# ---------------------------------------------------------------------------

@app.route("/2fa/regenerate", methods=["GET"])
def regenerate_2fa():
    """
    Allow user to regenerate their 2FA secret when:
    1. Logged in with pending 2FA (in verify_2fa page)
    2. Or add it to dashboard for users who already have 2FA enabled
    """
    pending_id = session.get("pending_2fa_user_id")
    if not pending_id:
        # Not in 2FA flow, redirect to login
        flash("Please log in first.", "info")
        return redirect(url_for("login"))

    user = db.get_user_by_id(pending_id)
    if not user:
        session.pop("pending_2fa_user_id", None)
        return redirect(url_for("login"))

    # Generate new secret
    new_secret = pyotp.random_base32()
    session["regenerated_totp_secret"] = new_secret
    
    totp = pyotp.TOTP(new_secret)
    provisioning_uri = totp.provisioning_uri(name=user["email"], issuer_name="SecureLoginDemo")

    # Render QR code
    qr_img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode()

    return render_template("regenerate_2fa.html", secret=new_secret, qr_base64=qr_base64)


@app.route("/2fa/regenerate/confirm", methods=["POST"])
@limiter.limit("10 per minute")
def confirm_regenerate_2fa():
    """Confirm the regenerated 2FA secret by verifying a code"""
    pending_id = session.get("pending_2fa_user_id")
    if not pending_id:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for("login"))

    user = db.get_user_by_id(pending_id)
    if not user:
        session.pop("pending_2fa_user_id", None)
        return redirect(url_for("login"))

    regenerated_secret = session.get("regenerated_totp_secret")
    if not regenerated_secret:
        flash("No regenerated secret found. Please try again.", "error")
        return redirect(url_for("regenerate_2fa"))

    # Get the token from the form
    token = request.form.get("token", "").strip()
    if not token:
        flash("Please enter the 6-digit code.", "error")
        return redirect(url_for("regenerate_2fa"))

    # Verify the token
    totp = pyotp.TOTP(regenerated_secret)
    if totp.verify(token, valid_window=1):
        # Update the database with the new secret
        db.set_totp_secret(pending_id, regenerated_secret)
        session.pop("pending_2fa_user_id", None)
        session.pop("regenerated_totp_secret", None)
        
        db.record_login_attempt(user["id"], user["username"], success=True,
                                 ip_address=request.remote_addr)
        login_user(User(user))
        flash("Two-factor authentication verified and updated!", "success")
        return redirect(url_for("dashboard"))
    else:
        flash("Invalid code. Please try again.", "error")
        return redirect(url_for("regenerate_2fa"))


if __name__ == "__main__":
    # debug=True is for local learning/demo only — never run a Flask
    # app with debug=True in production (it exposes an interactive
    # debugger/console that allows arbitrary code execution).
    app.run(debug=True, port=5000)
