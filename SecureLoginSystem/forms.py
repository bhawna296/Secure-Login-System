"""
forms.py
=========
Flask-WTF forms. Using WTForms (rather than reading request.form
directly) buys us two important things for free:

  1. CSRF protection: every form includes a hidden token that Flask-WTF
     validates on submit, preventing Cross-Site Request Forgery (a
     malicious site tricking a logged-in user's browser into submitting
     a request to this app on their behalf).
  2. Structured server-side input validation, which we combine with the
     custom rules in auth.py for password strength / username format.

Note: HTML5 'required'/'type=email' attributes on the client side are
a UX nicety only — they are trivially bypassed, so all real validation
happens here on the server.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=32)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=10, max=128)])
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=32)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128)])
    submit = SubmitField("Log In")


class TOTPForm(FlaskForm):
    token = StringField("Authentication Code", validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField("Verify")


class ForgotPasswordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    submit = SubmitField("Send reset link")


class ResetPasswordForm(FlaskForm):
    password = PasswordField("New password", validators=[DataRequired(), Length(min=10, max=128)])
    confirm_password = PasswordField(
        "Confirm new password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Reset password")