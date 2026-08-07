from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, g, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf.csrf import generate_csrf
from sqlalchemy import or_
from sqlalchemy.exc import OperationalError
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from urllib.parse import urlparse
import re
from datetime import datetime, timedelta
import os

from . import db, limiter
from .models import User, Company, UserActivity
from .audit_helpers import log_user_activity, log_audit


auth = Blueprint("auth", __name__)


def is_safe_url(target):
    """Validate that redirect target is a safe, relative URL."""
    if not target:
        return False
    parsed = urlparse(target)
    return not parsed.netloc and not parsed.scheme and target.startswith('/')


def clear_session():
    """Clear the session, dropping the memoised CSRF token along with it.

    generate_csrf() keeps the signed token on `g` and its raw half in the
    session; the two are only valid as a pair. Clearing the session alone
    strands the `g` copy, so anything rendered later in the request emits a
    token whose session half is gone — and validating it fails with
    "The CSRF session token is missing".
    """
    session.clear()
    g.pop(current_app.config.get("WTF_CSRF_FIELD_NAME", "csrf_token"), None)


@auth.route("/login", methods=["GET", "POST"])
@limiter.limit("5/minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.indexPage"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        remember = bool(request.form.get("remember"))

        user = User.query.filter_by(email=email).first()

        # Account lockout: after MAX_FAILED_LOGINS failures within LOCKOUT_WINDOW,
        # deny further attempts for the lockout period — independent from the
        # per-IP rate limit, so an attacker can't bypass it by rotating IPs.
        MAX_FAILED_LOGINS = 10
        LOCKOUT_WINDOW = timedelta(minutes=15)
        if user is not None:
            cutoff = datetime.utcnow() - LOCKOUT_WINDOW
            recent_failures = UserActivity.query.filter(
                UserActivity.user_id == user.id,
                UserActivity.activity_type == "login_failed",
                UserActivity.created_at >= cutoff,
            ).count()
            if recent_failures >= MAX_FAILED_LOGINS:
                log_user_activity("login_blocked", user.id, status="failed",
                                  failure_reason="account_locked")
                flash("Too many failed attempts. The account is temporarily locked. "
                      "Try again in 15 minutes.", "danger")
                return render_template("auth/login.html", email=email)

        if not user or not user.check_password(password):
            # Log failed login attempt
            if user:
                log_user_activity("login_failed", user.id, status="failed", failure_reason="invalid_password")
            else:
                log_user_activity("login_failed", None, status="failed", failure_reason="user_not_found")
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html", email=email)

        # Security: Check if user is active
        if not user.is_active:
            log_user_activity("login_failed", user.id, status="failed", failure_reason="user_inactive")
            flash("Your account has been deactivated. Please contact an administrator.", "danger")
            return render_template("auth/login.html", email=email)

        # Update last login timestamp
        # On Vercel (read-only SQLite), this write will fail, so make it optional via env flag.
        if not os.getenv("READ_ONLY_DB", "").lower() in {"1", "true", "yes"}:
            try:
                user.last_login = datetime.utcnow()
                db.session.commit()
            except OperationalError as e:
                # Silently ignore readonly database errors (e.g., on Vercel with SQLite)
                if "readonly" in str(e).lower():
                    db.session.rollback()
                else:
                    raise

        # Check if 2FA is enabled
        if user.totp_enabled and user.totp_secret:
            session["2fa_user_id"] = user.id
            session["2fa_remember"] = remember
            session["2fa_next"] = request.args.get("next")
            return redirect(url_for("auth.verify_2fa"))

        # Session-fixation protection: any session contents from before login
        # (set by a passing attacker, or stale state from a previous session)
        # are dropped. Flask then issues a fresh signed session cookie on the
        # next response, so an attacker who pre-set the SID gets nothing.
        clear_session()
        login_user(user, remember=remember)

        # Geo lookup for login location
        try:
            from .services.geo_service import get_location, format_location
            from .audit_helpers import get_client_ip
            ip = get_client_ip()
            geo = get_location(ip)
            location_str = format_location(geo) if geo else None
        except Exception:
            location_str = None

        # Log successful login
        log_user_activity("login", user.id, status="success", location=location_str)
        log_audit("login", "user", user.id, f"User {user.username} logged in successfully")

        next_url = request.args.get("next")
        if next_url and is_safe_url(next_url):
            return redirect(next_url)
        return redirect(url_for("main.indexPage"))

    return render_template("auth/login.html")


@auth.route("/api/auth/login", methods=["POST"])
@limiter.limit("10/minute")
def api_login():
    """API Login - get JWT token
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
            password:
              type: string
    responses:
      200:
        description: JWT access token
      401:
        description: Invalid credentials
    """
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"success": False, "error": "Email and password are required."}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        if user:
            log_user_activity("api_login_failed", user.id, status="failed", failure_reason="invalid_password")
        else:
            log_user_activity("api_login_failed", None, status="failed", failure_reason="user_not_found")
        return jsonify({"success": False, "error": "Invalid credentials."}), 401

    if not user.is_active:
        log_user_activity("api_login_failed", user.id, status="failed", failure_reason="user_inactive")
        return jsonify({"success": False, "error": "Account is inactive."}), 403

    access_token = create_access_token(identity=user.id)

    log_user_activity("api_login", user.id, status="success")
    log_audit("api_login", "user", user.id, f"User {user.username} obtained API token")

    return jsonify({
        "success": True,
        "access_token": access_token,
        "token_type": "Bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        },
    })


def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    return True, ""


def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


@auth.route("/register", methods=["GET", "POST"])
def register():
    from flask import current_app
    if not current_app.config.get('ALLOW_SELF_REGISTRATION', False):
        flash("Registration is disabled. Please contact an administrator.", "warning")
        return redirect(url_for("auth.login"))

    if current_user.is_authenticated:
        return redirect(url_for("main.indexPage"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""

        if not username or not email or not password:
            flash("All fields are required.", "warning")
            return render_template("auth/register.html", username=username, email=email)

        if len(username) < 3 or len(username) > 20:
            flash("Username must be between 3 and 20 characters.", "warning")
            return render_template("auth/register.html", username=username, email=email)

        if not validate_email(email):
            flash("Please enter a valid email address.", "warning")
            return render_template("auth/register.html", username=username, email=email)

        is_valid, error_msg = validate_password(password)
        if not is_valid:
            flash(error_msg, "warning")
            return render_template("auth/register.html", username=username, email=email)

        if password != confirm:
            flash("Passwords do not match.", "warning")
            return render_template("auth/register.html", username=username, email=email)

        existing = User.query.filter(or_(User.email == email, User.username == username)).first()
        if existing:
            flash("User with that email or username already exists.", "warning")
            return render_template("auth/register.html", username=username, email=email)

        # Extract domain and create/link company for members
        domain = Company.extract_domain(email)
        company = None
        if domain:
            # Only get existing company, don't create new one (only admins can create companies)
            company = Company.get_or_create_by_domain(domain, 'other', allow_create=False)
        
        user = User(username=username, email=email, role='member', company_id=company.id if company else None)
        user.set_password(password)
        db.session.add(user)
        try:
            db.session.commit()
            flash("Account created. Please sign in.", "success")
        except OperationalError as e:
            # On read-only DB (Vercel), registration will fail - show appropriate message
            if "readonly" in str(e).lower():
                db.session.rollback()
                flash("Registration is disabled in read-only mode. Please contact an administrator.", "warning")
            else:
                raise
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth.route("/logout")
@login_required
def logout():
    # Log logout activity
    user_id = current_user.id
    log_user_activity("logout", user_id, status="success")
    log_audit("logout", "user", user_id, f"User {current_user.username} logged out")
    
    # Clear session data
    clear_session()
    logout_user()
    flash("You have been signed out successfully.", "success")
    return redirect(url_for("auth.login"))


@auth.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        current_password = request.form.get("current_password") or ""
        new_password = request.form.get("new_password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        # Update username
        if username and username != current_user.username:
            if len(username) < 3 or len(username) > 20:
                flash("Username must be between 3 and 20 characters.", "warning")
                return redirect(url_for("auth.profile"))
            existing = User.query.filter(User.username == username, User.id != current_user.id).first()
            if existing:
                flash("Username already taken.", "warning")
                return redirect(url_for("auth.profile"))
            current_user.username = username

        # Update email
        if email and email != current_user.email:
            if not validate_email(email):
                flash("Please enter a valid email address.", "warning")
                return redirect(url_for("auth.profile"))
            existing = User.query.filter(User.email == email, User.id != current_user.id).first()
            if existing:
                flash("Email already in use.", "warning")
                return redirect(url_for("auth.profile"))
            current_user.email = email

        # Update password if provided
        if new_password:
            if not current_password or not current_user.check_password(current_password):
                flash("Current password is incorrect.", "danger")
                return redirect(url_for("auth.profile"))
            is_valid, error_msg = validate_password(new_password)
            if not is_valid:
                flash(error_msg, "warning")
                return redirect(url_for("auth.profile"))
            if new_password != confirm_password:
                flash("New passwords do not match.", "warning")
                return redirect(url_for("auth.profile"))
            current_user.set_password(new_password)
            password_changed = True
            flash("Password updated successfully.", "success")
        else:
            password_changed = False

        try:
            db.session.commit()
            # Regenerate session after password change to invalidate old sessions
            if password_changed:
                logout_user()
                login_user(current_user)
            flash("Profile updated successfully.", "success")
        except OperationalError as e:
            # On read-only DB (Vercel), profile updates will fail
            if "readonly" in str(e).lower():
                db.session.rollback()
                flash("Profile updates are disabled in read-only mode.", "warning")
            else:
                raise
        return redirect(url_for("auth.profile"))

    breadcrumb = {"parent": "User Profile", "child": "Profile"}
    return render_template("auth/profile.html", user=current_user, breadcrumb=breadcrumb)


@auth.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    import pyotp
    import qrcode
    import io
    import base64

    if request.method == "POST":
        # Verify the TOTP code to confirm setup
        token = request.form.get("token", "").strip()
        secret = session.get("2fa_setup_secret", "")
        if not token or not secret:
            flash("Please enter the verification code.", "warning")
            return redirect(url_for("auth.setup_2fa"))

        totp = pyotp.TOTP(secret)
        if totp.verify(token):
            current_user.totp_secret = secret
            current_user.totp_enabled = True
            db.session.commit()
            session.pop("2fa_setup_secret", None)
            flash("Two-factor authentication enabled successfully.", "success")
            return redirect(url_for("auth.profile"))
        else:
            flash("Invalid verification code. Please try again.", "danger")
            return redirect(url_for("auth.setup_2fa"))

    # Generate new secret and store in session (not in form)
    secret = pyotp.random_base32()
    session["2fa_setup_secret"] = secret
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=current_user.email, issuer_name="D-SECLAB")

    # Generate QR code as base64
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    breadcrumb = {"parent": "Settings", "child": "Two-Factor Authentication"}
    return render_template("auth/setup_2fa.html", secret=secret, qr_b64=qr_b64, breadcrumb=breadcrumb)


@auth.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    password = request.form.get("password", "")
    if not password or not current_user.check_password(password):
        flash("Current password is required to disable 2FA.", "danger")
        return redirect(url_for("auth.profile"))
    current_user.totp_secret = None
    current_user.totp_enabled = False
    db.session.commit()
    flash("Two-factor authentication disabled.", "info")
    return redirect(url_for("auth.profile"))


@auth.route("/2fa/verify", methods=["GET", "POST"])
@limiter.limit("5/minute")
def verify_2fa():
    import pyotp

    user_id = session.get("2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        token = request.form.get("token", "").strip()
        user = db.session.get(User, user_id)
        if not user:
            session.pop("2fa_user_id", None)
            return redirect(url_for("auth.login"))

        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(token):
            # Pull the keys we still need out of the session, then clear it
            # for session-fixation protection (mirrors the non-2FA login path).
            next_url = session.pop("2fa_next", None)
            remember = session.pop("2fa_remember", False)
            clear_session()
            if next_url:
                session["2fa_next"] = next_url  # re-stash so the post-login redirect below still works
            login_user(user, remember=remember)

            # Geo lookup for login location
            try:
                from .services.geo_service import get_location, format_location
                from .audit_helpers import get_client_ip
                ip = get_client_ip()
                geo = get_location(ip)
                _2fa_location = format_location(geo) if geo else None
            except Exception:
                _2fa_location = None

            log_user_activity("login", user.id, status="success", location=_2fa_location)
            log_audit("login", "user", user.id, f"User {user.username} logged in with 2FA")
            next_url = session.pop("2fa_next", None)
            if next_url and is_safe_url(next_url):
                return redirect(next_url)
            return redirect(url_for("main.indexPage"))
        else:
            flash("Invalid verification code.", "danger")

    return render_template("auth/verify_2fa.html")

