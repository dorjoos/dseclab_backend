from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf.csrf import generate_csrf
from sqlalchemy import or_
import re
from datetime import datetime

from . import db
from .models import User, Company


auth = Blueprint("auth", __name__)


@auth.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.indexPage"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        remember = bool(request.form.get("remember"))

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html", email=email)

        # Security: Check if user is active
        if not user.is_active:
            flash("Your account has been deactivated. Please contact an administrator.", "danger")
            return render_template("auth/login.html", email=email)

        # Update last login timestamp
        user.last_login = datetime.utcnow()
        db.session.commit()

        login_user(user, remember=remember)
        next_url = request.args.get("next")
        return redirect(next_url or url_for("main.indexPage"))

    return render_template("auth/login.html")


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
            company = Company.get_or_create_by_domain(domain, 'other')
        
        user = User(username=username, email=email, role='member', company_id=company.id if company else None)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Account created. Please sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth.route("/logout")
@login_required
def logout():
    # Clear session data
    session.clear()
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
            flash("Password updated successfully.", "success")

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for("auth.profile"))

    breadcrumb = {"parent": "User Profile", "child": "Profile"}
    return render_template("auth/profile.html", user=current_user, breadcrumb=breadcrumb)

