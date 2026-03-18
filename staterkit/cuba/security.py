from functools import wraps
import logging

from flask import redirect, url_for, flash
from flask_login import current_user

logger = logging.getLogger(__name__)


def admin_required(f):
    """Decorator to require admin role on a view."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please login to access this page.", "warning")
            return redirect(url_for("auth.login"))
        if not current_user.is_admin_user:
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for("main.indexPage"))
        return f(*args, **kwargs)
    return decorated_function


def permission_required(perm):
    """Decorator to require a specific permission."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please login.", "warning")
                return redirect(url_for("auth.login"))
            if not current_user.has_permission(perm):
                flash("You don't have permission for this action.", "danger")
                return redirect(url_for("main.indexPage"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_user_company_domain():
    """Get company domain for current user, None for admins."""
    if not current_user.is_authenticated:
        return None
    if current_user.is_admin_user:
        return None
    return current_user.company_domain


def get_user_watchlist_domains():
    """Get list of domains/IPs/values to match for current user."""
    user_domain = get_user_company_domain()
    if not user_domain:
        return []
    if current_user.company:
        return current_user.company.get_match_domains()
    return [user_domain]
