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
    """Get company domain for current user, None for admins.

    Deliberately does NOT fall back to the domain of the user's own email
    address. That fallback granted a company-less user scope over their mail
    provider's domain, so anyone on a free-mail address could read every
    credential with a matching username — including other clients' customers.
    A user with no company has no scope.
    """
    if not current_user.is_authenticated:
        return None
    if current_user.is_admin_user:
        return None
    return current_user.company.domain if current_user.company else None


def get_user_watchlist_domains():
    """Domains the current user may see.

    An empty list means "nothing", never "everything" — callers must not
    collapse it into an absent filter.
    """
    if not current_user.is_authenticated or current_user.is_admin_user:
        return []
    if current_user.company:
        return current_user.company.get_match_domains()
    return []


def get_scope_domains():
    """The ES domain scope for the current user. None is unrestricted.

    The one place that decides this, because the distinction is easy to lose:
    `None` means "see everything" and only an admin may have it, while `[]`
    means "see nothing" and _build_query turns it into a match-nothing clause.

    get_user_company_domain() must not be used to make this decision. It
    returns None both for an admin and for a non-admin with no company, and
    callers that branched on it handed the second group the first group's
    scope — a company-less member saw every tenant's credentials.
    """
    if not current_user.is_authenticated:
        return []
    if current_user.is_admin_user:
        return None
    return get_user_watchlist_domains()
