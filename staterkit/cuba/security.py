from functools import wraps

from flask import redirect, url_for, flash
from flask_login import current_user


def admin_required(f):
    """Decorator to require admin role on a view."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please login to access this page.", "warning")
            return redirect(url_for("auth.login"))
        if current_user.role != "admin" and not current_user.isAdmin:
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for("main.indexPage"))
        return f(*args, **kwargs)

    return decorated_function


def get_user_company_domain():
    """Get company domain for current user, None for admins."""
    if not current_user.is_authenticated:
        return None
    if current_user.role == "admin" or current_user.isAdmin:
        # Admins see all data, no domain restriction
        return None
    return current_user.company_domain


def get_user_watchlist_domains():
    """
    Get list of domains/IPs/values to match for current user
    (company domain + all watchlist entries).
    """
    user_domain = get_user_company_domain()
    if not user_domain:
        return []

    domains_to_match = [user_domain]
    user_company = current_user.company if current_user.company else None
    if user_company:
        # Include ALL watchlist entry types (domain, url, email, slug, ip_address)
        for entry in user_company.watchlist_entries:
            if entry.entry_value:
                entry_value = entry.entry_value.strip().lower()
                if entry_value:
                    domains_to_match.append(entry_value)

    # Deduplicate and drop empty
    return list({d for d in domains_to_match if d})


def can_user_access_breached_cred(breached_cred):
    """
    Check if current user can access a specific breached credential.
    Uses the same watchlist matching logic as the list view.

    Returns:
        bool: True if user can access, False otherwise
    """
    # Admins can access everything
    if current_user.role == "admin" or current_user.isAdmin:
        return True

    # Get user's company domain
    user_domain = get_user_company_domain()
    if not user_domain:
        # If user has no domain, they can't access anything
        return False

    # Get domains to match (company domain + watchlist entries)
    domains_to_match = get_user_watchlist_domains()
    if not domains_to_match:
        # Fallback to domain check if no watchlist
        return bool(
            breached_cred.domain
            and breached_cred.domain.lower() == user_domain.lower()
        )

    # Check if breached credential matches any watchlist entry
    for domain in domains_to_match:
        if not domain:
            continue
        domain = domain.lower().strip()
        if not domain:
            continue

        # Match domain field - exact match or contains
        if breached_cred.domain:
            domain_lower = breached_cred.domain.lower()
            if domain in domain_lower or domain_lower == domain:
                return True

        # Match username field
        if breached_cred.username:
            username_lower = breached_cred.username.lower()
            if domain in username_lower or username_lower == domain:
                return True
            # Check if username is an email format
            if "@" in username_lower:
                if f"@{domain}" in username_lower:
                    return True
                if f"@.{domain}" in username_lower:
                    return True

        # Match URL field - contains domain
        if breached_cred.url:
            url_lower = breached_cred.url.lower()
            if domain in url_lower:
                return True

    return False


def requires_breached_cred_access(f):
    """
    Decorator to load a BreachedCredential by ID and enforce access control.

    Usage:
        @threat_intel.route('/threat-intelligence/breached-creds/<int:id>')
        @login_required
        @requires_breached_cred_access
        def breached_creds_view(id, breached_cred):
            ...
    """

    @wraps(f)
    def decorated(id, *args, **kwargs):
        from .models import BreachedCredential  # local import to avoid circulars

        breached_cred = BreachedCredential.query.get_or_404(id)

        if not can_user_access_breached_cred(breached_cred):
            flash(
                "Access denied. You can only access records for your company.",
                "danger",
            )
            return redirect(url_for("threat_intel.breached_creds_list"))

        # Pass loaded object into the view
        return f(id=id, breached_cred=breached_cred, *args, **kwargs)

    return decorated



