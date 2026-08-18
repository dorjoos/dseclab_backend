"""Authorisation decorators and the tenancy scope every ES query is bound by."""
from __future__ import annotations

import logging
from collections.abc import Callable
from functools import wraps
from typing import Any, ParamSpec, TypeAlias, TypeVar

from flask import flash, redirect, url_for
from flask_login import current_user

logger = logging.getLogger(__name__)

_P = ParamSpec("_P")
_R = TypeVar("_R")

#: The set of watched domains an ES query is restricted to.
#:
#: The distinction this alias exists to make visible:
#:   ``None``  — unrestricted. Only an admin may ever hold this.
#:   ``[]``    — restricted to nothing. A real answer, not "no filter".
#:   ``[...]`` — restricted to these domains.
#:
#: Conflating the first two is not hypothetical: the dashboard and the analysis
#: view both did, and served a company-less member every tenant's credentials.
#: Annotate anything that carries a scope with this rather than ``list[str]``,
#: so the optionality is impossible to drop by accident.
DomainScope: TypeAlias = "list[str] | None"


def admin_required(f: Callable[_P, _R]) -> Callable[_P, Any]:
    """Require an admin role on a view."""
    @wraps(f)
    def decorated_function(*args: _P.args, **kwargs: _P.kwargs) -> Any:
        if not current_user.is_authenticated:
            flash("Please login to access this page.", "warning")
            return redirect(url_for("auth.login"))
        if not current_user.is_admin_user:
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for("main.indexPage"))
        return f(*args, **kwargs)
    return decorated_function


def permission_required(perm: str) -> Callable[[Callable[_P, _R]], Callable[_P, Any]]:
    """Require a specific permission on a view."""
    def decorator(f: Callable[_P, _R]) -> Callable[_P, Any]:
        @wraps(f)
        def decorated_function(*args: _P.args, **kwargs: _P.kwargs) -> Any:
            if not current_user.is_authenticated:
                flash("Please login.", "warning")
                return redirect(url_for("auth.login"))
            if not current_user.has_permission(perm):
                flash("You don't have permission for this action.", "danger")
                return redirect(url_for("main.indexPage"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_user_company_domain() -> str | None:
    """The current user's company domain, or None.

    Returns None for an admin *and* for a user with no company. Those are
    different situations and this function cannot tell you which one you have
    — use get_scope_domains() to decide what a user may see.

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


def get_user_watchlist_domains() -> list[str]:
    """Domains the current user may see, as a concrete list.

    Never None: an empty list means "nothing", and callers must not collapse
    it into an absent filter. Admins get [] here because "everything" is not
    expressible as a list — see get_scope_domains.
    """
    if not current_user.is_authenticated or current_user.is_admin_user:
        return []
    if current_user.company:
        domains: list[str] = current_user.company.get_match_domains()
        return domains
    return []


def get_scope_domains() -> DomainScope:
    """The ES domain scope for the current user. None is unrestricted.

    The one place that decides this, because the distinction is easy to lose:
    ``None`` means "see everything" and only an admin may have it, while ``[]``
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
