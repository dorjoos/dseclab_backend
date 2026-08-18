"""Authorisation decorators and the tenancy scope every ES query is bound by."""
from __future__ import annotations

import logging
from collections.abc import Callable
from functools import wraps
from typing import Any, Final, ParamSpec, TypeAlias, TypeVar

from flask import flash, redirect, url_for
from flask_login import current_user

logger = logging.getLogger(__name__)

_P = ParamSpec("_P")
_R = TypeVar("_R")

class Unrestricted:
    """Sentinel meaning "no domain filter". Only an admin may ever hold one.

    A sentinel rather than ``None`` on purpose. When unrestricted was spelled
    ``None`` it was indistinguishable from the many other things None means
    here — "no company", "not logged in", "argument omitted" — and the
    dashboard and analysis view both crossed those wires, handing a
    company-less member every tenant's credentials.

    Spelling it as its own type makes that a type error rather than a bug
    someone has to notice in review::

        # error: Incompatible type "frozenset[str] | None";
        #        expected "Unrestricted | frozenset[str]"
        scope = watched_domains() if user_domain else None

    Truthy, so the ``scope or something`` idiom keeps the unrestricted case
    instead of collapsing it the way ``None or []`` did.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "UNRESTRICTED"


#: The single unrestricted scope. Compare with ``isinstance(x, Unrestricted)``
#: rather than ``is UNRESTRICTED`` so a future subclass still works.
UNRESTRICTED: Final = Unrestricted()

#: What an ES query is scoped to.
#:
#:   ``UNRESTRICTED``   — every tenant. Admins only.
#:   ``frozenset()``    — nothing. A real answer, not "no filter".
#:   ``frozenset({..})``— these domains.
#:
#: frozenset rather than list because a scope is a set membership question and
#: nothing downstream depends on order; immutability also stops a caller
#: widening someone else's scope by mutating a shared list.
# Not a string alias: it is used at runtime in `DomainScope | None`
# annotations, and a str has no __or__.
DomainScope: TypeAlias = Unrestricted | frozenset[str]


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

    Never None: an empty list means "nothing". Admins get [] here because
    "everything" is not expressible as a list — that is precisely what
    get_scope_domains and the Unrestricted sentinel exist for, and why this
    function must not be used to decide a scope on its own.
    """
    if not current_user.is_authenticated or current_user.is_admin_user:
        return []
    if current_user.company:
        domains: list[str] = current_user.company.get_match_domains()
        return domains
    return []


def get_scope_domains() -> DomainScope:
    """The ES domain scope for the current user.

    The one place that decides this. An empty frozenset means "see nothing"
    and _build_query turns it into a match-nothing clause; UNRESTRICTED means
    "see everything" and only an admin gets it.

    get_user_company_domain() must not be used to make this decision. It
    returns None both for an admin and for a non-admin with no company, and
    callers that branched on it handed the second group the first group's
    scope — a company-less member saw every tenant's credentials.
    """
    if not current_user.is_authenticated:
        return frozenset()
    if current_user.is_admin_user:
        return UNRESTRICTED
    return frozenset(get_user_watchlist_domains())
