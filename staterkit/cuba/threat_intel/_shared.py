"""Scoping, access checks and notification helpers shared across the threat-intelligence views."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from flask import current_app, request
from flask_login import current_user
from sqlalchemy import or_

from .. import db
from ..models import BreachedCredMeta, Company, Notification, User
from ..security import DomainScope, get_scope_domains, get_user_watchlist_domains
from ..services.breached_creds_service import breached_creds_service as es_service

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from ..services.breached_creds_service import BreachedCredDoc

logger = logging.getLogger(__name__)

def _get_domain_filters() -> DomainScope:
    """Scope for the current user: None is unrestricted, a list restricts.

    Thin alias for security.get_scope_domains, kept because this name is used
    throughout the threat-intel views and by tests.
    """
    return get_scope_domains()


def _get_match_domains() -> list[str]:
    """Domains to label rows against in the Matched column.

    Distinct from _get_domain_filters, which answers "what may this user see"
    and returns None for an admin meaning unrestricted. That None collapsed to
    [] at the call site, and matching against no domains labels nothing — so
    every row showed a dash for admins, on the column whose whole job is
    saying which watched domain a credential hit.

    An admin sees every company's rows, so they get every company's watched
    domains. Everyone else gets their own, which is also exactly what they are
    filtered to.
    """
    from ..models import Company
    if not current_user.is_authenticated:
        return []
    if not current_user.is_admin_user:
        return get_user_watchlist_domains()
    # Shared with collect_creds, which faces the same question for a schedule
    # that targets no single company.
    return Company.all_match_domains()


def _get_employee_emails() -> list[str]:
    """Staff addresses in the current user's scope, for the Employees tab.

    Always a list, never None: unlike _get_domain_filters there is no
    "unrestricted" employee view. An admin sees every company's staff, a member
    sees their own company's, and an empty list means nobody is on file — which
    the query turns into a match-nothing clause, not an unfiltered list.
    """
    from ..models import WatchlistEntry
    if not current_user.is_authenticated:
        return []
    if current_user.is_admin_user:
        # One query, not one per company: walking Company.watchlist_entries
        # here is an N+1 that grows with the client roster.
        rows = WatchlistEntry.query.filter_by(entry_type='email').all()
        return sorted({r.entry_value.strip().lower()
                       for r in rows if r.entry_value and r.entry_value.strip()})
    company = current_user.company
    return company.get_employee_emails() if company else []


def _host_belongs_to(host: str, domain: str) -> bool:
    """True when `host` equals `domain` or is a subdomain of it.

    Substring matching would treat 'ibank.mn' as belonging to 'nibank.mn';
    suffix matching anchored on a '.' boundary prevents that.
    """
    if not host or not domain:
        return False
    host = host.lower().strip().rstrip(".")
    domain = domain.lower().strip().lstrip(".").rstrip(".")
    if not host or not domain:
        return False
    return host == domain or host.endswith("." + domain)


def _cred_matches_domain(cred: BreachedCredDoc, domain: str) -> bool:
    """True when any of cred.domain, the @-suffix of cred.username, or the
    host of cred.url belongs to `domain` (equal or subdomain)."""
    if not domain:
        return False
    if _host_belongs_to(cred.domain or "", domain):
        return True
    username = (cred.username or "").lower()
    if "@" in username and _host_belongs_to(username.split("@", 1)[1], domain):
        return True
    url = (cred.url or "").strip()
    if url:
        from urllib.parse import urlparse
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = (parsed.hostname or "").lower()
        if _host_belongs_to(host, domain):
            return True
    return False


def _check_cred_access(cred: BreachedCredDoc) -> bool:
    """Check if current user can access this credential. Returns True if allowed."""
    if current_user.is_admin_user:
        return True
    domain_filters = _get_domain_filters()
    if not domain_filters:
        return False
    return any(_cred_matches_domain(cred, d) for d in domain_filters)


def _attach_metadata(items: Sequence[BreachedCredDoc]) -> None:
    """Attach local metadata (marks) to a list of BreachedCredDoc items."""
    if not items:
        return
    es_ids = [item.es_id for item in items]
    metas = BreachedCredMeta.query.filter(BreachedCredMeta.es_id.in_(es_ids)).all()
    meta_map = {m.es_id: m for m in metas}
    for item in items:
        meta = meta_map.get(item.es_id)
        if meta:
            item.is_marked = meta.is_marked
            item.marked_by = meta.marked_by
            item.marked_at = meta.marked_at
            item.marker = meta.marker
            item.notes = meta.notes


def _send_breach_emails(users: Iterable[User], company_name: str,
                        creds: Sequence[BreachedCredDoc],
                        company_domain: str | None = None,
                        third_party_domains: Sequence[str] | None = None) -> int:
    """Best-effort email of matched breaches to users. Never raises."""
    try:
        from ..services.email_service import build_breach_email, is_email_configured, send_email
        if not is_email_configured():
            logger.info("Email not configured; skipping breach email for %s", company_name)
            return 0
        from flask import has_request_context
        # Prefer the configured base URL. request.url_root is derived from the
        # Host header, which ProxyFix trusts — a poisoned host would put an
        # attacker-controlled "View credential" link inside a breach alert,
        # which is exactly the mail a recipient is primed to click.
        base_url = current_app.config.get('APP_BASE_URL') or (
            request.url_root if has_request_context() else None)
        subject, body, text = build_breach_email(
            company_name, creds, base_url=base_url,
            company_domain=company_domain,
            third_party_domains=third_party_domains)
        sent = 0
        for user in users:
            # One message per recipient — never a shared To/CC, which would
            # disclose the client roster to everyone on it.
            if user.email and send_email(user.email, subject, body, text=text):
                sent += 1
        return sent
    except Exception as e:
        logger.error("Breach email send failed: %s", e)
        return 0


def _notify_new_breach(credential_id: str, company_domain: str | None,
                       company_name: str, email: str | None,
                       file_name: str | None = None) -> None:
    """Notify all users in a company about a new breach (in-app + email)."""
    try:
        if not company_domain:
            users = User.query.filter(
                User.role == 'admin',
                User.is_active == True
            ).all()
        else:
            company = Company.query.filter_by(domain=company_domain).first()
            if not company:
                users = User.query.filter(
                    User.role == 'admin',
                    User.is_active == True
                ).all()
            else:
                users = User.query.filter(
                    or_(
                        User.company_id == company.id,
                        User.role == 'admin',
                    ),
                    User.is_active == True
                ).all()

        for user in users:
            notification = Notification(
                user_id=user.id,
                notification_type='warning',
                title=f'New Breach Detected: {company_name}',
                message=f'Email: {email}',
                link=f'/threat-intelligence/breached-creds/{credential_id}'
            )
            db.session.add(notification)
        db.session.commit()
    except Exception as e:
        logger.error("Error creating notifications: %s", e)
        db.session.rollback()
        return

    # Email delivery is best-effort and must not affect the in-app flow above.
    cred = es_service.get_by_id(credential_id)
    if cred is None:
        from types import SimpleNamespace
        cred = SimpleNamespace(
            es_id=credential_id, username=email, domain=company_domain,
            file_name=file_name, source=None, type=None, created_at=None,
        )
    cred.matched_domain = company_domain
    # Label how it matched so the email can bucket it as staff vs customer.
    if not getattr(cred, 'match_path', None):
        _, cred.match_path = es_service.compute_match_detail(
            cred, [company_domain] if company_domain else [])
    if file_name and not getattr(cred, 'file_name', None):
        cred.file_name = file_name
    _send_breach_emails(users, company_name, [cred], company_domain=company_domain)
