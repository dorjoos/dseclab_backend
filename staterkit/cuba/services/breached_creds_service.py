from typing import Dict, Any

from sqlalchemy import func, or_

from .. import db
from ..models import BreachedCredential
from ..security import get_user_company_domain, get_user_watchlist_domains


def _build_domain_match_query(domains):
    """
    Build a query filter that matches breached credentials using watchlist entries.

    Matches based on:
    - Domain field matches watchlist entry (exact or contains)
    - Username field contains the watchlist domain
    - URL field contains the watchlist domain
    """
    if not domains:
        return None

    conditions = []
    for domain in domains:
        if not domain:
            continue
        domain = domain.lower().strip()
        if not domain:
            continue

        # Match domain field - exact match or contains
        conditions.append(BreachedCredential.domain.ilike(f"%{domain}%"))
        conditions.append(func.lower(BreachedCredential.domain) == domain)

        # Match username field (handles both email format and username format)
        # For email format: user@test.com, user@e.test.com
        conditions.append(BreachedCredential.username.ilike(f"%@{domain}"))
        conditions.append(BreachedCredential.username.ilike(f"%@%.{domain}"))
        # For username format: if username equals domain or contains domain
        conditions.append(func.lower(BreachedCredential.username) == domain)
        conditions.append(BreachedCredential.username.ilike(f"%{domain}%"))

        # Match URL field - contains domain
        conditions.append(BreachedCredential.url.ilike(f"%{domain}%"))

    if not conditions:
        return None
    return or_(*conditions)


def apply_breached_domain_filter(query, user_domain: str):
    """
    Apply domain/watchlist-based filtering for BreachedCredential queries.
    """
    if not user_domain:
        return query

    domains_to_match = get_user_watchlist_domains()
    domain_filter = _build_domain_match_query(domains_to_match)
    if domain_filter is not None:
        return query.filter(domain_filter)
    return query.filter(BreachedCredential.domain == user_domain)


def build_analysis_stats() -> Dict[str, Any]:
    """
    Build statistics for the analysis view (total, by_type, by_source, by_domain, recent, marked_count).
    Respects the current user's domain/watchlist filters.
    """
    user_domain = get_user_company_domain()

    # Base query
    base_query = BreachedCredential.query
    base_query = apply_breached_domain_filter(base_query, user_domain)

    total = base_query.count()

    # By type
    by_type_query = db.session.query(
        BreachedCredential.type, func.count(BreachedCredential.id).label("count")
    )
    by_type_query = apply_breached_domain_filter(by_type_query, user_domain)
    by_type = by_type_query.group_by(BreachedCredential.type).all()

    # By source
    by_source_query = db.session.query(
        BreachedCredential.source, func.count(BreachedCredential.id).label("count")
    )
    by_source_query = apply_breached_domain_filter(by_source_query, user_domain)
    by_source = by_source_query.group_by(BreachedCredential.source).all()

    # By domain (top 10)
    by_domain_query = db.session.query(
        BreachedCredential.domain, func.count(BreachedCredential.id).label("count")
    )
    by_domain_query = apply_breached_domain_filter(by_domain_query, user_domain)
    by_domain = (
        by_domain_query.group_by(BreachedCredential.domain)
        .order_by(func.count(BreachedCredential.id).desc())
        .limit(10)
        .all()
    )

    # Recent breaches (top 10)
    recent = (
        base_query.order_by(BreachedCredential.created_at.desc()).limit(10).all()
    )

    # Marked items
    marked_count = base_query.filter(BreachedCredential.is_marked.is_(True)).count()

    return {
        "user_domain": user_domain,
        "total": total,
        "by_type": dict(by_type),
        "by_source": dict(by_source),
        "by_domain": dict(by_domain),
        "recent": recent,
        "marked_count": marked_count,
    }


