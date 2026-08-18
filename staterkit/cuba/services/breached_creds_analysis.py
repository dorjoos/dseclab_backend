"""Breached credentials analysis helpers — aggregations for the analysis view."""
from __future__ import annotations

from typing import Any

from ..security import DomainScope, get_scope_domains, get_user_company_domain
from .breached_creds_service import breached_creds_service as es_service


def get_domain_filters() -> DomainScope:
    """Get current user's domain filters for ES queries.

    Delegates rather than deciding: branching on get_user_company_domain()
    here returned None — unrestricted — for a member with no company, which
    is the same value an admin gets.
    """
    return get_scope_domains()


def build_analysis_stats() -> dict[str, Any]:
    """Build statistics for the analysis view using ES aggregations."""
    domain_filters = get_domain_filters()
    user_domain = get_user_company_domain()

    stats = es_service.get_stats(domain_filters=domain_filters)
    recent = es_service.get_recent(limit=10, domain_filters=domain_filters)
    timeline_labels, timeline_data = es_service.get_daily_trends(days=7, domain_filters=domain_filters)

    return {
        "user_domain": user_domain,
        "total": stats['total'],
        "by_type": stats['by_type'],
        "by_source": stats['by_source'],
        "by_domain": stats['by_domain'],
        "recent": recent,
        "marked_count": 0,
        "timeline_labels": timeline_labels,
        "timeline_data": timeline_data,
    }
