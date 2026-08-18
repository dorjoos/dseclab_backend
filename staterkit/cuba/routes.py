from flask import Blueprint, render_template
from flask.typing import ResponseReturnValue
from flask_login import login_required

from .security import get_scope_domains, get_user_company_domain
from .services.breached_creds_service import breached_creds_service as es_service

main = Blueprint('main', __name__)


@main.route('/')
@main.route('/index')
@main.route('/dashboard')
@login_required
def indexPage() -> ResponseReturnValue:
    """Dashboard with leak statistics from Elasticsearch."""
    # Shown in the page header only. Never branch on it to pick a scope: it is
    # None both for an admin and for a member with no company, and treating the
    # second as the first served that member every tenant's stats and recent
    # credentials.
    user_domain = get_user_company_domain()
    domain_filters = get_scope_domains()

    stats = es_service.get_stats(domain_filters=domain_filters)
    chart_labels, chart_data = es_service.get_weekly_trends(weeks=12, domain_filters=domain_filters)
    latest_events = es_service.get_recent(limit=10, domain_filters=domain_filters)

    by_type = stats.get('by_type', {})
    by_source = stats.get('by_source', {})
    total_leaks = stats.get('total', 0)

    # Use top sources for the stat cards instead of hardcoded type categories
    source_items = sorted(by_source.items(), key=lambda x: x[1], reverse=True)
    top_source = source_items[0] if source_items else ('Unknown', 0)
    second_source = source_items[1] if len(source_items) > 1 else ('Other', 0)

    # Use by_source for category distribution donut chart
    category_distribution = by_source if by_source else {'No Data': 1}

    context = {
        "breadcrumb": {"parent": "Threat Intelligence", "child": "Dashboard"},
        "total_leaks": total_leaks,
        "total_change": 0,
        "total_change_text": "",
        "consumer_leaks": top_source[1],
        "consumer_change": 0,
        "consumer_change_text": top_source[0],
        "corporate_leaks": second_source[1],
        "corporate_change": 0,
        "corporate_change_text": second_source[0],
        "infected_ips_count": 0,
        "affected_computers_count": 0,
        "recent_exposure": by_type,
        "latest_events": latest_events,
        "user_domain": user_domain,
        "chart_labels": chart_labels,
        "chart_data": chart_data,
        "category_distribution": category_distribution,
        "type_chart_data": by_type
    }
    return render_template('general/index.html', **context)
