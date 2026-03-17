from flask import render_template, Blueprint
from flask_login import login_required

from .security import get_user_company_domain, get_user_watchlist_domains
from .services.elasticsearch_service import es_service

main = Blueprint('main', __name__)


@main.route('/')
@main.route('/index')
@main.route('/dashboard')
@login_required
def indexPage():
    """Dashboard with leak statistics from Elasticsearch."""
    user_domain = get_user_company_domain()
    domain_filters = get_user_watchlist_domains() if user_domain else None

    stats = es_service.get_stats(domain_filters=domain_filters)
    chart_labels, chart_data = es_service.get_daily_trends(days=30, domain_filters=domain_filters)
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
