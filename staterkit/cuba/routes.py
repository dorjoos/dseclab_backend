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
    total_leaks = stats.get('total', 0)
    consumer_leaks = by_type.get('combolist', 0)
    corporate_leaks = by_type.get('stealer', 0) + by_type.get('malware', 0)

    context = {
        "breadcrumb": {"parent": "Threat Intelligence", "child": "Dashboard"},
        "total_leaks": total_leaks,
        "total_change": 0,
        "total_change_text": "",
        "consumer_leaks": consumer_leaks,
        "consumer_change": 0,
        "consumer_change_text": "",
        "corporate_leaks": corporate_leaks,
        "corporate_change": 0,
        "corporate_change_text": "",
        "infected_ips_count": 0,
        "affected_computers_count": 0,
        "recent_exposure": by_type,
        "latest_events": latest_events,
        "user_domain": user_domain,
        "chart_labels": chart_labels,
        "chart_data": chart_data,
        "category_distribution": {'consumer': consumer_leaks, 'corporate': corporate_leaks},
        "type_chart_data": by_type
    }
    return render_template('general/index.html', **context)
