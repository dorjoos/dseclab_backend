"""Ransomware monitoring dashboard, backed by the `ransomware-feed` ES index."""
import logging
from flask import render_template, request
from flask_login import login_required

from ..api_utils import sanitize_input
from ._blueprint import threat_intel

logger = logging.getLogger(__name__)

@threat_intel.route('/threat-intelligence/ransomware')
@login_required
def ransomware_dashboard():
    """Ransomware threat monitoring dashboard — reads from the
    `ransomware-feed` ES index. Each fetch is wrapped so a transient ES
    outage degrades the dashboard to zeros instead of returning 500."""
    from ..services.ransomware_feed_service import ransomware_feed_service

    def _safe(fn, default):
        try:
            return fn()
        except Exception:
            logger.exception('ransomware_dashboard: %s failed', fn.__name__)
            return default

    groups = _safe(lambda: ransomware_feed_service.get_groups(top_n=8), [])

    # Pagination + filters for Recent Attacks via query string.
    try:
        rp = max(1, int(request.args.get('rp', 1) or 1))
    except ValueError:
        rp = 1
    rg = sanitize_input(request.args.get('rg', '') or '') or None      # group
    rc = sanitize_input(request.args.get('rc', '') or '') or None      # country
    rq = sanitize_input(request.args.get('rq', '') or '') or None      # query text
    empty_recent = {'items': [], 'page': 1, 'per_page': 10, 'total': 0,
                    'pages': 1, 'has_prev': False, 'has_next': False,
                    'filters': {'group': '', 'country': '', 'q': ''}}
    recent_p = _safe(
        lambda: ransomware_feed_service.get_recent(
            page=rp, per_page=10, group=rg, country=rc, query_text=rq),
        empty_recent,
    )
    recent = recent_p['items']
    empty_stats = {
        'total_attacks': 0, 'active_groups': 0, 'countries_affected': 0,
        'data_leaked_tb': 0, 'active_this_week': 0, 'attacks_this_month': 0,
        'sectors': {'Unknown': 0},
        'monthly_trend': [0] * 12,
        'monthly_labels': [''] * 12,
    }
    stats = _safe(lambda: ransomware_feed_service.get_dashboard_stats(), empty_stats)

    breadcrumb = {"parent": "Threat Intelligence", "child": "Ransomware"}
    return render_template('threat_intel/ransomware.html',
                          groups=groups, recent=recent, recent_pagination=recent_p,
                          stats=stats, breadcrumb=breadcrumb)
