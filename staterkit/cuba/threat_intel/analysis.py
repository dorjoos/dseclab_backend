"""Analysis dashboard, executive summary, and the timeline API behind them."""
from __future__ import annotations

from flask import render_template, request
from flask.typing import ResponseReturnValue
from flask_login import login_required

from ..services.breached_creds_analysis import build_analysis_stats
from ..services.breached_creds_service import breached_creds_service as es_service
from ._blueprint import threat_intel
from ._shared import _get_domain_filters


@threat_intel.route('/api/timeline', methods=['POST'])
@login_required
def timeline_api() -> ResponseReturnValue:
    """Get breach timeline data
    ---
    tags:
      - Analytics
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            period:
              type: string
              enum: [7d, week, month]
    responses:
      200:
        description: Timeline labels and data arrays
    """
    from flask import jsonify
    data = request.get_json(silent=True) or {}
    period = data.get('period', '7d')
    domain_filters = _get_domain_filters()

    if period == '7d':
        labels, values = es_service.get_daily_trends(days=7, domain_filters=domain_filters)
    elif period == 'week':
        labels, values = es_service.get_weekly_trends(weeks=8, domain_filters=domain_filters)
    elif period == 'month':
        labels, values = es_service.get_monthly_trends(months=12, domain_filters=domain_filters)
    else:
        labels, values = es_service.get_daily_trends(days=7, domain_filters=domain_filters)

    return jsonify({'labels': labels, 'data': values})


@threat_intel.route('/threat-intelligence/analysis')
@login_required
def analysis() -> ResponseReturnValue:
    stats = build_analysis_stats()
    breadcrumb = {"parent": "Threat Intelligence", "child": "Analysis",
                  "description": "Comprehensive threat intelligence analysis and statistics"}
    return render_template('threat_intel/analysis.html',
                          total=stats["total"], by_type=stats["by_type"],
                          by_source=stats["by_source"], by_domain=stats["by_domain"],
                          recent=stats["recent"], marked_count=stats["marked_count"],
                          user_domain=stats["user_domain"],
                          timeline_labels=stats["timeline_labels"],
                          timeline_data=stats["timeline_data"],
                          breadcrumb=breadcrumb)


@threat_intel.route('/threat-intelligence/summary')
@login_required
def breach_summary() -> ResponseReturnValue:
    """AI-generated executive breach summary."""
    from ..services.ai_summary import generate_executive_summary

    domain_filters = _get_domain_filters()
    stats = es_service.get_stats(domain_filters=domain_filters)
    tl_labels, tl_data = es_service.get_monthly_trends(months=6, domain_filters=domain_filters)

    summary = generate_executive_summary(stats, tl_labels, tl_data)

    breadcrumb = {"parent": "Threat Intelligence", "child": "Executive Summary"}
    return render_template('threat_intel/summary.html', summary=summary, breadcrumb=breadcrumb)
