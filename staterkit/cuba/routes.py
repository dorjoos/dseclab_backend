from flask import render_template, Blueprint
from flask_login import login_required, current_user
from sqlalchemy import func, and_, or_
from datetime import datetime, date, timedelta

from . import db, cache
from .models import BreachedCredential, Company

main = Blueprint('main', __name__)


def get_user_company_domain():
    """Get company domain for current user"""
    if current_user.is_authenticated:
        if current_user.role == 'admin' or current_user.isAdmin:
            return None  # Admins see all data
        return current_user.company_domain
    return None


@main.route('/')
@main.route('/index')
@main.route('/dashboard')
@login_required
def indexPage():
    """Dashboard with leak statistics"""
    user_domain = get_user_company_domain()
    
    # Base query
    query = BreachedCredential.query
    if user_domain:
        query = query.filter(BreachedCredential.domain == user_domain)
    
    # Total Leaks
    total_leaks = query.count()
    
    # Get previous month count for comparison
    last_month = date.today().replace(day=1) - timedelta(days=1)
    last_month_start = last_month.replace(day=1)
    current_month_start = date.today().replace(day=1)
    
    previous_total = query.filter(
        BreachedCredential.created_at >= datetime.combine(last_month_start, datetime.min.time()),
        BreachedCredential.created_at < datetime.combine(current_month_start, datetime.min.time())
    ).count()
    total_change = total_leaks - previous_total
    total_change_text = f"{'+' if total_change >= 0 else ''}{total_change} since {last_month.strftime('%b %Y')}"
    
    # Consumer Leaks - using type field as proxy (combolist = consumer-like)
    consumer_leaks = query.filter(BreachedCredential.type == 'combolist').count()
    previous_consumer = query.filter(
        BreachedCredential.type == 'combolist',
        BreachedCredential.created_at >= datetime.combine(last_month_start, datetime.min.time()),
        BreachedCredential.created_at < datetime.combine(current_month_start, datetime.min.time())
    ).count()
    consumer_change = consumer_leaks - previous_consumer
    consumer_change_text = f"{'+' if consumer_change >= 0 else ''}{consumer_change} since {last_month.strftime('%b %Y')}"
    
    # Corporate Leaks - using type field as proxy (stealer, malware = corporate-like)
    corporate_leaks = query.filter(BreachedCredential.type.in_(['stealer', 'malware'])).count()
    previous_corporate = query.filter(
        BreachedCredential.type.in_(['stealer', 'malware']),
        BreachedCredential.created_at >= datetime.combine(last_month_start, datetime.min.time()),
        BreachedCredential.created_at < datetime.combine(current_month_start, datetime.min.time())
    ).count()
    corporate_change = corporate_leaks - previous_corporate
    corporate_change_text = "↔ Stable" if corporate_change == 0 else f"{'+' if corporate_change >= 0 else ''}{corporate_change} since {last_month.strftime('%b %Y')}"
    
    # Infected IP Addresses - not available in new structure, set to 0
    infected_ips_count = 0
    
    # Affected Computers - not available in new structure, set to 0
    affected_computers_count = 0
    
    # Recent Exposure - This month's records by type
    this_month_start = date.today().replace(day=1)
    recent_exposure = db.session.query(
        BreachedCredential.type,
        func.count(BreachedCredential.id).label('count')
    ).filter(
        BreachedCredential.created_at >= datetime.combine(this_month_start, datetime.min.time())
    )
    if user_domain:
        recent_exposure = recent_exposure.filter(BreachedCredential.domain == user_domain)
    recent_exposure = recent_exposure.group_by(BreachedCredential.type).all()
    recent_exposure_dict = {item[0]: item[1] for item in recent_exposure if item[0]}
    
    # Latest Events - Recent breaches
    latest_events = query.order_by(BreachedCredential.created_at.desc()).limit(10).all()
    
    # Chart data: Leak trends over last 30 days
    days_ago_30 = date.today() - timedelta(days=30)
    
    # Get daily leak counts - SQLite compatible approach
    daily_leaks_dict = {}
    # Use strftime for SQLite date extraction
    daily_leaks_query = db.session.query(
        func.strftime('%Y-%m-%d', BreachedCredential.created_at).label('created_date'),
        func.count(BreachedCredential.id).label('count')
    ).filter(
        BreachedCredential.created_at >= datetime.combine(days_ago_30, datetime.min.time()),
        BreachedCredential.created_at.isnot(None)
    )
    if user_domain:
        daily_leaks_query = daily_leaks_query.filter(BreachedCredential.domain == user_domain)
    daily_leaks_query = daily_leaks_query.group_by(func.strftime('%Y-%m-%d', BreachedCredential.created_at)).all()
    
    # Convert to dictionary for easy lookup (key is string 'YYYY-MM-DD')
    for item in daily_leaks_query:
        if item[0]:  # created_date (string format)
            # Convert string to date object for lookup
            try:
                date_obj = datetime.strptime(item[0], '%Y-%m-%d').date()
                daily_leaks_dict[date_obj] = item[1]
            except (ValueError, TypeError):
                continue
    
    # Prepare chart data - ensure we have data for all 30 days
    chart_labels = []
    chart_data = []
    for i in range(30):
        day = date.today() - timedelta(days=29-i)
        chart_labels.append(day.strftime('%m/%d'))
        # Get count for this day, default to 0 if no data
        count = daily_leaks_dict.get(day, 0)
        chart_data.append(count)
    
    # Leak category distribution (for pie chart) - simplified
    category_distribution = {
        'consumer': consumer_leaks,
        'corporate': corporate_leaks
    }
    
    # Type distribution (for bar chart)
    type_distribution = db.session.query(
        BreachedCredential.type,
        func.count(BreachedCredential.id).label('count')
    )
    if user_domain:
        type_distribution = type_distribution.filter(BreachedCredential.domain == user_domain)
    type_distribution = type_distribution.group_by(BreachedCredential.type).all()
    type_chart_data = {item[0]: item[1] for item in type_distribution if item[0]}
    
    context = {
        "breadcrumb": {"parent": "Threat Intelligence Dashboard", "child": "Dashboard"},
        "total_leaks": total_leaks,
        "total_change": total_change,
        "total_change_text": total_change_text,
        "consumer_leaks": consumer_leaks,
        "consumer_change": consumer_change,
        "consumer_change_text": consumer_change_text,
        "corporate_leaks": corporate_leaks,
        "corporate_change": corporate_change,
        "corporate_change_text": corporate_change_text,
        "infected_ips_count": infected_ips_count,
        "affected_computers_count": affected_computers_count,
        "recent_exposure": recent_exposure_dict,
        "latest_events": latest_events,
        "user_domain": user_domain,
        "chart_labels": chart_labels,
        "chart_data": chart_data,
        "category_distribution": category_distribution,
        "type_chart_data": type_chart_data
    }
    return render_template('general/index.html', **context)

