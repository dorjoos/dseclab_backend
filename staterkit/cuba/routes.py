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
        query = query.filter(BreachedCredential.email_domain == user_domain)
    
    # Total Leaks (combined consumer and corporate)
    total_leaks = query.count()
    
    # Get previous month count for comparison
    last_month = date.today().replace(day=1) - timedelta(days=1)
    last_month_start = last_month.replace(day=1)
    current_month_start = date.today().replace(day=1)
    
    previous_total = query.filter(
        BreachedCredential.discovered_date >= last_month_start,
        BreachedCredential.discovered_date < current_month_start
    ).count()
    total_change = total_leaks - previous_total
    total_change_text = f"{'+' if total_change >= 0 else ''}{total_change} since {last_month.strftime('%b %Y')}"
    
    # Consumer Leaks
    consumer_leaks = query.filter(BreachedCredential.leak_category == 'consumer').count()
    previous_consumer = query.filter(
        BreachedCredential.leak_category == 'consumer',
        BreachedCredential.discovered_date >= last_month_start,
        BreachedCredential.discovered_date < current_month_start
    ).count()
    consumer_change = consumer_leaks - previous_consumer
    consumer_change_text = f"{'+' if consumer_change >= 0 else ''}{consumer_change} since {last_month.strftime('%b %Y')}"
    
    # Corporate Leaks
    corporate_leaks = query.filter(BreachedCredential.leak_category == 'corporate').count()
    previous_corporate = query.filter(
        BreachedCredential.leak_category == 'corporate',
        BreachedCredential.discovered_date >= last_month_start,
        BreachedCredential.discovered_date < current_month_start
    ).count()
    corporate_change = corporate_leaks - previous_corporate
    corporate_change_text = "↔ Stable" if corporate_change == 0 else f"{'+' if corporate_change >= 0 else ''}{corporate_change} since {last_month.strftime('%b %Y')}"
    
    # Infected IP Addresses (unique IPs linked to corporate emails)
    infected_ips = db.session.query(func.count(func.distinct(BreachedCredential.ip_address))).filter(
        BreachedCredential.leak_category == 'corporate',
        BreachedCredential.ip_address.isnot(None)
    )
    if user_domain:
        infected_ips = infected_ips.filter(BreachedCredential.email_domain == user_domain)
    infected_ips_count = infected_ips.scalar() or 0
    
    # Affected Computers (unique devices)
    affected_computers = db.session.query(func.count(func.distinct(BreachedCredential.device_info))).filter(
        BreachedCredential.leak_category == 'corporate',
        BreachedCredential.device_info.isnot(None)
    )
    if user_domain:
        affected_computers = affected_computers.filter(BreachedCredential.email_domain == user_domain)
    affected_computers_count = affected_computers.scalar() or 0
    
    # Recent Exposure - This month's records by type
    this_month_start = date.today().replace(day=1)
    recent_exposure = db.session.query(
        BreachedCredential.type,
        func.count(BreachedCredential.id).label('count')
    ).filter(
        BreachedCredential.discovered_date >= this_month_start
    )
    if user_domain:
        recent_exposure = recent_exposure.filter(BreachedCredential.email_domain == user_domain)
    recent_exposure = recent_exposure.group_by(BreachedCredential.type).all()
    recent_exposure_dict = {item[0]: item[1] for item in recent_exposure}
    
    # Latest Events - Recent breaches
    latest_events = query.order_by(BreachedCredential.discovered_date.desc(), BreachedCredential.created_at.desc()).limit(10).all()
    
    # Chart data: Leak trends over last 30 days
    days_ago_30 = date.today() - timedelta(days=30)
    
    # Get daily leak counts - SQLite compatible approach
    daily_leaks_dict = {}
    daily_leaks_query = db.session.query(
        BreachedCredential.discovered_date,
        func.count(BreachedCredential.id).label('count')
    ).filter(
        BreachedCredential.discovered_date >= days_ago_30,
        BreachedCredential.discovered_date.isnot(None)
    )
    if user_domain:
        daily_leaks_query = daily_leaks_query.filter(BreachedCredential.email_domain == user_domain)
    daily_leaks_query = daily_leaks_query.group_by(BreachedCredential.discovered_date).all()
    
    # Convert to dictionary for easy lookup
    for item in daily_leaks_query:
        if item[0]:  # discovered_date
            daily_leaks_dict[item[0]] = item[1]
    
    # Prepare chart data - ensure we have data for all 30 days
    chart_labels = []
    chart_data = []
    for i in range(30):
        day = date.today() - timedelta(days=29-i)
        chart_labels.append(day.strftime('%m/%d'))
        # Get count for this day, default to 0 if no data
        count = daily_leaks_dict.get(day, 0)
        chart_data.append(count)
    
    # Leak category distribution (for pie chart)
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
        type_distribution = type_distribution.filter(BreachedCredential.email_domain == user_domain)
    type_distribution = type_distribution.group_by(BreachedCredential.type).all()
    type_chart_data = {item[0]: item[1] for item in type_distribution}
    
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

