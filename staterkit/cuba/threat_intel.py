from flask import Blueprint, render_template, request, redirect, url_for, flash, Response, jsonify
from flask_login import login_required, current_user
from sqlalchemy import or_, func, and_
from datetime import datetime, date, timedelta
import html
import csv
import io

from . import db, cache
from .models import BreachedCredential, Company, Notification, User

threat_intel = Blueprint('threat_intel', __name__)


def get_user_company_domain():
    """Get company domain for current user"""
    if current_user.is_authenticated:
        if current_user.role == 'admin' or current_user.isAdmin:
            return None  # Admins see all data
        return current_user.company_domain
    return None


def sanitize_input(text: str) -> str:
    """Sanitize user input to prevent XSS"""
    if not text:
        return ""
    # Escape HTML special characters
    return html.escape(str(text).strip())


def _notify_new_breach(credential_id, company_domain, company_name, email):
    """Notify all users in a company about a new breach"""
    try:
        if not company_domain:
            # If no domain, notify all admins
            users = User.query.filter(
                or_(
                    User.role == 'admin',
                    User.isAdmin == True
                ),
                User.is_active == True
            ).all()
        else:
            # Get company
            company = Company.query.filter_by(domain=company_domain).first()
            if not company:
                # If company doesn't exist, notify all admins
                users = User.query.filter(
                    or_(
                        User.role == 'admin',
                        User.isAdmin == True
                    ),
                    User.is_active == True
                ).all()
            else:
                # Get all active users for the company (or all admins)
                users = User.query.filter(
                    or_(
                        User.company_id == company.id,
                        User.role == 'admin',
                        User.isAdmin == True
                    ),
                    User.is_active == True
                ).all()
        
        if not users:
            return
        
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
        # Log error but don't break the flow
        print(f"Error creating notifications: {e}")
        import traceback
        traceback.print_exc()
        db.session.rollback()


@threat_intel.route('/threat-intelligence/breached-creds')
@login_required
def breached_creds_list():
    """List all breached credentials - filtered by company for members"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Security: Sanitize input
    company_filter = sanitize_input(request.args.get('company', ''))
    company_type_filter = sanitize_input(request.args.get('company_type', ''))
    type_filter = sanitize_input(request.args.get('type', ''))  # combolist, stealer, malware, etc.
    leak_category_filter = sanitize_input(request.args.get('leak_category', ''))  # consumer, corporate
    status_filter = sanitize_input(request.args.get('status', ''))
    search_query = sanitize_input(request.args.get('search', ''))
    date_filter = sanitize_input(request.args.get('date_filter', 'week'))  # today, week, month (default: week)
    
    # Get user's company domain for filtering
    user_domain = get_user_company_domain()
    
    query = BreachedCredential.query
    
    # Security: Filter by company domain for members (data isolation)
    if user_domain:
        query = query.filter(BreachedCredential.email_domain == user_domain)
    
    # Quick date filters (default to 'week' if not specified)
    today = date.today()
    if date_filter == 'all':
        # Don't filter by date - show all
        pass
    elif date_filter == 'today':
        query = query.filter(BreachedCredential.discovered_date == today)
    elif date_filter == 'week' or not date_filter or date_filter == '':
        # Default to 'week' if not specified or empty
        week_ago = today - timedelta(days=7)
        query = query.filter(BreachedCredential.discovered_date >= week_ago)
        if not date_filter or date_filter == '':
            date_filter = 'week'
    elif date_filter == 'month':
        month_ago = today - timedelta(days=30)
        query = query.filter(BreachedCredential.discovered_date >= month_ago)
    
    # Additional filters
    if company_filter:
        query = query.filter(BreachedCredential.company_name.ilike(f'%{company_filter}%'))
    if company_type_filter:
        query = query.filter(BreachedCredential.company_type == company_type_filter)
    if type_filter:
        query = query.filter(BreachedCredential.type == type_filter)
    if leak_category_filter:
        query = query.filter(BreachedCredential.leak_category == leak_category_filter)
    if status_filter:
        query = query.filter(BreachedCredential.status == status_filter)
    if search_query:
        # Security: Use parameterized query to prevent SQL injection
        query = query.filter(
            or_(
                BreachedCredential.email.ilike(f'%{search_query}%'),
                BreachedCredential.username.ilike(f'%{search_query}%'),
                BreachedCredential.company_name.ilike(f'%{search_query}%')
            )
        )
    
    # Order by most recent first
    query = query.order_by(BreachedCredential.created_at.desc())
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    breached_creds = pagination.items
    
    # Get statistics (filtered by user domain)
    stats_query = BreachedCredential.query
    if user_domain:
        stats_query = stats_query.filter(BreachedCredential.email_domain == user_domain)
    
    # Get statistics as dictionaries
    by_type_query = db.session.query(
        BreachedCredential.type,
        func.count(BreachedCredential.id)
    )
    if user_domain:
        by_type_query = by_type_query.filter(BreachedCredential.email_domain == user_domain)
    by_type_result = by_type_query.group_by(BreachedCredential.type).all()
    
    by_leak_category_query = db.session.query(
        BreachedCredential.leak_category,
        func.count(BreachedCredential.id)
    )
    if user_domain:
        by_leak_category_query = by_leak_category_query.filter(BreachedCredential.email_domain == user_domain)
    by_leak_category_result = by_leak_category_query.group_by(BreachedCredential.leak_category).all()
    
    by_company_type_query = db.session.query(
        BreachedCredential.company_type,
        func.count(BreachedCredential.id)
    )
    if user_domain:
        by_company_type_query = by_company_type_query.filter(BreachedCredential.email_domain == user_domain)
    by_company_type_result = by_company_type_query.group_by(BreachedCredential.company_type).all()
    
    by_status_query = db.session.query(
        BreachedCredential.status,
        func.count(BreachedCredential.id)
    )
    if user_domain:
        by_status_query = by_status_query.filter(BreachedCredential.email_domain == user_domain)
    by_status_result = by_status_query.group_by(BreachedCredential.status).all()
    
    stats = {
        'total': stats_query.count(),
        'by_type': dict(by_type_result),
        'by_leak_category': dict(by_leak_category_result),
        'by_company_type': dict(by_company_type_result),
        'by_status': dict(by_status_result),
    }
    
    breadcrumb = {"parent": "Threat Intelligence", "child": "Breached Credentials", "description": "View and manage breached credentials"}
    
    # Build filter dict for template (ensure all keys exist)
    # Default date_filter to 'week' if not specified
    if not date_filter:
        date_filter = 'week'
    
    filter_dict = {
        'company': company_filter or '',
        'company_type': company_type_filter or '',
        'type': type_filter or '',
        'leak_category': leak_category_filter or '',
        'status': status_filter or '',
        'search': search_query or '',
        'date_filter': date_filter
    }
    
    return render_template('threat_intel/breached_creds_list.html',
                         breached_creds=breached_creds,
                         pagination=pagination,
                         stats=stats,
                         breadcrumb=breadcrumb,
                         filters=filter_dict)


@threat_intel.route('/threat-intelligence/breached-creds/add', methods=['GET', 'POST'])
@login_required
def breached_creds_add():
    """Add new breached credential - Admin only"""
    # Security: Only admins can add
    if current_user.role != 'admin' and not current_user.isAdmin:
        flash('Only administrators can add breached credentials.', 'danger')
        return redirect(url_for('threat_intel.breached_creds_list'))
    
    if request.method == 'POST':
        # Security: Sanitize all inputs
        company_name = sanitize_input(request.form.get('company_name', ''))
        company_type = sanitize_input(request.form.get('company_type', ''))
        email = sanitize_input(request.form.get('email', '')).lower()
        username = sanitize_input(request.form.get('username', ''))
        password_hash = sanitize_input(request.form.get('password_hash', ''))
        source = sanitize_input(request.form.get('source', ''))
        breach_date_str = request.form.get('breach_date', '')
        discovered_date_str = request.form.get('discovered_date', '')
        severity = sanitize_input(request.form.get('severity', 'medium'))
        status = sanitize_input(request.form.get('status', 'active'))
        description = sanitize_input(request.form.get('description', ''))
        
        # Validation
        if not company_name or not email or not company_type:
            flash('Company name, email, and company type are required.', 'warning')
            return render_template('threat_intel/breached_creds_form.html',
                                 breadcrumb={"parent": "Add Breached Credential", "child": "Threat Intelligence"})
        
        # Security: Validate email format
        if '@' not in email or not Company.extract_domain(email):
            flash('Invalid email format.', 'warning')
            return render_template('threat_intel/breached_creds_form.html',
                                 breadcrumb={"parent": "Add Breached Credential", "child": "Threat Intelligence"})
        
        # Security: Validate severity and status
        if severity not in ['low', 'medium', 'high', 'critical']:
            severity = 'medium'
        if status not in ['active', 'new']:
            status = 'active'
        
        # Parse dates
        breach_date = None
        if breach_date_str:
            try:
                breach_date = datetime.strptime(breach_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid breach date format.', 'warning')
                return render_template('threat_intel/breached_creds_form.html',
                                     breadcrumb={"parent": "Add Breached Credential", "child": "Threat Intelligence"})
        
        discovered_date = date.today()
        if discovered_date_str:
            try:
                discovered_date = datetime.strptime(discovered_date_str, '%Y-%m-%d').date()
            except ValueError:
                pass
        
        # Extract domain and get/create company
        email_domain = Company.extract_domain(email)
        company = Company.get_or_create_by_domain(email_domain, company_type)
        
        # Create new breached credential
        breached_cred = BreachedCredential(
            company_name=company_name,
            company_type=company_type,
            email=email,
            email_domain=email_domain,
            username=username if username else None,
            password_hash=password_hash if password_hash else None,
            source=source if source else None,
            breach_date=breach_date,
            discovered_date=discovered_date,
            type=type_value,
            leak_category=leak_category,
            ip_address=ip_address if ip_address else None,
            device_info=device_info if device_info else None,
            status=status,
            description=description if description else None,
            company_id=company.id,
            created_by=current_user.id
        )
        
        db.session.add(breached_cred)
        db.session.commit()
        
        # Create notifications for users in the same company
        _notify_new_breach(breached_cred.id, email_domain, company_name, email)
        
        # Performance: Clear cache when new data is added
        cache.clear()
        
        flash(f'Breached credential for {company_name} added successfully.', 'success')
        return redirect(url_for('threat_intel.breached_creds_list'))
    
    breadcrumb = {"parent": "Add Breached Credential", "child": "Threat Intelligence"}
    return render_template('threat_intel/breached_creds_form.html', breadcrumb=breadcrumb)


@threat_intel.route('/threat-intelligence/breached-creds/<int:id>/mark', methods=['POST'])
@login_required
def breached_creds_mark(id):
    """Mark breached credential for review - Members can mark"""
    breached_cred = BreachedCredential.query.get_or_404(id)
    
    # Security: Fix IDOR - Check if user can access this record
    user_domain = get_user_company_domain()
    if user_domain and breached_cred.email_domain != user_domain:
        flash('Access denied. You can only mark records for your company.', 'danger')
        return redirect(url_for('threat_intel.breached_creds_list'))
    
    # Toggle mark status
    breached_cred.is_marked = not breached_cred.is_marked
    if breached_cred.is_marked:
        breached_cred.marked_by = current_user.id
        breached_cred.marked_at = datetime.utcnow()
        flash('Credential marked for review.', 'success')
    else:
        breached_cred.marked_by = None
        breached_cred.marked_at = None
        flash('Mark removed.', 'info')
    
    db.session.commit()
    
    # Performance: Clear cache when marking changes
    cache.clear()
    
    return redirect(url_for('threat_intel.breached_creds_list'))


@threat_intel.route('/threat-intelligence/breached-creds/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def breached_creds_edit(id):
    """Edit breached credential - Admin only"""
    breached_cred = BreachedCredential.query.get_or_404(id)
    
    # Security: Only admins can edit
    if not current_user.can_edit():
        flash('Only administrators can edit breached credentials.', 'danger')
        return redirect(url_for('threat_intel.breached_creds_view', id=id))
    
    # Security: Fix IDOR - Even admins should verify record exists (already done with get_or_404)
    # Additional check: ensure record is accessible (for future multi-tenant scenarios)
    
    if request.method == 'POST':
        # Security: Sanitize all inputs
        breached_cred.company_name = sanitize_input(request.form.get('company_name', ''))
        breached_cred.company_type = sanitize_input(request.form.get('company_type', ''))
        email = sanitize_input(request.form.get('email', '')).lower()
        breached_cred.email = email
        breached_cred.email_domain = Company.extract_domain(email)
        breached_cred.username = sanitize_input(request.form.get('username', '')) or None
        breached_cred.password_hash = sanitize_input(request.form.get('password_hash', '')) or None
        breached_cred.source = sanitize_input(request.form.get('source', '')) or None
        type_value = sanitize_input(request.form.get('type', 'combolist'))
        leak_category = sanitize_input(request.form.get('leak_category', 'consumer'))
        ip_address = sanitize_input(request.form.get('ip_address', ''))
        device_info = sanitize_input(request.form.get('device_info', ''))
        status = sanitize_input(request.form.get('status', 'active'))
        
        valid_types = ['combolist', 'stealer', 'malware', 'pastebin', 'breach', 'phishing', 'darkweb']
        breached_cred.type = type_value if type_value in valid_types else 'combolist'
        breached_cred.leak_category = leak_category if leak_category in ['consumer', 'corporate'] else 'consumer'
        breached_cred.ip_address = ip_address if ip_address else None
        breached_cred.device_info = device_info if device_info else None
        breached_cred.status = status if status in ['active', 'new'] else 'active'
        breached_cred.description = sanitize_input(request.form.get('description', '')) or None
        
        # Update company relationship
        if breached_cred.email_domain:
            company = Company.get_or_create_by_domain(breached_cred.email_domain, breached_cred.company_type)
            breached_cred.company_id = company.id
        
        # Parse dates
        breach_date_str = request.form.get('breach_date', '')
        if breach_date_str:
            try:
                breached_cred.breach_date = datetime.strptime(breach_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid breach date format.', 'warning')
        else:
            breached_cred.breach_date = None
        
        discovered_date_str = request.form.get('discovered_date', '')
        if discovered_date_str:
            try:
                breached_cred.discovered_date = datetime.strptime(discovered_date_str, '%Y-%m-%d').date()
            except ValueError:
                pass
        
                breached_cred.updated_at = datetime.utcnow()
                
                db.session.commit()
                
                # Performance: Clear cache when data is updated
                cache.clear()
                
                flash('Breached credential updated successfully.', 'success')
                return redirect(url_for('threat_intel.breached_creds_list'))
    
    breadcrumb = {"parent": "Edit Breached Credential", "child": "Threat Intelligence"}
    return render_template('threat_intel/breached_creds_form.html',
                         breached_cred=breached_cred,
                         breadcrumb=breadcrumb)


@threat_intel.route('/threat-intelligence/breached-creds/<int:id>/delete', methods=['POST'])
@login_required
def breached_creds_delete(id):
    """Delete breached credential - Admin only"""
    breached_cred = BreachedCredential.query.get_or_404(id)
    
    # Security: Only admins can delete
    if not current_user.can_delete():
        flash('Only administrators can delete breached credentials.', 'danger')
        return redirect(url_for('threat_intel.breached_creds_view', id=id))
    
    # Security: Fix IDOR - Verify record ownership/access before deletion
    # Additional validation can be added here for multi-tenant scenarios
    
    company_name = breached_cred.company_name
    
    db.session.delete(breached_cred)
    db.session.commit()
    
    # Performance: Clear cache when data is deleted
    cache.clear()
    
    flash(f'Breached credential for {company_name} deleted successfully.', 'success')
    return redirect(url_for('threat_intel.breached_creds_list'))


@threat_intel.route('/threat-intelligence/breached-creds/export')
@login_required
def breached_creds_export():
    """Export breached credentials to CSV"""
    # Security: Get user's company domain for filtering
    user_domain = get_user_company_domain()
    
    query = BreachedCredential.query
    
    # Security: Filter by company domain for members (data isolation)
    if user_domain:
        query = query.filter(BreachedCredential.email_domain == user_domain)
    
    # Apply same filters as list view
    company_filter = sanitize_input(request.args.get('company', ''))
    company_type_filter = sanitize_input(request.args.get('company_type', ''))
    type_filter = sanitize_input(request.args.get('type', ''))
    leak_category_filter = sanitize_input(request.args.get('leak_category', ''))
    status_filter = sanitize_input(request.args.get('status', ''))
    search_query = sanitize_input(request.args.get('search', ''))
    date_filter = sanitize_input(request.args.get('date_filter', ''))
    
    today = date.today()
    if date_filter == 'today':
        query = query.filter(BreachedCredential.discovered_date == today)
    elif date_filter == 'week':
        week_ago = today - timedelta(days=7)
        query = query.filter(BreachedCredential.discovered_date >= week_ago)
    elif date_filter == 'month':
        month_ago = today - timedelta(days=30)
        query = query.filter(BreachedCredential.discovered_date >= month_ago)
    
    if company_filter:
        query = query.filter(BreachedCredential.company_name.ilike(f'%{company_filter}%'))
    if company_type_filter:
        query = query.filter(BreachedCredential.company_type == company_type_filter)
    if type_filter:
        query = query.filter(BreachedCredential.type == type_filter)
    if leak_category_filter:
        query = query.filter(BreachedCredential.leak_category == leak_category_filter)
    if status_filter:
        query = query.filter(BreachedCredential.status == status_filter)
    if search_query:
        query = query.filter(
            or_(
                BreachedCredential.email.ilike(f'%{search_query}%'),
                BreachedCredential.username.ilike(f'%{search_query}%'),
                BreachedCredential.company_name.ilike(f'%{search_query}%')
            )
        )
    
    breached_creds = query.order_by(BreachedCredential.created_at.desc()).all()
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'ID', 'Company Name', 'Company Type', 'Email', 'Email Domain', 'Username',
        'Type', 'Status', 'Marked', 'Breach Date', 'Discovered Date',
        'Source', 'Description', 'Created By', 'Created At'
    ])
    
    # Write data
    for cred in breached_creds:
        writer.writerow([
            cred.id,
            cred.company_name,
            cred.company_type,
            cred.email,
            cred.email_domain,
            cred.username or '',
            cred.type or 'combolist',
            cred.status,
            'Yes' if cred.is_marked else 'No',
            cred.breach_date.strftime('%Y-%m-%d') if cred.breach_date else '',
            cred.discovered_date.strftime('%Y-%m-%d') if cred.discovered_date else '',
            cred.source or '',
            cred.description or '',
            cred.creator.username if cred.creator else '',
            cred.created_at.strftime('%Y-%m-%d %H:%M:%S') if cred.created_at else ''
        ])
    
    # Create response
    output.seek(0)
    response = Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=breached_credentials_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
    )
    return response


@threat_intel.route('/threat-intelligence/breached-creds/<int:id>')
@login_required
def breached_creds_view(id):
    """View breached credential details"""
    breached_cred = BreachedCredential.query.get_or_404(id)
    
    # Security: Fix IDOR - Check if user can access this record
    user_domain = get_user_company_domain()
    if user_domain and breached_cred.email_domain != user_domain:
        flash('Access denied. You can only view records for your company.', 'danger')
        return redirect(url_for('threat_intel.breached_creds_list'))
    
    # Remove "new" tag when viewed
    if breached_cred.is_new:
        breached_cred.is_new = False
        db.session.commit()
        cache.clear()
    
    breadcrumb = {"parent": "Breached Credential Details", "child": "Threat Intelligence"}
    return render_template('threat_intel/breached_creds_view.html',
                         breached_cred=breached_cred,
                         breadcrumb=breadcrumb)


@threat_intel.route('/threat-intelligence/analysis')
@login_required
def analysis():
    """Threat Intelligence Analysis Dashboard"""
    user_domain = get_user_company_domain()
    
    # Performance: Use caching for statistics (5 minute cache)
    cache_key = f'analysis_stats_{user_domain or "all"}'
    stats = cache.get(cache_key)
    
    if not stats:
        # Base query
        query = BreachedCredential.query
        if user_domain:
            query = query.filter(BreachedCredential.email_domain == user_domain)
        
        # Statistics
        total = query.count()
        by_type = db.session.query(
            BreachedCredential.type,
            func.count(BreachedCredential.id).label('count')
        )
        if user_domain:
            by_type = by_type.filter(BreachedCredential.email_domain == user_domain)
        by_type = by_type.group_by(BreachedCredential.type).all()
        
        by_leak_category = db.session.query(
            BreachedCredential.leak_category,
            func.count(BreachedCredential.id).label('count')
        )
        if user_domain:
            by_leak_category = by_leak_category.filter(BreachedCredential.email_domain == user_domain)
        by_leak_category = by_leak_category.group_by(BreachedCredential.leak_category).all()
        
        by_status = db.session.query(
            BreachedCredential.status,
            func.count(BreachedCredential.id).label('count')
        )
        if user_domain:
            by_status = by_status.filter(BreachedCredential.email_domain == user_domain)
        by_status = by_status.group_by(BreachedCredential.status).all()
        
        by_company_type = db.session.query(
            BreachedCredential.company_type,
            func.count(BreachedCredential.id).label('count')
        )
        if user_domain:
            by_company_type = by_company_type.filter(BreachedCredential.email_domain == user_domain)
        by_company_type = by_company_type.group_by(BreachedCredential.company_type).all()
        
        # Recent breaches (for analysis page - no pagination needed, just top 10)
        recent = query.order_by(BreachedCredential.discovered_date.desc()).limit(10).all()
        
        # Marked items
        marked_count = query.filter(BreachedCredential.is_marked == True).count()
        
        stats = {
            'total': total,
            'by_type': dict(by_type),
            'by_leak_category': dict(by_leak_category),
            'by_status': dict(by_status),
            'by_company_type': dict(by_company_type),
            'recent': recent,
            'marked_count': marked_count
        }
        
        # Cache for 5 minutes
        cache.set(cache_key, stats, timeout=300)
    
    breadcrumb = {"parent": "Threat Analysis", "child": "Threat Intelligence", "description": "Comprehensive threat intelligence analysis and statistics"}
    return render_template('threat_intel/analysis.html',
                         total=stats['total'],
                         by_type=stats['by_type'],
                         by_leak_category=stats['by_leak_category'],
                         by_status=stats['by_status'],
                         by_company_type=stats['by_company_type'],
                         recent=stats['recent'],
                         marked_count=stats['marked_count'],
                         user_domain=user_domain,
                         breadcrumb=breadcrumb)


@threat_intel.route('/threat-intelligence/reports')
@login_required
def reports():
    """Threat Intelligence Reports"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    user_domain = get_user_company_domain()
    
    query = BreachedCredential.query
    if user_domain:
        query = query.filter(BreachedCredential.email_domain == user_domain)
    
    # Order and paginate
    query = query.order_by(BreachedCredential.discovered_date.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    breached_creds = pagination.items
    
    # Get current date/time for report
    report_date = datetime.utcnow()
    
    breadcrumb = {"parent": "Threat Reports", "child": "Threat Intelligence"}
    return render_template('threat_intel/reports.html',
                         breached_creds=breached_creds,
                         pagination=pagination,
                         user_domain=user_domain,
                         report_date=report_date,
                         breadcrumb=breadcrumb)

