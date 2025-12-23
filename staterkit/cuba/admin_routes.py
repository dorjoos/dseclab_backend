from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from sqlalchemy import or_, func
from sqlalchemy.sql import text
from datetime import datetime
import re

from . import db
from .models import User, Company, BreachedCredential, WatchlistEntry, AuditLog, UserActivity
from .auth import validate_password, validate_email
from .audit_helpers import log_audit

admin_bp = Blueprint('admin', __name__)


def build_domain_match_query(domains):
    """
    Build a query filter that matches breached credentials using watchlist entries.
    
    Matches based on:
    - Domain field matches watchlist entry (exact or contains)
    - Username field contains the watchlist domain
    - URL field contains the watchlist domain
    
    Args:
        domains: List of domain/IP/values from watchlist (e.g., ['test.com', '1.1.1.2', 'aduu.com'])
    
    Returns:
        SQLAlchemy filter condition
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
        conditions.append(BreachedCredential.domain.ilike(f'%{domain}%'))
        conditions.append(func.lower(BreachedCredential.domain) == domain)
        
        # Match username field (handles both email format and username format)
        # For email format: user@test.com, user@e.test.com
        conditions.append(BreachedCredential.username.ilike(f'%@{domain}'))
        conditions.append(BreachedCredential.username.ilike(f'%@%.{domain}'))
        # For username format: if username equals domain
        conditions.append(func.lower(BreachedCredential.username) == domain)
        conditions.append(BreachedCredential.username.ilike(f'%{domain}%'))
        
        # Match URL field - contains domain
        conditions.append(BreachedCredential.url.ilike(f'%{domain}%'))
    
    # Return None if no conditions, otherwise return or_() with at least one condition
    if not conditions:
        return None
    return or_(*conditions)


def admin_required(f):
    """Decorator to require admin role"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please login to access this page.", "warning")
            return redirect(url_for('auth.login'))
        if current_user.role != 'admin' and not current_user.isAdmin:
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for('main.indexPage'))
        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route('/admin/users')
@login_required
@admin_required
def user_management():
    """Admin user management page"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('search', '').strip()
    
    query = User.query
    
    if search:
        query = query.filter(
            or_(
                User.username.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%')
            )
        )
    
    query = query.order_by(User.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    users = pagination.items
    
    companies = Company.query.order_by(Company.name).all()
    
    breadcrumb = {"parent": "User Management", "child": "Admin"}
    return render_template('admin/user_management.html',
                         users=users,
                         pagination=pagination,
                         companies=companies,
                         search=search,
                         breadcrumb=breadcrumb)


@admin_bp.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    """Add new user or member"""
    companies = Company.query.order_by(Company.name).all()
    
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'member').strip()
        company_id = request.form.get('company_id', type=int)
        is_active = bool(request.form.get('is_active'))
        
        # Security: Input validation
        if not username or not email or not password:
            flash('All required fields must be filled.', 'warning')
            return render_template('admin/user_form.html', companies=companies,
                                 breadcrumb={"parent": "Add User", "child": "Admin"})
        
        # Validate password match
        if password != confirm_password:
            flash('Passwords do not match.', 'warning')
            return render_template('admin/user_form.html', companies=companies,
                                 breadcrumb={"parent": "Add User", "child": "Admin"})
        
        # Validate username
        if len(username) < 3 or len(username) > 50:
            flash('Username must be between 3 and 50 characters.', 'warning')
            return render_template('admin/user_form.html', companies=companies,
                                 breadcrumb={"parent": "Add User", "child": "Admin"})
        
        # Security: Validate username contains only safe characters
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            flash('Username can only contain letters, numbers, underscores, and hyphens.', 'warning')
            return render_template('admin/user_form.html', companies=companies,
                                 breadcrumb={"parent": "Add User", "child": "Admin"})
        
        # Validate email
        if not validate_email(email):
            flash('Please enter a valid email address.', 'warning')
            return render_template('admin/user_form.html', companies=companies,
                                 breadcrumb={"parent": "Add User", "child": "Admin"})
        
        # Validate password
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            flash(error_msg, 'warning')
            return render_template('admin/user_form.html', companies=companies,
                                 breadcrumb={"parent": "Add User", "child": "Admin"})
        
        # Validate role
        if role not in ['admin', 'member']:
            flash('Invalid role selected.', 'warning')
            return render_template('admin/user_form.html', companies=companies,
                                 breadcrumb={"parent": "Add User", "child": "Admin"})
        
        # Check for existing user
        existing = User.query.filter(or_(User.email == email, User.username == username)).first()
        if existing:
            flash('User with that email or username already exists.', 'warning')
            return render_template('admin/user_form.html', companies=companies,
                                 breadcrumb={"parent": "Add User", "child": "Admin"})
        
        # Create user
        user = User(
            username=username,
            email=email,
            role=role,
            isAdmin=(role == 'admin'),
            company_id=company_id if company_id else None,
            is_active=is_active
        )
        user.set_password(password)
        
        # If member and no company selected, link to existing company from email domain
        # NO auto-creation - companies must be created through Company Management page
        if role == 'member' and not company_id:
            domain = Company.extract_domain(email)
            if domain:
                # Only link to existing company, never create
                company = Company.get_or_create_by_domain(domain, company_type='other', allow_create=False)
                user.company_id = company.id if company else None
        
        db.session.add(user)
        db.session.commit()
        
        flash(f'User "{username}" added successfully.', 'success')
        return redirect(url_for('admin.user_management'))
    
    breadcrumb = {"parent": "Add User", "child": "Admin"}
    return render_template('admin/user_form.html', companies=companies, breadcrumb=breadcrumb)


@admin_bp.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    """Edit user"""
    user = User.query.get_or_404(user_id)
    
    # Security: Fix IDOR - Additional validation (get_or_404 already handles non-existent)
    # In multi-tenant scenarios, add company access checks here
    companies = Company.query.order_by(Company.name).all()
    
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        role = request.form.get('role', 'member').strip()
        company_id = request.form.get('company_id', type=int)
        is_active = bool(request.form.get('is_active'))
        new_password = request.form.get('password', '').strip()  # Use 'password' field name
        
        # Security: Input validation
        if not username or not email:
            flash('Username and email are required.', 'warning')
            return render_template('admin/user_form.html', user=user, companies=companies,
                                 breadcrumb={"parent": "Edit User", "child": "Admin"})
        
        # Validate username
        if len(username) < 3 or len(username) > 50:
            flash('Username must be between 3 and 50 characters.', 'warning')
            return render_template('admin/user_form.html', user=user, companies=companies,
                                 breadcrumb={"parent": "Edit User", "child": "Admin"})
        
        # Security: Validate username
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            flash('Username can only contain letters, numbers, underscores, and hyphens.', 'warning')
            return render_template('admin/user_form.html', user=user, companies=companies,
                                 breadcrumb={"parent": "Edit User", "child": "Admin"})
        
        # Validate email
        if not validate_email(email):
            flash('Please enter a valid email address.', 'warning')
            return render_template('admin/user_form.html', user=user, companies=companies,
                                 breadcrumb={"parent": "Edit User", "child": "Admin"})
        
        # Validate role
        if role not in ['admin', 'member']:
            flash('Invalid role selected.', 'warning')
            return render_template('admin/user_form.html', user=user, companies=companies,
                                 breadcrumb={"parent": "Edit User", "child": "Admin"})
        
        # Check for duplicate username/email
        existing = User.query.filter(
            or_(User.email == email, User.username == username),
            User.id != user_id
        ).first()
        if existing:
            flash('User with that email or username already exists.', 'warning')
            return render_template('admin/user_form.html', user=user, companies=companies,
                                 breadcrumb={"parent": "Edit User", "child": "Admin"})
        
        # Update user
        user.username = username
        user.email = email
        user.role = role
        user.isAdmin = (role == 'admin')
        user.company_id = company_id if company_id else None
        user.is_active = is_active
        user.updated_at = datetime.utcnow()
        
        # Update password if provided
        if new_password:
            is_valid, error_msg = validate_password(new_password)
            if not is_valid:
                flash(error_msg, 'warning')
                return render_template('admin/user_form.html', user=user, companies=companies,
                                     breadcrumb={"parent": "Edit User", "child": "Admin"})
            user.set_password(new_password)
        
        db.session.commit()
        flash(f'User "{username}" updated successfully.', 'success')
        return redirect(url_for('admin.user_management'))
    
    breadcrumb = {"parent": "Edit User", "child": "Admin"}
    return render_template('admin/user_form.html', user=user, companies=companies, breadcrumb=breadcrumb)


@admin_bp.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete user"""
    # Security: Fix IDOR - Prevent self-deletion
    if user_id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin.user_management'))
    
    user = User.query.get_or_404(user_id)
    
    # Security: Fix IDOR - Verify user exists and is accessible
    # Additional checks can be added for multi-tenant scenarios
    username = user.username
    
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User "{username}" deleted successfully.', 'success')
    return redirect(url_for('admin.user_management'))


@admin_bp.route('/admin/companies')
@login_required
@admin_required
def company_management():
    """Company management page"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    query = Company.query.order_by(Company.name)
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    companies = pagination.items
    
    # Get breached credentials count for each company (by domain match including subdomains)
    company_stats = {}
    for company in companies:
        # Get domains to match (company domain + all watchlist entries - domain, url, email, slug, ip_address)
        domains_to_match = [company.domain]
        # Get all watchlist entries (all types, not just domains)
        watchlist_values = [entry.entry_value.strip().lower() for entry in company.watchlist_entries if entry.entry_value]
        domains_to_match.extend(watchlist_values)
        
        # Build query with subdomain and email matching
        domain_filter = build_domain_match_query(domains_to_match)
        if domain_filter is not None:
            breached_count = BreachedCredential.query.filter(domain_filter).count()
        else:
            breached_count = 0
        company_stats[company.id] = breached_count
    
    breadcrumb = {"parent": "Company Management", "child": "Admin"}
    return render_template('admin/company_management.html', 
                         companies=companies, 
                         pagination=pagination,
                         company_stats=company_stats,
                         breadcrumb=breadcrumb)


@admin_bp.route('/admin/companies/<int:company_id>/breached-creds')
@login_required
@admin_required
def company_breached_creds(company_id):
    """View breached credentials for company employees"""
    company = Company.query.get_or_404(company_id)
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Get domains to match (company domain + all watchlist entries - domain, url, email, slug, ip_address)
    domains_to_match = []
    if company.domain:
        domains_to_match.append(company.domain.lower().strip())
    
    # Get all watchlist entries (all types, not just domains)
    for entry in company.watchlist_entries:
        if entry.entry_value:
            entry_value = entry.entry_value.strip().lower()
            if entry_value:
                domains_to_match.append(entry_value)
    
    # Remove duplicates and empty strings
    domains_to_match = list(set([d for d in domains_to_match if d]))
    
    # Debug: Log what we're matching (can be removed in production)
    # print(f"DEBUG: Company: {company.name}, Domains to match: {domains_to_match}")
    
    # Build query with subdomain and email matching
    # Matches: exact domains, subdomains (e.test.com, prod-test.com), emails (@test.com, @erp.test.com), and company_name
    domain_filter = build_domain_match_query(domains_to_match)
    if domain_filter is not None:
        query = BreachedCredential.query.filter(domain_filter)
    else:
        query = BreachedCredential.query.filter(False)  # No matches if no domains
    
    query = query.order_by(BreachedCredential.created_at.desc())
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    breached_creds = pagination.items
    
    breadcrumb = {"parent": "Company Management", "child": f"Breached Credentials - {company.name}"}
    return render_template('admin/company_breached_creds.html',
                         company=company,
                         breached_creds=breached_creds,
                         pagination=pagination,
                         breadcrumb=breadcrumb)


@admin_bp.route('/admin/companies/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_company():
    """Add new company"""
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        domain = (request.form.get('domain') or '').strip().lower()
        company_type = request.form.get('company_type', 'other').strip()
        description = (request.form.get('description') or '').strip()
        
        # Security: Input validation
        if not name or not domain:
            flash('Company name and domain are required.', 'warning')
            return render_template('admin/company_form.html',
                                 breadcrumb={"parent": "Add Company", "child": "Admin"})
        
        # Validate domain format
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', domain):
            flash('Invalid domain format.', 'warning')
            return render_template('admin/company_form.html',
                                 breadcrumb={"parent": "Add Company", "child": "Admin"})
        
        # Check for existing company
        existing = Company.query.filter_by(domain=domain).first()
        if existing:
            flash('Company with that domain already exists.', 'warning')
            return render_template('admin/company_form.html',
                                 breadcrumb={"parent": "Add Company", "child": "Admin"})
        
        company = Company(
            name=name,
            domain=domain,
            company_type=company_type,
            description=description if description else None
        )
        db.session.add(company)
        db.session.flush()  # Get company.id
        
        # Process watchlist entries (multiple entries per type)
        watchlist_entries = []
        for entry_type in ['domain', 'url', 'email', 'slug', 'ip_address']:
            # Get all entries of this type from form (e.g., watchlist_domain[], watchlist_url[], etc.)
            entry_values = request.form.getlist(f'watchlist_{entry_type}[]')
            entry_descriptions = request.form.getlist(f'watchlist_{entry_type}_desc[]')
            
            for idx, value in enumerate(entry_values):
                value = value.strip()
                if value:  # Only add non-empty entries
                    desc = entry_descriptions[idx].strip() if idx < len(entry_descriptions) else None
                    watchlist_entries.append(WatchlistEntry(
                        company_id=company.id,
                        entry_type=entry_type,
                        entry_value=value,
                        description=desc if desc else None
                    ))
        
        # Add all watchlist entries
        for entry in watchlist_entries:
            db.session.add(entry)
        
        try:
            db.session.commit()
            flash(f'Company "{name}" added successfully with {len(watchlist_entries)} watchlist entries.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding company: {str(e)}', 'danger')
        return redirect(url_for('admin.company_management'))
    
    breadcrumb = {"parent": "Add Company", "child": "Admin"}
    return render_template('admin/company_form.html', breadcrumb=breadcrumb)


@admin_bp.route('/admin/companies/<int:company_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_company(company_id):
    """Edit company"""
    company = Company.query.get_or_404(company_id)
    
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        domain = (request.form.get('domain') or '').strip().lower()
        company_type = request.form.get('company_type', 'other').strip()
        description = (request.form.get('description') or '').strip()
        
        # Security: Input validation
        if not name or not domain:
            flash('Company name and domain are required.', 'warning')
            return render_template('admin/company_form.html', company=company,
                                 breadcrumb={"parent": "Edit Company", "child": "Admin"})
        
        # Validate domain format
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', domain):
            flash('Invalid domain format.', 'warning')
            return render_template('admin/company_form.html', company=company,
                                 breadcrumb={"parent": "Edit Company", "child": "Admin"})
        
        # Check for duplicate domain (excluding current company)
        existing = Company.query.filter(Company.domain == domain, Company.id != company_id).first()
        if existing:
            flash('Company with that domain already exists.', 'warning')
            return render_template('admin/company_form.html', company=company,
                                 breadcrumb={"parent": "Edit Company", "child": "Admin"})
        
        # Update company
        company.name = name
        company.domain = domain
        company.company_type = company_type
        company.description = description if description else None
        company.updated_at = datetime.utcnow()
        
        # Delete existing watchlist entries
        WatchlistEntry.query.filter_by(company_id=company.id).delete()
        
        # Process new watchlist entries (multiple entries per type)
        watchlist_entries = []
        for entry_type in ['domain', 'url', 'email', 'slug', 'ip_address']:
            # Get all entries of this type from form (e.g., watchlist_domain[], watchlist_url[], etc.)
            entry_values = request.form.getlist(f'watchlist_{entry_type}[]')
            entry_descriptions = request.form.getlist(f'watchlist_{entry_type}_desc[]')
            
            for idx, value in enumerate(entry_values):
                value = value.strip()
                if value:  # Only add non-empty entries
                    desc = entry_descriptions[idx].strip() if idx < len(entry_descriptions) else None
                    watchlist_entries.append(WatchlistEntry(
                        company_id=company.id,
                        entry_type=entry_type,
                        entry_value=value,
                        description=desc if desc else None
                    ))
        
        # Add all watchlist entries
        for entry in watchlist_entries:
            db.session.add(entry)
        
        try:
            db.session.commit()
            flash(f'Company "{name}" updated successfully with {len(watchlist_entries)} watchlist entries.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating company: {str(e)}', 'danger')
        return redirect(url_for('admin.company_management'))
    
    breadcrumb = {"parent": "Edit Company", "child": "Admin"}
    return render_template('admin/company_form.html', company=company, breadcrumb=breadcrumb)


@admin_bp.route('/admin/companies/<int:company_id>/watchlist/add', methods=['POST'])
@login_required
@admin_required
def add_watchlist_entry(company_id):
    """Add a single watchlist entry (auto-save)"""
    company = Company.query.get_or_404(company_id)
    
    entry_type = request.form.get('entry_type', '').strip()
    entry_value = request.form.get('entry_value', '').strip()
    description = request.form.get('description', '').strip() or None
    
    # Validate entry type
    if entry_type not in ['domain', 'url', 'email', 'slug', 'ip_address']:
        return jsonify({'success': False, 'error': 'Invalid entry type'}), 400
    
    # Validate entry value
    if not entry_value:
        return jsonify({'success': False, 'error': 'Entry value is required'}), 400
    
    # Check for duplicates
    existing = WatchlistEntry.query.filter_by(
        company_id=company_id,
        entry_type=entry_type,
        entry_value=entry_value
    ).first()
    
    if existing:
        return jsonify({'success': False, 'error': 'This entry already exists'}), 400
    
    # Create new entry
    entry = WatchlistEntry(
        company_id=company_id,
        entry_type=entry_type,
        entry_value=entry_value,
        description=description
    )
    
    try:
        db.session.add(entry)
        db.session.commit()
        return jsonify({
            'success': True,
            'entry_id': entry.id,
            'entry_type': entry.entry_type,
            'entry_value': entry.entry_value,
            'description': entry.description
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/admin/companies/<int:company_id>/watchlist/<int:entry_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_watchlist_entry(company_id, entry_id):
    """Delete a single watchlist entry"""
    company = Company.query.get_or_404(company_id)
    entry = WatchlistEntry.query.filter_by(id=entry_id, company_id=company_id).first_or_404()
    
    try:
        db.session.delete(entry)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/admin/audit-logs')
@login_required
@admin_required
def audit_logs():
    """View audit logs - Admin only"""
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    # Filters
    action_filter = request.args.get('action_type', '')
    resource_filter = request.args.get('resource_type', '')
    user_filter = request.args.get('user_id', type=int)
    status_filter = request.args.get('status', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    query = AuditLog.query
    
    # Apply filters
    if action_filter:
        query = query.filter(AuditLog.action_type == action_filter)
    if resource_filter:
        query = query.filter(AuditLog.resource_type == resource_filter)
    if user_filter:
        query = query.filter(AuditLog.user_id == user_filter)
    if status_filter:
        query = query.filter(AuditLog.status == status_filter)
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(AuditLog.created_at >= date_from_obj)
        except ValueError:
            pass
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
            query = query.filter(AuditLog.created_at <= date_to_obj)
        except ValueError:
            pass
    
    # Order by most recent first
    query = query.order_by(AuditLog.created_at.desc())
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    audit_logs = pagination.items
    
    # Get unique action types and resource types for filters
    action_types = db.session.query(AuditLog.action_type).distinct().all()
    resource_types = db.session.query(AuditLog.resource_type).distinct().all()
    
    breadcrumb = {"parent": "Audit Logs", "child": "Admin"}
    return render_template('admin/audit_logs.html',
                         audit_logs=audit_logs,
                         pagination=pagination,
                         action_types=[a[0] for a in action_types],
                         resource_types=[r[0] for r in resource_types],
                         breadcrumb=breadcrumb)


@admin_bp.route('/admin/user-activities')
@login_required
@admin_required
def user_activities():
    """View user activities - Admin only"""
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    # Filters
    activity_filter = request.args.get('activity_type', '')
    user_filter = request.args.get('user_id', type=int)
    status_filter = request.args.get('status', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    query = UserActivity.query
    
    # Apply filters
    if activity_filter:
        query = query.filter(UserActivity.activity_type == activity_filter)
    if user_filter:
        query = query.filter(UserActivity.user_id == user_filter)
    if status_filter:
        query = query.filter(UserActivity.status == status_filter)
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(UserActivity.created_at >= date_from_obj)
        except ValueError:
            pass
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
            query = query.filter(UserActivity.created_at <= date_to_obj)
        except ValueError:
            pass
    
    # Order by most recent first
    query = query.order_by(UserActivity.created_at.desc())
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    activities = pagination.items
    
    # Get unique activity types for filters
    activity_types = db.session.query(UserActivity.activity_type).distinct().all()
    
    breadcrumb = {"parent": "User Activities", "child": "Admin"}
    return render_template('admin/user_activities.html',
                         activities=activities,
                         pagination=pagination,
                         activity_types=[a[0] for a in activity_types],
                         breadcrumb=breadcrumb)

