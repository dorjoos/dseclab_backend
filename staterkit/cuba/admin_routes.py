from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from sqlalchemy import or_, func
from datetime import datetime
import re
import logging

from . import db
from .api_utils import escape_like
from .models import User, Company, WatchlistEntry, AuditLog, UserActivity
from .auth import validate_password, validate_email
from .audit_helpers import log_audit
from .security import admin_required
from .services.breached_creds_service import breached_creds_service as es_service

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__)


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
                User.username.ilike(f'%{escape_like(search)}%'),
                User.email.ilike(f'%{escape_like(search)}%')
            )
        )
    
    query = query.order_by(User.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    users = pagination.items
    
    companies = Company.query.order_by(Company.name).all()
    
    breadcrumb = {"parent": "Admin", "child": "User Management"}
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
        company_id = request.form.get('company_id', '').strip() or None
        is_active = bool(request.form.get('is_active'))
        
        # Security: Input validation
        if not username or not email or not password:
            flash('All required fields must be filled.', 'warning')
            return render_template('admin/user_form.html', companies=companies,
                                 breadcrumb={"parent": "Admin", "child": "Add User"})
        
        # Validate password match
        if password != confirm_password:
            flash('Passwords do not match.', 'warning')
            return render_template('admin/user_form.html', companies=companies,
                                 breadcrumb={"parent": "Admin", "child": "Add User"})
        
        # Validate username
        if len(username) < 3 or len(username) > 50:
            flash('Username must be between 3 and 50 characters.', 'warning')
            return render_template('admin/user_form.html', companies=companies,
                                 breadcrumb={"parent": "Admin", "child": "Add User"})
        
        # Security: Validate username contains only safe characters
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            flash('Username can only contain letters, numbers, underscores, and hyphens.', 'warning')
            return render_template('admin/user_form.html', companies=companies,
                                 breadcrumb={"parent": "Admin", "child": "Add User"})
        
        # Validate email
        if not validate_email(email):
            flash('Please enter a valid email address.', 'warning')
            return render_template('admin/user_form.html', companies=companies,
                                 breadcrumb={"parent": "Admin", "child": "Add User"})
        
        # Validate password
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            flash(error_msg, 'warning')
            return render_template('admin/user_form.html', companies=companies,
                                 breadcrumb={"parent": "Admin", "child": "Add User"})
        
        # Validate role
        if role not in ['admin', 'member']:
            flash('Invalid role selected.', 'warning')
            return render_template('admin/user_form.html', companies=companies,
                                 breadcrumb={"parent": "Admin", "child": "Add User"})
        
        # Check for existing user
        existing = User.query.filter(or_(User.email == email, User.username == username)).first()
        if existing:
            flash('User with that email or username already exists.', 'warning')
            return render_template('admin/user_form.html', companies=companies,
                                 breadcrumb={"parent": "Admin", "child": "Add User"})
        
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
        log_audit("create_user", "user", user.id, f"Created user '{username}'")

        flash(f'User "{username}" added successfully.', 'success')
        return redirect(url_for('admin.user_management'))

    breadcrumb = {"parent": "Admin", "child": "Add User"}
    return render_template('admin/user_form.html', companies=companies, breadcrumb=breadcrumb)


@admin_bp.route('/admin/users/<user_id>/edit', methods=['GET', 'POST'])
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
        company_id = request.form.get('company_id', '').strip() or None
        is_active = bool(request.form.get('is_active'))
        new_password = request.form.get('password', '').strip()  # Use 'password' field name
        
        # Security: Input validation
        if not username or not email:
            flash('Username and email are required.', 'warning')
            return render_template('admin/user_form.html', user=user, companies=companies,
                                 breadcrumb={"parent": "Admin", "child": "Edit User"})
        
        # Validate username
        if len(username) < 3 or len(username) > 50:
            flash('Username must be between 3 and 50 characters.', 'warning')
            return render_template('admin/user_form.html', user=user, companies=companies,
                                 breadcrumb={"parent": "Admin", "child": "Edit User"})
        
        # Security: Validate username
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            flash('Username can only contain letters, numbers, underscores, and hyphens.', 'warning')
            return render_template('admin/user_form.html', user=user, companies=companies,
                                 breadcrumb={"parent": "Admin", "child": "Edit User"})
        
        # Validate email
        if not validate_email(email):
            flash('Please enter a valid email address.', 'warning')
            return render_template('admin/user_form.html', user=user, companies=companies,
                                 breadcrumb={"parent": "Admin", "child": "Edit User"})
        
        # Validate role
        if role not in ['admin', 'member']:
            flash('Invalid role selected.', 'warning')
            return render_template('admin/user_form.html', user=user, companies=companies,
                                 breadcrumb={"parent": "Admin", "child": "Edit User"})
        
        # Check for duplicate username/email
        existing = User.query.filter(
            or_(User.email == email, User.username == username),
            User.id != user_id
        ).first()
        if existing:
            flash('User with that email or username already exists.', 'warning')
            return render_template('admin/user_form.html', user=user, companies=companies,
                                 breadcrumb={"parent": "Admin", "child": "Edit User"})
        
        # Update user
        user.username = username
        user.email = email
        user.role = role
        user.isAdmin = (role == 'admin')
        user.company_id = company_id if company_id else None
        user.is_active = is_active
        user.updated_at = datetime.utcnow()

        # Permissions
        permissions = request.form.getlist('permissions')
        user.permissions = ','.join(permissions)

        # Update password if provided
        if new_password:
            is_valid, error_msg = validate_password(new_password)
            if not is_valid:
                flash(error_msg, 'warning')
                return render_template('admin/user_form.html', user=user, companies=companies,
                                     breadcrumb={"parent": "Admin", "child": "Edit User"})
            user.set_password(new_password)
        
        db.session.commit()
        log_audit("update_user", "user", user_id, f"Updated user '{username}'")
        flash(f'User "{username}" updated successfully.', 'success')
        return redirect(url_for('admin.user_management'))

    breadcrumb = {"parent": "Admin", "child": "Edit User"}
    return render_template('admin/user_form.html', user=user, companies=companies, breadcrumb=breadcrumb)


@admin_bp.route('/admin/users/<user_id>/delete', methods=['POST'])
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
    log_audit("delete_user", "user", user_id, f"Deleted user '{username}'")

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
    
    # Get breached credentials count for each company via Elasticsearch
    company_stats = {}
    for company in companies:
        domains = company.get_match_domains()
        if domains:
            stats = es_service.get_stats(domain_filters=domains)
            company_stats[company.id] = stats['total']
        else:
            company_stats[company.id] = 0
    
    breadcrumb = {"parent": "Admin", "child": "Company Management"}
    return render_template('admin/company_management.html', 
                         companies=companies, 
                         pagination=pagination,
                         company_stats=company_stats,
                         breadcrumb=breadcrumb)


@admin_bp.route('/admin/companies/<company_id>/breached-creds')
@login_required
@admin_required
def company_breached_creds(company_id):
    """View breached credentials for company employees"""
    company = Company.query.get_or_404(company_id)
    page = request.args.get('page', 1, type=int)
    per_page = 20

    domains = company.get_match_domains()

    # Optional watchlist filter: narrow to a single watched domain.
    selected_watchlist = (request.args.get('watchlist') or '').strip().lower()
    if selected_watchlist and selected_watchlist in domains:
        active_domains = [selected_watchlist]
    else:
        selected_watchlist = ''
        active_domains = domains

    pagination = es_service.search(domain_filters=active_domains, page=page, per_page=per_page)
    if pagination.error:
        flash('Search backend (Elasticsearch) is unavailable — check that Elasticsearch '
              'is running. Showing no results.', 'danger')
    es_service.attach_matched_domain(pagination.items, active_domains)
    breached_creds = pagination.items

    breadcrumb = {"parent": "Admin", "child": f"Breached Credentials - {company.name}"}
    return render_template('admin/company_breached_creds.html',
                         company=company,
                         breached_creds=breached_creds,
                         pagination=pagination,
                         watchlist_domains=domains,
                         selected_watchlist=selected_watchlist,
                         breadcrumb=breadcrumb)


@admin_bp.route('/admin/companies/<company_id>/notify-breaches', methods=['POST'])
@login_required
@admin_required
def notify_company_breaches(company_id):
    """Email a company's active users a summary of their matched breaches."""
    from .models import Notification
    from .threat_intel import _send_breach_emails
    from .services.email_service import is_email_configured

    company = Company.query.get_or_404(company_id)
    domains = company.get_match_domains()

    pagination = es_service.search(domain_filters=domains, page=1, per_page=50)
    if pagination.error:
        flash('Cannot notify: Elasticsearch is unavailable.', 'danger')
        return redirect(url_for('admin.company_breached_creds', company_id=company_id))

    creds = es_service.attach_matched_domain(pagination.items, domains)
    if not creds:
        flash('No matched breaches to notify about.', 'warning')
        return redirect(url_for('admin.company_breached_creds', company_id=company_id))

    users = User.query.filter(
        or_(User.company_id == company.id, User.role == 'admin'),
        User.is_active == True
    ).all()

    if not is_email_configured():
        flash('Email is not configured (set MAIL_USERNAME / MAIL_PASSWORD). '
              'No emails were sent.', 'warning')
        return redirect(url_for('admin.company_breached_creds', company_id=company_id))

    sent = _send_breach_emails(
        users, company.name, creds,
        company_domain=company.domain,
        third_party_domains=company.get_third_party_domains())
    # In-app notification for each recipient as well.
    for user in users:
        db.session.add(Notification(
            user_id=user.id,
            notification_type='warning',
            title=f'Breach summary sent: {company.name}',
            message=f'{len(creds)} matched credential(s).',
            link=url_for('admin.company_breached_creds', company_id=company_id),
        ))
    db.session.commit()
    log_audit('notify_company', 'company', company_id,
              f'Emailed {sent} user(s) about {len(creds)} breach(es)')
    flash(f'Notified {sent} user(s) about {len(creds)} matched breach(es).', 'success')
    return redirect(url_for('admin.company_breached_creds', company_id=company_id))


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
                                 breadcrumb={"parent": "Admin", "child": "Add Company"})
        
        # Validate domain format
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', domain):
            flash('Invalid domain format.', 'warning')
            return render_template('admin/company_form.html',
                                 breadcrumb={"parent": "Admin", "child": "Add Company"})
        
        # Check for existing company
        existing = Company.query.filter_by(domain=domain).first()
        if existing:
            flash('Company with that domain already exists.', 'warning')
            return render_template('admin/company_form.html',
                                 breadcrumb={"parent": "Admin", "child": "Add Company"})
        
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
        for entry_type in ['domain', 'url', 'email', 'slug', 'ip_address', 'third_party']:
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
            log_audit("create_company", "company", company.id, f"Created company '{name}'")
            flash(f'Company "{name}" added successfully with {len(watchlist_entries)} watchlist entries.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'danger')
            logger.error("Error: %s", e)
        return redirect(url_for('admin.company_management'))

    breadcrumb = {"parent": "Admin", "child": "Add Company"}
    return render_template('admin/company_form.html', breadcrumb=breadcrumb)


@admin_bp.route('/admin/companies/<company_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_company(company_id):
    """Delete a company and its watchlist entries."""
    company = Company.query.get_or_404(company_id)

    # Optional safety: prevent deleting if users still assigned
    if company.users:
        flash("Cannot delete a company that still has users assigned.", "warning")
        return redirect(url_for('admin.company_management'))

    try:
        company_name = company.name
        WatchlistEntry.query.filter_by(company_id=company.id).delete()
        db.session.delete(company)
        db.session.commit()
        log_audit("delete_company", "company", company_id, f"Deleted company '{company_name}'")
        flash(f'Company "{company_name}" deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred. Please try again.', 'danger')
        logger.error("Error: %s", e)

    return redirect(url_for('admin.company_management'))


@admin_bp.route('/admin/companies/<company_id>/edit', methods=['GET', 'POST'])
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
                                 breadcrumb={"parent": "Admin", "child": "Edit Company"})
        
        # Validate domain format
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', domain):
            flash('Invalid domain format.', 'warning')
            return render_template('admin/company_form.html', company=company,
                                 breadcrumb={"parent": "Admin", "child": "Edit Company"})
        
        # Check for duplicate domain (excluding current company)
        existing = Company.query.filter(Company.domain == domain, Company.id != company_id).first()
        if existing:
            flash('Company with that domain already exists.', 'warning')
            return render_template('admin/company_form.html', company=company,
                                 breadcrumb={"parent": "Admin", "child": "Edit Company"})
        
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
        for entry_type in ['domain', 'url', 'email', 'slug', 'ip_address', 'third_party']:
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
            log_audit("update_company", "company", company_id, f"Updated company '{name}'")
            flash(f'Company "{name}" updated successfully with {len(watchlist_entries)} watchlist entries.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'danger')
            logger.error("Error: %s", e)
        return redirect(url_for('admin.company_management'))

    breadcrumb = {"parent": "Admin", "child": "Edit Company"}
    return render_template('admin/company_form.html', company=company, breadcrumb=breadcrumb)


def _wants_json():
    """True when the caller is fetch/XHR rather than a plain form post.

    The company form submits this endpoint as an ordinary <form>, so a bare
    jsonify() navigates the browser to a page of raw JSON. Answer in whichever
    form the caller actually asked for.
    """
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True
    accept = request.accept_mimetypes
    return accept['application/json'] > accept['text/html']


def _watchlist_reply(company_id, payload, status=200, message=None, category='success'):
    if _wants_json():
        return jsonify(payload), status
    if message:
        flash(message, category)
    return redirect(url_for('admin.edit_company', company_id=company_id))


@admin_bp.route('/admin/companies/<company_id>/watchlist/add', methods=['POST'])
@login_required
@admin_required
def add_watchlist_entry(company_id):
    """Add a single watchlist entry (auto-save)"""
    company = Company.query.get_or_404(company_id)

    entry_type = request.form.get('entry_type', '').strip()
    entry_value = request.form.get('entry_value', '').strip()
    description = request.form.get('description', '').strip() or None

    # Validate entry type
    if entry_type not in ['domain', 'url', 'email', 'slug', 'ip_address', 'third_party']:
        return _watchlist_reply(company_id, {'success': False, 'error': 'Invalid entry type'},
                                400, 'Invalid entry type.', 'warning')

    # Validate entry value
    if not entry_value:
        return _watchlist_reply(company_id, {'success': False, 'error': 'Entry value is required'},
                                400, 'Entry value is required.', 'warning')

    # Check for duplicates
    existing = WatchlistEntry.query.filter_by(
        company_id=company_id,
        entry_type=entry_type,
        entry_value=entry_value
    ).first()

    if existing:
        return _watchlist_reply(company_id, {'success': False, 'error': 'This entry already exists'},
                                400, f'{entry_value} is already on the watchlist.', 'info')
    
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
        return _watchlist_reply(company_id, {
            'success': True,
            'entry_id': entry.id,
            'entry_type': entry.entry_type,
            'entry_value': entry.entry_value,
            'description': entry.description,
        }, message=f'Added {entry.entry_value} to the watchlist.')
    except Exception as e:
        db.session.rollback()
        logger.error("Error: %s", e)
        return _watchlist_reply(company_id,
                                {'success': False, 'error': 'An error occurred. Please try again.'},
                                500, 'Could not add the entry. Please try again.', 'danger')


@admin_bp.route('/admin/companies/<company_id>/watchlist/<entry_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_watchlist_entry(company_id, entry_id):
    """Delete a single watchlist entry"""
    company = Company.query.get_or_404(company_id)
    entry = WatchlistEntry.query.filter_by(id=entry_id, company_id=company_id).first_or_404()
    
    try:
        value = entry.entry_value
        db.session.delete(entry)
        db.session.commit()
        return _watchlist_reply(company_id, {'success': True},
                                message=f'Removed {value} from the watchlist.', category='info')
    except Exception as e:
        db.session.rollback()
        logger.error("Error: %s", e)
        return _watchlist_reply(company_id,
                                {'success': False, 'error': 'An error occurred. Please try again.'},
                                500, 'Could not remove the entry. Please try again.', 'danger')


@admin_bp.route('/admin/companies/<company_id>/report-recipients/add', methods=['POST'])
@login_required
@admin_required
def add_report_recipient(company_id):
    """Approve an address to receive this company's reports."""
    from .models import ReportRecipient
    from .services.report_scheduler import _EMAIL_RE

    company = Company.query.get_or_404(company_id)
    email = (request.form.get('email') or '').strip().lower()

    # Exact addresses only. A domain here would undo the domain binding this
    # list exists to make a narrow exception to.
    if not _EMAIL_RE.match(email):
        flash('Report recipient must be a single valid email address.', 'warning')
        return redirect(url_for('admin.edit_company', company_id=company_id))

    if ReportRecipient.query.filter_by(company_id=company.id, email=email).first():
        flash(f'{email} is already an approved recipient.', 'info')
        return redirect(url_for('admin.edit_company', company_id=company_id))

    db.session.add(ReportRecipient(
        company_id=company.id, email=email,
        description=(request.form.get('description') or '').strip() or None,
        created_by=current_user.id))
    db.session.commit()
    log_audit('report_recipient_add', 'company', company.id,
              f'Approved {email} to receive {company.name} reports')
    flash(f'{email} approved for {company.name} reports.', 'success')
    return redirect(url_for('admin.edit_company', company_id=company_id))


@admin_bp.route('/admin/companies/<company_id>/report-recipients/<recipient_id>/delete',
                methods=['POST'])
@login_required
@admin_required
def delete_report_recipient(company_id, recipient_id):
    """Revoke an approved report recipient."""
    from .models import ReportRecipient
    recipient = ReportRecipient.query.filter_by(
        id=recipient_id, company_id=company_id).first_or_404()
    email = recipient.email
    db.session.delete(recipient)
    db.session.commit()
    log_audit('report_recipient_remove', 'company', company_id,
              f'Revoked {email}')
    flash(f'{email} removed from approved recipients.', 'info')
    return redirect(url_for('admin.edit_company', company_id=company_id))


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
    user_filter = request.args.get('user_id', '')
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
    
    breadcrumb = {"parent": "Admin", "child": "Audit Logs"}
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
    user_filter = request.args.get('user_id', '')
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
    
    breadcrumb = {"parent": "Admin", "child": "User Activities"}
    return render_template('admin/user_activities.html',
                         activities=activities,
                         pagination=pagination,
                         activity_types=[a[0] for a in activity_types],
                         breadcrumb=breadcrumb)


@admin_bp.route('/admin/compliance')
@login_required
@admin_required
def compliance_dashboard():
    """Compliance status dashboard."""
    from .models import User, Company, AuditLog, UserActivity, ScheduledReport, AlertRule
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    thirty_days_ago = now - timedelta(days=30)

    # Compliance metrics
    metrics = {
        'total_users': User.query.count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'mfa_enabled': User.query.filter_by(totp_enabled=True).count(),
        'total_companies': Company.query.count(),
        'audit_logs_30d': AuditLog.query.filter(AuditLog.created_at >= thirty_days_ago).count(),
        'failed_logins_30d': UserActivity.query.filter(
            UserActivity.activity_type == 'login_failed',
            UserActivity.created_at >= thirty_days_ago
        ).count(),
        'active_schedules': ScheduledReport.query.filter_by(is_active=True).count() if hasattr(ScheduledReport, 'query') else 0,
        'active_alerts': AlertRule.query.filter_by(is_active=True).count() if hasattr(AlertRule, 'query') else 0,
    }

    # Calculate scores
    mfa_rate = (metrics['mfa_enabled'] / max(metrics['total_users'], 1)) * 100
    metrics['mfa_rate'] = round(mfa_rate)
    metrics['audit_score'] = 'A' if metrics['audit_logs_30d'] > 100 else 'B' if metrics['audit_logs_30d'] > 20 else 'C'
    metrics['security_score'] = 'A' if mfa_rate > 80 else 'B' if mfa_rate > 50 else 'C' if mfa_rate > 20 else 'D'

    breadcrumb = {"parent": "Admin", "child": "Compliance"}
    return render_template('admin/compliance.html', metrics=metrics, breadcrumb=breadcrumb)

