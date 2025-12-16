from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from sqlalchemy import or_, func
from datetime import datetime
import re

from . import db
from .models import User, Company, BreachedCredential
from .auth import validate_password, validate_email

admin_bp = Blueprint('admin', __name__)


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
        
        # If member and no company selected, create/link company from email domain
        if role == 'member' and not company_id:
            domain = Company.extract_domain(email)
            if domain:
                company = Company.get_or_create_by_domain(domain, company_type='other')
                user.company_id = company.id
        
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
    
    breadcrumb = {"parent": "Company Management", "child": "Admin"}
    return render_template('admin/company_management.html', 
                         companies=companies, 
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
        db.session.commit()
        
        flash(f'Company "{name}" added successfully.', 'success')
        return redirect(url_for('admin.company_management'))
    
    breadcrumb = {"parent": "Add Company", "child": "Admin"}
    return render_template('admin/company_form.html', breadcrumb=breadcrumb)

