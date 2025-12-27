from flask import Blueprint, render_template, request, redirect, url_for, flash, Response, jsonify
from flask_login import login_required, current_user
from sqlalchemy import or_, func, and_
from datetime import datetime, date, timedelta
import html
import csv
import io
import json
try:
    from openpyxl import Workbook
    from openpyxl.styles import Font, Alignment
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from . import db, cache
from .models import BreachedCredential, Company, Notification, User
from .audit_helpers import log_audit
from .security import (
    get_user_company_domain,
    get_user_watchlist_domains,
    can_user_access_breached_cred,
    requires_breached_cred_access,
)
from .services.filters import build_date_filter
from .services.breached_creds_service import (
    build_analysis_stats,
    apply_breached_domain_filter,
)
from .security import (
    get_user_company_domain,
    get_user_watchlist_domains,
    can_user_access_breached_cred,
)

threat_intel = Blueprint('threat_intel', __name__)


def _build_domain_match_query(domains):
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
        # For username format: if username equals domain or contains domain
        conditions.append(func.lower(BreachedCredential.username) == domain)
        conditions.append(BreachedCredential.username.ilike(f'%{domain}%'))
        
        # Match URL field - contains domain
        conditions.append(BreachedCredential.url.ilike(f'%{domain}%'))
    
    # Return None if no conditions, otherwise return or_() with at least one condition
    if not conditions:
        return None
    return or_(*conditions)


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
    page = request.args.get("page", 1, type=int)
    per_page = 10

    # Security: Sanitize input
    type_filter = sanitize_input(request.args.get("type", ""))  # combolist, stealer, malware, etc.
    source_filter = sanitize_input(request.args.get("source", ""))
    domain_filter_param = sanitize_input(request.args.get("domain", ""))
    search_query = sanitize_input(request.args.get("search", ""))
    raw_date_filter = sanitize_input(request.args.get("date_filter", "all"))  # today, week, month, all (default: all)

    # Get user's company domain for filtering
    user_domain = get_user_company_domain()

    query = BreachedCredential.query

    # Security: Filter by company domain and watchlist for members (data isolation)
    if user_domain:
        query = apply_breached_domain_filter(query, user_domain)

    # Quick date filters via reusable helper
    query, date_filter = build_date_filter(
        query, BreachedCredential.created_at, raw_date_filter
    )
    
    # Additional filters
    if type_filter:
        query = query.filter(BreachedCredential.type == type_filter)
    if source_filter:
        query = query.filter(BreachedCredential.source.ilike(f'%{source_filter}%'))
    if domain_filter_param:
        query = query.filter(BreachedCredential.domain.ilike(f'%{domain_filter_param}%'))
    if search_query:
        # Security: Use parameterized query to prevent SQL injection
        query = query.filter(
            or_(
                BreachedCredential.username.ilike(f'%{search_query}%'),
                BreachedCredential.domain.ilike(f'%{search_query}%'),
                BreachedCredential.password.ilike(f'%{search_query}%'),
                BreachedCredential.source.ilike(f'%{search_query}%')
            )
        )
    
    # Order by most recent first
    query = query.order_by(BreachedCredential.created_at.desc())
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    breached_creds = pagination.items
    
    # Get statistics (filtered by user domain and watchlist)
    stats_query = BreachedCredential.query
    if user_domain:
        domains_to_match = get_user_watchlist_domains()
        stats_domain_filter = _build_domain_match_query(domains_to_match)
        if stats_domain_filter is not None:
            stats_query = stats_query.filter(stats_domain_filter)
        else:
            stats_query = stats_query.filter(BreachedCredential.domain == user_domain)
    
    # Get statistics as dictionaries
    by_type_query = db.session.query(
        BreachedCredential.type,
        func.count(BreachedCredential.id)
    )
    if user_domain:
        domains_to_match = get_user_watchlist_domains()
        stats_domain_filter = _build_domain_match_query(domains_to_match)
        if stats_domain_filter is not None:
            by_type_query = by_type_query.filter(stats_domain_filter)
        else:
            by_type_query = by_type_query.filter(BreachedCredential.domain == user_domain)
    by_type_result = by_type_query.group_by(BreachedCredential.type).all()
    
    stats = {
        'total': stats_query.count(),
        'by_type': dict(by_type_result),
    }
    
    breadcrumb = {"parent": "Threat Intelligence", "child": "Breached Credentials", "description": "View and manage breached credentials"}
    
    # Build filter dict for template (ensure all keys exist)
    # Default date_filter to 'week' if not specified
    if not date_filter:
        date_filter = 'week'
    
    filter_dict = {
        'type': type_filter or '',
        'source': source_filter or '',
        'domain': domain_filter_param or '',
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
        _id = sanitize_input(request.form.get('_id', ''))
        _index = sanitize_input(request.form.get('_index', ''))
        _score_str = request.form.get('_score', '')
        _ignored_str = request.form.get('_ignored', '0')
        username = sanitize_input(request.form.get('username', ''))
        domain = sanitize_input(request.form.get('domain', ''))
        password = sanitize_input(request.form.get('password', ''))
        source = sanitize_input(request.form.get('source', ''))
        type_value = sanitize_input(request.form.get('type', ''))
        url = sanitize_input(request.form.get('url', ''))
        
        # Parse _score
        _score = None
        if _score_str:
            try:
                _score = float(_score_str)
            except ValueError:
                pass
        
        # Parse _ignored
        _ignored = _ignored_str == '1'
        
        # Link to existing company if domain is provided
        company = None
        if domain:
            domain_clean = domain.strip().lower()
            # Try to find existing company by domain
            company = Company.query.filter_by(domain=domain_clean).first()
        
        # Create new breached credential
        breached_cred = BreachedCredential(
            _id=_id if _id else None,
            _index=_index if _index else None,
            _score=_score,
            _ignored=_ignored,
            username=username if username else None,
            domain=domain if domain else None,
            password=password if password else None,
            source=source if source else None,
            type=type_value if type_value else None,
            url=url if url else None,
            company_id=company.id if company else None,
            created_by=current_user.id
        )
        
        db.session.add(breached_cred)
        db.session.commit()
        
        # Create notifications for users in the same company
        if domain:
            _notify_new_breach(breached_cred.id, domain, domain, username or domain)
        
        # Performance: Clear cache when new data is added
        cache.clear()
        
        flash(f'Breached credential added successfully.', 'success')
        return redirect(url_for('threat_intel.breached_creds_list'))
    
    breadcrumb = {"parent": "Add Breached Credential", "child": "Threat Intelligence"}
    return render_template('threat_intel/breached_creds_form.html', breadcrumb=breadcrumb)


@threat_intel.route('/threat-intelligence/breached-creds/<int:id>/mark', methods=['POST'])
@login_required
@requires_breached_cred_access
def breached_creds_mark(id, breached_cred):
    """Mark breached credential for review - Members can mark"""
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
@requires_breached_cred_access
def breached_creds_edit(id, breached_cred):
    """Edit breached credential - Admin only"""
    # Security: Only admins can edit
    if not current_user.can_edit():
        flash('Only administrators can edit breached credentials.', 'danger')
        return redirect(url_for('threat_intel.breached_creds_view', id=id))
    
    # Security: Fix IDOR - Even admins should verify record exists (already done with get_or_404)
    # Additional check: ensure record is accessible (for future multi-tenant scenarios)
    
    if request.method == 'POST':
        # Security: Sanitize all inputs
        breached_cred._id = sanitize_input(request.form.get('_id', '')) or None
        breached_cred._index = sanitize_input(request.form.get('_index', '')) or None
        _score_str = request.form.get('_score', '')
        _ignored_str = request.form.get('_ignored', '0')
        breached_cred.username = sanitize_input(request.form.get('username', '')) or None
        breached_cred.domain = sanitize_input(request.form.get('domain', '')) or None
        breached_cred.password = sanitize_input(request.form.get('password', '')) or None
        breached_cred.source = sanitize_input(request.form.get('source', '')) or None
        breached_cred.type = sanitize_input(request.form.get('type', '')) or None
        breached_cred.url = sanitize_input(request.form.get('url', '')) or None
        
        # Parse _score
        if _score_str:
            try:
                breached_cred._score = float(_score_str)
            except ValueError:
                breached_cred._score = None
        else:
            breached_cred._score = None
        
        # Parse _ignored
        breached_cred._ignored = _ignored_str == '1'
        
        # Update company relationship - Link to existing company if domain is provided
        company = None
        if breached_cred.domain:
            domain_clean = breached_cred.domain.strip().lower()
            # Try to find existing company by domain
            company = Company.query.filter_by(domain=domain_clean).first()
        
        breached_cred.company_id = company.id if company else None
        breached_cred.updated_at = datetime.utcnow()
                
        try:
            db.session.commit()
            flash('Breached credential updated successfully.', 'success')
        except OperationalError as e:
            # On read-only DB (Vercel), updates will fail
            if "readonly" in str(e).lower():
                db.session.rollback()
                flash('Updates are disabled in read-only mode.', 'warning')
            else:
                raise
        return redirect(url_for('threat_intel.breached_creds_list'))
    
    breadcrumb = {"parent": "Edit Breached Credential", "child": "Threat Intelligence"}
    return render_template('threat_intel/breached_creds_form.html',
                         breached_cred=breached_cred,
                         breadcrumb=breadcrumb)


@threat_intel.route('/threat-intelligence/breached-creds/<int:id>/delete', methods=['POST'])
@login_required
@requires_breached_cred_access
def breached_creds_delete(id, breached_cred):
    """Delete breached credential - Admin only"""
    # Security: Only admins can delete
    if not current_user.can_delete():
        flash('Only administrators can delete breached credentials.', 'danger')
        return redirect(url_for('threat_intel.breached_creds_view', id=id))
    
    # Security: Fix IDOR - Verify record ownership/access before deletion
    # Additional validation can be added here for multi-tenant scenarios
    
    identifier = breached_cred.username or breached_cred.domain or str(breached_cred.id)
    
    db.session.delete(breached_cred)
    db.session.commit()
    
    # Performance: Clear cache when data is deleted
    cache.clear()
    
    flash(f'Breached credential deleted successfully.', 'success')
    return redirect(url_for('threat_intel.breached_creds_list'))


@threat_intel.route('/threat-intelligence/breached-creds/export')
@login_required
def breached_creds_export():
    """Export breached credentials - supports CSV, Excel, JSON, PDF"""
    export_format = request.args.get('format', 'csv').lower()  # csv, xlsx, json, pdf
    # Security: Get user's company domain for filtering
    user_domain = get_user_company_domain()
    
    query = BreachedCredential.query
    
    # Security: Filter by company domain for members (data isolation)
    if user_domain:
        domains_to_match = get_user_watchlist_domains()
        domain_filter = _build_domain_match_query(domains_to_match)
        if domain_filter is not None:
            query = query.filter(domain_filter)
        else:
            query = query.filter(BreachedCredential.domain == user_domain)
    
    # Apply same filters as list view
    type_filter = sanitize_input(request.args.get('type', ''))
    source_filter = sanitize_input(request.args.get('source', ''))
    domain_filter_param = sanitize_input(request.args.get('domain', ''))
    search_query = sanitize_input(request.args.get('search', ''))
    date_filter = sanitize_input(request.args.get('date_filter', ''))
    
    today = date.today()
    if date_filter == 'today':
        query = query.filter(BreachedCredential.created_at >= datetime.combine(today, datetime.min.time()))
    elif date_filter == 'week':
        week_ago = today - timedelta(days=7)
        query = query.filter(BreachedCredential.created_at >= datetime.combine(week_ago, datetime.min.time()))
    elif date_filter == 'month':
        month_ago = today - timedelta(days=30)
        query = query.filter(BreachedCredential.created_at >= datetime.combine(month_ago, datetime.min.time()))
    
    if type_filter:
        query = query.filter(BreachedCredential.type == type_filter)
    if source_filter:
        query = query.filter(BreachedCredential.source.ilike(f'%{source_filter}%'))
    if domain_filter_param:
        query = query.filter(BreachedCredential.domain.ilike(f'%{domain_filter_param}%'))
    if search_query:
        query = query.filter(
            or_(
                BreachedCredential.username.ilike(f'%{search_query}%'),
                BreachedCredential.domain.ilike(f'%{search_query}%'),
                BreachedCredential.password.ilike(f'%{search_query}%'),
                BreachedCredential.source.ilike(f'%{search_query}%')
            )
        )
    
    breached_creds = query.order_by(BreachedCredential.created_at.desc()).all()
    
    # Log export action
    log_audit("export", "breached_credential", None, 
              f"Exported {len(breached_creds)} breached credentials in {export_format.upper()} format")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Handle different export formats
    if export_format == 'json':
        # JSON export
        data = []
        for cred in breached_creds:
            data.append({
                'id': cred.id,
                '_id': cred._id,
                '_index': cred._index,
                '_score': cred._score,
                '_ignored': cred._ignored,
                'username': cred.username,
                'domain': cred.domain,
                'password': cred.password,
                'source': cred.source,
                'type': cred.type,
                'url': cred.url,
                'is_marked': cred.is_marked,
                'created_by': cred.creator.username if cred.creator else None,
                'created_at': cred.created_at.isoformat() if cred.created_at else None
            })
        
        response = Response(
            json.dumps(data, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename=breached_credentials_{timestamp}.json'}
        )
        return response
    
    elif export_format == 'xlsx' and OPENPYXL_AVAILABLE:
        # Excel export
        wb = Workbook()
        ws = wb.active
        ws.title = "Breached Credentials"
        
        # Headers
        headers = ['ID', '_id', '_index', '_score', '_ignored', 'Username', 'Domain', 'Password',
                  'Source', 'Type', 'URL', 'Marked', 'Created By', 'Created At']
        ws.append(headers)
        
        # Style header row
        for cell in ws[1]:
            cell.font = Font(bold=True)
            cell.alignment = Alignment(horizontal='center')
        
        # Data rows
        for cred in breached_creds:
            ws.append([
                cred.id,
                cred._id or '',
                cred._index or '',
                cred._score if cred._score is not None else '',
                'Yes' if cred._ignored else 'No',
                cred.username or '',
                cred.domain or '',
                cred.password or '',
                cred.source or '',
                cred.type or '',
                cred.url or '',
                'Yes' if cred.is_marked else 'No',
                cred.creator.username if cred.creator else '',
                cred.created_at.strftime('%Y-%m-%d %H:%M:%S') if cred.created_at else ''
            ])
        
        # Save to BytesIO
        output = io.BytesIO()
        wb.save(output)
        output.seek(0)
        
        response = Response(
            output.getvalue(),
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={'Content-Disposition': f'attachment; filename=breached_credentials_{timestamp}.xlsx'}
        )
        return response
    
    elif export_format == 'pdf' and REPORTLAB_AVAILABLE:
        # PDF export
        output = io.BytesIO()
        doc = SimpleDocTemplate(output, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        title = Paragraph("Breached Credentials Report", styles['Title'])
        elements.append(title)
        elements.append(Spacer(1, 12))
        
        # Summary
        summary = Paragraph(f"Total Records: {len(breached_creds)}<br/>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                           styles['Normal'])
        elements.append(summary)
        elements.append(Spacer(1, 12))
        
        # Table data
        data = [['ID', 'Username', 'Domain', 'Type', 'Source', 'Created']]
        for cred in breached_creds[:100]:  # Limit to 100 rows for PDF
            data.append([
                str(cred.id),
                (cred.username or '')[:30],  # Truncate long values
                (cred.domain or '')[:30],
                cred.type or '',
                (cred.source or '')[:30],
                cred.created_at.strftime('%Y-%m-%d') if cred.created_at else ''
            ])
        
        # Create table
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
        ]))
        
        elements.append(table)
        doc.build(elements)
        output.seek(0)
        
        response = Response(
            output.getvalue(),
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename=breached_credentials_{timestamp}.pdf'}
        )
        return response
    
    else:
        # Default: CSV export
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', '_id', '_index', '_score', '_ignored', 'Username', 'Domain', 'Password',
                        'Source', 'Type', 'URL', 'Marked', 'Created By', 'Created At'])
    for cred in breached_creds:
        writer.writerow([
            cred.id,
            cred._id or '',
            cred._index or '',
            cred._score if cred._score is not None else '',
            'Yes' if cred._ignored else 'No',
            cred.username or '',
            cred.domain or '',
            cred.password or '',
            cred.source or '',
            cred.type or '',
            cred.url or '',
            'Yes' if cred.is_marked else 'No',
            cred.creator.username if cred.creator else '',
            cred.created_at.strftime('%Y-%m-%d %H:%M:%S') if cred.created_at else ''
        ])
    
    # Create response
    output.seek(0)
    response = Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=breached_credentials_{timestamp}.csv'}
    )
    return response


@threat_intel.route('/threat-intelligence/breached-creds/<int:id>')
@login_required
@requires_breached_cred_access
def breached_creds_view(id, breached_cred):
    """View breached credential details"""
    # No is_new field in new structure, so this check is removed
    
    breadcrumb = {"parent": "Breached Credential Details", "child": "Threat Intelligence"}
    return render_template('threat_intel/breached_creds_view.html',
                         breached_cred=breached_cred,
                         breadcrumb=breadcrumb)


@threat_intel.route('/threat-intelligence/analysis')
@login_required
def analysis():
    """Threat Intelligence Analysis Dashboard"""
    stats = build_analysis_stats()
    user_domain = stats["user_domain"]

    breadcrumb = {"parent": "Threat Analysis", "child": "Threat Intelligence", "description": "Comprehensive threat intelligence analysis and statistics"}
    return render_template('threat_intel/analysis.html',
                         total=stats["total"],
                         by_type=stats["by_type"],
                         by_source=stats["by_source"],
                         by_domain=stats["by_domain"],
                         recent=stats["recent"],
                         marked_count=stats["marked_count"],
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
        domains_to_match = get_user_watchlist_domains()
        domain_filter = _build_domain_match_query(domains_to_match)
        if domain_filter is not None:
            query = query.filter(domain_filter)
        else:
            query = query.filter(BreachedCredential.domain == user_domain)
    
    # Order and paginate
    query = query.order_by(BreachedCredential.created_at.desc())
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

