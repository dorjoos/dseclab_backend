from flask import Blueprint, render_template, request, redirect, url_for, flash, Response, jsonify, abort, current_app
from flask_login import login_required, current_user
from sqlalchemy import or_
from datetime import datetime, timezone
import csv
import io
import json
import logging

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

from . import db, cache, csrf, limiter
from .models import BreachedCredMeta, Company, Notification, User
from .api_utils import sanitize_input
from .audit_helpers import log_audit, log_user_activity
from .security import get_user_company_domain, get_user_watchlist_domains
from .services.breached_creds_service import breached_creds_service as es_service
from .services.breached_creds_analysis import build_analysis_stats
from .services.data_masking import mask_value

logger = logging.getLogger(__name__)

threat_intel = Blueprint('threat_intel', __name__)


def _get_domain_filters():
    """Scope for the current user: None is unrestricted, a list restricts.

    Only an admin may get None. Everyone else gets their company's domains,
    and an empty list is a real answer meaning "no access" — _build_query
    turns it into a match-nothing clause rather than dropping the filter.
    """
    if not current_user.is_authenticated:
        return []
    if current_user.is_admin_user:
        return None
    return get_user_watchlist_domains()


def _host_belongs_to(host: str, domain: str) -> bool:
    """True when `host` equals `domain` or is a subdomain of it.

    Substring matching would treat 'ibank.mn' as belonging to 'nibank.mn';
    suffix matching anchored on a '.' boundary prevents that.
    """
    if not host or not domain:
        return False
    host = host.lower().strip().rstrip(".")
    domain = domain.lower().strip().lstrip(".").rstrip(".")
    if not host or not domain:
        return False
    return host == domain or host.endswith("." + domain)


def _cred_matches_domain(cred, domain: str) -> bool:
    """True when any of cred.domain, the @-suffix of cred.username, or the
    host of cred.url belongs to `domain` (equal or subdomain)."""
    if not domain:
        return False
    if _host_belongs_to(cred.domain or "", domain):
        return True
    username = (cred.username or "").lower()
    if "@" in username:
        if _host_belongs_to(username.split("@", 1)[1], domain):
            return True
    url = (cred.url or "").strip()
    if url:
        from urllib.parse import urlparse
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = (parsed.hostname or "").lower()
        if _host_belongs_to(host, domain):
            return True
    return False


def _check_cred_access(cred):
    """Check if current user can access this credential. Returns True if allowed."""
    if current_user.is_admin_user:
        return True
    domain_filters = _get_domain_filters()
    if not domain_filters:
        return False
    return any(_cred_matches_domain(cred, d) for d in domain_filters)


def _attach_metadata(items):
    """Attach local metadata (marks) to a list of BreachedCredDoc items."""
    if not items:
        return
    es_ids = [item.es_id for item in items]
    metas = BreachedCredMeta.query.filter(BreachedCredMeta.es_id.in_(es_ids)).all()
    meta_map = {m.es_id: m for m in metas}
    for item in items:
        meta = meta_map.get(item.es_id)
        if meta:
            item.is_marked = meta.is_marked
            item.marked_by = meta.marked_by
            item.marked_at = meta.marked_at
            item.marker = meta.marker
            item.notes = meta.notes


def _send_breach_emails(users, company_name, creds, company_domain=None,
                        third_party_domains=None):
    """Best-effort email of matched breaches to users. Never raises."""
    try:
        from .services.email_service import build_breach_email, send_email, is_email_configured
        if not is_email_configured():
            logger.info("Email not configured; skipping breach email for %s", company_name)
            return 0
        from flask import has_request_context
        # Prefer the configured base URL. request.url_root is derived from the
        # Host header, which ProxyFix trusts — a poisoned host would put an
        # attacker-controlled "View credential" link inside a breach alert,
        # which is exactly the mail a recipient is primed to click.
        base_url = current_app.config.get('APP_BASE_URL') or (
            request.url_root if has_request_context() else None)
        subject, body, text = build_breach_email(
            company_name, creds, base_url=base_url,
            company_domain=company_domain,
            third_party_domains=third_party_domains)
        sent = 0
        for user in users:
            # One message per recipient — never a shared To/CC, which would
            # disclose the client roster to everyone on it.
            if user.email and send_email(user.email, subject, body, text=text):
                sent += 1
        return sent
    except Exception as e:
        logger.error("Breach email send failed: %s", e)
        return 0


def _notify_new_breach(credential_id, company_domain, company_name, email, file_name=None):
    """Notify all users in a company about a new breach (in-app + email)."""
    try:
        if not company_domain:
            users = User.query.filter(
                User.role == 'admin',
                User.is_active == True
            ).all()
        else:
            company = Company.query.filter_by(domain=company_domain).first()
            if not company:
                users = User.query.filter(
                    User.role == 'admin',
                    User.is_active == True
                ).all()
            else:
                users = User.query.filter(
                    or_(
                        User.company_id == company.id,
                        User.role == 'admin',
                    ),
                    User.is_active == True
                ).all()

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
        logger.error("Error creating notifications: %s", e)
        db.session.rollback()
        return

    # Email delivery is best-effort and must not affect the in-app flow above.
    cred = es_service.get_by_id(credential_id)
    if cred is None:
        from types import SimpleNamespace
        cred = SimpleNamespace(
            es_id=credential_id, username=email, domain=company_domain,
            file_name=file_name, source=None, type=None, created_at=None,
        )
    cred.matched_domain = company_domain
    # Label how it matched so the email can bucket it as staff vs customer.
    if not getattr(cred, 'match_path', None):
        _, cred.match_path = es_service.compute_match_detail(
            cred, [company_domain] if company_domain else [])
    if file_name and not getattr(cred, 'file_name', None):
        cred.file_name = file_name
    _send_breach_emails(users, company_name, [cred], company_domain=company_domain)


@threat_intel.route('/threat-intelligence/breached-creds')
@login_required
def breached_creds_list():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    if per_page not in (10, 20, 50):
        per_page = 20

    type_filter = sanitize_input(request.args.get("type", ""))
    source_filter = sanitize_input(request.args.get("source", ""))
    domain_filter_param = sanitize_input(request.args.get("domain", ""))
    search_query = sanitize_input(request.args.get("search", ""))
    date_filter = sanitize_input(request.args.get("date_filter", "all"))

    domain_filters = _get_domain_filters()

    filters = {}
    if type_filter:
        filters['type'] = type_filter
    if source_filter:
        filters['source'] = source_filter
    if domain_filter_param:
        filters['domain'] = domain_filter_param
    if date_filter and date_filter != 'all':
        filters['date_filter'] = date_filter

    pagination = es_service.search(
        query_text=search_query or None,
        filters=filters if filters else None,
        domain_filters=domain_filters,
        page=page,
        per_page=per_page
    )
    if pagination.error:
        flash('Search backend (Elasticsearch) is unavailable — results may be incomplete. '
              'Please check that Elasticsearch is running.', 'danger')
    _attach_metadata(pagination.items)

    stats_data = es_service.get_stats(domain_filters=domain_filters)
    stats = {'total': stats_data['total'], 'by_type': stats_data['by_type']}

    if not date_filter:
        date_filter = 'all'

    filter_dict = {
        'type': type_filter or '',
        'source': source_filter or '',
        'domain': domain_filter_param or '',
        'search': search_query or '',
        'date_filter': date_filter
    }

    breadcrumb = {"parent": "Threat Intelligence", "child": "Breached Credentials"}
    return render_template('threat_intel/breached_creds_list.html',
                          breached_creds=pagination.items,
                          pagination=pagination,
                          stats=stats,
                          filters=filter_dict,
                          breadcrumb=breadcrumb)


@threat_intel.route('/api/timeline', methods=['POST'])
@login_required
def timeline_api():
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


@threat_intel.route('/api/breached-creds/search', methods=['POST'])
@login_required
@limiter.limit("30/minute")
def breached_creds_api():
    """Search breached credentials
    ---
    tags:
      - Breached Credentials
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            page:
              type: integer
              default: 1
            per_page:
              type: integer
              default: 20
            search:
              type: string
            type:
              type: string
            source:
              type: string
            domain:
              type: string
            date_filter:
              type: string
              enum: [all, today, week, month]
    responses:
      200:
        description: Paginated search results
    """
    from flask import jsonify
    data = request.get_json(silent=True) or {}

    page = data.get('page', 1)
    per_page = data.get('per_page', 20)
    per_page = min(max(int(per_page), 1), 50)
    search_query = sanitize_input(data.get('search', ''))
    if search_query and len(search_query.strip()) < 3:
        search_query = None  # Too short, ignore
    type_filter = sanitize_input(data.get('type', ''))
    source_filter = sanitize_input(data.get('source', ''))
    domain_filter_param = sanitize_input(data.get('domain', ''))
    date_filter = sanitize_input(data.get('date_filter', 'all'))

    domain_filters = _get_domain_filters()

    filters = {}
    if type_filter:
        filters['type'] = type_filter
    if source_filter:
        filters['source'] = source_filter
    if domain_filter_param:
        filters['domain'] = domain_filter_param
    if date_filter and date_filter != 'all':
        filters['date_filter'] = date_filter

    pagination = es_service.search(
        query_text=search_query or None,
        filters=filters if filters else None,
        domain_filters=domain_filters,
        page=page,
        per_page=per_page
    )
    _attach_metadata(pagination.items)
    es_service.attach_matched_domain(pagination.items, domain_filters or [])

    rows = []
    for i, cred in enumerate(pagination.items):
        rows.append({
            'num': (page - 1) * per_page + i + 1,
            'es_id': cred.es_id,
            'username': cred.username or '',
            'domain': cred.domain or '',
            'matched_domain': cred.matched_domain or '',
            'password': '********' if cred.password else '',  # Always masked in list API
            'source': cred.source or '',
            'type': cred.type or '',
            'date': cred.created_at.strftime('%b %d') if cred.created_at else '',
            'is_marked': cred.is_marked,
        })

    return jsonify({
        'rows': rows,
        'page': pagination.page,
        'pages': pagination.pages,
        'total': pagination.total,
        'has_prev': pagination.has_prev,
        'has_next': pagination.has_next,
        'error': pagination.error,
    })


@threat_intel.route('/threat-intelligence/breached-creds/<doc_id>')
@login_required
def breached_creds_view(doc_id):
    cred = es_service.get_by_id(doc_id)
    if not cred:
        flash('Record not found.', 'warning')
        return redirect(url_for('threat_intel.breached_creds_list'))
    if not _check_cred_access(cred):
        flash('Access denied.', 'danger')
        return redirect(url_for('threat_intel.breached_creds_list'))
    _attach_metadata([cred])
    # Server never renders plaintext password into HTML for any role.
    # Plaintext is delivered only via the reveal-password endpoint, which
    # re-runs _check_cred_access and writes an audit row per reveal.
    if cred.password:
        cred.password = '********'
    breadcrumb = {"parent": "Threat Intelligence", "child": "Credential Details"}
    return render_template('threat_intel/breached_creds_view.html',
                          breached_cred=cred, breadcrumb=breadcrumb)


@threat_intel.route('/threat-intelligence/breached-creds/<doc_id>/reveal-password', methods=['POST'])
@login_required
@limiter.limit("30/minute")
def breached_creds_reveal_password(doc_id):
    """Return the plaintext password for a breached cred the user is authorized to see.

    Gated by the same tenancy check as the detail view. Every successful and
    denied call is recorded in the audit log so reveals are accountable.
    """
    cred = es_service.get_by_id(doc_id)
    if not cred:
        return jsonify({"error": "not_found"}), 404
    if not _check_cred_access(cred):
        log_audit("reveal_password_denied", "breached_cred", doc_id,
                  f"User {current_user.username} denied reveal for cred {doc_id}",
                  status="failed")
        db.session.commit()
        return jsonify({"error": "access_denied"}), 403
    log_audit("reveal_password", "breached_cred", doc_id,
              f"User {current_user.username} revealed password for cred {doc_id} "
              f"(domain={cred.domain or 'unknown'})")
    log_user_activity("reveal_password", current_user.id, status="success")
    db.session.commit()
    return jsonify({"password": cred.password or ""})


@threat_intel.route('/threat-intelligence/breached-creds/add', methods=['GET', 'POST'])
@login_required
def breached_creds_add():
    if not current_user.is_admin_user:
        flash('Only administrators can add breached credentials.', 'danger')
        return redirect(url_for('threat_intel.breached_creds_list'))

    if request.method == 'POST':
        doc = {
            'username': sanitize_input(request.form.get('username', '')) or None,
            'domain': sanitize_input(request.form.get('domain', '')) or None,
            'password': request.form.get('password', '') or None,
            'source': sanitize_input(request.form.get('source', '')) or None,
            'type': sanitize_input(request.form.get('type', '')) or None,
            'url': sanitize_input(request.form.get('url', '')) or None,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        doc = {k: v for k, v in doc.items() if v is not None}

        es_id = es_service.index_document(doc)
        if es_id:
            # Real-time broadcast
            from .ws_events import broadcast_new_breach
            broadcast_new_breach({
                'es_id': es_id,
                'username': doc.get('username', ''),
                'domain': doc.get('domain', ''),
                'source': doc.get('source', ''),
                'type': doc.get('type', ''),
            })
            if doc.get('domain'):
                _notify_new_breach(es_id, doc.get('domain'), doc.get('domain'), doc.get('username', ''))
            cache.clear()
            flash('Breached credential added successfully.', 'success')
        else:
            flash('Failed to add credential.', 'danger')
        return redirect(url_for('threat_intel.breached_creds_list'))

    breadcrumb = {"parent": "Threat Intelligence", "child": "Add Credential"}
    return render_template('threat_intel/breached_creds_form.html', breadcrumb=breadcrumb)


@threat_intel.route('/threat-intelligence/breached-creds/<doc_id>/mark', methods=['POST'])
@login_required
def breached_creds_mark(doc_id):
    cred = es_service.get_by_id(doc_id)
    if not cred:
        flash('Record not found.', 'warning')
        return redirect(url_for('threat_intel.breached_creds_list'))
    if not _check_cred_access(cred):
        flash('Access denied.', 'danger')
        return redirect(url_for('threat_intel.breached_creds_list'))

    meta = BreachedCredMeta.query.filter_by(es_id=doc_id).first()
    if not meta:
        meta = BreachedCredMeta(es_id=doc_id)
        db.session.add(meta)

    meta.is_marked = not meta.is_marked
    if meta.is_marked:
        meta.marked_by = current_user.id
        meta.marked_at = datetime.now(timezone.utc)
        flash('Credential marked for review.', 'success')
    else:
        meta.marked_by = None
        meta.marked_at = None
        flash('Mark removed.', 'info')

    db.session.commit()
    cache.clear()
    return redirect(url_for('threat_intel.breached_creds_list'))


@threat_intel.route('/threat-intelligence/breached-creds/<doc_id>/edit', methods=['GET', 'POST'])
@login_required
def breached_creds_edit(doc_id):
    if not current_user.is_admin_user:
        flash('Only administrators can edit breached credentials.', 'danger')
        return redirect(url_for('threat_intel.breached_creds_view', doc_id=doc_id))

    cred = es_service.get_by_id(doc_id)
    if not cred:
        flash('Record not found.', 'warning')
        return redirect(url_for('threat_intel.breached_creds_list'))
    if not _check_cred_access(cred):
        flash('Access denied.', 'danger')
        return redirect(url_for('threat_intel.breached_creds_list'))

    if request.method == 'POST':
        doc = {
            'username': sanitize_input(request.form.get('username', '')) or None,
            'domain': sanitize_input(request.form.get('domain', '')) or None,
            'password': request.form.get('password', '') or None,
            'source': sanitize_input(request.form.get('source', '')) or None,
            'type': sanitize_input(request.form.get('type', '')) or None,
            'url': sanitize_input(request.form.get('url', '')) or None,
        }
        doc = {k: v for k, v in doc.items() if v is not None}

        if es_service.update_document(doc_id, doc):
            flash('Breached credential updated successfully.', 'success')
        else:
            flash('Failed to update credential.', 'danger')
        return redirect(url_for('threat_intel.breached_creds_list'))

    breadcrumb = {"parent": "Threat Intelligence", "child": "Edit Credential"}
    return render_template('threat_intel/breached_creds_form.html',
                          breached_cred=cred, breadcrumb=breadcrumb)


@threat_intel.route('/threat-intelligence/breached-creds/<doc_id>/delete', methods=['POST'])
@login_required
def breached_creds_delete(doc_id):
    if not current_user.is_admin_user:
        flash('Only administrators can delete breached credentials.', 'danger')
        return redirect(url_for('threat_intel.breached_creds_list'))

    cred = es_service.get_by_id(doc_id)
    if not cred:
        flash('Record not found.', 'warning')
        return redirect(url_for('threat_intel.breached_creds_list'))
    if not _check_cred_access(cred):
        flash('Access denied.', 'danger')
        return redirect(url_for('threat_intel.breached_creds_list'))

    if es_service.delete_document(doc_id):
        BreachedCredMeta.query.filter_by(es_id=doc_id).delete()
        db.session.commit()
        cache.clear()
        flash('Breached credential deleted successfully.', 'success')
    else:
        flash('Failed to delete credential.', 'danger')
    return redirect(url_for('threat_intel.breached_creds_list'))


@threat_intel.route('/threat-intelligence/breached-creds/export')
@login_required
@limiter.limit("3/minute")
def breached_creds_export():
    """Export breached credentials
    ---
    tags:
      - Breached Credentials
    parameters:
      - name: format
        in: query
        type: string
        enum: [csv, xlsx, json, pdf]
        default: csv
      - name: ids
        in: query
        type: string
        description: Comma-separated ES document IDs for selected export
    responses:
      200:
        description: File download
    """
    if not current_user.has_permission('export'):
        abort(403)
    export_format = request.args.get('format', 'csv').lower()
    domain_filters = _get_domain_filters()

    # Check for selected IDs (export only checked rows)
    selected_ids = request.args.get('ids', '').strip()

    if selected_ids:
        # Export specific documents by ID
        id_list = [i.strip() for i in selected_ids.split(',') if i.strip()][:500]
        creds = []
        for doc_id in id_list:
            cred = es_service.get_by_id(doc_id)
            if cred and _check_cred_access(cred):
                creds.append(cred)

        log_audit("export", "breached_credential", None,
                  f"Exported {len(creds)} selected breached credentials in {export_format.upper()} format")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    else:
        # Export all matching filters
        filters = {}
        type_filter = sanitize_input(request.args.get('type', ''))
        source_filter = sanitize_input(request.args.get('source', ''))
        domain_filter_param = sanitize_input(request.args.get('domain', ''))
        date_filter = sanitize_input(request.args.get('date_filter', ''))

        if type_filter:
            filters['type'] = type_filter
        if source_filter:
            filters['source'] = source_filter
        if domain_filter_param:
            filters['domain'] = domain_filter_param
        if date_filter and date_filter != 'all':
            filters['date_filter'] = date_filter

        creds = es_service.export(filters=filters if filters else None, domain_filters=domain_filters)

        log_audit("export", "breached_credential", None,
                  f"Exported {len(creds)} breached credentials in {export_format.upper()} format")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if export_format == 'json':
        data = [{
            'id': c.es_id, 'username': c.username, 'domain': c.domain,
            'password': '********', 'source': c.source, 'type': c.type,
            'url': c.url, 'timestamp': c.timestamp.isoformat() if c.timestamp else None
        } for c in creds]
        return Response(json.dumps(data, indent=2), mimetype='application/json',
                       headers={'Content-Disposition': f'attachment; filename=breached_credentials_{timestamp}.json'})

    elif export_format == 'xlsx' and OPENPYXL_AVAILABLE:
        wb = Workbook()
        ws = wb.active
        ws.title = "Breached Credentials"
        headers = ['ID', 'Username', 'Domain', 'Password', 'Source', 'Type', 'URL', 'Timestamp']
        ws.append(headers)
        for cell in ws[1]:
            cell.font = Font(bold=True)
            cell.alignment = Alignment(horizontal='center')
        for c in creds:
            ws.append([c.es_id, c.username or '', c.domain or '', '********',
                       c.source or '', c.type or '', c.url or '',
                       c.timestamp.strftime('%Y-%m-%d %H:%M:%S') if c.timestamp else ''])
        output = io.BytesIO()
        wb.save(output)
        output.seek(0)
        return Response(output.getvalue(),
                       mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                       headers={'Content-Disposition': f'attachment; filename=breached_credentials_{timestamp}.xlsx'})

    elif export_format == 'pdf' and REPORTLAB_AVAILABLE:
        output = io.BytesIO()
        doc_pdf = SimpleDocTemplate(output, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        # Branded header
        from reportlab.lib.units import inch
        title_style = styles['Title']
        title_style.textColor = colors.HexColor('#1a56db')
        elements.append(Paragraph("D-SECLAB", title_style))
        elements.append(Paragraph("Breached Credentials Report", styles['Heading2']))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(
            f"Generated by: {current_user.username}<br/>"
            f"Total Records: {len(creds)}<br/>"
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            styles['Normal']))
        elements.append(Spacer(1, 12))
        data = [['Username', 'Domain', 'Type', 'Source', 'Date']]
        for c in creds[:100]:
            data.append([(c.username or '')[:30], (c.domain or '')[:30], c.type or '',
                         (c.source or '')[:30], c.timestamp.strftime('%Y-%m-%d') if c.timestamp else ''])
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a56db')),
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
        doc_pdf.build(elements)
        output.seek(0)
        return Response(output.getvalue(), mimetype='application/pdf',
                       headers={'Content-Disposition': f'attachment; filename=breached_credentials_{timestamp}.pdf'})

    else:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Username', 'Domain', 'Password', 'Source', 'Type', 'URL', 'Timestamp'])
        for c in creds:
            writer.writerow([c.es_id, c.username or '', c.domain or '', '********',
                            c.source or '', c.type or '', c.url or '',
                            c.timestamp.strftime('%Y-%m-%d %H:%M:%S') if c.timestamp else ''])
        output.seek(0)
        return Response(output.getvalue(), mimetype='text/csv',
                       headers={'Content-Disposition': f'attachment; filename=breached_credentials_{timestamp}.csv'})


@threat_intel.route('/threat-intelligence/analysis')
@login_required
def analysis():
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


@threat_intel.route('/threat-intelligence/ransomware')
@login_required
def ransomware_dashboard():
    """Ransomware threat monitoring dashboard — reads from the
    `ransomware-feed` ES index. Each fetch is wrapped so a transient ES
    outage degrades the dashboard to zeros instead of returning 500."""
    from .services.ransomware_feed_service import ransomware_feed_service

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


@threat_intel.route('/threat-intelligence/summary')
@login_required
def breach_summary():
    """AI-generated executive breach summary."""
    from .services.ai_summary import generate_executive_summary

    domain_filters = _get_domain_filters()
    stats = es_service.get_stats(domain_filters=domain_filters)
    tl_labels, tl_data = es_service.get_monthly_trends(months=6, domain_filters=domain_filters)

    summary = generate_executive_summary(stats, tl_labels, tl_data)

    breadcrumb = {"parent": "Threat Intelligence", "child": "Executive Summary"}
    return render_template('threat_intel/summary.html', summary=summary, breadcrumb=breadcrumb)


@threat_intel.route('/threat-intelligence/reports')
@login_required
def reports():
    from .models import ScheduledReport, AlertRule, ReportHistory

    schedules = ScheduledReport.query.filter_by(created_by=current_user.id).order_by(ScheduledReport.created_at.desc()).all()
    if current_user.is_admin_user:
        schedules = ScheduledReport.query.order_by(ScheduledReport.created_at.desc()).all()

    alerts = AlertRule.query.filter_by(created_by=current_user.id).order_by(AlertRule.created_at.desc()).all()
    if current_user.is_admin_user:
        alerts = AlertRule.query.order_by(AlertRule.created_at.desc()).all()

    history = ReportHistory.query.filter_by(generated_by=current_user.id).order_by(ReportHistory.created_at.desc()).limit(20).all()
    if current_user.is_admin_user:
        history = ReportHistory.query.order_by(ReportHistory.created_at.desc()).limit(20).all()

    # Companies a schedule may target: admins pick any client, everyone else is
    # limited to their own so a schedule can't be pointed at another company.
    from .models import Company
    if current_user.is_admin_user:
        companies = Company.query.order_by(Company.name).all()
    elif current_user.company:
        companies = [current_user.company]
    else:
        companies = []

    breadcrumb = {"parent": "Threat Intelligence", "child": "Reports"}
    return render_template('threat_intel/reports.html',
                          schedules=schedules, alerts=alerts, history=history,
                          companies=companies, breadcrumb=breadcrumb)


@threat_intel.route('/threat-intelligence/reports/schedule/add', methods=['POST'])
@login_required
def add_schedule():
    from .models import ScheduledReport
    name = sanitize_input(request.form.get('name', ''))
    frequency = request.form.get('frequency', 'weekly')
    fmt = request.form.get('format', 'pdf')
    email_to = sanitize_input(request.form.get('email_to', ''))

    if not name:
        flash('Report name is required.', 'warning')
        return redirect(url_for('threat_intel.reports'))

    from .services.report_scheduler import compute_next_run
    from .models import Company
    from datetime import datetime as _dt

    # Never trust the posted company: a non-admin may only target their own.
    company_id = (request.form.get('company_id') or '').strip() or None
    if company_id:
        company = Company.query.get(company_id)
        if company is None or (not current_user.is_admin_user
                               and current_user.company_id != company.id):
            flash('Invalid company selection.', 'danger')
            return redirect(url_for('threat_intel.reports'))

    # Local wall-clock time of day plus which days it applies to. run_days is
    # ISO weekdays for weekly ("1,5"), a day of the month for monthly ("15"),
    # and unused for daily.
    run_time = (request.form.get('run_time') or '').strip()
    if frequency == 'weekly':
        run_days = ','.join(d for d in request.form.getlist('run_days')
                            if d.isdigit() and 1 <= int(d) <= 7)
        if not run_days:
            # Silently falling back to "whatever day it is now" would make the
            # schedule run on a day nobody chose.
            flash('Pick at least one day of the week.', 'warning')
            return redirect(url_for('threat_intel.reports'))
    elif frequency == 'monthly':
        day = (request.form.get('run_day_of_month') or '').strip()
        run_days = day if day.isdigit() and 1 <= int(day) <= 31 else ''
    else:
        run_days = ''

    next_run = compute_next_run(frequency, _dt.utcnow(), run_time, run_days)

    schedule = ScheduledReport(
        name=name, frequency=frequency, format=fmt,
        email_to=email_to or None,
        run_time=run_time or None, run_days=run_days or None,
        next_run=next_run, company_id=company_id,
        created_by=current_user.id, is_active=True
    )

    # Recipients are bound to the target company's own domains, so a client's
    # breach data cannot be scheduled out to an unrelated address. Rejected
    # here rather than silently dropped at send time, so the mistake is visible.
    if email_to:
        from .services.report_scheduler import validate_recipients
        schedule.creator = current_user
        schedule.company = Company.query.get(company_id) if company_id else None
        allowed, rejected = validate_recipients(schedule, email_to)
        if rejected:
            flash('Cannot send to ' + '; '.join(f'{a} ({why})' for a, why in rejected),
                  'danger')
            return redirect(url_for('threat_intel.reports'))
        schedule.email_to = ','.join(allowed)

    db.session.add(schedule)
    db.session.commit()
    log_audit('scheduled_report_create', 'scheduled_report', schedule.id,
              f'{schedule.name} → {schedule.email_to or "no recipients"} '
              f'({"company " + schedule.company.name if schedule.company else "creator scope"})')
    if next_run:
        from .services.report_scheduler import to_local
        local = to_local(next_run)
        flash(f'Scheduled report "{name}" created — first run '
              f'{local.strftime("%Y-%m-%d %H:%M")} ({local.tzname()}).', 'success')
    else:
        flash(f'Scheduled report "{name}" created, but "{frequency}" is not a '
              f'known frequency so it has no run time.', 'warning')
    return redirect(url_for('threat_intel.reports'))


@threat_intel.route('/threat-intelligence/reports/schedule/<sid>/toggle', methods=['POST'])
@login_required
def toggle_schedule(sid):
    from .models import ScheduledReport
    schedule = ScheduledReport.query.get_or_404(sid)
    if schedule.created_by != current_user.id and not current_user.is_admin_user:
        flash('Access denied.', 'danger')
        return redirect(url_for('threat_intel.reports'))
    schedule.is_active = not schedule.is_active
    db.session.commit()
    flash(f'Schedule {"enabled" if schedule.is_active else "disabled"}.', 'info')
    return redirect(url_for('threat_intel.reports'))


@threat_intel.route('/threat-intelligence/reports/schedule/<sid>/delete', methods=['POST'])
@login_required
def delete_schedule(sid):
    from .models import ScheduledReport
    schedule = ScheduledReport.query.get_or_404(sid)
    if schedule.created_by != current_user.id and not current_user.is_admin_user:
        flash('Access denied.', 'danger')
        return redirect(url_for('threat_intel.reports'))
    db.session.delete(schedule)
    db.session.commit()
    flash('Schedule deleted.', 'info')
    return redirect(url_for('threat_intel.reports'))


@threat_intel.route('/threat-intelligence/reports/alert/add', methods=['POST'])
@login_required
def add_alert():
    from .models import AlertRule
    name = sanitize_input(request.form.get('name', ''))
    condition_type = request.form.get('condition_type', 'new_breach')
    condition_value = sanitize_input(request.form.get('condition_value', ''))
    notify_method = request.form.get('notify_method', 'in_app')
    notify_target = sanitize_input(request.form.get('notify_target', ''))

    if not name or not condition_value:
        flash('Alert name and condition are required.', 'warning')
        return redirect(url_for('threat_intel.reports') + '#alerts')

    # Validate webhook URL if notify_method is webhook
    if notify_method == 'webhook' and notify_target:
        if not notify_target.startswith('https://'):
            flash('Webhook URL must use HTTPS.', 'danger')
            return redirect(url_for('threat_intel.reports') + '#alerts')
        # Block private/internal IPs in webhook URLs
        from urllib.parse import urlparse
        parsed = urlparse(notify_target)
        hostname = parsed.hostname or ''
        # Reject localhost, internal hostnames, and private IP ranges
        if hostname in ('localhost', '127.0.0.1', '::1', '0.0.0.0') or hostname.startswith('10.') or hostname.startswith('192.168.') or hostname.startswith('172.16.') or hostname.endswith('.local') or hostname.endswith('.internal'):
            flash('Webhook URL must not point to a private/internal address.', 'danger')
            return redirect(url_for('threat_intel.reports') + '#alerts')

    alert = AlertRule(
        name=name, condition_type=condition_type, condition_value=condition_value,
        notify_method=notify_method, notify_target=notify_target or None,
        created_by=current_user.id, is_active=True
    )
    db.session.add(alert)
    db.session.commit()
    flash(f'Alert rule "{name}" created.', 'success')
    return redirect(url_for('threat_intel.reports') + '#alerts')


@threat_intel.route('/threat-intelligence/reports/alert/<aid>/toggle', methods=['POST'])
@login_required
def toggle_alert(aid):
    from .models import AlertRule
    alert = AlertRule.query.get_or_404(aid)
    if alert.created_by != current_user.id and not current_user.is_admin_user:
        flash('Access denied.', 'danger')
        return redirect(url_for('threat_intel.reports') + '#alerts')
    alert.is_active = not alert.is_active
    db.session.commit()
    flash(f'Alert {"enabled" if alert.is_active else "disabled"}.', 'info')
    return redirect(url_for('threat_intel.reports') + '#alerts')


@threat_intel.route('/threat-intelligence/reports/alert/<aid>/delete', methods=['POST'])
@login_required
def delete_alert(aid):
    from .models import AlertRule
    alert = AlertRule.query.get_or_404(aid)
    if alert.created_by != current_user.id and not current_user.is_admin_user:
        flash('Access denied.', 'danger')
        return redirect(url_for('threat_intel.reports') + '#alerts')
    db.session.delete(alert)
    db.session.commit()
    flash('Alert rule deleted.', 'info')
    return redirect(url_for('threat_intel.reports') + '#alerts')


@threat_intel.route('/threat-intelligence/reports/generate', methods=['POST'])
@login_required
@limiter.limit("3/minute")
def generate_report():
    """Generate a report now and save to history."""
    from .models import ReportHistory
    fmt = request.form.get('format', 'csv')

    domain_filters = _get_domain_filters()
    creds = es_service.export(domain_filters=domain_filters, max_records=5000)

    # Estimate file size (rough: ~100 bytes per record for CSV)
    size_map = {'csv': 100, 'xlsx': 150, 'json': 200, 'pdf': 80}
    estimated_size = len(creds) * size_map.get(fmt, 100)

    history = ReportHistory(
        name=f'Breach Report {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")}',
        format=fmt, record_count=len(creds), file_size=estimated_size, status='completed',
        source='manual', generated_by=current_user.id
    )
    db.session.add(history)
    db.session.commit()

    # Redirect to actual export
    return redirect(url_for('threat_intel.breached_creds_export', format=fmt))
