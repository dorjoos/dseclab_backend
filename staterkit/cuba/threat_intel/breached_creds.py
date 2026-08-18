"""Breached-credential list, detail, editing and export, plus the Employees tab."""
import csv
import io
import json
from datetime import datetime, timezone
from typing import Any

from flask import Response, abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

try:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from .. import cache, db, limiter
from ..api_utils import sanitize_input
from ..audit_helpers import log_audit, log_user_activity
from ..models import BreachedCredMeta
from ..services.breached_creds_service import breached_creds_service as es_service
from ._blueprint import threat_intel
from ._shared import (
    _attach_metadata,
    _check_cred_access,
    _get_domain_filters,
    _get_employee_emails,
    _get_match_domains,
    _notify_new_breach,
)


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

    filters: dict[str, Any] = {}
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


@threat_intel.route('/threat-intelligence/breached-creds/employees')
@login_required
def breached_creds_employees():
    """Breaches limited to the watched staff addresses in the user's scope.

    The table itself is filled by the same /api/breached-creds/search endpoint
    the All tab uses, with employees_only set — so scoping, masking and
    pagination stay in one place rather than being reimplemented here.
    """
    employees = _get_employee_emails()
    breadcrumb = {"parent": "Threat Intelligence", "child": "Employee Credentials"}
    return render_template('threat_intel/breached_creds_employees.html',
                           employee_count=len(employees),
                           breadcrumb=breadcrumb)


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
    search_query: str | None = sanitize_input(data.get('search', ''))
    if search_query and len(search_query.strip()) < 3:
        search_query = None  # Too short, ignore
    type_filter = sanitize_input(data.get('type', ''))
    source_filter = sanitize_input(data.get('source', ''))
    domain_filter_param = sanitize_input(data.get('domain', ''))
    date_filter = sanitize_input(data.get('date_filter', 'all'))

    domain_filters = _get_domain_filters()

    filters: dict[str, Any] = {}
    if type_filter:
        filters['type'] = type_filter
    if source_filter:
        filters['source'] = source_filter
    if domain_filter_param:
        filters['domain'] = domain_filter_param
    if date_filter and date_filter != 'all':
        filters['date_filter'] = date_filter
    if data.get('employees_only'):
        # Narrow to the watched staff addresses in the caller's own scope. The
        # domain filter still applies underneath, so this can only subtract.
        filters['employees'] = _get_employee_emails()

    pagination = es_service.search(
        query_text=search_query or None,
        filters=filters if filters else None,
        domain_filters=domain_filters,
        page=page,
        per_page=per_page
    )
    _attach_metadata(pagination.items)
    # Not `domain_filters or []`: that is None for an admin, and matching
    # against nothing labelled every row with a dash.
    es_service.attach_matched_domain(pagination.items, _get_match_domains())

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
        cred.password = '********'  # noqa: S105 — this is the mask, not a secret
    # The raw dump line is the same secret in a different shape — it usually
    # carries the plaintext inline — so it goes behind the same gate rather
    # than being rendered into the page.
    has_raw = bool(cred.value)
    if cred.value:
        cred.value = '********'
    breadcrumb = {"parent": "Threat Intelligence", "child": "Credential Details"}
    return render_template('threat_intel/breached_creds_view.html',
                          breached_cred=cred, has_raw=has_raw,
                          breadcrumb=breadcrumb)


@threat_intel.route('/threat-intelligence/breached-creds/<doc_id>/reveal-password', methods=['POST'])
@login_required
@limiter.limit("30/minute")
def breached_creds_reveal_password(doc_id):
    """Return a masked-on-page field for a cred the user is authorized to see.

    Two fields go through here: 'password' (the plaintext) and 'raw' (the
    original dump line, which normally quotes that same plaintext inline).
    Both are gated by the same tenancy check as the detail view, and every
    successful and denied call is recorded in the audit log so reveals are
    accountable. The field is named in the audit row, so revealing a raw line
    is never filed as a password reveal.

    Defaults to 'password' when unspecified, keeping older callers working.
    """
    field = (request.form.get('field') or 'password').strip()
    if field not in ('password', 'raw'):
        return jsonify({"error": "unknown_field"}), 400

    cred = es_service.get_by_id(doc_id)
    if not cred:
        return jsonify({"error": "not_found"}), 404
    if not _check_cred_access(cred):
        log_audit(f"reveal_{field}_denied", "breached_cred", doc_id,
                  f"User {current_user.username} denied reveal for cred {doc_id}",
                  status="failed")
        db.session.commit()
        return jsonify({"error": "access_denied"}), 403
    log_audit(f"reveal_{field}", "breached_cred", doc_id,
              f"User {current_user.username} revealed {field} for cred {doc_id} "
              f"(domain={cred.domain or 'unknown'})")
    log_user_activity(f"reveal_{field}", current_user.id, status="success")
    db.session.commit()
    value = cred.password if field == 'password' else cred.value
    return jsonify({field: value or ""})


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
            from ..ws_events import broadcast_new_breach
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
        filters: dict[str, Any] = {}
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
        if request.args.get('employees_only') in ('1', 'true', 'yes'):
            # Mirrors the Employees tab, so its Export button downloads the
            # list on screen rather than every credential in scope.
            filters['employees'] = _get_employee_emails()

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

    if export_format == 'xlsx' and OPENPYXL_AVAILABLE:
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

    if export_format == 'pdf' and REPORTLAB_AVAILABLE:
        output = io.BytesIO()
        doc_pdf = SimpleDocTemplate(output, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        # Branded header
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
        pdf_rows: list[list[str]] = [['Username', 'Domain', 'Type', 'Source', 'Date']]
        for c in creds[:100]:
            pdf_rows.append([(c.username or '')[:30], (c.domain or '')[:30], c.type or '',
                         (c.source or '')[:30], c.timestamp.strftime('%Y-%m-%d') if c.timestamp else ''])
        table = Table(pdf_rows)
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

    csv_output = io.StringIO()
    writer = csv.writer(csv_output)
    writer.writerow(['ID', 'Username', 'Domain', 'Password', 'Source', 'Type', 'URL', 'Timestamp'])
    for c in creds:
        writer.writerow([c.es_id, c.username or '', c.domain or '', '********',
                        c.source or '', c.type or '', c.url or '',
                        c.timestamp.strftime('%Y-%m-%d %H:%M:%S') if c.timestamp else ''])
    output.seek(0)
    return Response(csv_output.getvalue(), mimetype='text/csv',
                   headers={'Content-Disposition': f'attachment; filename=breached_credentials_{timestamp}.csv'})
