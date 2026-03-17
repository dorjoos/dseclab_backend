from flask import Blueprint, render_template, request, redirect, url_for, flash, Response, jsonify
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

from . import db, cache, csrf
from .models import BreachedCredMeta, Company, Notification, User
from .api_utils import sanitize_input
from .audit_helpers import log_audit
from .security import get_user_company_domain, get_user_watchlist_domains
from .services.elasticsearch_service import es_service
from .services.breached_creds_service import build_analysis_stats

logger = logging.getLogger(__name__)

threat_intel = Blueprint('threat_intel', __name__)


def _get_domain_filters():
    user_domain = get_user_company_domain()
    if not user_domain:
        return None
    return get_user_watchlist_domains()


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


def _notify_new_breach(credential_id, company_domain, company_name, email):
    """Notify all users in a company about a new breach."""
    try:
        if not company_domain:
            users = User.query.filter(
                or_(User.role == 'admin', User.isAdmin == True),
                User.is_active == True
            ).all()
        else:
            company = Company.query.filter_by(domain=company_domain).first()
            if not company:
                users = User.query.filter(
                    or_(User.role == 'admin', User.isAdmin == True),
                    User.is_active == True
                ).all()
            else:
                users = User.query.filter(
                    or_(
                        User.company_id == company.id,
                        User.role == 'admin',
                        User.isAdmin == True
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


@threat_intel.route('/api/breached-creds/search', methods=['POST'])
@csrf.exempt
@login_required
def breached_creds_api():
    """AJAX API: POST filters, return JSON results from ES."""
    from flask import jsonify
    data = request.get_json(silent=True) or {}

    page = data.get('page', 1)
    per_page = data.get('per_page', 20)
    search_query = sanitize_input(data.get('search', ''))
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

    rows = []
    for i, cred in enumerate(pagination.items):
        rows.append({
            'num': (page - 1) * per_page + i + 1,
            'es_id': cred.es_id,
            'username': cred.username or '',
            'domain': cred.domain or '',
            'password': cred.password or '',
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
    })


@threat_intel.route('/threat-intelligence/breached-creds/<doc_id>')
@login_required
def breached_creds_view(doc_id):
    cred = es_service.get_by_id(doc_id)
    if not cred:
        flash('Record not found.', 'warning')
        return redirect(url_for('threat_intel.breached_creds_list'))
    _attach_metadata([cred])
    breadcrumb = {"parent": "Threat Intelligence", "child": "Credential Details"}
    return render_template('threat_intel/breached_creds_view.html',
                          breached_cred=cred, breadcrumb=breadcrumb)


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
def breached_creds_export():
    export_format = request.args.get('format', 'csv').lower()
    domain_filters = _get_domain_filters()

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
        elements.append(Paragraph("Breached Credentials Report", styles['Title']))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(
            f"Total Records: {len(creds)}<br/>Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
            styles['Normal']))
        elements.append(Spacer(1, 12))
        data = [['Username', 'Domain', 'Type', 'Source', 'Date']]
        for c in creds[:100]:
            data.append([(c.username or '')[:30], (c.domain or '')[:30], c.type or '',
                         (c.source or '')[:30], c.timestamp.strftime('%Y-%m-%d') if c.timestamp else ''])
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


@threat_intel.route('/threat-intelligence/reports')
@login_required
def reports():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    domain_filters = _get_domain_filters()

    pagination = es_service.search(domain_filters=domain_filters, page=page, per_page=per_page)
    _attach_metadata(pagination.items)

    breadcrumb = {"parent": "Threat Intelligence", "child": "Reports"}
    return render_template('threat_intel/reports.html',
                          breached_creds=pagination.items, pagination=pagination,
                          user_domain=get_user_company_domain(),
                          report_date=datetime.now(timezone.utc), breadcrumb=breadcrumb)
