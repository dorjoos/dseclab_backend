"""Vulnerabilities blueprint — CISA KEV browser."""
import csv
import io
import logging

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash, Response,
    jsonify, abort,
)
from flask_login import login_required, current_user

from . import db, limiter
from .api_utils import sanitize_input
from .audit_helpers import log_audit
from .services.cisa_kev_service import cisa_kev_service

logger = logging.getLogger(__name__)

vulnerabilities = Blueprint('vulnerabilities', __name__)


MEMBER_FIELDS = {
    'cve_id', 'vendor', 'product', 'vulnerability_name',
    'date_added', 'due_date', 'known_ransomware_use',
}
FULL_FIELDS = MEMBER_FIELDS | {
    'short_description', 'required_action', 'notes', 'cwes',
}


def _is_full_access():
    return current_user.role in ('admin', 'analyst')


def _serialize(doc, fields):
    def fmt_date(d):
        return d.strftime('%Y-%m-%d') if d else ''
    payload = {
        'cve_id': doc.cve_id or '',
        'vendor': doc.vendor or '',
        'product': doc.product or '',
        'vulnerability_name': doc.vulnerability_name or '',
        'date_added': fmt_date(doc.date_added),
        'due_date': fmt_date(doc.due_date),
        'known_ransomware_use': doc.known_ransomware_use or '',
        'short_description': doc.short_description or '',
        'required_action': doc.required_action or '',
        'notes': doc.notes or '',
        'cwes': doc.cwes or [],
    }
    return {k: v for k, v in payload.items() if k in fields}


@vulnerabilities.route('/threat-intelligence/vulnerabilities')
@login_required
def list_page():
    breadcrumb = {'parent': 'Threat Intelligence', 'child': 'Vulnerabilities'}
    return render_template('threat_intel/vulnerabilities_list.html',
                          breadcrumb=breadcrumb,
                          full_access=_is_full_access())


@vulnerabilities.route('/api/vulnerabilities/search', methods=['POST'])
@login_required
@limiter.limit('60/minute')
def search_api():
    data = request.get_json(silent=True) or {}
    page = int(data.get('page', 1) or 1)
    per_page = int(data.get('per_page', 20) or 20)
    per_page = min(max(per_page, 1), 100)
    query_text = sanitize_input(data.get('search', '') or None)
    filters = {}
    for k in ('vendor', 'product', 'ransomware_use'):
        v = sanitize_input(data.get(k, '') or None)
        if v:
            filters[k] = v
    pagination = cisa_kev_service.search(
        query_text=query_text,
        filters=filters or None,
        page=page,
        per_page=per_page,
    )
    fields = FULL_FIELDS if _is_full_access() else MEMBER_FIELDS
    rows = [_serialize(d, fields) for d in pagination.items]
    return jsonify({
        'rows': rows,
        'page': pagination.page,
        'pages': pagination.pages,
        'total': pagination.total,
        'has_prev': pagination.has_prev,
        'has_next': pagination.has_next,
    })


@vulnerabilities.route('/threat-intelligence/vulnerabilities/<cve_id>')
@login_required
def detail_page(cve_id):
    if not _is_full_access():
        flash('Detail view is available for analysts and administrators only.', 'warning')
        return redirect(url_for('vulnerabilities.list_page'))
    doc = cisa_kev_service.get_by_id(cve_id)
    if not doc:
        abort(404)
    log_audit('vulnerabilities_view', 'cisa_kev', doc.cve_id,
              f'User {current_user.username} viewed {doc.cve_id} detail')
    db.session.commit()
    breadcrumb = {'parent': 'Vulnerabilities', 'child': doc.cve_id}
    return render_template('threat_intel/vulnerabilities_view.html',
                          vuln=doc, breadcrumb=breadcrumb)


@vulnerabilities.route('/threat-intelligence/vulnerabilities/export.csv')
@login_required
def export_csv():
    if not _is_full_access():
        flash('Export is available for analysts and administrators only.', 'warning')
        return redirect(url_for('vulnerabilities.list_page'))
    pagination = cisa_kev_service.search(page=1, per_page=10000)
    log_audit('vulnerabilities_export', 'cisa_kev_index', None,
              f'User {current_user.username} exported {pagination.total} CISA KEV rows as CSV')
    db.session.commit()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        'cve_id', 'vendor', 'product', 'vulnerability_name',
        'date_added', 'due_date', 'known_ransomware_use',
        'short_description', 'required_action', 'notes',
    ])
    for d in pagination.items:
        writer.writerow([
            d.cve_id or '',
            d.vendor or '',
            d.product or '',
            d.vulnerability_name or '',
            d.date_added.strftime('%Y-%m-%d') if d.date_added else '',
            d.due_date.strftime('%Y-%m-%d') if d.due_date else '',
            d.known_ransomware_use or '',
            d.short_description or '',
            d.required_action or '',
            d.notes or '',
        ])
    return Response(
        buf.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=cisa-kev.csv'},
    )
