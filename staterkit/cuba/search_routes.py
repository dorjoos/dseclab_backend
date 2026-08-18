from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy import or_
from . import limiter
from .api_utils import sanitize_input, escape_like
from .models import Company
from .security import get_scope_domains
from .services.breached_creds_service import breached_creds_service as es_service

search_bp = Blueprint('search', __name__)


@search_bp.route('/api/search')
@login_required
@limiter.limit("30/minute")
def search():
    """Global search
    ---
    tags:
      - Search
    parameters:
      - name: q
        in: query
        type: string
        required: true
        description: Search query (min 2 chars)
    responses:
      200:
        description: Array of search results
    """
    query = sanitize_input(request.args.get('q', ''))
    if not query or len(query.strip()) < 3:
        return jsonify([])

    results = []

    domain_filters = get_scope_domains()

    pagination = es_service.search(query_text=query, domain_filters=domain_filters, per_page=5)
    for cred in pagination.items:
        display_name = cred.username or 'N/A'
        if cred.domain:
            display_name += f" ({cred.domain})"
        results.append({
            'name': display_name,
            'url': f'/threat-intelligence/breached-creds/{cred.es_id}',
            'type': 'Breached Credential',
            'icon': 'shield'
        })

    if current_user.is_admin_user:
        companies = Company.query.filter(
            or_(Company.name.ilike(f'%{escape_like(query)}%'), Company.domain.ilike(f'%{escape_like(query)}%'))
        ).limit(3).all()
        for company in companies:
            results.append({
                'name': f"{company.name} ({company.domain})",
                'url': f'/admin/companies/{company.id}/edit',
                'type': 'Company',
                'icon': 'briefcase'
            })

    return jsonify(results)
