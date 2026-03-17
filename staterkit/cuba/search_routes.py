from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy import or_
from .api_utils import sanitize_input
from .models import Company
from .security import get_user_watchlist_domains
from .services.elasticsearch_service import es_service

search_bp = Blueprint('search', __name__)


@search_bp.route('/api/search')
@login_required
def search():
    query = sanitize_input(request.args.get('q', ''))
    if not query or len(query) < 2:
        return jsonify([])

    results = []

    domain_filters = None
    if not current_user.is_admin_user:
        domain_filters = get_user_watchlist_domains()

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
            or_(Company.name.ilike(f'%{query}%'), Company.domain.ilike(f'%{query}%'))
        ).limit(3).all()
        for company in companies:
            results.append({
                'name': f"{company.name} ({company.domain})",
                'url': f'/admin/companies/{company.id}/edit',
                'type': 'Company',
                'icon': 'briefcase'
            })

    return jsonify(results)
