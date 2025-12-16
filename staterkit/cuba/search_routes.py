from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy import or_
from . import db
from .models import BreachedCredential, Company, User

search_bp = Blueprint('search', __name__)


@search_bp.route('/api/search')
@login_required
def search():
    """Global search endpoint for header search"""
    query = request.args.get('q', '').strip()
    
    if not query or len(query) < 2:
        return jsonify([])
    
    results = []
    
    # Search breached credentials
    creds_query = BreachedCredential.query.filter(
        or_(
            BreachedCredential.email.ilike(f'%{query}%'),
            BreachedCredential.company_name.ilike(f'%{query}%'),
            BreachedCredential.username.ilike(f'%{query}%'),
            BreachedCredential.email_domain.ilike(f'%{query}%')
        )
    ).limit(5).all()
    
    # Filter by company domain for members
    if current_user.role != 'admin' and not current_user.isAdmin:
        user_domain = current_user.company_domain
        creds_query = [c for c in creds_query if c.email_domain == user_domain]
    
    for cred in creds_query:
        results.append({
            'name': f"{cred.company_name} - {cred.email}",
            'url': f'/threat-intelligence/breached-creds/{cred.id}',
            'type': 'Breached Credential',
            'icon': 'shield'
        })
    
    # Search companies (admin only)
    if current_user.role == 'admin' or current_user.isAdmin:
        companies = Company.query.filter(
            or_(
                Company.name.ilike(f'%{query}%'),
                Company.domain.ilike(f'%{query}%')
            )
        ).limit(3).all()
        
        for company in companies:
            results.append({
                'name': f"{company.name} ({company.domain})",
                'url': f'/admin/companies/{company.id}/edit',
                'type': 'Company',
                'icon': 'briefcase'
            })
    
    return jsonify(results)

