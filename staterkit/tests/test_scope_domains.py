"""A member with no company must see nothing, not everything.

get_user_company_domain() returns None for two unrelated situations: an admin
(unrestricted) and a non-admin with no company (no scope at all). Callers that
branched on it —

    domain_filters = get_user_watchlist_domains() if user_domain else None

— handed the second group the first group's scope. None reaches _build_query
as "no domain clause", so a company-less member got the dashboard and analysis
view of the entire corpus: totals across every tenant, and the ten most recent
credentials with their usernames and domains.

security.get_scope_domains() is now the single place that decides this.
"""
import pytest
from flask_login import login_user

from cuba.security import get_scope_domains
from tests.conftest import _make_user, login


@pytest.fixture()
def orphan(db):
    """A non-admin belonging to no company."""
    return _make_user(db, email='orphan@nowhere.example', role='member',
                      company=None)


# --- the helper ---

def test_admin_is_unrestricted(app, admin_user):
    with app.test_request_context():
        login_user(admin_user)
        assert get_scope_domains() is None


def test_member_is_scoped_to_their_company(app, member_acme, company_acme):
    with app.test_request_context():
        login_user(member_acme)
        assert get_scope_domains() == ['acme.com']


def test_company_less_member_sees_nothing_not_everything(app, orphan):
    """[] is a real answer. None here would mean unrestricted."""
    with app.test_request_context():
        login_user(orphan)
        assert get_scope_domains() == [], 'a company-less member got a scope'


def test_anonymous_sees_nothing(app):
    with app.test_request_context():
        assert get_scope_domains() == []


# --- the surfaces that got it wrong ---

def _capture(monkeypatch, module):
    seen = {}
    monkeypatch.setattr(module.es_service, 'get_stats',
                        lambda **kw: seen.update(kw) or
                        {'total': 0, 'by_type': {}, 'by_source': {}, 'by_domain': {}})
    monkeypatch.setattr(module.es_service, 'get_weekly_trends', lambda **kw: ([], []))
    monkeypatch.setattr(module.es_service, 'get_daily_trends', lambda **kw: ([], []))
    monkeypatch.setattr(module.es_service, 'get_recent', lambda **kw: [])
    return seen


def test_dashboard_scopes_a_company_less_member(client, orphan, monkeypatch):
    from cuba import routes
    seen = _capture(monkeypatch, routes)
    login(client, orphan.email)
    assert client.get('/dashboard').status_code == 200
    assert seen['domain_filters'] == [], (
        f'dashboard was unrestricted: {seen["domain_filters"]!r}')


def test_analysis_scopes_a_company_less_member(client, orphan, monkeypatch):
    from cuba.services import breached_creds_analysis as bca
    seen = _capture(monkeypatch, bca)
    login(client, orphan.email)
    assert client.get('/threat-intelligence/analysis').status_code == 200
    assert seen['domain_filters'] == [], (
        f'analysis was unrestricted: {seen["domain_filters"]!r}')


def test_dashboard_still_unrestricted_for_an_admin(client, admin_user, monkeypatch):
    """The fix must not take an admin's reach away."""
    from cuba import routes
    seen = _capture(monkeypatch, routes)
    login(client, admin_user.email)
    client.get('/dashboard')
    assert seen['domain_filters'] is None


def test_dashboard_still_scoped_for_a_normal_member(client, member_acme,
                                                    company_acme, monkeypatch):
    from cuba import routes
    seen = _capture(monkeypatch, routes)
    login(client, member_acme.email)
    client.get('/dashboard')
    assert seen['domain_filters'] == ['acme.com']


def test_one_place_decides_the_scope():
    """Four call sites made this decision independently and one pair got it
    wrong. Keep them delegating."""
    import pathlib
    for path in ('cuba/routes.py', 'cuba/search_routes.py',
                 'cuba/services/breached_creds_analysis.py',
                 'cuba/threat_intel/_shared.py'):
        src = pathlib.Path(path).read_text()
        assert 'get_scope_domains' in src, f'{path} no longer delegates'
        assert 'if user_domain else None' not in src, (
            f'{path} branches on get_user_company_domain again')
