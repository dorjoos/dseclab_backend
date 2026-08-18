"""The Employees tab: breaches limited to a company's watched staff addresses.

Employees are the WatchlistEntry rows with entry_type='email'. The rule that
matters most here is the empty case — a company with nobody on file must see
nothing, not everything.
"""
from cuba.models import WatchlistEntry
from tests.conftest import login


def _add_employees(db, company, *emails):
    for email in emails:
        db.session.add(WatchlistEntry(company_id=company.id, entry_type='email',
                                      entry_value=email))
    db.session.commit()


# --- the model helper ---

def test_employee_emails_come_from_email_entries_only(db, company_acme):
    from cuba.models import Company
    _add_employees(db, company_acme, 'B.Otgon@acme.com', 'd.saraa@acme.com')
    db.session.add(WatchlistEntry(company_id=company_acme.id, entry_type='domain',
                                  entry_value='mail.acme.com'))
    db.session.commit()

    company = db.session.get(Company, company_acme.id)
    # Lowercased and deduped; the domain entry is not an employee.
    assert company.get_employee_emails() == ['b.otgon@acme.com', 'd.saraa@acme.com']


def test_employee_emails_are_empty_when_none_are_on_file(db, company_acme):
    from cuba.models import Company
    company = db.session.get(Company, company_acme.id)
    assert company.get_employee_emails() == []


# --- the ES clause ---

def _clause(emails):
    from cuba.services.breached_creds_service import es_service
    return es_service.build_employee_filter(emails)


def test_empty_employee_list_matches_nothing_not_everything(app):
    """The trap this mirrors: treating [] as 'no filter' would turn a company
    with no staff on file into one that sees every credential in scope."""
    with app.app_context():
        assert _clause([]) == {'bool': {'must_not': {'match_all': {}}}}
        assert _clause(None) == {'bool': {'must_not': {'match_all': {}}}}


def test_employee_clause_matches_the_whole_address(app):
    """Exact, not suffix: one employee must not pull in the whole domain."""
    with app.app_context():
        should = _clause(['B.Otgon@acme.com'])['bool']['should']
        assert {'term': {'username.keyword': {'value': 'b.otgon@acme.com',
                                              'case_insensitive': True}}} in should


def test_employee_clause_matches_a_split_address(app):
    """Feeds that store the local part in username and the host in domain.

    Both halves are required, so this cannot reach a different person at the
    same domain."""
    with app.app_context():
        should = _clause(['b.otgon@acme.com'])['bool']['should']
        assert {'bool': {'filter': [
            {'term': {'username.keyword': {'value': 'b.otgon',
                                           'case_insensitive': True}}},
            {'term': {'domain.keyword': {'value': 'acme.com',
                                         'case_insensitive': True}}},
        ]}} in should
        assert _clause(['b.otgon@acme.com'])['bool']['minimum_should_match'] == 1


def test_employee_clause_uses_no_wildcards(app):
    """A substring match would let on@acme.com hit otgon@acme.com."""
    import json
    with app.app_context():
        blob = json.dumps(_clause(['on@acme.com', 'b.otgon@acme.com']))
        assert 'wildcard' not in blob
        assert 'regexp' not in blob
        assert '*' not in blob


def test_malformed_entries_get_no_split_clause(app):
    """A watchlist 'email' entry that isn't an address must not produce a
    half-clause that matches on domain alone."""
    with app.app_context():
        should = _clause(['not-an-address'])['bool']['should']
        assert should == [{'term': {'username.keyword': {
            'value': 'not-an-address', 'case_insensitive': True}}}]


def test_employee_clause_is_capped_and_says_so(app, caplog):
    """A silent cap would read as 'searched everyone' when it didn't."""
    import logging

    from cuba.services.breached_creds_service import es_service
    with app.app_context():
        many = [f'user{i}@acme.com' for i in range(es_service.MAX_EMPLOYEES + 5)]
        with caplog.at_level(logging.WARNING):
            clause = _clause(many)
        # Two clauses per employee: whole-address, and the split form.
        assert len(clause['bool']['should']) == es_service.MAX_EMPLOYEES * 2
        assert 'truncated' in caplog.text


# --- scope ---

def test_member_sees_only_their_own_company_employees(app, db, member_acme,
                                                      company_acme, company_other):
    from cuba import threat_intel as ti
    _add_employees(db, company_acme, 'b.otgon@acme.com')
    _add_employees(db, company_other, 'someone@other.com')

    with app.test_request_context():
        from flask_login import login_user
        login_user(member_acme)
        assert ti._get_employee_emails() == ['b.otgon@acme.com']


def test_admin_sees_every_company_employee(app, db, admin_user, company_acme,
                                           company_other):
    from cuba import threat_intel as ti
    _add_employees(db, company_acme, 'b.otgon@acme.com')
    _add_employees(db, company_other, 'someone@other.com')

    with app.test_request_context():
        from flask_login import login_user
        login_user(admin_user)
        assert ti._get_employee_emails() == ['b.otgon@acme.com', 'someone@other.com']


# --- the page and the API ---

def test_employees_tab_renders_and_flags_the_filter(client, db, member_acme,
                                                    company_acme):
    _add_employees(db, company_acme, 'b.otgon@acme.com')
    login(client, member_acme.email)
    resp = client.get('/threat-intelligence/breached-creds/employees')
    assert resp.status_code == 200
    body = resp.data.decode()
    assert 'EMPLOYEES_ONLY = true' in body
    assert 'av-tab--active' in body


def test_employees_tab_explains_itself_when_nobody_is_on_file(client, member_acme,
                                                              company_acme):
    login(client, member_acme.email)
    body = client.get('/threat-intelligence/breached-creds/employees').data.decode()
    assert 'No employee addresses are on file' in body


def test_all_tab_does_not_set_the_employee_filter(client, member_acme):
    login(client, member_acme.email)
    body = client.get('/threat-intelligence/breached-creds').data.decode()
    assert 'EMPLOYEES_ONLY = false' in body


def test_api_applies_the_employee_filter(client, db, member_acme, company_acme,
                                         monkeypatch):
    """The API must pass the caller's own employee list to the query, not the
    client-supplied one."""
    _add_employees(db, company_acme, 'b.otgon@acme.com')
    seen = {}

    from cuba import threat_intel as ti

    class _Pag:
        items, page, pages, total = [], 1, 1, 0
        has_prev = has_next = False
        error = False

    def fake_search(**kwargs):
        seen.update(kwargs)
        return _Pag()

    monkeypatch.setattr(ti.es_service, 'search', fake_search)
    login(client, member_acme.email)
    resp = client.post('/api/breached-creds/search',
                       json={'page': 1, 'employees_only': True},
                       headers={'X-CSRFToken': _token(client)})
    assert resp.status_code == 200
    assert seen['filters']['employees'] == ['b.otgon@acme.com']


def test_api_without_the_flag_has_no_employee_filter(client, db, member_acme,
                                                     company_acme, monkeypatch):
    _add_employees(db, company_acme, 'b.otgon@acme.com')
    seen = {}

    from cuba import threat_intel as ti

    class _Pag:
        items, page, pages, total = [], 1, 1, 0
        has_prev = has_next = False
        error = False

    def fake_search(**kwargs):
        seen.update(kwargs)
        return _Pag()

    monkeypatch.setattr(ti.es_service, 'search', fake_search)
    login(client, member_acme.email)
    client.post('/api/breached-creds/search', json={'page': 1},
                headers={'X-CSRFToken': _token(client)})
    assert 'employees' not in (seen.get('filters') or {})


def test_export_honours_the_employee_filter(client, db, admin_user, company_acme,
                                            monkeypatch):
    """The Employees tab's Export must download the list on screen, not every
    credential in scope."""
    _add_employees(db, company_acme, 'b.otgon@acme.com')
    seen = {}

    from cuba import threat_intel as ti
    monkeypatch.setattr(ti.es_service, 'export',
                        lambda **kw: seen.update(kw) or [])

    login(client, admin_user.email)
    resp = client.get('/threat-intelligence/breached-creds/export'
                      '?format=json&employees_only=1')
    assert resp.status_code == 200
    assert seen['filters']['employees'] == ['b.otgon@acme.com']


def test_export_without_the_flag_is_unfiltered(client, db, admin_user, company_acme,
                                               monkeypatch):
    _add_employees(db, company_acme, 'b.otgon@acme.com')
    seen = {}

    from cuba import threat_intel as ti
    monkeypatch.setattr(ti.es_service, 'export',
                        lambda **kw: seen.update(kw) or [])

    login(client, admin_user.email)
    client.get('/threat-intelligence/breached-creds/export?format=json')
    assert 'employees' not in (seen.get('filters') or {})


def test_employees_tab_export_links_carry_the_flag(client, db, member_acme,
                                                   company_acme):
    _add_employees(db, company_acme, 'b.otgon@acme.com')
    login(client, member_acme.email)
    body = client.get('/threat-intelligence/breached-creds/employees').data.decode()
    assert 'employees_only=1' in body


def _token(client):
    import re
    r = client.get('/threat-intelligence/breached-creds')
    m = re.search(rb'window\.CSRF_TOKEN\s*=\s*"([^"]+)"', r.data)
    assert m, f'no CSRF token on the page (status={r.status_code})'
    return m.group(1).decode()
