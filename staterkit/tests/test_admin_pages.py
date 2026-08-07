"""Admin pages render, and the endpoints their templates reference exist.

Regression cover for a BuildError that reached production: helper functions
were inserted between a @route decorator and its view, so the decorators bound
to the helper instead and `admin.add_watchlist_entry` silently stopped being a
route. Nothing failed until a template tried to url_for() it.
"""
import pytest

from tests.conftest import login


# Endpoints referenced by admin templates. A missing one is a 500 at render
# time, so assert registration directly rather than waiting for a page to break.
REQUIRED_ENDPOINTS = [
    'admin.edit_company',
    'admin.add_watchlist_entry',
    'admin.delete_watchlist_entry',
    'admin.add_report_recipient',
    'admin.delete_report_recipient',
    'admin.user_management',
    'admin.company_management',
]


@pytest.mark.parametrize('endpoint', REQUIRED_ENDPOINTS)
def test_endpoint_is_registered(app, endpoint):
    assert endpoint in app.view_functions, f'{endpoint} is not a registered route'


def test_company_edit_page_renders(client, admin_user, company_acme):
    """Exercises every url_for() in company_form.html, including the
    report-recipients card."""
    login(client, admin_user.email)
    resp = client.get(f'/admin/companies/{company_acme.id}/edit')
    assert resp.status_code == 200
    body = resp.data.decode()
    assert 'Watchlist Entries' in body
    assert 'Report Recipients' in body


def test_company_edit_lists_approved_recipients(client, db, admin_user, company_acme):
    from cuba.models import ReportRecipient
    db.session.add(ReportRecipient(company_id=company_acme.id,
                                   email='ciso@consultancy.example'))
    db.session.commit()
    login(client, admin_user.email)
    resp = client.get(f'/admin/companies/{company_acme.id}/edit')
    assert resp.status_code == 200
    assert 'ciso@consultancy.example' in resp.data.decode()


def test_watchlist_add_redirects_for_a_form_post(client, admin_user, company_acme):
    """A browser form post must come back to the page, not a page of JSON."""
    login(client, admin_user.email)
    token = _csrf(client, company_acme.id)
    resp = client.post(f'/admin/companies/{company_acme.id}/watchlist/add',
                       data={'csrf_token': token, 'entry_type': 'domain',
                             'entry_value': 'sub.acme.com'})
    assert resp.status_code == 302
    assert f'/admin/companies/{company_acme.id}/edit' in resp.headers['Location']


def test_watchlist_add_still_answers_json_for_xhr(client, admin_user, company_acme):
    login(client, admin_user.email)
    token = _csrf(client, company_acme.id)
    resp = client.post(f'/admin/companies/{company_acme.id}/watchlist/add',
                       headers={'X-Requested-With': 'XMLHttpRequest'},
                       data={'csrf_token': token, 'entry_type': 'domain',
                             'entry_value': 'other.acme.com'})
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True


def test_report_recipient_must_be_an_address_not_a_domain(client, admin_user,
                                                          company_acme):
    """A domain here would undo the binding the allowlist is an exception to."""
    from cuba.models import ReportRecipient
    login(client, admin_user.email)
    token = _csrf(client, company_acme.id)
    client.post(f'/admin/companies/{company_acme.id}/report-recipients/add',
                data={'csrf_token': token, 'email': 'acme.com'})
    assert ReportRecipient.query.count() == 0


def _csrf(client, company_id):
    """Read a token from a page the logged-in user can actually see.

    /login redirects once authenticated, so it has no form to read.
    """
    import re
    resp = client.get(f'/admin/companies/{company_id}/edit')
    m = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', resp.data)
    assert m, f'no csrf token on the company page (status={resp.status_code})'
    return m.group(1).decode()


# --- reports form: the Company default must not be the one that fails ---

def test_member_reports_form_preselects_their_company(client, member_acme):
    """The blank 'All I can see' option rejects every approved recipient, so a
    member must not be shown it as the default."""
    login(client, member_acme.email)
    resp = client.get('/threat-intelligence/reports')
    assert resp.status_code == 200
    body = resp.data.decode()
    assert 'All I can see' not in body
    assert 'selected' in body and 'Acme Co' in body


def test_admin_reports_form_still_offers_all(client, admin_user, company_acme):
    login(client, admin_user.email)
    resp = client.get('/threat-intelligence/reports')
    assert resp.status_code == 200
    assert 'All I can see' in resp.data.decode()
