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


def test_watchlist_add_always_answers_json(client, admin_user, company_acme):
    """No Accept-header negotiation. Sniffing it is what silently broke the
    delete button: fetch sends '*/*', the sniff called that a browser, and the
    caller's r.json() choked on a redirect to HTML."""
    login(client, admin_user.email)
    token = _csrf(client, company_acme.id)
    resp = client.post(f'/admin/companies/{company_acme.id}/watchlist/add',
                       data={'csrf_token': token, 'entry_type': 'domain',
                             'entry_value': 'sub.acme.com'})
    assert resp.status_code == 200
    assert resp.is_json
    body = resp.get_json()
    assert body['success'] is True
    assert body['entry_value'] == 'sub.acme.com'
    # The page renders this as a toast, in place of the old flash+redirect.
    assert 'sub.acme.com' in body['message']


def test_watchlist_add_answers_json_for_xhr_too(client, admin_user, company_acme):
    """Same answer whether or not the caller announces itself as XHR."""
    login(client, admin_user.email)
    token = _csrf(client, company_acme.id)
    resp = client.post(f'/admin/companies/{company_acme.id}/watchlist/add',
                       headers={'X-Requested-With': 'XMLHttpRequest'},
                       data={'csrf_token': token, 'entry_type': 'domain',
                             'entry_value': 'other.acme.com'})
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True


def test_watchlist_add_reports_a_duplicate_as_json(client, db, admin_user,
                                                   company_acme):
    """Failures answer JSON too — the old redirect path swallowed them."""
    from cuba.models import WatchlistEntry
    db.session.add(WatchlistEntry(company_id=company_acme.id, entry_type='domain',
                                  entry_value='dupe.acme.com'))
    db.session.commit()
    login(client, admin_user.email)
    token = _csrf(client, company_acme.id)
    resp = client.post(f'/admin/companies/{company_acme.id}/watchlist/add',
                       data={'csrf_token': token, 'entry_type': 'domain',
                             'entry_value': 'dupe.acme.com'})
    assert resp.status_code == 400
    assert resp.is_json
    assert resp.get_json()['success'] is False


def test_watchlist_delete_answers_json_for_xhr(client, db, admin_user, company_acme):
    """The delete button reads r.json(); a redirect here is what broke it."""
    from cuba.models import WatchlistEntry
    entry = WatchlistEntry(company_id=company_acme.id, entry_type='domain',
                           entry_value='doomed.acme.com')
    db.session.add(entry)
    db.session.commit()
    entry_id = entry.id

    login(client, admin_user.email)
    token = _csrf(client, company_acme.id)
    resp = client.post(
        f'/admin/companies/{company_acme.id}/watchlist/{entry_id}/delete',
        headers={'X-Requested-With': 'XMLHttpRequest', 'X-CSRFToken': token})
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True
    assert db.session.get(WatchlistEntry, entry_id) is None


def test_watchlist_delete_button_is_wired_up(client, db, admin_user, company_acme):
    """The bug that made Remove a no-op: the ids are UUID strings, and
    interpolated bare into an inline onclick they parse as arithmetic over
    undefined names, so the handler never ran.

    (The other half — the endpoint redirecting instead of answering JSON — is
    now impossible by construction; see test_watchlist_add_always_answers_json.)
    """
    from cuba.models import WatchlistEntry
    db.session.add(WatchlistEntry(company_id=company_acme.id, entry_type='domain',
                                  entry_value='wired.acme.com'))
    db.session.commit()

    login(client, admin_user.email)
    body = client.get(f'/admin/companies/{company_acme.id}/edit').data.decode()
    # Ids reach JS as data attributes, never as bare onclick arguments.
    assert f'deleteWatchlistEntry({company_acme.id}' not in body
    assert f'data-company-id="{company_acme.id}"' in body
    assert 'data-wl-delete' in body
    # The add form is posted with fetch as well, so both paths agree.
    assert 'data-wl-add' in body


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


def test_reports_form_prefills_email_to_with_the_signed_in_user(client, member_acme):
    import re
    login(client, member_acme.email)
    resp = client.get('/threat-intelligence/reports')
    assert resp.status_code == 200
    field = re.search(r'<input[^>]*name="email_to"[^>]*>', resp.data.decode())
    assert field, 'the email_to input is gone'
    assert f'value="{member_acme.email}"' in field.group(0)


def test_weekly_schedule_requires_a_day(client, admin_user, company_acme):
    """Falling back to today's weekday would run on a day nobody picked."""
    from cuba.models import ScheduledReport
    login(client, admin_user.email)
    token = _csrf(client, company_acme.id)
    client.post('/threat-intelligence/reports/schedule/add',
                data={'csrf_token': token, 'name': 'W', 'frequency': 'weekly',
                      'format': 'pdf', 'run_time': '09:00',
                      'company_id': company_acme.id})
    assert ScheduledReport.query.count() == 0


def test_weekly_schedule_stores_the_chosen_days(client, admin_user, company_acme):
    from cuba.models import ScheduledReport
    login(client, admin_user.email)
    token = _csrf(client, company_acme.id)
    client.post('/threat-intelligence/reports/schedule/add',
                data={'csrf_token': token, 'name': 'W', 'frequency': 'weekly',
                      'format': 'pdf', 'run_time': '09:00',
                      'run_days': ['1', '5'], 'company_id': company_acme.id})
    row = ScheduledReport.query.one()
    assert row.run_days == '1,5'
    assert row.run_time == '09:00'
    assert row.next_run is not None


# --- editing an existing schedule ---

def _csrf_reports(client):
    """A token from the reports page, which any logged-in user may open."""
    import re
    resp = client.get('/threat-intelligence/reports')
    m = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', resp.data)
    assert m, f'no csrf token on the reports page (status={resp.status_code})'
    return m.group(1).decode()


def _make_schedule(client, company, token, **overrides):
    """Create one through the real route, so it starts in a valid state."""
    from cuba.models import ScheduledReport
    data = {'csrf_token': token, 'name': 'Original', 'frequency': 'daily',
            'format': 'pdf', 'run_time': '09:00', 'company_id': company.id}
    data.update(overrides)
    client.post('/threat-intelligence/reports/schedule/add', data=data)
    return ScheduledReport.query.one()


def test_edit_updates_the_schedule(client, admin_user, company_acme):
    login(client, admin_user.email)
    token = _csrf(client, company_acme.id)
    sched = _make_schedule(client, company_acme, token)
    last_run_before = sched.last_run

    resp = client.post(f'/threat-intelligence/reports/schedule/{sched.id}/edit',
                       data={'csrf_token': token, 'name': 'Renamed',
                             'frequency': 'weekly', 'format': 'csv',
                             'run_time': '17:30', 'run_days': ['2', '4'],
                             'company_id': company_acme.id})
    assert resp.status_code == 302

    from cuba.models import ScheduledReport
    row = ScheduledReport.query.one()
    assert row.name == 'Renamed'
    assert row.frequency == 'weekly'
    assert row.format == 'csv'
    assert row.run_time == '17:30'
    assert row.run_days == '2,4'
    assert row.next_run is not None
    # Editing the cadence doesn't undo the runs it already had.
    assert row.last_run == last_run_before


def test_edit_leaves_the_active_flag_alone(client, admin_user, company_acme):
    """Pause/Enable owns is_active; a stray posted field must not flip it."""
    from cuba.models import ScheduledReport
    login(client, admin_user.email)
    token = _csrf(client, company_acme.id)
    sched = _make_schedule(client, company_acme, token)
    client.post(f'/threat-intelligence/reports/schedule/{sched.id}/toggle',
                data={'csrf_token': token})
    assert ScheduledReport.query.one().is_active is False

    client.post(f'/threat-intelligence/reports/schedule/{sched.id}/edit',
                data={'csrf_token': token, 'name': 'Renamed', 'frequency': 'daily',
                      'format': 'pdf', 'run_time': '08:00',
                      'company_id': company_acme.id, 'is_active': 'true'})
    assert ScheduledReport.query.one().is_active is False


def test_edit_enforces_the_weekly_day_rule(client, admin_user, company_acme):
    """The create form's validation must hold on edit too."""
    from cuba.models import ScheduledReport
    login(client, admin_user.email)
    token = _csrf(client, company_acme.id)
    sched = _make_schedule(client, company_acme, token)

    client.post(f'/threat-intelligence/reports/schedule/{sched.id}/edit',
                data={'csrf_token': token, 'name': 'Original',
                      'frequency': 'weekly', 'format': 'pdf',
                      'run_time': '09:00', 'company_id': company_acme.id})
    row = ScheduledReport.query.one()
    assert row.frequency == 'daily', 'a dayless weekly edit was accepted'


def test_edit_enforces_the_recipient_domain_rule(client, admin_user, company_acme):
    """Edit must not become a way to redirect a client's report elsewhere."""
    from cuba.models import ScheduledReport
    login(client, admin_user.email)
    token = _csrf(client, company_acme.id)
    sched = _make_schedule(client, company_acme, token)

    client.post(f'/threat-intelligence/reports/schedule/{sched.id}/edit',
                data={'csrf_token': token, 'name': 'Renamed', 'frequency': 'daily',
                      'format': 'csv', 'run_time': '09:00',
                      'company_id': company_acme.id,
                      'email_to': 'attacker@golomtbank.com'})
    row = ScheduledReport.query.one()
    assert row.email_to != 'attacker@golomtbank.com'
    # A rejected recipient rolls the whole edit back, so the row can't be left
    # half-updated with the rest of the posted changes applied.
    assert row.name == 'Original'
    assert row.format == 'pdf'


def test_edit_rejects_another_users_schedule(client, admin_user, member_other,
                                             company_acme):
    from cuba.models import ScheduledReport
    login(client, admin_user.email)
    token = _csrf(client, company_acme.id)
    sched = _make_schedule(client, company_acme, token)

    client.get('/logout')
    login(client, member_other.email)
    resp = client.post(f'/threat-intelligence/reports/schedule/{sched.id}/edit',
                       data={'csrf_token': _csrf_reports(client), 'name': 'Hijacked',
                             'frequency': 'daily', 'format': 'pdf',
                             'run_time': '09:00'})
    assert resp.status_code == 302
    assert ScheduledReport.query.one().name == 'Original'


def test_edit_panel_renders_for_each_schedule(client, admin_user, company_acme):
    login(client, admin_user.email)
    token = _csrf(client, company_acme.id)
    sched = _make_schedule(client, company_acme, token)
    body = client.get('/threat-intelligence/reports').data.decode()
    assert f'id="edit-{sched.id}"' in body
    assert f'data-edit-toggle="edit-{sched.id}"' in body
    assert f'/schedule/{sched.id}/edit' in body


def test_day_pills_render_as_toggles_not_bare_checkboxes(client, admin_user,
                                                         company_acme):
    """Scoped to the create form on purpose: every inline edit panel renders
    the same seven pills, so a page-wide count is really a schedule count."""
    login(client, admin_user.email)
    token = _csrf(client, company_acme.id)
    _make_schedule(client, company_acme, token)
    body = client.get('/threat-intelligence/reports').data.decode()
    assert 'class="rp-days"' in body
    create_form = body.split('id="edit-')[0]
    assert create_form.count('class="rp-day"') == 7


def test_frequency_defaults_to_daily(client, admin_user):
    login(client, admin_user.email)
    body = client.get('/threat-intelligence/reports').data.decode()
    assert '<option value="daily" selected>' in body


def test_static_urls_carry_a_version(client, admin_user):
    """nginx serves /static/ as immutable for 30 days, so an unversioned URL
    means a changed stylesheet never reaches a returning browser."""
    login(client, admin_user.email)
    body = client.get('/threat-intelligence/reports').data.decode()
    assert 'reports.css?v=' in body
