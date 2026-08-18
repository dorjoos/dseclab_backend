"""The Matched column, and the table width that hid the View button.

Two defects visible on one screenshot of the Breached Credentials list:

1. Every row showed a dash under Matched. `_get_domain_filters()` returns None
   for an admin meaning "unrestricted", the call site collapsed that to `[]`
   with `or []`, and matching against no domains labels nothing — so the column
   whose whole job is naming the watched domain a credential hit was blank for
   exactly the role that sees every company's rows.

2. The View button was clipped to "V...". The table is `table-layout: fixed`,
   so declared widths are honoured literally rather than squeezed; adding the
   Matched header reused av-th-domain's 14% and took the total past 100%,
   pushing the actions column off the right edge.
"""
import re

import pytest

from tests.conftest import login
from cuba.models import WatchlistEntry


ACME_CRED = {
    'username': 'victim@acme.com', 'domain': 'acme.com',
    'password': 'hunter2', 'source': 'Telegram/Combolist', 'type': 'url',
    'url': 'https://acme.com/login', 'timestamp': '2026-01-01T00:00:00',
}


# --- 1. the Matched column ---

def test_admin_gets_every_companys_watched_domains(app, db, admin_user,
                                                   company_acme, company_other):
    """An admin sees every company's rows, so must be able to label them all."""
    from cuba import threat_intel as ti
    db.session.add(WatchlistEntry(company_id=company_acme.id,
                                  entry_type='domain', entry_value='mail.acme.com'))
    db.session.commit()

    with app.test_request_context():
        from flask_login import login_user
        login_user(admin_user)
        domains = ti._get_match_domains()

    assert 'acme.com' in domains          # the company's own domain
    assert 'mail.acme.com' in domains     # and its watchlist entries
    assert 'other.com' in domains         # and other tenants'


def test_member_gets_only_their_own(app, db, member_acme, company_acme,
                                    company_other):
    from cuba import threat_intel as ti
    with app.test_request_context():
        from flask_login import login_user
        login_user(member_acme)
        domains = ti._get_match_domains()
    assert 'acme.com' in domains
    assert 'other.com' not in domains


def test_anonymous_gets_nothing(app):
    from cuba import threat_intel as ti
    with app.test_request_context():
        assert ti._get_match_domains() == []


def test_matched_domain_is_populated_for_an_admin(client, admin_user,
                                                  company_acme, fake_cred,
                                                  monkeypatch):
    """The regression itself, end to end through the list API."""
    from cuba import threat_intel as ti
    from cuba.services.breached_creds_service import BreachedCredDoc, ESPagination

    doc = BreachedCredDoc('acme-1', ACME_CRED)
    monkeypatch.setattr(ti.es_service, 'search',
                        lambda **kw: ESPagination([doc], 1, 20, 1))

    login(client, admin_user.email)
    token = _token(client)
    resp = client.post('/api/breached-creds/search', json={'page': 1},
                       headers={'X-CSRFToken': token})
    assert resp.status_code == 200
    row = resp.get_json()['rows'][0]
    assert row['matched_domain'] == 'acme.com', (
        'admin rows are unlabelled — the Matched column is blank again')


def test_matched_domain_still_works_for_a_member(client, member_acme,
                                                 company_acme, monkeypatch):
    """The member path was never broken; keep it that way."""
    from cuba import threat_intel as ti
    from cuba.services.breached_creds_service import BreachedCredDoc, ESPagination

    doc = BreachedCredDoc('acme-1', ACME_CRED)
    monkeypatch.setattr(ti.es_service, 'search',
                        lambda **kw: ESPagination([doc], 1, 20, 1))

    login(client, member_acme.email)
    resp = client.post('/api/breached-creds/search', json={'page': 1},
                       headers={'X-CSRFToken': _token(client)})
    assert resp.get_json()['rows'][0]['matched_domain'] == 'acme.com'


# --- 2. the table that clipped the View button ---

WIDTH_RE = re.compile(r'\.av-table \.av-th-([a-z]+)\s*\{[^}]*?width:\s*([0-9.]+)(%|px)')


def _column_widths():
    css = open('cuba/static/assets/css/pages/breached-creds.css').read()
    return {name: (float(n), unit) for name, n, unit in WIDTH_RE.findall(css)}


def test_declared_column_widths_fit_the_table():
    """table-layout:fixed honours these literally. Overrun and the last column
    — the one holding View — is pushed out of sight rather than shrinking."""
    widths = _column_widths()
    percent = sum(v for v, unit in widths.values() if unit == '%')
    pixels = sum(v for v, unit in widths.values() if unit == 'px')
    assert percent <= 92, (
        f'columns declare {percent}% plus {pixels:.0f}px; the actions column '
        'will be pushed off the right edge')


def test_every_column_has_its_own_width_class():
    """Matched borrowed av-th-domain's width, which is how the overrun crept
    in unnoticed — the total changed without any width value changing."""
    panel = open('cuba/templates/threat_intel/_breached_creds_panel.html').read()
    classes = re.findall(r'<th class="(av-th-[a-z]+)', panel)
    assert len(classes) == len(set(classes)), f'duplicate width class: {classes}'


def test_domain_and_matched_are_one_column():
    """They name the same thing, so the table shows one Domain column and the
    row falls back to matched_domain when the feed carried no domain field."""
    panel = open('cuba/templates/threat_intel/_breached_creds_panel.html').read()
    script = open('cuba/templates/threat_intel/_breached_creds_script.html').read()
    assert '>Matched<' not in panel, 'the Matched column is back'
    assert panel.count('>Domain<') == 1
    assert 'row.domain || row.matched_domain' in script, 'the fallback is gone'


def test_column_count_matches_the_header():
    """colSpan and the skeleton loader are counted by hand; dropping a column
    without updating them leaves the empty and error rows mis-spanned."""
    panel = open('cuba/templates/threat_intel/_breached_creds_panel.html').read()
    script = open('cuba/templates/threat_intel/_breached_creds_script.html').read()
    headers = len(re.findall(r'<th class="av-th-', panel))
    assert f'colspan="{headers}"' in panel, f'loading row is not colspan={headers}'
    assert f'td.colSpan = {headers};' in script, f'error row is not colSpan={headers}'
    assert f'c < {headers};' in script, f'skeleton draws the wrong cell count'


def test_actions_column_can_hold_the_view_button():
    """At 50px the cell clipped 'View' to 'V...'."""
    widths = _column_widths()
    value, unit = widths['actions']
    assert unit == 'px' and value >= 70, f'actions column is {value}{unit}'


def test_checkbox_cell_does_not_ellipsise():
    """tbody td sets text-overflow:ellipsis. At 32px wide with 14px of padding
    each side the checkbox had ~4px of content box, overflowed, and the browser
    drew a "…" next to every row's checkbox."""
    css = open('cuba/static/assets/css/pages/breached-creds.css').read()
    block = re.search(r'\.av-table \.av-th-checkbox\s*\{([^}]*)\}', css)
    assert block, 'the checkbox column lost its rule'
    rule = block.group(1)

    width = float(re.search(r'width:\s*([0-9.]+)px', rule).group(1))
    pad_left = float(re.search(r'padding-left:\s*([0-9.]+)px', rule).group(1))
    pad_right_m = re.search(r'padding-right:\s*([0-9.]+)px', rule)
    # tbody td's shorthand supplies 14px when the column does not override it.
    pad_right = float(pad_right_m.group(1)) if pad_right_m else 14.0

    content = width - pad_left - pad_right
    assert content >= 16, (
        f'only {content}px of content box for a ~16px checkbox — it will '
        'overflow and render an ellipsis')
    assert 'text-overflow:clip' in rule.replace(' ', ''), (
        'the cell holds an input, not text; ellipsis must be turned off')


def _token(client):
    r = client.get('/threat-intelligence/breached-creds')
    m = re.search(rb'window\.CSRF_TOKEN\s*=\s*"([^"]+)"', r.data)
    assert m, f'no CSRF token (status={r.status_code})'
    return m.group(1).decode()
