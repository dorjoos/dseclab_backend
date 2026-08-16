"""Every <script> block the app renders must actually parse.

The watchlist Remove button shipped broken because its inline handler was a
JavaScript syntax/reference error — HTML assertions all passed, the page looked
right, and the button silently did nothing. Rendering a page and asserting a
string is in it says nothing about whether the browser can run the result.

So: render the real pages, extract their inline JS, and hand it to Node. Skips
cleanly where Node is absent, so it never blocks a machine without it.
"""
import html as html_mod
import re
import shutil
import subprocess

import pytest

from tests.conftest import login

NODE = shutil.which('node')
pytestmark = pytest.mark.skipif(NODE is None, reason='node is not installed')

SCRIPT_RE = re.compile(
    r'<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
# Inline event handlers — onclick, onchange, onmouseover... This is where the
# watchlist bug lived, so a <script>-only check would have missed it entirely.
HANDLER_RE = re.compile(r'\bon[a-z]+\s*=\s*"([^"]*)"', re.IGNORECASE)


def _parses(source):
    """(ok, stderr) for a fragment, parsed but never executed."""
    proc = subprocess.run([NODE, '--check', '-'], input=source,
                          capture_output=True, text=True)
    return proc.returncode == 0, proc.stderr.strip()


def _assert_parses(html, where):
    blocks = [s for s in SCRIPT_RE.findall(html) if s.strip()]
    assert blocks, f'{where}: expected at least one inline script'
    for i, block in enumerate(blocks):
        ok, err = _parses(block)
        assert ok, (f'{where}: inline <script> #{i} does not parse\n{err}\n'
                    f'--- source ---\n{block[:1500]}')

    handlers = {html_mod.unescape(h) for h in HANDLER_RE.findall(html) if h.strip()}
    for handler in sorted(handlers):
        # Wrapped in a function body, which is the context a handler runs in —
        # `this` and bare statements are legal there.
        ok, err = _parses('function _h(event){' + handler + '\n}')
        assert ok, (f'{where}: inline event handler does not parse\n{err}\n'
                    f'--- handler ---\n{handler[:500]}')
    return blocks, handlers


#: A UUID starting with a digit. Interpolated bare into JS this is '3f2a...',
#: an invalid numeric literal — a hard SyntaxError rather than a
#: parses-but-throws ReferenceError. Fixed rather than random so this test
#: cannot pass by luck: only 6 of the 16 possible leading hex characters are
#: letters, so a generated id would make the check flaky.
DIGIT_LEADING_ID = '3f2a1b4c-0000-4000-8000-000000000001'


def test_company_form_javascript_parses(client, db, admin_user, company_acme):
    """The page that shipped the broken Remove button."""
    from cuba.models import WatchlistEntry
    db.session.add(WatchlistEntry(id=DIGIT_LEADING_ID, company_id=company_acme.id,
                                  entry_type='domain', entry_value='a.acme.com'))
    db.session.commit()
    login(client, admin_user.email)
    html = client.get(f'/admin/companies/{company_acme.id}/edit').data.decode()
    _assert_parses(html, 'company_form')


def test_reports_page_javascript_parses(client, admin_user, company_acme):
    """Renders with a schedule present, so the inline edit panels are in the
    output — an unquoted id there would be the same class of bug."""
    import re as _re
    login(client, admin_user.email)
    page = client.get('/threat-intelligence/reports')
    token = _re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', page.data).group(1).decode()
    client.post('/threat-intelligence/reports/schedule/add',
                data={'csrf_token': token, 'name': 'Parses', 'frequency': 'weekly',
                      'format': 'pdf', 'run_time': '09:00', 'run_days': ['2', '5'],
                      'company_id': company_acme.id})
    html = client.get('/threat-intelligence/reports').data.decode()
    assert 'rpt-edit-panel' in html, 'no edit panel rendered; test is not covering it'
    _assert_parses(html, 'reports')


@pytest.mark.parametrize('path', [
    '/threat-intelligence/breached-creds',
    '/threat-intelligence/breached-creds/employees',
    '/threat-intelligence/ransomware',
])
def test_threat_intel_pages_javascript_parses(client, admin_user, company_acme, path):
    login(client, admin_user.email)
    resp = client.get(path)
    assert resp.status_code == 200, f'{path} returned {resp.status_code}'
    _assert_parses(resp.data.decode(), path)


def test_credential_detail_javascript_parses(client, member_acme, fake_cred):
    fake_cred({'acme-1': {
        'username': 'user@acme.com', 'domain': 'acme.com',
        'password': 'P@ssw0rd!', 'value': 'https://acme.com:user@acme.com:P@ssw0rd!',
        'source': 'test', 'type': 'combolist',
    }})
    login(client, member_acme.email)
    html = client.get('/threat-intelligence/breached-creds/acme-1').data.decode()
    _assert_parses(html, 'breached_creds_view')
