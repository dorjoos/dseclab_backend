"""Behavioral tests for the CISA KEV Vulnerabilities page.

Plan: docs/superpowers/plans/2026-06-10-cisa-kev-vulnerabilities-page.md
"""
import re
import pytest
from tests.conftest import login


LIST_PATH = '/threat-intelligence/vulnerabilities'
SEARCH_PATH = '/api/vulnerabilities/search'
EXPORT_PATH = '/threat-intelligence/vulnerabilities/export.csv'

CVE_A = 'CVE-2024-0001'
CVE_B = 'CVE-2024-0002'
SAMPLE = {
    CVE_A: {
        'cveID': CVE_A,
        'vendorProject': 'Microsoft',
        'product': 'Windows',
        'vulnerabilityName': 'Win32k EoP',
        'dateAdded': '2024-01-15',
        'shortDescription': 'Use-after-free in Win32k leading to privilege escalation.',
        'requiredAction': 'Apply MS-24-XXX',
        'dueDate': '2024-02-05',
        'knownRansomwareCampaignUse': 'Known',
        'notes': 'https://msrc.microsoft.com/CVE-2024-0001',
        'cwes': ['CWE-416'],
    },
    CVE_B: {
        'cveID': CVE_B,
        'vendorProject': 'Apache',
        'product': 'Struts',
        'vulnerabilityName': 'OGNL Injection',
        'dateAdded': '2024-02-01',
        'shortDescription': 'Remote code execution via crafted Content-Type header.',
        'requiredAction': 'Upgrade to 2.5.33',
        'dueDate': '2024-02-22',
        'knownRansomwareCampaignUse': 'Unknown',
        'notes': 'https://cve.mitre.org/CVE-2024-0002',
        'cwes': ['CWE-917'],
    },
}


def _csrf_token(client):
    r = client.get('/threat-intelligence/breached-creds', follow_redirects=True)
    m = re.search(rb'window\.CSRF_TOKEN\s*=\s*"([^"]+)"', r.data)
    assert m, f'CSRF token not found (status={r.status_code})'
    return m.group(1).decode()


# --- shell access (all roles allowed) ---

def test_admin_can_get_list_shell(client, admin_user, fake_kev):
    fake_kev(SAMPLE)
    login(client, admin_user.email)
    r = client.get(LIST_PATH)
    assert r.status_code == 200
    assert b'Vulnerabilities' in r.data or b'CISA' in r.data


def test_member_can_get_list_shell(client, member_acme, fake_kev):
    fake_kev(SAMPLE)
    login(client, member_acme.email)
    r = client.get(LIST_PATH)
    assert r.status_code == 200


# --- AJAX search: role-aware field projection ---

def test_admin_search_returns_full_fields(client, admin_user, fake_kev):
    fake_kev(SAMPLE)
    login(client, admin_user.email)
    token = _csrf_token(client)
    r = client.post(SEARCH_PATH, headers={'X-CSRFToken': token},
                    json={'page': 1, 'per_page': 10})
    assert r.status_code == 200
    rows = r.get_json()['rows']
    assert len(rows) == 2
    sample_row = rows[0]
    assert 'short_description' in sample_row
    assert 'required_action' in sample_row
    assert 'notes' in sample_row
    assert 'cwes' in sample_row


def test_member_search_omits_sensitive_fields(client, member_acme, fake_kev):
    fake_kev(SAMPLE)
    login(client, member_acme.email)
    token = _csrf_token(client)
    r = client.post(SEARCH_PATH, headers={'X-CSRFToken': token},
                    json={'page': 1, 'per_page': 10})
    assert r.status_code == 200
    rows = r.get_json()['rows']
    assert len(rows) == 2
    sample_row = rows[0]
    assert 'cve_id' in sample_row
    assert 'vendor' in sample_row
    assert 'product' in sample_row
    assert 'short_description' not in sample_row
    assert 'required_action' not in sample_row
    assert 'notes' not in sample_row
    assert 'cwes' not in sample_row


def test_filter_by_vendor(client, admin_user, fake_kev):
    fake_kev(SAMPLE)
    login(client, admin_user.email)
    token = _csrf_token(client)
    r = client.post(SEARCH_PATH, headers={'X-CSRFToken': token},
                    json={'page': 1, 'per_page': 10, 'vendor': 'Microsoft'})
    assert r.status_code == 200
    rows = r.get_json()['rows']
    assert len(rows) == 1
    assert rows[0]['cve_id'] == CVE_A


def test_filter_by_ransomware_use(client, admin_user, fake_kev):
    fake_kev(SAMPLE)
    login(client, admin_user.email)
    token = _csrf_token(client)
    r = client.post(SEARCH_PATH, headers={'X-CSRFToken': token},
                    json={'page': 1, 'per_page': 10, 'ransomware_use': 'Known'})
    assert r.status_code == 200
    rows = r.get_json()['rows']
    assert len(rows) == 1
    assert rows[0]['cve_id'] == CVE_A


# --- detail page ---

def test_member_denied_on_detail(client, member_acme, fake_kev):
    fake_kev(SAMPLE)
    login(client, member_acme.email)
    r = client.get(f'{LIST_PATH}/{CVE_A}', follow_redirects=False)
    assert r.status_code in (302, 403)
    assert b'Use-after-free' not in r.data


def test_analyst_can_view_detail(client, analyst_user, fake_kev):
    fake_kev(SAMPLE)
    login(client, analyst_user.email)
    r = client.get(f'{LIST_PATH}/{CVE_A}')
    assert r.status_code == 200
    assert b'Use-after-free' in r.data
    assert b'Apply MS-24-XXX' in r.data


def test_unknown_cve_returns_404(client, admin_user, fake_kev):
    fake_kev({})
    login(client, admin_user.email)
    r = client.get(f'{LIST_PATH}/CVE-9999-9999')
    assert r.status_code == 404


# --- export ---

def test_member_denied_on_export(client, member_acme, fake_kev):
    fake_kev(SAMPLE)
    login(client, member_acme.email)
    r = client.get(EXPORT_PATH, follow_redirects=False)
    assert r.status_code in (302, 403)
    assert b'CVE-2024-0001' not in r.data


def test_admin_can_export(client, admin_user, fake_kev):
    fake_kev(SAMPLE)
    login(client, admin_user.email)
    r = client.get(EXPORT_PATH)
    assert r.status_code == 200
    assert r.mimetype.startswith('text/csv')
    body = r.data.decode()
    assert 'cve_id' in body.lower() or 'cveid' in body.lower()
    assert CVE_A in body


# --- audit ---

def test_detail_view_writes_audit_row(client, db, analyst_user, fake_kev):
    from cuba.models import AuditLog
    fake_kev(SAMPLE)
    login(client, analyst_user.email)
    r = client.get(f'{LIST_PATH}/{CVE_A}')
    assert r.status_code == 200
    rows = AuditLog.query.filter_by(action_type='vulnerabilities_view').all()
    assert len(rows) == 1
    assert rows[0].resource_id == CVE_A


def test_export_writes_audit_row(client, db, admin_user, fake_kev):
    from cuba.models import AuditLog
    fake_kev(SAMPLE)
    login(client, admin_user.email)
    r = client.get(EXPORT_PATH)
    assert r.status_code == 200
    rows = AuditLog.query.filter_by(action_type='vulnerabilities_export').all()
    assert len(rows) == 1


# --- unauthenticated ---

def test_unauthenticated_search_does_not_leak(client, fake_kev):
    fake_kev(SAMPLE)
    r = client.post(SEARCH_PATH)
    assert r.status_code in (302, 400, 401)
    assert b'Use-after-free' not in r.data


def test_list_page_renders_ssr_stats(client, admin_user, fake_kev, monkeypatch):
    """The list shell must include the SSR stats row text so the page is
    informative even before the table AJAX resolves."""
    fake_kev(SAMPLE)
    from cuba.services import cisa_kev_service as svc_mod
    monkeypatch.setattr(svc_mod.cisa_kev_service, 'get_stats',
                        lambda: {'total': 1607, 'by_vendor': [('Microsoft', 377)],
                                 'by_ransomware': {'Known': 325, 'Unknown': 1282},
                                 'due_soon': 47, 'overdue': 12})
    login(client, admin_user.email)
    r = client.get(LIST_PATH)
    assert r.status_code == 200
    body = r.data
    assert b'Total' in body
    assert b'1607' in body
    assert b'Ransom' in body or b'KEV' in body
    assert b'325' in body  # Known KEV count from the stub


def test_member_sees_aggregate_stats_no_export(client, member_acme, fake_kev, monkeypatch):
    """Member sees stats + table shell. Member must NOT see Export link."""
    fake_kev(SAMPLE)
    from cuba.services import cisa_kev_service as svc_mod
    monkeypatch.setattr(svc_mod.cisa_kev_service, 'get_stats',
                        lambda: {'total': 1607, 'by_vendor': [('Microsoft', 377)],
                                 'by_ransomware': {'Known': 325, 'Unknown': 1282},
                                 'due_soon': 47, 'overdue': 12})
    login(client, member_acme.email)
    r = client.get(LIST_PATH)
    assert r.status_code == 200
    assert b'Total' in r.data
    assert b'1607' in r.data
    # Export button must be hidden for member. The href to the export endpoint
    # is the load-bearing string; "Export" as a word could appear elsewhere.
    assert b'export.csv' not in r.data


def test_get_stats_includes_due_counts(app, monkeypatch):
    """get_stats() must surface due_soon and overdue integer counts."""
    from cuba.services import cisa_kev_service as svc_mod

    def fake_search(body):
        return {
            'hits': {'total': {'value': 1607}, 'hits': []},
            'aggregations': {
                'by_vendor': {'buckets': [{'key': 'Microsoft', 'doc_count': 377}]},
                'by_ransomware': {'buckets': [{'key': 'Known', 'doc_count': 325},
                                              {'key': 'Unknown', 'doc_count': 1282}]},
            },
        }
    counts = iter([47, 12])  # due_soon, overdue

    def fake_count(query=None):
        return next(counts)

    monkeypatch.setattr(svc_mod.cisa_kev_service, '_search', fake_search)
    monkeypatch.setattr(svc_mod.cisa_kev_service, '_count', fake_count)

    with app.app_context():
        s = svc_mod.cisa_kev_service.get_stats()
    assert s['total'] == 1607
    assert s['by_vendor'][:1] == [('Microsoft', 377)]
    assert s['by_ransomware'] == {'Known': 325, 'Unknown': 1282}
    assert s['due_soon'] == 47
    assert s['overdue'] == 12
