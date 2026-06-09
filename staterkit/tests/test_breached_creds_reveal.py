"""Behavioral tests for the breached-cred password reveal flow.

Plan: docs/superpowers/plans/2026-06-09-member-breached-cred-password-reveal.md
"""
from tests.conftest import login
from cuba.models import AuditLog, UserActivity


REAL_PASSWORD = "P@ssw0rd!Real"
CRED_ID = "acme-1"
CRED_SRC = {
    "username": "user@acme.com",
    "domain": "acme.com",
    "password": REAL_PASSWORD,
    "source": "test",
    "type": "combolist",
    "url": "https://acme.com/login",
    "timestamp": "2026-01-01T00:00:00",
}


def test_detail_page_never_contains_plaintext_member(client, member_acme, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})
    login(client, member_acme.email)
    resp = client.get(f"/threat-intelligence/breached-creds/{CRED_ID}")
    assert resp.status_code == 200
    assert REAL_PASSWORD.encode() not in resp.data, \
        "Plaintext password leaked into detail page HTML for member"


def test_detail_page_never_contains_plaintext_analyst(client, analyst_user, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})
    login(client, analyst_user.email)
    resp = client.get(f"/threat-intelligence/breached-creds/{CRED_ID}")
    assert resp.status_code == 200
    assert REAL_PASSWORD.encode() not in resp.data, \
        "Plaintext password leaked into detail page HTML for analyst"


def test_detail_page_never_contains_plaintext_admin(client, admin_user, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})
    login(client, admin_user.email)
    resp = client.get(f"/threat-intelligence/breached-creds/{CRED_ID}")
    assert resp.status_code == 200
    assert REAL_PASSWORD.encode() not in resp.data, \
        "Plaintext password leaked into detail page HTML for admin"
