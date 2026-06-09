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


REVEAL_PATH = f"/threat-intelligence/breached-creds/{CRED_ID}/reveal-password"


def _csrf_token(client):
    """Pull window.CSRF_TOKEN from an authenticated page (rendered by base.html)."""
    import re
    r = client.get("/threat-intelligence/breached-creds", follow_redirects=True)
    m = re.search(rb'window\.CSRF_TOKEN\s*=\s*"([^"]+)"', r.data)
    assert m, f"CSRF token not found on authenticated page (status={r.status_code})"
    return m.group(1).decode()


def test_reveal_owning_member_gets_plaintext(client, db, member_acme, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})
    login(client, member_acme.email)
    token = _csrf_token(client)
    resp = client.post(REVEAL_PATH, headers={"X-CSRFToken": token})
    assert resp.status_code == 200
    assert resp.is_json
    assert resp.get_json()["password"] == REAL_PASSWORD
    rows = AuditLog.query.filter_by(action_type="reveal_password").all()
    assert len(rows) == 1
    assert rows[0].resource_id == CRED_ID
    assert REAL_PASSWORD not in (rows[0].description or "")
    assert REAL_PASSWORD not in (rows[0].new_values or "")
    activities = UserActivity.query.filter_by(activity_type="reveal_password").all()
    assert len(activities) == 1


def test_reveal_cross_company_member_denied(client, db, member_other, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})  # cred belongs to acme.com
    login(client, member_other.email)  # user is at other.com
    token = _csrf_token(client)
    resp = client.post(REVEAL_PATH, headers={"X-CSRFToken": token})
    assert resp.status_code == 403
    assert REAL_PASSWORD.encode() not in resp.data
    granted = AuditLog.query.filter_by(action_type="reveal_password").all()
    denied = AuditLog.query.filter_by(action_type="reveal_password_denied").all()
    assert granted == [], "Denied reveal should not write a success audit row"
    assert len(denied) == 1, "Denied reveal should write a denial audit row"
    assert denied[0].resource_id == CRED_ID


def test_reveal_analyst_gets_plaintext(client, db, analyst_user, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})
    login(client, analyst_user.email)
    token = _csrf_token(client)
    resp = client.post(REVEAL_PATH, headers={"X-CSRFToken": token})
    assert resp.status_code == 200
    assert resp.get_json()["password"] == REAL_PASSWORD


def test_reveal_admin_gets_plaintext(client, db, admin_user, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})
    login(client, admin_user.email)
    token = _csrf_token(client)
    resp = client.post(REVEAL_PATH, headers={"X-CSRFToken": token})
    assert resp.status_code == 200
    assert resp.get_json()["password"] == REAL_PASSWORD
    rows = AuditLog.query.filter_by(action_type="reveal_password").all()
    assert len(rows) == 1


def test_reveal_missing_csrf_rejected(client, member_acme, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})
    login(client, member_acme.email)
    resp = client.post(REVEAL_PATH)
    assert resp.status_code == 400, f"Expected 400 without CSRF, got {resp.status_code}"


def test_reveal_unauthenticated_does_not_leak(client, fake_cred):
    """Unauthenticated POST must not return plaintext. Flask-WTF CSRF rejects (400)
    before @login_required's redirect (302) / 401 — either is a safe rejection."""
    fake_cred({CRED_ID: CRED_SRC})
    resp = client.post(REVEAL_PATH)
    assert resp.status_code in (302, 400, 401), f"Expected 302/400/401, got {resp.status_code}"
    assert REAL_PASSWORD.encode() not in resp.data


def test_reveal_unknown_doc_returns_404(client, member_acme, fake_cred):
    fake_cred({})  # nothing in store
    login(client, member_acme.email)
    token = _csrf_token(client)
    resp = client.post(REVEAL_PATH, headers={"X-CSRFToken": token})
    assert resp.status_code == 404


NIBANK_CRED_ID = "nibank-1"
NIBANK_SRC = {
    "username": "victim@nibank.mn",
    "domain": "nibank.mn",
    "password": "different-bank-secret",
    "source": "test",
    "type": "url",
    "url": "https://nibank.mn/login",
    "timestamp": "2026-01-01T00:00:00",
}
IBANK_SUB_CRED_ID = "ibank-sub-1"
IBANK_SUB_SRC = {
    "username": "real@mail.ibank.mn",
    "domain": "mail.ibank.mn",
    "password": "subdomain-secret",
    "source": "test",
    "type": "url",
    "url": "https://mail.ibank.mn/login",
    "timestamp": "2026-01-01T00:00:00",
}


def test_member_cannot_see_substring_lookalike_company(client, db, member_ibank, fake_cred):
    """Regression: ibank.mn member must NOT see nibank.mn creds, even though
    'ibank.mn' is a substring of 'nibank.mn'. Pre-fix this leaked."""
    fake_cred({NIBANK_CRED_ID: NIBANK_SRC})
    login(client, member_ibank.email)
    # Detail page must deny.
    resp = client.get(f"/threat-intelligence/breached-creds/{NIBANK_CRED_ID}",
                      follow_redirects=False)
    assert resp.status_code in (302, 403), (
        f"ibank.mn member reached detail page of nibank.mn cred (status={resp.status_code})"
    )
    # Reveal endpoint must also deny.
    token = _csrf_token(client)
    reveal = client.post(
        f"/threat-intelligence/breached-creds/{NIBANK_CRED_ID}/reveal-password",
        headers={"X-CSRFToken": token},
    )
    assert reveal.status_code == 403
    assert b"different-bank-secret" not in reveal.data


def test_member_still_sees_own_subdomain_creds(client, db, member_ibank, fake_cred):
    """Sanity: tightening must not break legitimate subdomain matches.
    mail.ibank.mn is part of ibank.mn and must remain visible."""
    fake_cred({IBANK_SUB_CRED_ID: IBANK_SUB_SRC})
    login(client, member_ibank.email)
    resp = client.get(f"/threat-intelligence/breached-creds/{IBANK_SUB_CRED_ID}")
    assert resp.status_code == 200, (
        f"ibank.mn member cannot see mail.ibank.mn cred (status={resp.status_code})"
    )
    token = _csrf_token(client)
    reveal = client.post(
        f"/threat-intelligence/breached-creds/{IBANK_SUB_CRED_ID}/reveal-password",
        headers={"X-CSRFToken": token},
    )
    assert reveal.status_code == 200
    assert reveal.get_json()["password"] == "subdomain-secret"


def test_reveal_rate_limit_blocks_31st_call(client, member_acme, fake_cred):
    """The endpoint is decorated @limiter.limit('30/minute'); the 31st call returns 429."""
    from cuba import limiter
    try:
        limiter.reset()
    except Exception:
        pass
    fake_cred({CRED_ID: CRED_SRC})
    login(client, member_acme.email)
    token = _csrf_token(client)
    last_status = None
    for i in range(31):
        resp = client.post(REVEAL_PATH, headers={"X-CSRFToken": token})
        last_status = resp.status_code
        if last_status == 429:
            break
    assert last_status == 429, f"Expected 429 within 31 calls, got {last_status}"
