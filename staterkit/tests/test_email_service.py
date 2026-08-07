"""Tests for email_service breach-email builder, hardening, and config helper."""
from types import SimpleNamespace

import pytest

from cuba.services import email_service
from cuba.services.email_service import (
    build_breach_email,
    is_email_configured,
    _clean_header,
    _cred_url,
    _recipients,
    send_email,
)


def _cred(**kw):
    kw.setdefault("es_id", "abc123")
    kw.setdefault("username", None)
    kw.setdefault("domain", None)
    kw.setdefault("matched_domain", None)
    kw.setdefault("file_name", None)
    kw.setdefault("source", None)
    kw.setdefault("type", None)
    kw.setdefault("created_at", None)
    return SimpleNamespace(**kw)


# --- builder ---

def test_subject_includes_count_and_company():
    subject, _, _ = build_breach_email("Acme Co", [_cred(), _cred()])
    assert "2" in subject and "Acme Co" in subject


def test_body_includes_matched_domain_and_file_name():
    cred = _cred(username="alice@acme.com", domain="acme.com",
                 matched_domain="acme.com", file_name="stealer_log_2026.txt")
    _, body, _ = build_breach_email("Acme Co", [cred])
    assert "acme.com" in body
    assert "stealer_log_2026.txt" in body
    assert "Matched domain" in body
    assert "File name" in body


def test_body_includes_view_link_when_base_url_given():
    cred = _cred(es_id="XYZ")
    _, body, _ = build_breach_email("Acme Co", [cred], base_url="https://app.example/")
    assert "https://app.example/threat-intelligence/breached-creds/XYZ" in body


def test_body_escapes_html():
    cred = _cred(username="<script>alert(1)</script>")
    _, body, _ = build_breach_email("Acme", [cred])
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_one_card_per_credential():
    creds = [_cred(username=f"user{i}@acme.com") for i in range(5)]
    _, body, _ = build_breach_email("Acme Co", creds)
    for i in range(5):
        assert f"user{i}@acme.com" in body


# --- text/plain alternative ---

def test_text_part_carries_the_same_data():
    cred = _cred(username="alice@acme.com", domain="acme.com",
                 matched_domain="acme.com", file_name="dump.txt")
    _, _, text = build_breach_email("Acme Co", [cred], base_url="https://app.example")
    assert "<" not in text  # no markup leaked into the plain part
    assert "alice@acme.com" in text
    assert "dump.txt" in text
    assert "https://app.example/threat-intelligence/breached-creds/abc123" in text


# --- autolink defense ---

def test_values_are_wrapped_in_our_own_anchors():
    """Gmail autolinks bare addresses/domains and paints them blue; text already
    inside an <a> is left alone."""
    cred = _cred(username="alice@acme.com", domain="acme.com")
    _, body, _ = build_breach_email("Acme Co", [cred])
    assert '<a style="color:#111827;text-decoration:none;">acme.com</a>' in body


# --- defense in depth ---

def test_password_never_reaches_the_message():
    """The renderer reads an allowlist, so a doc carrying a password can't leak it."""
    cred = _cred(username="alice@acme.com", domain="acme.com")
    cred.password = "SuperSecret123!"
    _, body, text = build_breach_email("Acme Co", [cred], base_url="https://app.example")
    assert "SuperSecret123!" not in body
    assert "SuperSecret123!" not in text


def test_clean_header_strips_crlf():
    assert _clean_header("Acme\r\nBcc: attacker@evil.com") == "Acme Bcc: attacker@evil.com"


def test_subject_cannot_carry_injected_headers():
    subject, _, _ = build_breach_email("Acme\r\nBcc: attacker@evil.com", [_cred()])
    assert "\r" not in subject and "\n" not in subject


def test_cred_url_quotes_the_es_id():
    url = _cred_url("https://app.example", "a b/../c")
    assert url == "https://app.example/threat-intelligence/breached-creds/a%20b%2F..%2Fc"


def test_cred_url_none_without_base_url_or_id():
    assert _cred_url("", "abc") is None
    assert _cred_url("https://app.example", None) is None


def test_no_link_markup_when_base_url_missing():
    _, body, _ = build_breach_email("Acme Co", [_cred(username="a@acme.com")])
    assert "href" not in body


@pytest.mark.parametrize("raw,expected", [
    ("a@x.com, b@y.com", ["a@x.com", "b@y.com"]),
    ("a@x.com,,  ", ["a@x.com"]),
    ("bad-address", []),
    ("a@x.com\r\nBcc: evil@x.com", []),
    ("", []),
])
def test_recipients_validation(raw, expected):
    assert _recipients(raw) == expected


# --- send_email ---

class _FakeSMTP:
    sent = []

    def __init__(self, server, port):
        self.server, self.port = server, port

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self):
        pass

    def login(self, username, password):
        pass

    def sendmail(self, sender, recipients, message):
        _FakeSMTP.sent.append({"sender": sender, "recipients": recipients,
                               "message": message})


@pytest.fixture()
def fake_smtp(monkeypatch):
    _FakeSMTP.sent = []
    monkeypatch.setattr(email_service.smtplib, "SMTP", _FakeSMTP)
    return _FakeSMTP


def _configure(app):
    app.config.update(MAIL_USERNAME="resend", MAIL_PASSWORD="re_key",
                      MAIL_DEFAULT_SENDER="report@notification.dseclab.mn",
                      MAIL_SERVER="smtp.example", MAIL_PORT=587, MAIL_USE_TLS=True)


def test_send_email_builds_multipart_alternative(app, fake_smtp):
    with app.app_context():
        _configure(app)
        assert send_email("dest@example.com", "Subject", "<p>hi</p>", text="hi") is True
    message = fake_smtp.sent[0]["message"]
    assert "multipart/alternative" in message
    assert "text/plain" in message
    assert "text/html" in message


def test_send_email_derives_text_when_not_given(app, fake_smtp):
    with app.app_context():
        _configure(app)
        assert send_email("dest@example.com", "Subject", "<p>hello there</p>") is True
    assert "text/plain" in fake_smtp.sent[0]["message"]


def test_send_email_rejects_malformed_recipient(app, fake_smtp):
    with app.app_context():
        _configure(app)
        assert send_email("not-an-address", "Subject", "<p>hi</p>") is False
    assert fake_smtp.sent == []


def test_send_email_returns_false_when_unconfigured(app, fake_smtp):
    with app.app_context():
        app.config.update(MAIL_USERNAME="", MAIL_PASSWORD="")
        assert send_email("dest@example.com", "Subject", "<p>hi</p>") is False
    assert fake_smtp.sent == []


def test_is_email_configured(app):
    with app.app_context():
        app.config["MAIL_USERNAME"] = ""
        app.config["MAIL_PASSWORD"] = ""
        assert is_email_configured() is False
        app.config["MAIL_USERNAME"] = "resend"
        app.config["MAIL_PASSWORD"] = "re_key"
        assert is_email_configured() is True
