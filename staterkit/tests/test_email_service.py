"""Tests for email_service breach-email builder and config helper."""
from types import SimpleNamespace

from cuba.services.email_service import build_breach_email, is_email_configured


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


def test_subject_includes_count_and_company():
    subject, _ = build_breach_email("Acme Co", [_cred(), _cred()])
    assert "2" in subject and "Acme Co" in subject


def test_body_includes_matched_domain_and_file_name():
    cred = _cred(username="alice@acme.com", domain="acme.com",
                 matched_domain="acme.com", file_name="stealer_log_2026.txt")
    _, body = build_breach_email("Acme Co", [cred])
    assert "acme.com" in body
    assert "stealer_log_2026.txt" in body
    assert "Matched domain" in body
    assert "File name" in body


def test_body_includes_view_link_when_base_url_given():
    cred = _cred(es_id="XYZ")
    _, body = build_breach_email("Acme Co", [cred], base_url="https://app.example/")
    assert "https://app.example/threat-intelligence/breached-creds/XYZ" in body


def test_body_escapes_html():
    cred = _cred(username="<script>alert(1)</script>")
    _, body = build_breach_email("Acme", [cred])
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_is_email_configured(app):
    with app.app_context():
        app.config["MAIL_USERNAME"] = ""
        app.config["MAIL_PASSWORD"] = ""
        assert is_email_configured() is False
        app.config["MAIL_USERNAME"] = "resend"
        app.config["MAIL_PASSWORD"] = "re_key"
        assert is_email_configured() is True
