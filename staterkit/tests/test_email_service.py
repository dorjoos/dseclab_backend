"""Tests for email_service breach-email builder, hardening, and config helper."""
from datetime import date
from types import SimpleNamespace

import pytest

from cuba.services import email_service
from cuba.services.email_service import (
    MN,
    build_breach_email,
    classify_creds,
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
    kw.setdefault("match_path", None)
    kw.setdefault("source", None)
    kw.setdefault("type", None)
    return SimpleNamespace(**kw)


# --- builder ---

def test_subject_is_english_and_carries_count_and_company():
    subject, _, _ = build_breach_email("Acme Co", [_cred(), _cred()])
    assert "2" in subject and "Acme Co" in subject
    assert "breached credential" in subject


def test_body_is_mongolian():
    _, body, _ = build_breach_email("Acme Co", [_cred(username="a@acme.mn")])
    assert MN["stripe"] in body
    assert MN["actions"] in body
    assert MN["recent"] in body
    for step in MN["steps"]:
        assert step in body


def test_body_includes_view_link_when_base_url_given():
    cred = _cred(es_id="XYZ")
    _, body, _ = build_breach_email("Acme Co", [cred], base_url="https://app.example/")
    assert "https://app.example/threat-intelligence/breached-creds/XYZ" in body


def test_body_escapes_html():
    cred = _cred(username="<script>alert(1)</script>")
    _, body, _ = build_breach_email("Acme", [cred])
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_one_row_per_credential():
    creds = [_cred(username=f"user{i}@acme.mn") for i in range(5)]
    _, body, _ = build_breach_email("Acme Co", creds)
    for i in range(5):
        assert f"user{i}@acme.mn" in body


def test_report_date_is_rendered():
    _, body, _ = build_breach_email("Acme Co", [_cred()], report_date=date(2026, 6, 1))
    assert "2026-06-01" in body


def test_company_domain_shown_when_given():
    _, body, _ = build_breach_email("Statebank", [_cred()], company_domain="statebank.mn")
    assert "statebank.mn" in body


# --- classification / tiles ---

def test_classify_splits_staff_customer_and_third_party():
    staff = _cred(username="j@acme.mn", matched_domain="acme.mn", match_path="username")
    customer = _cred(username="x@gmail.com", matched_domain="acme.mn", match_path="site")
    vendor = _cred(username="v@supplier.mn", matched_domain="supplier.mn",
                   match_path="username")
    buckets = classify_creds([staff, customer, vendor],
                             third_party_domains=["supplier.mn"])
    assert buckets["staff"] == [staff]
    assert buckets["customer"] == [customer]
    assert buckets["third_party"] == [vendor]


def test_third_party_domain_wins_over_username_match():
    """A supplier's own staff still count as third party to us."""
    vendor = _cred(username="v@supplier.mn", matched_domain="supplier.mn",
                   match_path="username")
    buckets = classify_creds([vendor], third_party_domains=["supplier.mn"])
    assert buckets["staff"] == []
    assert buckets["third_party"] == [vendor]


def test_unlabelled_credentials_count_as_customer():
    """match_path is absent on older call paths; don't inflate the staff tile."""
    buckets = classify_creds([_cred(username="x@gmail.com")])
    assert buckets["customer"]
    assert buckets["staff"] == []


def test_tile_counts_appear_in_body():
    creds = [
        _cred(username="j@acme.mn", matched_domain="acme.mn", match_path="username"),
        _cred(username="a@gmail.com", matched_domain="acme.mn", match_path="site"),
        _cred(username="b@gmail.com", matched_domain="acme.mn", match_path="site"),
    ]
    _, body, text = build_breach_email("Acme Co", creds)
    assert MN["tile_staff"][0] in body
    assert MN["tile_third_party"][0] in body
    assert f"{MN['tile_customer'][0]}: 2" in text
    assert f"{MN['tile_staff'][0]}: 1" in text


# --- provenance chip ---

def test_source_renders_as_a_chip():
    """Live docs carry a compound source and a separate technical type; the
    chip is the source, not the two concatenated."""
    cred = _cred(username="a@acme.mn", source="Telegram/Stealerlog", type="url")
    _, body, _ = build_breach_email("Acme Co", [cred])
    assert "Telegram/Stealerlog" in body
    assert "Telegram/Stealerlog/url" not in body


def test_chip_falls_back_to_type_without_a_source():
    cred = _cred(username="a@acme.mn", source=None, type="combolist")
    _, body, _ = build_breach_email("Acme Co", [cred])
    assert "combolist" in body


# --- text/plain alternative ---

def test_text_part_carries_the_same_data():
    cred = _cred(username="alice@acme.mn", source="Telegram/Stealerlog", type="url")
    _, _, text = build_breach_email("Acme Co", [cred], base_url="https://app.example")
    assert "<" not in text  # no markup leaked into the plain part
    assert "alice@acme.mn" in text
    assert "Telegram/Stealerlog" in text
    assert "https://app.example/threat-intelligence/breached-creds/abc123" in text
    for step in MN["steps"]:
        assert step in text


# --- autolink defense ---

def test_values_are_wrapped_in_our_own_anchors():
    """Gmail autolinks bare addresses and paints them blue; text already inside
    an <a> is left alone."""
    cred = _cred(username="alice@acme.mn")
    _, body, _ = build_breach_email("Acme Co", [cred])
    assert ">alice@acme.mn</a>" in body


# --- defense in depth ---

def test_password_never_reaches_the_message():
    """The renderers read a fixed set of attributes, so a doc carrying a
    password cannot leak it."""
    cred = _cred(username="alice@acme.mn", matched_domain="acme.mn")
    cred.password = "SuperSecret123!"
    _, body, text = build_breach_email("Acme Co", [cred], base_url="https://app.example")
    assert "SuperSecret123!" not in body
    assert "SuperSecret123!" not in text


def test_file_name_is_not_surfaced():
    cred = _cred(username="alice@acme.mn")
    cred.file_name = "stealer_log_2026.txt"
    _, body, text = build_breach_email("Acme Co", [cred])
    assert "stealer_log_2026.txt" not in body
    assert "stealer_log_2026.txt" not in text


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
    _, body, _ = build_breach_email("Acme Co", [_cred(username="a@acme.mn")],
                                    company_domain="acme.mn")
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
