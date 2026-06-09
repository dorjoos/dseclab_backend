"""Pytest fixtures for dseclab tests.

Uses an in-memory SQLite DB and a monkey-patched es_service so tests
don't depend on Elasticsearch being available locally.

CRITICAL: We MUST set DATABASE_URL *before* importing cuba. The
DevelopmentConfig reads DATABASE_URL at class-load time and Flask-SQLAlchemy
binds the engine during create_app(). If we override the URI only after
create_app(), drop_all() in the test teardown will destroy the real dev DB.
"""
import os

# Force tests to use a throwaway file-backed SQLite DB so the engine is
# decisively NOT bound to instance/cuba.db. A shared in-memory URI ("?cache=shared")
# is fragile across Flask-SQLAlchemy sessions, so use a tempfile-backed DB.
import tempfile as _tempfile
_TEST_DB_FD, _TEST_DB_PATH = _tempfile.mkstemp(prefix="dseclab_test_", suffix=".db")
os.close(_TEST_DB_FD)
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB_PATH}"
os.environ.setdefault("FLASK_CONFIG", "development")

import atexit
atexit.register(lambda p=_TEST_DB_PATH: os.path.exists(p) and os.unlink(p))

import pytest

from cuba import create_app, db as _db
from cuba.models import Company, User
from cuba.services.breached_creds_service import BreachedCredDoc


@pytest.fixture()
def app():
    app = create_app()
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=True,
        SERVER_NAME="localhost.localdomain",
        SECRET_KEY="test-secret",
    )
    # Belt-and-braces guard: refuse to run if the engine is somehow bound
    # to the dev DB. Should never trip given the DATABASE_URL override at
    # module import — but if it does, we want a loud failure, not silent
    # data loss.
    uri = str(app.config.get("SQLALCHEMY_DATABASE_URI", ""))
    assert "instance/cuba.db" not in uri and "/instance/" not in uri, (
        f"Test DB URI must not point at the dev DB. Got: {uri}"
    )
    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def db(app):
    return _db


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def company_acme(db):
    c = Company(name="Acme Co", domain="acme.com", company_type="customer")
    db.session.add(c)
    db.session.commit()
    return c


@pytest.fixture()
def company_other(db):
    c = Company(name="Other Co", domain="other.com", company_type="customer")
    db.session.add(c)
    db.session.commit()
    return c


def _make_user(db, *, email, role, company=None, password="Test@123"):
    u = User(username=email.split("@")[0], email=email, role=role,
             company_id=company.id if company else None, is_active=True)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture()
def member_acme(db, company_acme):
    return _make_user(db, email="alice@acme.com", role="member", company=company_acme)


@pytest.fixture()
def member_other(db, company_other):
    return _make_user(db, email="bob@other.com", role="member", company=company_other)


@pytest.fixture()
def company_ibank(db):
    """Customer whose domain is a substring of another customer's domain.

    Used to test that domain matching is suffix-aware, not substring-based:
    ibank.mn must NOT match nibank.mn.
    """
    c = Company(name="iBank", domain="ibank.mn", company_type="bank")
    db.session.add(c)
    db.session.commit()
    return c


@pytest.fixture()
def member_ibank(db, company_ibank):
    return _make_user(db, email="carol@ibank.mn", role="member", company=company_ibank)


@pytest.fixture()
def analyst_user(db, company_acme):
    return _make_user(db, email="ana@acme.com", role="analyst", company=company_acme)


@pytest.fixture()
def admin_user(db):
    return _make_user(db, email="admin@dseclab.com", role="admin", company=None)


def login(client, email, password="Test@123"):
    """Helper: GET /login to grab CSRF, then POST credentials."""
    resp = client.get("/login")
    import re
    m = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', resp.data)
    assert m, "CSRF token not found on /login page"
    token = m.group(1).decode()
    return client.post("/login", data={
        "csrf_token": token,
        "email": email,
        "password": password,
    }, follow_redirects=False)


@pytest.fixture()
def fake_cred(monkeypatch):
    """Install a fake es_service.get_by_id and return a setter the test can call.

    Usage:
        fake_cred({"acme-1": {"username": "user@acme.com", "domain": "acme.com",
                              "password": "P@ssw0rd!"}})
    """
    from cuba.services import breached_creds_service as es_mod
    from cuba import threat_intel as ti_mod

    store = {}

    def setter(mapping):
        store.update(mapping)

    def fake_get_by_id(doc_id):
        src = store.get(doc_id)
        if src is None:
            return None
        return BreachedCredDoc(doc_id, src)

    monkeypatch.setattr(ti_mod.es_service, "get_by_id", fake_get_by_id)
    monkeypatch.setattr(es_mod.es_service, "get_by_id", fake_get_by_id)
    return setter


@pytest.fixture()
def fake_kev(monkeypatch):
    """Mirror of fake_cred but for cisa_kev_service.

    Usage:
        fake_kev({"CVE-2024-1": {"cveID": "CVE-2024-1", "vendorProject": "Microsoft",
                                  "product": "Windows", "vulnerabilityName": "RCE",
                                  "shortDescription": "blah", "knownRansomwareCampaignUse": "Known"}})
    """
    from cuba.services import cisa_kev_service as svc_mod
    from cuba.services.cisa_kev_service import CisaKevDoc, cisa_kev_service
    from cuba.services.breached_creds_service import ESPagination

    store = {}

    def setter(mapping):
        store.update(mapping)

    def fake_get_by_id(doc_id):
        src = store.get(doc_id)
        if src is None:
            return None
        return CisaKevDoc(doc_id, src)

    def fake_search(query_text=None, filters=None, page=1, per_page=20):
        items = [CisaKevDoc(k, v) for k, v in store.items()]
        if filters:
            if filters.get('vendor'):
                v = filters['vendor'].lower()
                items = [i for i in items if (i.vendor or '').lower() == v]
            if filters.get('product'):
                p = filters['product'].lower()
                items = [i for i in items if (i.product or '').lower() == p]
            if filters.get('ransomware_use'):
                ru = filters['ransomware_use']
                items = [i for i in items if (i.known_ransomware_use or '') == ru]
        if query_text:
            q = query_text.lower()
            items = [
                i for i in items
                if q in (i.cve_id or '').lower()
                or q in (i.vulnerability_name or '').lower()
                or q in (i.short_description or '').lower()
            ]
        total = len(items)
        start = (page - 1) * per_page
        end = start + per_page
        return ESPagination(items=items[start:end], page=page, per_page=per_page, total=total)

    monkeypatch.setattr(svc_mod.cisa_kev_service, 'get_by_id', fake_get_by_id)
    monkeypatch.setattr(svc_mod.cisa_kev_service, 'search', fake_search)
    monkeypatch.setattr(cisa_kev_service, 'get_by_id', fake_get_by_id)
    monkeypatch.setattr(cisa_kev_service, 'search', fake_search)
    return setter
