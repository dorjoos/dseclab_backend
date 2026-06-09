"""Pytest fixtures for dseclab tests.

Uses an in-memory SQLite DB and a monkey-patched es_service so tests
don't depend on Elasticsearch being available locally.
"""
import os
import pytest

os.environ.setdefault("FLASK_CONFIG", "development")

from cuba import create_app, db as _db
from cuba.models import Company, User
from cuba.services.elasticsearch_service import BreachedCredDoc


@pytest.fixture()
def app():
    app = create_app()
    app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        WTF_CSRF_ENABLED=True,
        SERVER_NAME="localhost.localdomain",
        SECRET_KEY="test-secret",
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
    from cuba.services import elasticsearch_service as es_mod
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
