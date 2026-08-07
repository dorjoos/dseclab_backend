"""Read-scope authorization: a user with no company sees nothing.

Regression cover for the email-domain fallback, which granted a company-less
user scope over their own mail provider's domain — so anyone on a free-mail
address could read every credential with a matching username, including other
clients' customers.
"""
import pytest
from flask_login import login_user

from cuba.models import User
from cuba.security import get_user_company_domain, get_user_watchlist_domains
from cuba.services.breached_creds_service import breached_creds_service as es


@pytest.fixture()
def freemail_member(db):
    user = User(username="freemail", email="someone@gmail.com", role="member",
                company_id=None, is_active=True)
    user.set_password("Test@123")
    db.session.add(user)
    db.session.commit()
    return user


def _scope_for(app, user):
    with app.test_request_context():
        login_user(user)
        return get_user_company_domain(), get_user_watchlist_domains()


def test_company_less_user_has_no_scope(app, freemail_member):
    domain, watchlist = _scope_for(app, freemail_member)
    assert domain is None
    assert watchlist == []


def test_scope_is_not_taken_from_the_email_domain(app, freemail_member):
    """The whole point: gmail.com must never become an access scope."""
    _, watchlist = _scope_for(app, freemail_member)
    assert "gmail.com" not in watchlist


def test_member_with_company_keeps_its_domains(app, member_acme):
    domain, watchlist = _scope_for(app, member_acme)
    assert domain == "acme.com"
    assert "acme.com" in watchlist


def test_admin_is_unrestricted(app, admin_user):
    domain, watchlist = _scope_for(app, admin_user)
    assert domain is None
    assert watchlist == []  # None domain_filters is what grants admins access


def test_empty_scope_matches_nothing_not_everything():
    """[] must not collapse into an absent filter — that would invert it."""
    query = es._build_query(domain_filters=[])
    assert query != {"match_all": {}}
    clauses = query["bool"]["filter"]
    assert {"bool": {"must_not": {"match_all": {}}}} in clauses


def test_none_scope_is_unrestricted():
    assert es._build_query(domain_filters=None) == {"match_all": {}}


def test_populated_scope_still_filters():
    query = es._build_query(domain_filters=["acme.com"])
    clauses = query["bool"]["filter"]
    assert {"bool": {"must_not": {"match_all": {}}}} not in clauses
    assert clauses  # a real domain clause was added


def test_route_helper_gives_admins_none_and_others_a_list(app, admin_user, member_acme,
                                                          freemail_member):
    from cuba.threat_intel import _get_domain_filters

    with app.test_request_context():
        login_user(admin_user)
        assert _get_domain_filters() is None          # unrestricted
    with app.test_request_context():
        login_user(member_acme)
        assert "acme.com" in _get_domain_filters()    # scoped
    with app.test_request_context():
        login_user(freemail_member)
        assert _get_domain_filters() == []            # denied, not unrestricted
