"""Tests for BreachedCredsService.compute_matched_domain (suffix-aware)."""
from cuba.services.breached_creds_service import BreachedCredDoc, breached_creds_service as svc


def _doc(**source):
    return BreachedCredDoc("id1", source)


DOMAINS = ["acme.com", "ibank.mn"]


def test_matches_exact_domain_field():
    assert svc.compute_matched_domain(_doc(domain="acme.com"), DOMAINS) == "acme.com"


def test_matches_subdomain_in_domain_field():
    assert svc.compute_matched_domain(_doc(domain="mail.acme.com"), DOMAINS) == "acme.com"


def test_matches_email_username_host():
    assert svc.compute_matched_domain(_doc(username="alice@acme.com"), DOMAINS) == "acme.com"


def test_matches_email_subdomain_host():
    assert svc.compute_matched_domain(_doc(username="bob@corp.acme.com"), DOMAINS) == "acme.com"


def test_matches_url_host():
    assert svc.compute_matched_domain(_doc(url="https://portal.ibank.mn/login"), DOMAINS) == "ibank.mn"


def test_matches_url_without_scheme():
    assert svc.compute_matched_domain(_doc(url="ibank.mn/login"), DOMAINS) == "ibank.mn"


def test_substring_collision_does_not_match():
    # ibank.mn must NOT match nibank.mn
    assert svc.compute_matched_domain(_doc(domain="nibank.mn"), DOMAINS) is None
    assert svc.compute_matched_domain(_doc(username="x@nibank.mn"), DOMAINS) is None


def test_no_match_returns_none():
    assert svc.compute_matched_domain(_doc(domain="example.org"), DOMAINS) is None


def test_empty_domains_returns_none():
    assert svc.compute_matched_domain(_doc(domain="acme.com"), []) is None


def test_attach_matched_domain_sets_attribute():
    items = [_doc(domain="acme.com"), _doc(domain="example.org")]
    svc.attach_matched_domain(items, DOMAINS)
    assert items[0].matched_domain == "acme.com"
    assert items[1].matched_domain is None


def test_domain_filter_treats_domain_and_matched_domain_alike():
    """Filtering by a domain must match the domain field, email-username host,
    and URL host (matched_domain semantics), not just domain.keyword."""
    import json
    q = svc._build_query(filters={"domain": "acme.com"})
    blob = json.dumps(q)
    assert "domain.keyword" in blob
    assert "username.keyword" in blob
    assert '"url"' in blob


def test_domain_filter_strips_leading_at():
    """'@khanbank.mn' must behave identically to 'khanbank.mn'."""
    assert svc._build_query(filters={"domain": "@acme.com"}) == \
           svc._build_query(filters={"domain": "acme.com"})
