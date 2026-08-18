"""Unit tests for ransomware_feed_service.

In particular: source_url scheme validation — any non-http(s) URL coming out
of the feed is stripped to '' so it never reaches a template href.
"""
import pytest

from cuba.services.ransomware_feed_service import _safe_http_url


@pytest.mark.parametrize("raw,expected", [
    ("https://ransomfeed.it/post/1", "https://ransomfeed.it/post/1"),
    ("http://example.com", "http://example.com"),
    ("HTTPS://EXAMPLE.COM/", "HTTPS://EXAMPLE.COM/"),
    ("  https://example.com  ", "https://example.com"),
    # All non-http(s) schemes must be stripped — these are the XSS vectors
    # we're defending against.
    ("javascript:alert(1)", ""),
    ("JaVaScRiPt:alert(1)", ""),
    ("data:text/html,<script>alert(1)</script>", ""),
    ("file:///etc/passwd", ""),
    ("vbscript:msgbox(1)", ""),
    ("//evil.example.com/x", ""),
    ("ftp://anon@evil/", ""),
    ("relative/path", ""),
    ("", ""),
    (None, ""),
])
def test_safe_http_url_only_passes_http_and_https(raw, expected):
    assert _safe_http_url(raw) == expected


# --- get_recent: the filters it echoes back drive the pagination links ---

def _stub_hits(monkeypatch, groups, total):
    """Make _search return one hit per name in `groups`."""
    from cuba.services.ransomware_feed_service import ransomware_feed_service

    def fake_search(body):
        return {'hits': {
            'total': {'value': total},
            'hits': [{'_id': f'r{i}', '_source': {'ransomware_group': g}}
                     for i, g in enumerate(groups)],
        }}

    monkeypatch.setattr(ransomware_feed_service, '_search', fake_search)
    return ransomware_feed_service


def test_unfiltered_recent_echoes_an_empty_group_filter(monkeypatch):
    """Regression: the result loop reassigned the `group` parameter, so an
    unfiltered page reported the last row's group as the active filter. The
    template pastes that into every page link as &rg=..., which silently
    filtered the list and changed the page count on the next click."""
    svc = _stub_hits(monkeypatch, ['lockbit', 'clop', 'akira'], total=45)
    result = svc.get_recent(page=1, per_page=10)
    assert result['filters']['group'] == ''
    assert result['filters']['country'] == ''
    assert result['filters']['q'] == ''
    # The rows still carry their own groups.
    assert [r['group'] for r in result['items']] == ['lockbit', 'clop', 'akira']


def test_recent_echoes_the_group_filter_it_was_given(monkeypatch):
    svc = _stub_hits(monkeypatch, ['lockbit', 'lockbit'], total=2)
    result = svc.get_recent(page=1, per_page=10, group='lockbit')
    assert result['filters']['group'] == 'lockbit'


def test_recent_page_math(monkeypatch):
    svc = _stub_hits(monkeypatch, ['lockbit'], total=45)
    first = svc.get_recent(page=1, per_page=10)
    assert (first['pages'], first['has_prev'], first['has_next']) == (5, False, True)
    last = svc.get_recent(page=5, per_page=10)
    assert (last['pages'], last['has_prev'], last['has_next']) == (5, True, False)


# --- the rendered page: links must survive the filters they carry ---

def test_page_links_do_not_smuggle_a_group_filter(client, admin_user, monkeypatch):
    """The whole point of the shadowing fix: an unfiltered list must produce
    bare ?rp=N links, not ones that pin the next page to a group."""
    from tests.conftest import login
    _stub_hits(monkeypatch, ['lockbit', 'clop'], total=45)
    login(client, admin_user.email)
    body = client.get('/threat-intelligence/ransomware').data.decode()
    assert '?rp=2#recent-attacks' in body
    assert 'rg=lockbit' not in body and 'rg=clop' not in body


def test_dashboard_survives_all_zero_sector_counts(client, admin_user, monkeypatch):
    """The degraded-ES fallback is {'Unknown': 0}, which used to divide the
    bar-width expression by zero and 500 the whole page."""
    from cuba.services.ransomware_feed_service import ransomware_feed_service
    from tests.conftest import login
    _stub_hits(monkeypatch, ['lockbit'], total=45)
    monkeypatch.setattr(ransomware_feed_service, 'get_dashboard_stats',
                        lambda: {'total_attacks': 0, 'active_groups': 0,
                                 'countries_affected': 0, 'data_leaked_tb': 0,
                                 'active_this_week': 0, 'attacks_this_month': 0,
                                 'sectors': {'Unknown': 0},
                                 'monthly_trend': [0] * 12,
                                 'monthly_labels': [''] * 12})
    login(client, admin_user.email)
    resp = client.get('/threat-intelligence/ransomware')
    assert resp.status_code == 200


def test_page_links_urlencode_the_search_text(client, admin_user, monkeypatch):
    """A '#' in the query would otherwise cut the link short at the fragment."""
    from tests.conftest import login
    _stub_hits(monkeypatch, ['lockbit'], total=45)
    login(client, admin_user.email)
    body = client.get('/threat-intelligence/ransomware?rq=ACME %231').data.decode()
    assert 'rq=ACME%20%231' in body or 'rq=ACME+%231' in body
    assert 'rq=ACME #1' not in body
