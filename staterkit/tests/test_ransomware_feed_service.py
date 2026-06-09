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
