"""Paging past ES's result window must not look like an outage.

ES rejects from+size beyond index.max_result_window (10,000). That rejection
used to be caught by search()'s except block and returned as error=True, which
the list page renders as "Search backend (Elasticsearch) is unavailable" — a
lie when ES is perfectly healthy and the user simply paged too deep.
"""
from cuba.services.breached_creds_service import (
    BreachedCredsService, ESPagination, breached_creds_service as svc,
)

WINDOW = BreachedCredsService.MAX_RESULT_WINDOW


def _capture(monkeypatch, total=900_000):
    """Record the body search() sends to ES, and answer with `total` hits."""
    seen = {}

    class _ES:
        @staticmethod
        def search(index, body):
            seen.update(body)
            return {'hits': {'total': {'value': total}, 'hits': []}}

    monkeypatch.setattr(svc, '_es', _ES(), raising=False)
    monkeypatch.setattr(type(svc), 'es', property(lambda self: _ES()))
    return seen


def test_page_within_the_window_is_sent_through_untouched(app, monkeypatch):
    seen = _capture(monkeypatch)
    with app.app_context():
        result = svc.search(page=3, per_page=20)
    assert seen['from'] == 40
    assert result.page == 3
    assert result.error is False


def test_page_past_the_window_is_clamped_not_rejected(app, monkeypatch):
    """The whole point: no exception, no error flag, no fake outage."""
    seen = _capture(monkeypatch)
    with app.app_context():
        result = svc.search(page=9999, per_page=20)
    last_reachable = WINDOW // 20
    assert result.page == last_reachable
    assert seen['from'] == (last_reachable - 1) * 20
    assert seen['from'] + seen['size'] <= WINDOW
    assert result.error is False


def test_pagination_does_not_offer_unreachable_pages(app, monkeypatch):
    """900k hits is 45,000 nominal pages, but only 500 can be served."""
    _capture(monkeypatch, total=900_000)
    with app.app_context():
        result = svc.search(page=1, per_page=20)
    assert result.total == 900_000
    assert result.pages == WINDOW // 20
    assert result.truncated is True


def test_small_result_sets_are_not_marked_truncated(app, monkeypatch):
    _capture(monkeypatch, total=45)
    with app.app_context():
        result = svc.search(page=1, per_page=20)
    assert result.pages == 3
    assert result.truncated is False


def test_pagination_without_a_cap_keeps_its_old_behaviour():
    """Callers that don't pass max_pages must be unaffected."""
    p = ESPagination([], page=1, per_page=20, total=900_000)
    assert p.pages == 45_000
    assert p.truncated is False
