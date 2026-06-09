# Vulnerabilities Page UI/UX Refresh — Design

**Date:** 2026-06-10
**Status:** Draft (awaiting user review)
**Owner:** dorjsambuu
**Builds on:** `2026-06-10-cisa-kev-vulnerabilities-page-design.md`

## Problem

The Vulnerabilities page shipped in commits `7a2c411..d59f068` works correctly — 14 tests pass, AJAX returns real data from the 1,607-doc `cisa-kev` ES index — but the page is **table-only and visually plain**. Two specific symptoms the user reported:

1. "Default no data" — on first paint the page shows the empty-state placeholder briefly until the AJAX call resolves, and shows nothing useful at all if the AJAX call silently fails (network blip, CSRF mismatch, ES outage). For a list-table-only page, "no rows in the table" reads as "the page is broken."
2. The visual style is bare Bootstrap/Cuba table classes — inconsistent with the polished Ransomware page that's already in the app.

## Goal

Modernize the Vulnerabilities page to match the Ransomware page's dashboard pattern:

- **Hero header** with title, subtitle, and a "Known KEV" count badge — server-side rendered so the page always has something to look at.
- **Stat row** (4 metrics: Total, Ransomware-tagged, Due ≤ 7d, Overdue) — server-side rendered from aggregate ES queries.
- **Two visual cards** (Top Vendors with horizontal bars, Ransomware Use breakdown) — server-side rendered.
- **Search + filter toolbar** unchanged in capability, restyled.
- **Table** retains the AJAX behavior and role-aware field projection from the original spec; rows gain visual chips for ransomware ("★ KEV") and a date-aware due-date pill (red overdue, amber ≤ 7d).

Server-rendering the dashboard above the table means "default no data" stops being a failure mode — when the table AJAX hasn't loaded yet (or has failed), the user still sees aggregate context.

## Non-goals (YAGNI)

- No Chart.js / D3 / sparklines — horizontal bar widths via inline CSS suffice.
- No real-time / WebSocket updates of stats.
- No vendor-detail drill-down ("show me all Microsoft CVEs as a page") beyond the existing vendor filter.
- No "compare CVE A vs CVE B" feature.
- No saved searches, preset filters, dark-mode-specific tweaks, or per-CVE mark/notes (still in non-goals from the original spec).
- No new dependencies.

## Architecture

The shape of the page changes; the server/route contract changes minimally; the field-projection / role-gate logic is unchanged.

### Backend — `cuba/services/cisa_kev_service.py`

`get_stats()` returns a richer dict:

```python
{
    'total': int,                         # existed
    'by_vendor': list[tuple[str, int]],   # existed (top 10)
    'by_ransomware': dict[str, int],      # existed
    'due_soon': int,                      # NEW — today (00:00 UTC) <= dueDate < today + 7d
    'overdue': int,                       # NEW — dueDate < today (00:00 UTC)
}
```

Two extra `_count` calls with `range` queries on `dueDate`. Both tolerate camelCase + snake_case via `bool/should` (matches the existing `_build_query` pattern). If `_count` raises, both default to `0` so the hero degrades gracefully.

### Route — `cuba/vulnerabilities.py`

`list_page()` is the only changed route. It now also fetches stats:

```python
@vulnerabilities.route('/threat-intelligence/vulnerabilities')
@login_required
def list_page():
    try:
        stats = cisa_kev_service.get_stats()
    except Exception:
        logger.exception('vulnerabilities list_page: get_stats failed')
        stats = {'total': 0, 'by_vendor': [], 'by_ransomware': {},
                 'due_soon': 0, 'overdue': 0}
    breadcrumb = {'parent': 'Threat Intelligence', 'child': 'Vulnerabilities'}
    return render_template(
        'threat_intel/vulnerabilities_list.html',
        breadcrumb=breadcrumb,
        full_access=_is_full_access(),
        stats=stats,
    )
```

`/api/vulnerabilities/search`, `detail_page`, and `export_csv` are unchanged.

### Template — `cuba/templates/threat_intel/vulnerabilities_list.html`

Full rewrite. Loads new CSS:

```html
{% block css %}
<link rel="stylesheet" href="{{ url_for('static', filename='assets/css/pages/vulnerabilities.css') }}">
{% endblock %}
```

Layout (top to bottom):
1. **Hero** — title, subtitle, KEV-count badge (`stats['by_ransomware'].get('Known', 0)`).
2. **Stats row** — 4 cells (Total / Ransomware / Due ≤ 7d / Overdue). Pulled from `stats`.
3. **Two cards row** — Top Vendors (horizontal bars from `stats['by_vendor'][:5]`), Ransomware Use (two horizontal bars: Known vs Unknown).
4. **Toolbar** — search input, vendor select, ransomware select, Export CSV button (admin/analyst only).
5. **Table** — same columns as today + "Status" chip column (Overdue/Due-Soon/OK), "Tag" column (★ KEV when known ransomware).
6. **Pagination** — same.

The AJAX search JS is updated to:
- Render an `★ KEV` chip when `row.known_ransomware_use == 'Known'`.
- Render a date-aware "Status" chip with `vn-status--overdue`/`vn-status--soon`/`vn-status--ok` based on `due_date` vs today.
- Continue to render CVE ID as `<a>` only for full-access roles.

### CSS — `cuba/static/assets/css/pages/vulnerabilities.css` (new)

Names use the `vn-` prefix to avoid collision with `rw-` (ransomware) and `av-` (analysis view). Tokens borrowed from `ransomware.css` for consistency. About ~150 lines, all selectors page-scoped via `.vn-page`.

Key class skeleton:
```
.vn-page
  .vn-hero
    .vn-hero-title-row    .vn-hero-icon  .vn-hero-title
    .vn-hero-subtitle
    .vn-hero-badge
  .vn-stats-row
    .vn-stat  .vn-stat-val  .vn-stat-label
    .vn-stat-divider
  .vn-row (flex row of two)
    .vn-card
      .vn-card-title
      .vn-bar-row  .vn-bar-label  .vn-bar  .vn-bar-fill  .vn-bar-count
  .vn-toolbar
    .vn-search  .vn-filter  .vn-btn  .vn-btn-filled
  .vn-table
    .vn-status--overdue (red bg, white text)
    .vn-status--soon (amber bg)
    .vn-status--ok (neutral)
    .vn-tag-kev (red outline, ★ icon)
```

No new fonts, icons reuse the existing `feather-icon` set.

## Data flow

```
GET /threat-intelligence/vulnerabilities
  ├─ cisa_kev_service.get_stats()  → {total, by_vendor, by_ransomware, due_soon, overdue}
  ├─ render hero/stats/cards SSR
  └─ return shell HTML

  (browser parses, JS auto-fires)
  POST /api/vulnerabilities/search {page:1, per_page:20}
    → cisa_kev_service.search(...)
    → role-aware field projection
    → rows JSON
  (table populates; chips computed client-side from row.due_date / row.known_ransomware_use)
```

If the `get_stats` call raises (ES down), the route renders zeros — the page is still useful as a navigation shell and the table AJAX still tries. If the AJAX call fails, the user still has hero + stats + cards visible.

## Error handling

| Condition | Behavior |
|---|---|
| `get_stats()` raises | Caught, logged, stats default to zero/empty; page renders with "0 Total" etc. |
| AJAX 401/403/404/429/5xx | Toolbar shows inline error text; hero+stats+cards remain visible |
| Date parsing fails on `due_date` | "Status" chip falls back to neutral / blank |
| Member tries to click a CVE row | Not clickable (no `<a>`) — no request fires |

## Member view rules (unchanged behavior, restated for clarity)

| Element | Member | Analyst/Admin |
|---|---|---|
| Hero, stats row, vendor + ransomware cards | yes | yes |
| Search + filters | yes | yes |
| Export CSV button | hidden | visible |
| Table rows | reduced fields (no description/notes/cwes), non-clickable | full fields, clickable |
| Status + KEV chips on rows | yes | yes |

The aggregate stats (total counts by vendor and ransomware-use) are not per-record sensitive — they're already exposed via the CISA public catalog. Hiding them from members would be ceremony without security benefit.

## Tests

Existing 14 tests in `tests/test_vulnerabilities.py` stay green (role gating, field projection, audit logging — none change).

Add **3 new tests**:

1. **`test_list_page_renders_ssr_stats`** — admin GET `/threat-intelligence/vulnerabilities`, response body contains the literal "Total" label AND a non-empty digit run nearby (regression for the "default no data" symptom).
2. **`test_member_sees_aggregate_stats_no_export`** — member GET same path, body contains "Total" and "Vulnerabilities" but does NOT contain `Export CSV` anywhere (member's restriction is preserved in the new layout).
3. **`test_get_stats_includes_due_counts`** — monkeypatch the underlying `_search` to return canned aggregate + count results; assert `cisa_kev_service.get_stats()` returns a dict with both `due_soon` and `overdue` keys present.

Test 3 needs a small extension to the `fake_kev` fixture or a separate monkeypatch helper — simplest is to override `cisa_kev_service.get_stats` directly in the test.

## Migration / deployment notes

- No DB migration.
- No new Python dependencies.
- New static file (`vulnerabilities.css`) ships with the next deploy; gunicorn doesn't need a config change. After `git pull`, run `sudo systemctl restart dseclab` and the new layout appears.
- The existing systemd unit, env file, and `update.sh` script need no changes.

## Risks

| Risk | Mitigation |
|---|---|
| Two extra `_count` calls per page load increase ES traffic | Negligible — these are aggregations on 1,607 docs; cached at the HTTP layer would be a follow-up. Acceptable for v1. |
| CSS naming collision with future pages | Page-scoped under `.vn-page`; `vn-` prefix unique within the project. |
| Date math edge cases (timezone, missing `due_date`) | All date logic centralised in two helpers: server-side counts use ES `range` clauses; client-side chip falls back to neutral on parse failure. |
| `get_stats` slowness on a cold ES blocks the page render | Acceptable — it's one round-trip on page load and the route still returns even if it errors. If we observe latency, add `@cache.cached(timeout=60)` in a follow-up. |
