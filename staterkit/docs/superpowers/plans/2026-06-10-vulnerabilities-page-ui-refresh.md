# Vulnerabilities Page UI Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restyle the Vulnerabilities page from a table-only view into a Ransomware-style dashboard (hero + stats row + cards + table), with `due_soon` / `overdue` counts on the stats API.

**Architecture:** Add two `range`-based `_count` calls to `CisaKevService.get_stats()` (returns `due_soon`, `overdue`). Route `list_page()` fetches stats and passes them to the template. Template is fully rewritten to match Ransomware's `rw-*` idiom under a new `vn-*` namespace, with a new `vulnerabilities.css` (~250 lines) mirroring `ransomware.css` tokens. Table AJAX behavior, role-aware field projection, and audit logging are untouched.

**Tech Stack:** Flask, Jinja2, vanilla JS `fetch`, elasticsearch-py, CSS3 grid/flex.

**Spec reference:** `docs/superpowers/specs/2026-06-10-vulnerabilities-page-ui-refresh-design.md`

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `cuba/services/cisa_kev_service.py` | Modify | Add `due_soon` + `overdue` keys to `get_stats()` return; helper `_today_iso()` |
| `cuba/vulnerabilities.py` | Modify | `list_page()` fetches stats and passes to template (with try/except fallback) |
| `cuba/templates/threat_intel/vulnerabilities_list.html` | Replace | New dashboard layout with hero, stats, cards, restyled table |
| `cuba/static/assets/css/pages/vulnerabilities.css` | Create | `.vn-*` styling, mirrors `ransomware.css` patterns |
| `tests/test_vulnerabilities.py` | Modify | Add 3 tests (SSR stats render, member-no-export, get_stats returns due fields) |

---

## Task 1: `get_stats()` returns `due_soon` + `overdue`

**Files:**
- Modify: `cuba/services/cisa_kev_service.py`
- Modify: `tests/test_vulnerabilities.py` (failing test first)

- [ ] **Step 1: Write the failing test**

Append to `staterkit/tests/test_vulnerabilities.py`:

```python
def test_get_stats_includes_due_counts(monkeypatch):
    """get_stats() must surface due_soon and overdue integer counts."""
    from cuba.services import cisa_kev_service as svc_mod

    # Stub _search to return aggs + total (used by get_stats existing path).
    def fake_search(body):
        return {
            'hits': {'total': {'value': 1607}, 'hits': []},
            'aggregations': {
                'by_vendor': {'buckets': [{'key': 'Microsoft', 'doc_count': 377}]},
                'by_ransomware': {'buckets': [{'key': 'Known', 'doc_count': 325},
                                              {'key': 'Unknown', 'doc_count': 1282}]},
            },
        }
    # Stub _count to return distinct values for the two extra calls.
    counts = iter([47, 12])  # due_soon, overdue
    def fake_count(query=None):
        return next(counts)

    monkeypatch.setattr(svc_mod.cisa_kev_service, '_search', fake_search)
    monkeypatch.setattr(svc_mod.cisa_kev_service, '_count', fake_count)

    s = svc_mod.cisa_kev_service.get_stats()
    assert s['total'] == 1607
    assert s['by_vendor'][:1] == [('Microsoft', 377)]
    assert s['by_ransomware'] == {'Known': 325, 'Unknown': 1282}
    assert s['due_soon'] == 47
    assert s['overdue'] == 12
```

- [ ] **Step 2: Run the test — confirm it fails**

```bash
source venv/bin/activate && python -m pytest tests/test_vulnerabilities.py::test_get_stats_includes_due_counts -v 2>&1 | tail -10
```

Expected: FAIL with `KeyError: 'due_soon'` or similar.

- [ ] **Step 3: Add the two counts to `get_stats()`**

In `staterkit/cuba/services/cisa_kev_service.py`, find the `get_stats` method. The current body ends with:

```python
        return {
            'total': int(total),
            'by_vendor': [...],
            'by_ransomware': {...},
        }
```

Replace the return block with this, and add the helper `_today_iso` at module scope:

```python
def _today_iso():
    """Return today at 00:00 UTC as ISO8601 — boundary for due_soon/overdue ranges."""
    return datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
```

(Add it just below the existing `_clean` function at the top of the file.)

Then in `get_stats`, after the existing aggregation result and **before** the return, compute the two extra counts. Replace the existing return with:

```python
        today = _today_iso()
        # 7 days from today, exclusive upper bound. Naive UTC datetime math.
        in_7d = (datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                 + timedelta(days=7)).isoformat()

        due_soon = self._count({
            'bool': {
                'should': [
                    {'range': {'dueDate': {'gte': today, 'lt': in_7d}}},
                    {'range': {'due_date': {'gte': today, 'lt': in_7d}}},
                ],
                'minimum_should_match': 1,
            }
        })
        overdue = self._count({
            'bool': {
                'should': [
                    {'range': {'dueDate': {'lt': today}}},
                    {'range': {'due_date': {'lt': today}}},
                ],
                'minimum_should_match': 1,
            }
        })

        return {
            'total': int(total),
            'by_vendor': [
                (b['key'], b['doc_count'])
                for b in aggs.get('by_vendor', {}).get('buckets', [])
            ],
            'by_ransomware': {
                b['key']: b['doc_count']
                for b in aggs.get('by_ransomware', {}).get('buckets', [])
            },
            'due_soon': int(due_soon or 0),
            'overdue': int(overdue or 0),
        }
```

Also confirm the file has `from datetime import datetime, timedelta` at the top — the current file has only `from datetime import datetime`. Update to:

```python
from datetime import datetime, timedelta
```

- [ ] **Step 4: Re-run the test — confirm it passes**

```bash
source venv/bin/activate && python -m pytest tests/test_vulnerabilities.py::test_get_stats_includes_due_counts -v 2>&1 | tail -5
```

Expected: PASS.

- [ ] **Step 5: Run the full test file — confirm no regression**

```bash
source venv/bin/activate && python -m pytest tests/test_vulnerabilities.py -v 2>&1 | tail -5
```

Expected: 15 passed (14 original + 1 new).

- [ ] **Step 6: Commit**

```bash
git -C /Users/jooy/Development/dseclab_backend add staterkit/cuba/services/cisa_kev_service.py staterkit/tests/test_vulnerabilities.py
git -C /Users/jooy/Development/dseclab_backend -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: get_stats() now returns due_soon and overdue counts

Two extra ES _count calls with range queries on dueDate (or its
snake_case alias). Used by the upcoming dashboard hero+stats row
so the page renders useful aggregates even before the table AJAX
resolves.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Route fetches stats and passes them to template

**Files:**
- Modify: `cuba/vulnerabilities.py` (route `list_page`)
- Modify: `tests/test_vulnerabilities.py` (2 new tests)

- [ ] **Step 1: Write the failing SSR-render test**

Append to `staterkit/tests/test_vulnerabilities.py`:

```python
def test_list_page_renders_ssr_stats(client, admin_user, fake_kev, monkeypatch):
    """The list shell must include the SSR stats row text so the page is
    informative even before the table AJAX resolves."""
    fake_kev(SAMPLE)
    # Stub get_stats so we can assert on a known value in the rendered HTML.
    from cuba.services import cisa_kev_service as svc_mod
    monkeypatch.setattr(svc_mod.cisa_kev_service, 'get_stats',
                        lambda: {'total': 1607, 'by_vendor': [('Microsoft', 377)],
                                 'by_ransomware': {'Known': 325, 'Unknown': 1282},
                                 'due_soon': 47, 'overdue': 12})
    login(client, admin_user.email)
    r = client.get(LIST_PATH)
    assert r.status_code == 200
    body = r.data
    # SSR stat labels and at least one of the numeric values must be on the page.
    assert b'Total' in body
    assert b'1607' in body
    assert b'Ransom' in body or b'KEV' in body
    assert b'325' in body  # Known KEV count from the stub


def test_member_sees_aggregate_stats_no_export(client, member_acme, fake_kev, monkeypatch):
    """Member sees stats + table shell. Member must NOT see Export button."""
    fake_kev(SAMPLE)
    from cuba.services import cisa_kev_service as svc_mod
    monkeypatch.setattr(svc_mod.cisa_kev_service, 'get_stats',
                        lambda: {'total': 1607, 'by_vendor': [('Microsoft', 377)],
                                 'by_ransomware': {'Known': 325, 'Unknown': 1282},
                                 'due_soon': 47, 'overdue': 12})
    login(client, member_acme.email)
    r = client.get(LIST_PATH)
    assert r.status_code == 200
    assert b'Total' in r.data
    assert b'1607' in r.data
    # Export button must be hidden for member. The href to the export endpoint
    # is the load-bearing string; "Export" as a word could appear elsewhere.
    assert b'export.csv' not in r.data
```

- [ ] **Step 2: Run both tests — confirm they fail**

```bash
source venv/bin/activate && python -m pytest tests/test_vulnerabilities.py::test_list_page_renders_ssr_stats tests/test_vulnerabilities.py::test_member_sees_aggregate_stats_no_export -v 2>&1 | tail -15
```

Expected: both FAIL (the current template doesn't render any stats).

- [ ] **Step 3: Update `list_page()` to fetch and pass stats**

In `staterkit/cuba/vulnerabilities.py`, replace the existing `list_page` function:

```python
@vulnerabilities.route('/threat-intelligence/vulnerabilities')
@login_required
def list_page():
    breadcrumb = {'parent': 'Threat Intelligence', 'child': 'Vulnerabilities'}
    return render_template('threat_intel/vulnerabilities_list.html',
                          breadcrumb=breadcrumb,
                          full_access=_is_full_access())
```

With:

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
    return render_template('threat_intel/vulnerabilities_list.html',
                          breadcrumb=breadcrumb,
                          full_access=_is_full_access(),
                          stats=stats)
```

(Tests still fail at this point because the template doesn't use `stats` yet — Task 4 covers the template. Don't commit yet.)

- [ ] **Step 4: No verification here**

We won't have green tests for this route change until Task 4 rewrites the template to consume `stats`. Move directly to Task 3 (CSS).

---

## Task 3: New CSS file

**Files:**
- Create: `cuba/static/assets/css/pages/vulnerabilities.css`

- [ ] **Step 1: Create the CSS file**

Create `staterkit/cuba/static/assets/css/pages/vulnerabilities.css`:

```css
/* ==========================================================================
   Vulnerabilities (CISA KEV) — /threat-intelligence/vulnerabilities
   Prefix: vn-
   ========================================================================== */

/* Hero */
.vn-hero {
  background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 50%, #1e40af 100%);
  border-radius: 16px;
  padding: 32px;
  color: #fff;
  margin-bottom: 20px;
  position: relative;
  overflow: hidden;
}
.vn-hero::before {
  content: '';
  position: absolute;
  top: -60px; right: -60px;
  width: 250px; height: 250px; border-radius: 50%;
  background: rgba(250, 204, 21, 0.08);
}
.vn-hero::after {
  content: '';
  position: absolute;
  bottom: -80px; left: 20%;
  width: 300px; height: 300px; border-radius: 50%;
  background: rgba(248, 113, 113, 0.06);
}
.vn-hero-inner { position: relative; z-index: 1; }
.vn-hero-top {
  display: flex; justify-content: space-between; align-items: flex-start;
  flex-wrap: wrap; gap: 16px;
}
.vn-hero-title-row { display: flex; align-items: center; gap: 10px; }
.vn-hero-title { font-size: 26px; font-weight: 800; letter-spacing: -0.03em; }
.vn-hero-subtitle { font-size: 14px; opacity: 0.85; margin-top: 4px; }
.vn-hero-badge {
  display: inline-flex; align-items: center; gap: 8px;
  background: rgba(239, 68, 68, 0.18);
  border: 1px solid rgba(239, 68, 68, 0.5);
  color: #fff; padding: 6px 14px; border-radius: 999px;
  font-size: 13px; font-weight: 600;
}
.vn-hero-badge-dot {
  width: 8px; height: 8px; border-radius: 50%; background: #ef4444;
  box-shadow: 0 0 8px rgba(239, 68, 68, 0.8);
}

/* Stats row */
.vn-stats-row {
  display: flex; flex-wrap: wrap; gap: 0;
  margin-top: 24px; padding-top: 16px;
  border-top: 1px solid rgba(255, 255, 255, 0.1);
}
.vn-stat { flex: 1; min-width: 120px; text-align: center; }
.vn-stat-val { font-size: 28px; font-weight: 800; line-height: 1.1; color: #fff; }
.vn-stat-label {
  font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em;
  opacity: 0.7; margin-top: 4px;
}
.vn-stat-divider {
  width: 1px; background: rgba(255, 255, 255, 0.1); margin: 0 8px;
}

/* Card row */
.vn-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
@media (max-width: 768px) { .vn-row { grid-template-columns: 1fr; } }
.vn-card {
  background: var(--bs-body-bg, #fff);
  border: 1px solid var(--bs-border-color, #e5e7eb);
  border-radius: 12px;
  padding: 20px;
}
.vn-card-title {
  font-size: 13px; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.05em; color: var(--bs-secondary-color, #6b7280);
  margin-bottom: 14px;
}
.vn-bar-row {
  display: grid;
  grid-template-columns: 120px 1fr 50px;
  align-items: center; gap: 10px;
  padding: 6px 0; font-size: 13px;
}
.vn-bar-label {
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  color: var(--bs-body-color, #111827);
}
.vn-bar {
  height: 8px; border-radius: 999px;
  background: var(--bs-tertiary-bg, #f3f4f6); overflow: hidden;
}
.vn-bar-fill {
  height: 100%; border-radius: 999px;
  background: linear-gradient(90deg, #3b82f6, #6366f1);
}
.vn-bar-fill--ransomware { background: linear-gradient(90deg, #ef4444, #f97316); }
.vn-bar-count {
  text-align: right; font-variant-numeric: tabular-nums;
  color: var(--bs-secondary-color, #6b7280);
}

/* Toolbar + table */
.vn-toolbar {
  display: flex; justify-content: space-between; align-items: center;
  gap: 12px; flex-wrap: wrap;
  padding: 12px 16px;
  background: var(--bs-body-bg, #fff);
  border: 1px solid var(--bs-border-color, #e5e7eb);
  border-radius: 12px 12px 0 0; border-bottom: none;
}
.vn-toolbar-left, .vn-toolbar-right {
  display: flex; gap: 10px; align-items: center; flex-wrap: wrap;
}
.vn-count { font-size: 13px; color: var(--bs-secondary-color, #6b7280); }
.vn-search input, .vn-filter {
  height: 36px; padding: 0 12px;
  border: 1px solid var(--bs-border-color, #e5e7eb);
  border-radius: 8px;
  background: var(--bs-body-bg, #fff);
  color: var(--bs-body-color, #111827);
  font-size: 13px;
}
.vn-search input { min-width: 220px; }
.vn-btn {
  display: inline-flex; align-items: center; gap: 6px;
  height: 36px; padding: 0 14px; border-radius: 8px;
  background: var(--bs-body-bg, #fff);
  border: 1px solid var(--bs-border-color, #e5e7eb);
  color: var(--bs-body-color, #111827);
  font-size: 13px; font-weight: 600;
  text-decoration: none; cursor: pointer;
}
.vn-btn:hover { background: var(--bs-tertiary-bg, #f3f4f6); }

.vn-table-wrap {
  background: var(--bs-body-bg, #fff);
  border: 1px solid var(--bs-border-color, #e5e7eb);
  border-radius: 0 0 12px 12px;
  overflow: hidden;
}
.vn-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.vn-table thead th {
  text-align: left; padding: 10px 16px; font-weight: 700;
  font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em;
  color: var(--bs-secondary-color, #6b7280);
  background: var(--bs-tertiary-bg, #f9fafb);
  border-bottom: 1px solid var(--bs-border-color, #e5e7eb);
}
.vn-table tbody td {
  padding: 12px 16px;
  border-bottom: 1px solid var(--bs-border-color, #f3f4f6);
  vertical-align: middle;
}
.vn-table tbody tr:hover { background: var(--bs-tertiary-bg, #f9fafb); }
.vn-table a { color: #2563eb; text-decoration: none; font-weight: 600; }
.vn-table a:hover { text-decoration: underline; }

/* Status & KEV chips */
.vn-chip {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 2px 10px; border-radius: 999px;
  font-size: 11px; font-weight: 700; letter-spacing: 0.02em;
}
.vn-status--overdue { background: rgba(239, 68, 68, 0.12); color: #b91c1c; }
.vn-status--soon    { background: rgba(245, 158, 11, 0.14); color: #b45309; }
.vn-status--ok      { background: rgba(107, 114, 128, 0.12); color: #4b5563; }
.vn-tag-kev {
  background: rgba(239, 68, 68, 0.08);
  border: 1px solid rgba(239, 68, 68, 0.4);
  color: #b91c1c;
}

.vn-empty {
  padding: 40px; text-align: center;
  color: var(--bs-secondary-color, #6b7280);
  font-size: 14px;
}
```

- [ ] **Step 2: No commit yet** — CSS without the template that uses it is dead weight. Commit at the end of Task 4.

---

## Task 4: Rewrite the list template

**Files:**
- Replace: `cuba/templates/threat_intel/vulnerabilities_list.html`

- [ ] **Step 1: Replace the template entirely**

Overwrite `staterkit/cuba/templates/threat_intel/vulnerabilities_list.html` with:

```html
{% extends "base.html" %}
{% block title %}D-SECLAB | Vulnerabilities{% endblock %}
{% block css %}
<link rel="stylesheet" href="{{ url_for('static', filename='assets/css/pages/vulnerabilities.css') }}">
{% endblock %}
{% block content %}
<div class="container-fluid p-0 vn-page">

  {# --- Hero with stats row --- #}
  <div class="vn-hero">
    <div class="vn-hero-inner">
      <div class="vn-hero-top">
        <div>
          <div class="vn-hero-title-row">
            <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28"
                 viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2"
                 stroke-linecap="round" stroke-linejoin="round">
              <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
              <line x1="12" y1="9" x2="12" y2="13"/>
              <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
            <div class="vn-hero-title">Vulnerabilities (CISA KEV)</div>
          </div>
          <div class="vn-hero-subtitle">Known Exploited Vulnerabilities catalog</div>
        </div>
        <div class="vn-hero-badge">
          <span class="vn-hero-badge-dot"></span>
          {{ stats.by_ransomware.get('Known', 0) }} Ransomware-tagged
        </div>
      </div>

      <div class="vn-stats-row">
        <div class="vn-stat">
          <div class="vn-stat-val">{{ stats.total }}</div>
          <div class="vn-stat-label">Total CVEs</div>
        </div>
        <div class="vn-stat-divider"></div>
        <div class="vn-stat">
          <div class="vn-stat-val">{{ stats.by_ransomware.get('Known', 0) }}</div>
          <div class="vn-stat-label">Ransomware Use</div>
        </div>
        <div class="vn-stat-divider"></div>
        <div class="vn-stat">
          <div class="vn-stat-val">{{ stats.due_soon }}</div>
          <div class="vn-stat-label">Due ≤ 7 Days</div>
        </div>
        <div class="vn-stat-divider"></div>
        <div class="vn-stat">
          <div class="vn-stat-val">{{ stats.overdue }}</div>
          <div class="vn-stat-label">Overdue</div>
        </div>
      </div>
    </div>
  </div>

  {# --- Two cards: top vendors + ransomware use --- #}
  {% set max_vendor = (stats.by_vendor | map(attribute=1) | max | default(1)) if stats.by_vendor else 1 %}
  {% set known = stats.by_ransomware.get('Known', 0) %}
  {% set unknown = stats.by_ransomware.get('Unknown', 0) %}
  {% set rmax = (known if known > unknown else unknown) or 1 %}

  <div class="vn-row">
    <div class="vn-card">
      <div class="vn-card-title">Top Vendors</div>
      {% for vendor, count in stats.by_vendor[:5] %}
      <div class="vn-bar-row">
        <div class="vn-bar-label" title="{{ vendor }}">{{ vendor }}</div>
        <div class="vn-bar">
          <div class="vn-bar-fill" style="width: {{ (count * 100 / max_vendor) | round(0, 'floor') }}%;"></div>
        </div>
        <div class="vn-bar-count">{{ count }}</div>
      </div>
      {% else %}
      <div class="vn-empty">No data</div>
      {% endfor %}
    </div>

    <div class="vn-card">
      <div class="vn-card-title">Ransomware Use</div>
      <div class="vn-bar-row">
        <div class="vn-bar-label">Known</div>
        <div class="vn-bar">
          <div class="vn-bar-fill vn-bar-fill--ransomware"
               style="width: {{ (known * 100 / rmax) | round(0, 'floor') }}%;"></div>
        </div>
        <div class="vn-bar-count">{{ known }}</div>
      </div>
      <div class="vn-bar-row">
        <div class="vn-bar-label">Unknown</div>
        <div class="vn-bar">
          <div class="vn-bar-fill" style="width: {{ (unknown * 100 / rmax) | round(0, 'floor') }}%;"></div>
        </div>
        <div class="vn-bar-count">{{ unknown }}</div>
      </div>
    </div>
  </div>

  {# --- Toolbar --- #}
  <div class="vn-toolbar">
    <div class="vn-toolbar-left">
      <span class="vn-count" id="vulns-total">Loading...</span>
    </div>
    <div class="vn-toolbar-right">
      <div class="vn-search">
        <input type="text" id="vulns-search" placeholder="Search CVE / name / description...">
      </div>
      <select id="vulns-vendor" class="vn-filter">
        <option value="">All vendors</option>
        {% for vendor, _ in stats.by_vendor[:20] %}
        <option value="{{ vendor }}">{{ vendor }}</option>
        {% endfor %}
      </select>
      <select id="vulns-ransomware" class="vn-filter">
        <option value="">Any ransomware-use</option>
        <option value="Known">Known</option>
        <option value="Unknown">Unknown</option>
      </select>
      {% if full_access %}
      <a href="{{ url_for('vulnerabilities.export_csv') }}" class="vn-btn">Export CSV</a>
      {% endif %}
    </div>
  </div>

  {# --- Table --- #}
  <div class="vn-table-wrap">
    <table class="vn-table" id="vulns-table">
      <thead>
        <tr>
          <th>#</th>
          <th>CVE ID</th>
          <th>Vendor</th>
          <th>Product</th>
          <th>Vulnerability</th>
          <th>Added</th>
          <th>Due</th>
          <th>Status</th>
          <th>Tag</th>
        </tr>
      </thead>
      <tbody id="vulns-body"></tbody>
    </table>
    <div class="vn-empty" id="vulns-empty" style="display:none;">No results found</div>
  </div>

  <div class="vn-pagination" id="vulns-pagination"></div>
</div>

<script>
(function() {
  var FULL_ACCESS = {{ 'true' if full_access else 'false' }};
  var state = { page: 1, per_page: 20 };

  function fmt(s) { return s == null ? '' : String(s); }

  function statusChip(dueStr) {
    if (!dueStr) return '';
    var due = new Date(dueStr + 'T00:00:00Z');
    if (isNaN(due.getTime())) return '';
    var today = new Date(); today.setUTCHours(0,0,0,0);
    var diffMs = due - today;
    var diffDays = Math.round(diffMs / 86400000);
    if (diffDays < 0) {
      return '<span class="vn-chip vn-status--overdue">Overdue ' + (-diffDays) + 'd</span>';
    }
    if (diffDays <= 7) {
      return '<span class="vn-chip vn-status--soon">Due ' + diffDays + 'd</span>';
    }
    return '<span class="vn-chip vn-status--ok">' + diffDays + 'd</span>';
  }

  function kevTag(known) {
    return known === 'Known'
      ? '<span class="vn-chip vn-tag-kev">★ KEV</span>'
      : '';
  }

  function load() {
    var body = {
      page: state.page,
      per_page: state.per_page,
      search: document.getElementById('vulns-search').value,
      vendor: document.getElementById('vulns-vendor').value,
      ransomware_use: document.getElementById('vulns-ransomware').value
    };
    fetch('/api/vulnerabilities/search', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': window.CSRF_TOKEN || '',
        'Accept': 'application/json'
      },
      body: JSON.stringify(body)
    }).then(function(r) { return r.ok ? r.json() : null; })
      .then(function(data) {
        if (!data) {
          document.getElementById('vulns-empty').style.display = '';
          document.getElementById('vulns-total').textContent = 'Could not load';
          return;
        }
        document.getElementById('vulns-total').textContent = data.total + ' total';
        var tbody = document.getElementById('vulns-body');
        tbody.innerHTML = '';
        if (!data.rows.length) {
          document.getElementById('vulns-empty').style.display = '';
          return;
        }
        document.getElementById('vulns-empty').style.display = 'none';
        data.rows.forEach(function(row, i) {
          var tr = document.createElement('tr');
          var cveCell = FULL_ACCESS
            ? '<a href="/threat-intelligence/vulnerabilities/' + encodeURIComponent(row.cve_id) + '">' + fmt(row.cve_id) + '</a>'
            : fmt(row.cve_id);
          tr.innerHTML =
            '<td>' + ((state.page - 1) * state.per_page + i + 1) + '</td>' +
            '<td>' + cveCell + '</td>' +
            '<td>' + fmt(row.vendor) + '</td>' +
            '<td>' + fmt(row.product) + '</td>' +
            '<td>' + fmt(row.vulnerability_name) + '</td>' +
            '<td>' + fmt(row.date_added) + '</td>' +
            '<td>' + fmt(row.due_date) + '</td>' +
            '<td>' + statusChip(row.due_date) + '</td>' +
            '<td>' + kevTag(row.known_ransomware_use) + '</td>';
          tbody.appendChild(tr);
        });
      });
  }

  document.getElementById('vulns-search').addEventListener('input', function() {
    state.page = 1; load();
  });
  document.getElementById('vulns-vendor').addEventListener('change', function() {
    state.page = 1; load();
  });
  document.getElementById('vulns-ransomware').addEventListener('change', function() {
    state.page = 1; load();
  });
  load();
})();
</script>
{% endblock %}
```

- [ ] **Step 2: Run the test sweep**

```bash
source venv/bin/activate && python -m pytest tests/test_vulnerabilities.py -v 2>&1 | tail -25
```

Expected: **all 17 PASS** (14 original + 3 new). The new tests verify the SSR stats render and the member-no-export rule.

- [ ] **Step 3: Run the whole suite**

```bash
source venv/bin/activate && python -m pytest tests/ -q 2>&1 | tail -3
```

Expected: 30 passed (13 breached-creds + 17 vulnerabilities).

- [ ] **Step 4: Commit the route + CSS + template + tests together**

```bash
git -C /Users/jooy/Development/dseclab_backend add \
  staterkit/cuba/vulnerabilities.py \
  staterkit/cuba/static/assets/css/pages/vulnerabilities.css \
  staterkit/cuba/templates/threat_intel/vulnerabilities_list.html \
  staterkit/tests/test_vulnerabilities.py
git -C /Users/jooy/Development/dseclab_backend -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: modernise Vulnerabilities page with dashboard layout

Replaces the table-only view with a Ransomware-style dashboard:
SSR hero, 4-stat row (Total, Ransomware Use, Due <= 7d, Overdue),
Top-Vendors and Ransomware-Use cards above the existing AJAX table.
Table rows gain a date-aware Status chip (Overdue/Due-d/Days) and a
KEV tag for ransomware-known CVEs.

list_page() route now also calls cisa_kev_service.get_stats() with
a try/except fallback (defaults to zeros if ES is down). Member field
projection, role gates, audit logging, and the search/detail/export
endpoints are unchanged.

Three new tests cover SSR stats rendering and member-no-export.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Live smoke + push

**Files:** none — verification only.

- [ ] **Step 1: Restart the local dev server**

```bash
lsof -ti:8003 2>/dev/null | xargs -r kill -9
sleep 1
cd /Users/jooy/Development/dseclab_backend/staterkit
source venv/bin/activate
python -c "from cuba import create_app, socketio; app = create_app(); socketio.run(app, debug=True, port=8003, allow_unsafe_werkzeug=True)" &
sleep 4
```

- [ ] **Step 2: Confirm SSR stats appear**

```bash
# Login as admin and grab the rendered page.
rm -f /tmp/c.txt
csrf=$(curl -s -c /tmp/c.txt http://localhost:8003/login | grep -oE 'name="csrf_token"[^>]*value="[^"]+"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -b /tmp/c.txt -c /tmp/c.txt -o /dev/null -X POST http://localhost:8003/login -d "csrf_token=$csrf&email=admin@dseclab.com&password=Admin@123"
curl -s -b /tmp/c.txt http://localhost:8003/threat-intelligence/vulnerabilities | grep -oE 'vn-stat-val">[^<]+|vn-hero-title">[^<]+|Ransomware-tagged' | head -10
```

Expected: lines like
```
vn-hero-title">Vulnerabilities (CISA KEV)
vn-stat-val">1607
vn-stat-val">325
Ransomware-tagged
```

- [ ] **Step 3: Browser eyeball check (manual)**

1. Open http://localhost:8003 → log in as `admin@dseclab.com` / `Admin@123`.
2. Click "Vulnerabilities" in the sidebar.
3. Confirm: gradient hero, 4-stat row, two cards (Top Vendors with horizontal bars, Ransomware Use), toolbar with vendor dropdown populated, table with Status + Tag columns and chips rendering.
4. Click Status filter or type in search — table updates without reloading.
5. Click any CVE row → detail page opens.
6. Log out, log in as `dorjoo@test.com` / `Test@123` (member) → same hero/stats but no Export button, no clickable rows.

- [ ] **Step 4: Push to GitHub**

```bash
git -C /Users/jooy/Development/dseclab_backend push origin main 2>&1 | tail -5
```

Expected: `main -> main` line. Two new commits land on `origin/main`.

- [ ] **Step 5: Deploy note**

On the remote (`213.163.197.81` via your SSH session):

```bash
# As root (since /opt/dseclab/.git is root-owned per the earlier session)
git -C /opt/dseclab pull
git -C /opt/dseclab-repo pull
sudo systemctl restart dseclab
sudo journalctl -u dseclab -n 30 --no-pager
```

No DB migration, no new deps — purely template/CSS/Python source change.

---

## Risks & verification notes

- **`max | default(1)` in Jinja**: prevents division-by-zero when `stats.by_vendor` is empty (fresh ES cluster). Tested implicitly by the test_member_sees_aggregate_stats_no_export test which uses non-empty stats; if you need to harden, add a unit test that calls `list_page` with `get_stats` returning all zeros and asserts `200`.
- **`@cache.cached(timeout=60)` on `list_page`**: deliberately NOT added. Two extra `_count` calls per page load on 1,607 docs is sub-millisecond ES work; caching is a follow-up if real latency is observed.
- **Test #2 (`test_member_sees_aggregate_stats_no_export`)** asserts `b'export.csv' not in r.data` rather than the literal word "Export" — the export URL is the load-bearing string; "Export" as a word could appear elsewhere (column header, button label, etc.).
- **Dark mode**: CSS uses Bootstrap CSS variables (`var(--bs-body-bg)` etc.) which the Cuba template already swaps for dark mode. No extra dark-mode tweaks needed.
