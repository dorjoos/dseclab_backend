# Design: Follow-up hardening after the reports/watchlist/employees batch

**Date:** 2026-08-16
**Status:** Approved (user: "all")

Eight follow-ups from reviewing [the previous
batch](2026-08-15-reports-watchlist-employees-design.md). The first two are
debt that batch introduced; the rest are pre-existing.

## 1. A test that would have broken confusingly

`test_day_pills_render_as_toggles_not_bare_checkboxes` asserted the page held
exactly seven `rp-day` pills. The reports template now renders that loop twice
— once in the create form, once per inline edit panel — so the assertion only
held because the test created no schedules. Adding one fixture would have
failed it with a count of 14 and no hint why.

Now creates a schedule on purpose and scopes the count to the create form, so
it measures what it claims to.

## 2. Legacy `Query.get()`

Two of the three sites came from the edit-schedule work. `db.session.get()`
throughout. The one remaining warning is inside Flask-SQLAlchemy's own
`get_or_404()`, which we don't control.

## 3. N+1 in `_get_employee_emails`

The admin branch walked `Company.watchlist_entries` per company. One
`WatchlistEntry` query filtered on `entry_type='email'` instead.

## 4. Deep pagination claimed Elasticsearch was down

ES rejects `from + size` past `index.max_result_window` (10,000). That
rejection was caught by `search()`'s except block and returned as
`error=True`, which the list page renders as "Search backend (Elasticsearch)
is unavailable" — a lie when ES is healthy and the user merely paged too deep.

`search()` now clamps the page to the last reachable one, and `ESPagination`
takes a `max_pages` so the UI stops offering pages the backend cannot serve: a
900k-hit search has 45,000 nominal pages but only 500 are reachable. Going
further needs `search_after`, not a bigger offset — noted for when it matters.

## 5. `_wants_json()` removed

It sniffed the Accept header and redirected for anything that looked like a
browser. `fetch` sends `Accept: */*`, the sniff read that as a browser, and the
caller's `r.json()` choked on a redirect to HTML — which is precisely how the
watchlist Remove button shipped broken.

Both watchlist endpoints now answer JSON unconditionally and the page drives
both with `fetch`, rendering the returned `message` as a toast in place of the
old flash-and-redirect. One content type, nothing to guess. The add path
inserts the new row into the DOM rather than reloading.

Audited all nine `fetch()` call sites first: the rest hit endpoints that always
returned JSON, so this was the only latent instance.

## 6. Employee matching

`build_employee_filter` only matched `username`. It now also matches the split
form — local part in `username`, host in `domain` — which some feeds produce.
Both halves are required, so it stays exactly as precise: it cannot reach a
different person at the same domain.

Deliberately **not** matched: the raw dump line. It normally contains the same
address the pipeline already extracted into `username`, so scanning it is
mostly redundant, and doing it precisely needs an anchored regexp per employee
— too slow at this clause count to pay for the narrow case of a feed that
failed to parse its own row. Revisit if real data shows those rows exist.

Every clause is an exact term; there are no wildcards, so `on@acme.com` cannot
quietly match inside `otgon@acme.com`. A test asserts that directly.

## 7. `threat_intel.py` split into a package

1,190 lines carrying breached credentials, reports, ransomware and analysis.
It was the file every change in the previous batch touched, which is why those
five items could not be committed separately.

Now `cuba/threat_intel/` with `_shared`, `breached_creds`, `reports`,
`ransomware` and `analysis`. **One blueprint, not several**: templates
reference `url_for('threat_intel.*')` throughout, and separate blueprints would
have renamed every endpoint. `_blueprint.py` holds it so submodules can import
it without importing each other.

The split was generated from AST line spans rather than retyped, and verified
three ways: the route table is byte-identical before and after, all 34
functions have identical ASTs, and the suite passes unchanged. A guard test
pins the full endpoint set, because `__init__` imports the submodules purely
for their registration side effect — one dropped import would silently remove
a page.

## 8. Verifying rendered JavaScript

**The browser check could not run.** The Chrome extension has no site
permission for the local dev server, so its requests never reached the app.
The inline edit panel, tab strip and reveal interaction still have no visual
confirmation.

What went in instead is the check that would actually have caught the shipped
bug. Rendering a page and asserting a string is present says nothing about
whether a browser can run the result — the Remove button's HTML assertions all
passed while the button did nothing. So the new test renders the real pages,
extracts both `<script>` blocks **and inline event-handler attributes**, and
parses each with `node --check`.

The handler attributes are the point: a `<script>`-only check passes on the
buggy template. Confirmed against the pre-fix version from `main`, where it
fails with `SyntaxError: Invalid or unexpected token`.

The watchlist fixture uses a fixed id beginning with a digit. A generated UUID
would make the check flaky — only 6 of 16 possible leading hex characters are
letters, and it is the digit case that produces a hard syntax error rather than
a parses-but-throws reference error.

This is not a substitute for looking at the page. It closes the specific hole
that let a dead button ship.
