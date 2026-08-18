# Design: Schedule editing, watchlist delete, raw text, ransomware paging, Employees tab

**Date:** 2026-08-15
**Status:** Approved (user chose options via prompt, then "keep working")

Six independent items from one review pass. They share no code except the two
that touch the reports form, so each is specified on its own below.

---

## 1. Edit a scheduled report

**Problem.** A schedule could be paused, enabled or deleted, never edited. Fixing
a typo in a name or moving a run time meant deleting and recreating, which loses
`last_run` and the audit trail.

**Approach.** An `Edit` button on each row expands an inline panel below it,
prefilled from the schedule (user's choice over reusing the top create form).
`POST /threat-intelligence/reports/schedule/<sid>/edit` applies it.

The create and edit routes share `_parse_schedule_form()` and
`_bind_recipients()`. This is not tidiness: `_bind_recipients` is the only thing
stopping a client's breach data being mailed to an unrelated address, and an
edit route that reimplemented it would eventually drift. One parser, one binder,
two thin routes.

Deliberately **not** editable:

- `is_active` — Pause/Enable owns it. A stray posted field must not flip it.
- `last_run` — editing the cadence doesn't undo runs that already happened.

`next_run` recomputes from the new cadence. A rejected recipient rolls the whole
edit back, so a row can't be left half-updated.

Only one panel opens at a time; two stacked forms push the list off-screen and
make it unclear which row is being edited.

## 2. "Email To" prefills the signed-in user

**Problem.** The field started empty, so the common case — mail this to me —
took typing.

**Approach.** `value="{{ current_user.email }}"`, still editable and clearable.

**This required a change to the recipient guard.** `validate_recipients` allowed
the creator's own address only when no company was selected, so an admin at
`admin@dseclab.mn` picking "Khan Bank" had their own prefilled address rejected
and every create failed by default.

The creator-self check now runs **ahead** of the domain rule, so the creator may
always mail themselves. This doesn't widen exposure: `resolve_domains` already
clamps a report to the creator's own visible scope, and `run_due_schedules`
disables a schedule whose creator goes missing or inactive. Every row in the
attachment is one the creator can already read in the UI. The old placement
looks like an oversight rather than intent.

Only the creator's exact address is exempt — the domain rule is untouched for
everyone else.

## 3. Watchlist entry delete

**Problem.** The Remove button did nothing at all. Two stacked defects:

1. `onclick="deleteWatchlistEntry({{ company.id }}, {{ entry.id }}, this)"` —
   ids are UUID strings, so unquoted they parse as arithmetic over undefined
   names and the handler dies before it runs.
2. The `fetch` omitted `X-Requested-With`, so `_wants_json()` returned False and
   the route answered a redirect. `r.json()` then threw on HTML — into a catch
   block that only showed a generic toast.

**Approach.** Ids travel as `data-company-id` / `data-entry-id` with a delegated
listener, which sidesteps HTML-in-JS quoting entirely. The fetch sets
`X-Requested-With`. The handler now surfaces `data.error` instead of ignoring a
`success: false`, and the item count refreshes.

The count refresh is scoped to the button's own card: Watchlist Entries and
Report Recipients are built from the same `cf-wl-*` classes, so a
document-wide lookup would find whichever card came first.

## 4. Raw text on the credential detail page

**Problem.** `BreachedCred.value` — the original dump line — was parsed and
never shown.

**Approach.** A full-width "Raw Text" cell in Credential Details.

The raw line normally quotes the plaintext password inline, so rendering it
would route straight around the click-to-reveal gate the password already sits
behind. It gets the same treatment: masked server-side, fetched on demand from
the existing reveal endpoint.

That endpoint now takes a `field` of `password` (default, so older callers keep
working) or `raw`, and names the field in the audit row — revealing a raw line
is never filed as a password reveal. Any other field value is a 400, so the
parameter can't become a way to read arbitrary attributes.

## 5. Ransomware "Recent Attacks" pagination

**Problem.** Three defects.

1. `get_recent()` reassigned its own `group` parameter inside the result loop,
   so the `filters` it echoed back carried the **last row's** group instead of
   the caller's filter. The template pastes that into every page link as
   `&rg=...`, so clicking Next silently filtered the list to a group nobody
   chose and changed the page count.
2. Query-string values weren't URL-encoded. A search containing `#` or `&` cut
   the link short and dropped the page number.
3. `max_sector` came from `stats.sectors.values()|max`, and the degraded-ES
   fallback is `{'Unknown': 0}` — truthy, but maxes to 0. The bar-width
   expression then divided by zero and 500'd the page, on exactly the outage
   the route's `_safe()` wrapper exists to ride out.

**Approach.** Rename the loop variable; build the filter query string once with
`|urlencode` and reuse it across all three link sites; guard `max_sector` with
`or 1`.

## 6. Employees tab in Breached Credentials

**Problem.** No way to see only staff breaches.

**Approach.** Employees are the existing `entry_type='email'` watchlist entries
(user's choice over a new model) — stored by the admin form today and read by
nothing, so this gives them a purpose with no schema change. `Company` gets
`get_employee_emails()`.

A separate Employees tab (user's choice over an inline toggle) at
`/threat-intelligence/breached-creds/employees`. The table, filters, pagination
and script are extracted into `_breached_creds_panel.html` and
`_breached_creds_script.html`, which both tabs include with `employees_only`
flipped — so the two tabs can't drift.

`build_employee_filter` matches **exact** addresses, not suffixes: the question
is "was this person breached", so one employee must not pull in every address at
the domain. The unfiltered tab already does that.

Two traps handled explicitly:

- **An empty employee list matches nothing, not everything.** Same shape as the
  `domain_filters == []` case: a company with nobody on file has no employee
  breaches, which is not the same as having no filter.
- **The clause count is capped** at 1000, well above any real payroll, so the
  list can't grow past ES's `max_clause_count` and turn the tab into an error.
  Truncation is logged, never silent.

The domain scope filter still applies underneath, so `employees_only` can only
ever subtract from what the caller may already see. Export takes the same flag,
so the Employees tab's Export downloads the list on screen rather than every
credential in scope.
