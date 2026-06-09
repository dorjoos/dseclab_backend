# Member Breached-Cred Password Reveal — Design

**Date:** 2026-06-09
**Status:** Draft (awaiting user review)
**Owner:** dorjsambuu

## Problem

Non-admin company users (`User.role == 'member'`) viewing a breached-credential detail page see the "Click to reveal" affordance, but it only reveals `********` instead of the real password. This is caused by `config.DATA_MASKING['member'] = ['password']` combined with `threat_intel.breached_creds_view` calling `mask_value('password', cred.password)` before rendering — the plaintext never reaches the template, so the JS toggle reveals only the masked string.

Members legitimately need to see plaintext passwords for breached credentials that belong to **their own company**, so they can rotate them, notify affected employees, and run incident response.

## Goal

A member who has access (per the existing `_check_cred_access` tenancy check) to a breached-cred detail page can reveal the real password via an explicit click. The plaintext password never appears in server-rendered HTML for any role; it is fetched on demand via an authenticated, audited, rate-limited AJAX endpoint.

## Non-goals (YAGNI)

- Reveal on the list/table view — list stays masked. Reveals are one-at-a-time, intentional, harder to leak in bulk via screenshot.
- Reveal-with-justification text box.
- Auto-hide after N seconds.
- Re-authentication (e.g., re-enter password) before reveal.
- Per-cred (rather than per-user) rate limiting.
- Changing the existing `DATA_MASKING` config — it stays as a safety net for any future route that exposes a cred without tenancy checking.

## Tenancy: already enforced

`cuba/threat_intel.py:_check_cred_access` already gates every cred read for non-admins. For a non-admin user:

```python
def _check_cred_access(cred):
    if current_user.is_admin_user:
        return True
    domain_filters = _get_domain_filters()  # company.get_match_domains()
    if not domain_filters:
        return False
    cred_domain = (cred.domain or '').lower()
    cred_username = (cred.username or '').lower()
    cred_url = (cred.url or '').lower()
    for d in domain_filters:
        if d.lower() in cred_domain or d.lower() in cred_username or d.lower() in cred_url:
            return True
    return False
```

So by the time a member reaches the detail page or the reveal endpoint, the cred is already known to belong to their company. The design does **not** introduce a new authorization rule; it replaces the inline plaintext rendering with an explicit, audited delivery channel.

## Architecture

**Server never renders plaintext passwords into HTML, for any role.**

1. GET `/threat-intelligence/breached-creds/<doc_id>` — `breached_creds_view` always sets `cred.password = '********'` before render (or leaves the existing `mask_value` call but applies it to all roles, not just members). The template ships `********` in the DOM.
2. User clicks `.password-mask` on the detail page → JS calls the reveal endpoint.
3. POST `/threat-intelligence/breached-creds/<doc_id>/reveal-password` (new) — server re-runs `_check_cred_access`, writes audit log, returns plaintext JSON.
4. JS injects the plaintext into `.revealed-password` and shows it. Second click → re-mask: set the span text back to `********` and hide. Plaintext is not retained in DOM after re-mask.

## Components

### Backend — `cuba/threat_intel.py`

**Modify** `breached_creds_view` (currently at ~line 311):

- Always overwrite `cred.password` with `'********'` before render, regardless of role. (Replaces the role-dependent `mask_value` call for the detail-view path; `mask_value` remains in use elsewhere as a safety net.)

**Add** `breached_creds_reveal_password`:

```python
@threat_intel.route('/threat-intelligence/breached-creds/<doc_id>/reveal-password', methods=['POST'])
@login_required
@limiter.limit("30/minute")
def breached_creds_reveal_password(doc_id):
    cred = es_service.get_by_id(doc_id)
    if not cred:
        return jsonify({"error": "not_found"}), 404
    if not _check_cred_access(cred):
        log_audit("reveal_password_denied", "breached_cred", doc_id,
                  f"User {current_user.username} denied reveal for cred {doc_id}")
        return jsonify({"error": "access_denied"}), 403
    log_audit("reveal_password", "breached_cred", doc_id,
              f"User {current_user.username} revealed password for cred {doc_id} (domain={cred.domain or 'unknown'})")
    log_user_activity("reveal_password", current_user.id, status="success")
    return jsonify({"password": cred.password or ""})
```

CSRF: the endpoint accepts an `X-CSRFToken` header validated by Flask-WTF (matching the existing global `WTF_CSRF_ENABLED = True` setting). No new CSRF infrastructure required.

### Templates

**`cuba/templates/threat_intel/breached_creds_view.html`** (~line 65–68):

Replace:
```html
<div class="password-mask">
  <span class="masked-password">Click to reveal</span>
  <span class="revealed-password">{{ breached_cred.password }}</span>
</div>
```

With:
```html
<div class="password-mask" data-cred-id="{{ breached_cred.es_id }}">
  <span class="masked-password">Click to reveal</span>
  <span class="revealed-password" data-placeholder="********">********</span>
</div>
```

Plaintext is no longer interpolated into the template. The `data-cred-id` lets the JS know which endpoint to hit.

**`cuba/templates/base.html`** (lines 124–134):

Replace the existing hover-based reveal with a click-based, AJAX-driven reveal:

- First click on `.password-mask`: read `data-cred-id`, `fetch('/threat-intelligence/breached-creds/<id>/reveal-password', {method: 'POST', headers: {'X-CSRFToken': csrf, 'Accept': 'application/json'}})`. On 200, set `.revealed-password` text content to the returned password, show it, hide the masked span.
- Second click: set `.revealed-password` text content back to `********` (drop plaintext from DOM), hide it, show the masked span.
- CSRF token source: existing project pattern — either a `<meta name="csrf-token">` tag in `base.html` or the Flask-WTF helper. Confirm during implementation; add a meta tag if not already present.

### Config & models

No changes. `DATA_MASKING` config stays. `User`, `Company`, `BreachedCredMeta` unchanged.

## Data flow

```
[Browser]                                     [Server]
   |                                              |
   | GET  /breached-creds/<id>                    |
   |--------------------------------------------->|
   |                                              | _check_cred_access(cred)  ── pass ──
   |                                              | cred.password = '********'
   | <-------------------- HTML (no plaintext) ---|
   |                                              |
   | (user clicks .password-mask)                 |
   | POST /breached-creds/<id>/reveal-password    |
   |   X-CSRFToken: ...                           |
   |--------------------------------------------->|
   |                                              | _check_cred_access(cred)  ── pass ──
   |                                              | log_audit("reveal_password", ...)
   |                                              | log_user_activity("reveal_password", ...)
   | <----------------- {"password": "<real>"} ---|
   |                                              |
   | (inject into .revealed-password, show)       |
```

## Error handling

| Status | Cause | User-facing message |
|---|---|---|
| 401 | Session expired | "Session expired. Please log in again." |
| 403 | `_check_cred_access` fails (defense in depth) | "Access denied." |
| 404 | Cred deleted between page load and reveal | "Credential no longer exists." |
| 429 | Rate limit hit | "Too many reveal attempts. Try again in a minute." |
| 5xx | Server error | "Could not reveal password. Try again." |

Errors render as a small inline message below the password field. No plaintext is ever exposed in an error path.

## Audit

Each successful reveal writes one `AuditLog` row:
- `action_type = "reveal_password"`
- `resource_type = "breached_cred"`
- `resource_id = doc_id`
- `description = "User <username> revealed password for cred <doc_id> (domain=<cred.domain>)"`
- `user_id`, `ip_address`, `user_agent` captured by the existing `log_audit` helper

Each denied reveal writes one row with `action_type = "reveal_password_denied"` and `status = "failed"`. This catches lateral-movement probes (a member trying to reveal another company's cred via direct POST).

`UserActivity` row written in parallel via `log_user_activity` for the activity feed.

## Rate limiting

`@limiter.limit("30/minute")` per user. Matches the style of existing endpoints (login is `5/minute`, API login is `10/minute`). 30 is generous enough for legitimate incident response (looking up a list of compromised users) but slows down automated abuse.

## Testing

Test file: `tests/test_breached_creds_reveal.py` (new — confirm pytest infra exists; if not, add a minimal `tests/conftest.py` with an app fixture that uses an in-memory SQLite DB and a fake `es_service`).

1. **No plaintext in detail page HTML.** GET `/threat-intelligence/breached-creds/<id>` as member, analyst, admin — response body never contains the plaintext password substring.
2. **Cross-company member denied.** POST `/reveal-password` as a member whose company domain does not match the cred → 403, one `reveal_password_denied` audit row, no `reveal_password` row.
3. **Owning member allowed.** POST as a member whose company domain matches → 200, response JSON `{"password": "<plaintext>"}`, one `reveal_password` audit row.
4. **Admin allowed.** POST as admin → 200 + plaintext + audit row.
5. **Analyst allowed.** POST as analyst → 200 + plaintext + audit row.
6. **CSRF missing.** POST without `X-CSRFToken` → 400 (Flask-WTF default).
7. **Rate limit.** 31st POST inside one minute → 429.
8. **Cred not found.** POST with non-existent `doc_id` → 404.
9. **Unauthenticated.** POST without session → 401 (or redirect, per `@login_required`).

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| Plaintext leaked via browser history / screen share if user keeps reveal visible | Re-mask on second click clears DOM. Document that users should re-mask before sharing screens. |
| `_check_cred_access` has a substring-match bug (e.g., a member at `co.com` matches a cred at `evilco.com` because `"co.com" in "evilco.com"`) | **Pre-existing risk**, not introduced here. Flag for follow-up: tighten to suffix match (`endswith("@" + domain)` for emails, host match for URLs). Out of scope for this spec. |
| AJAX endpoint reachable from any logged-in user, not just from the detail page | That's by design — the access check is the gate, not the referrer. A direct POST from `curl` is equivalent to a click on the page. |
| Audit log growth | Negligible — one row per reveal click. AuditLog already used for many actions. |

## Open follow-up (separate spec)

The substring-match logic in `_check_cred_access` is permissive (line 59: `if d in cred_domain or d in cred_username or d in cred_url`). A company at domain `co.com` matches any cred whose URL contains the string `co.com`. Tightening this to suffix/exact match is a separate hardening spec and should not be bundled with this UX fix.
