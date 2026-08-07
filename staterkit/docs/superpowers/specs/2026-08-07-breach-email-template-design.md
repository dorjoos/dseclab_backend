# Design: Breach-Notification Email Template Redesign

**Date:** 2026-08-07
**Status:** Approved (user: "go ahead")

## Problem

The breach-alert email built by `build_breach_email()` renders badly in Gmail:

1. **Gmail autolinks the data.** Usernames and domains are emitted as bare text, so
   Gmail's autolinker wraps them in its own blue underlined anchors. This is most of
   what makes the mail look unfinished.
2. **The red accent reads as a stray line.** `border-left` on a table with
   `padding-left` produces a floating rule next to the content, not a card.
3. **No container, no branding.** Content sits directly on the client background with
   no width constraint and no DSECLab identity.
4. **HTML-only message.** `MIMEMultipart()` defaults to `mixed` and only an HTML part is
   attached. A missing `text/plain` alternative is a spam-filter signal and degrades
   deliverability to corporate mail servers.
5. **No dark-mode handling.** Unpainted regions get force-inverted by Gmail.

Alongside the visual work, the notification path carries a security defect (see
Defense in Depth below).

## Approach

Keep the markup in `services/email_service.py` as a rewritten Python builder (user's
choice over a Jinja template file), decomposed into small helpers so it does not drift
again. Email HTML conventions apply throughout: 600px table layout, all CSS inline,
`role="presentation"`, no flex/grid.

## Visual design

Brand colors sampled from `static/assets/images/logo/logo.png`:
`#A800F0` → `#8424F0` → `#249CFC`.

| Token | Value | Use |
|---|---|---|
| `BRAND` | `#8424F0` | header bar, CTA button |
| `BRAND_ALT` | `#249CFC` | gradient end (degrades to solid `BRAND`) |
| `INK` | `#111827` | primary text |
| `MUTED` | `#6B7280` | labels, footer |
| `BORDER` | `#E5E7EB` | card borders |
| `PAGE_BG` | `#F4F5F7` | page background behind the card |
| `ALERT` | `#DC2626` | breach accent edge, alert dot |

Structure: brand header → alert headline (count + company) → one card per credential →
CTA button → footer. The username is promoted to each card's heading; remaining fields
render as label/value rows. The red accent becomes a 3px left edge on a bordered card.

Near-white `#F4F5F7` and near-black `#111827` are used instead of pure `#FFF`/`#000` so
Gmail's dark-mode inversion stays legible, and every cell gets an explicit background.

## Components (`services/email_service.py`)

| Function | Responsibility |
|---|---|
| `_esc(value)` | `html.escape(str(value), quote=True)`, `""` for `None` |
| `_clean_header(value)` | strip CR/LF — header-injection guard |
| `_cred_url(base_url, es_id)` | build a credential URL with `quote()`d id, or `None` |
| `_row(label, value)` | one label/value row |
| `_card(cred, base_url)` | one credential card |
| `_shell(inner, preheader)` | full HTML doc: head, page bg, 600px wrapper, header, footer |
| `_text_body(company_name, creds, base_url)` | the `text/plain` alternative |
| `build_breach_email(...)` | assembles; returns `(subject, html, text)` |

`send_email()` gains a keyword-only `text` parameter and switches to
`multipart/alternative` (wrapped in `multipart/mixed` only when an attachment is
present). `text` is keyword-only so existing positional calls keep working.

**Breaking change:** `build_breach_email()` returns a 3-tuple instead of 2. Call sites
updated: `cuba/threat_intel.py` and four in `tests/test_email_service.py`.

## Defense in depth

1. **Pin link base URL to config.** `deploy/nginx.conf` forwards `Host $host` under
   `server_name _`, and `ProxyFix(x_host=1)` trusts `X-Forwarded-Host`, so
   `request.url_root` at `threat_intel.py:118` is attacker-influenceable. A poisoned
   host puts an attacker-controlled "View credential" link inside a breach alert —
   a high-yield phishing position, since recipients are primed to click urgently.
   Add `APP_BASE_URL` to config; use `request.url_root` only as a fallback when unset.
2. **Explicit field allowlist.** Only username, domain, matched_domain, file_name,
   source, type, date are rendered. If `BreachedCredDoc` later grows a `password`
   attribute, the template remains structurally incapable of leaking it.
3. **Escape into attributes, not just text.** `quote=True` everywhere;
   `urllib.parse.quote` on `es_id` before it enters a URL path.
4. **Strip CR/LF from subject and recipients**, and validate recipients before
   `sendmail()`. The subject embeds `company_name`, which is admin-controlled input.
5. **One message per recipient.** Already the behavior; locked in by test so it is not
   later "optimized" into a shared CC that leaks the client list.

## Testing

Extend `tests/test_email_service.py`:

- subject/count and card count match the input creds
- `matched_domain` and `file_name` still surface (existing assertions)
- a `text/plain` part is produced and contains the credential data
- values are wrapped in app-owned anchors (autolink defense)
- a cred carrying a `password` attribute never leaks it into html or text
- `_clean_header` strips CR/LF from a company name with embedded newlines
- `_cred_url` returns `None` without a base_url and quotes odd `es_id`s
- `send_email` builds `multipart/alternative` and rejects malformed recipients

Then a live send to `test@dseclab.mn` for visual confirmation.

## Out of scope

- Jinja template files (considered, user chose the Python builder)
- Logo image embedding (CID/hosted) — text wordmark chosen so nothing is image-blocked
- Localization; the app is English-only with no i18n framework
