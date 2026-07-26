# Design: Resend Email Notifications + matched_domain + Creds Search Fix

**Date:** 2026-07-26
**Status:** Approved (user: "go")

## Problem

1. **Email notifications don't work.** `services/email_service.py` uses `smtplib` but `MAIL_USERNAME/PASSWORD` are unset, so `send_email()` only logs a warning and returns `False`. We want real delivery via **Resend (SMTP relay)**.
2. **"Employee creds search doesn't work."** Root cause: when Elasticsearch is down, `es_service.search()` catches the exception and **silently returns empty results** (`ESPagination([], …)`), so the UI shows an empty table indistinguishable from "no matches".
3. **No `matched_domain`.** When a credential matches a company's watchlist, we don't surface *which* watched domain matched — needed in the UI and the notification email.
4. **`file_name` not surfaced.** ES docs carry `file_name` (stealer-log source file); it should appear in notifications.
5. **No watchlist filter.** Users want to filter the breached-creds list by a watched domain and see the `matched_domain` per row.

## Approach

Reuse the existing `smtplib` code with Resend's SMTP relay (config-only) rather than adding the Resend HTTP SDK — smallest change, matches the chosen delivery method.

## Components

### 1. Resend SMTP email (config)
- `.env` (gitignored): `RESEND_API_KEY`, `MAIL_SERVER=smtp.resend.com`, `MAIL_PORT=587`, `MAIL_USE_TLS=true`, `MAIL_USERNAME=resend`, `MAIL_PASSWORD=${RESEND_API_KEY}`, `MAIL_FROM=<verified sender>`.
- `config.py` already reads all `MAIL_*` from env — no code change. `MAIL_DEFAULT_SENDER` maps to `MAIL_FROM`.
- `services/email_service.py`: keep `send_email()`; add `build_breach_email(company_name, creds, base_url)` → `(subject, html)` including domain, **matched_domain**, **file_name**, source, date, link.

### 2. matched_domain
- `breached_creds_service.py`: add suffix-aware `compute_matched_domain(doc, domains)` (mirrors `build_domain_filter` logic in Python) returning the watched domain that matched, else `None`.
- Attach `matched_domain` to each `BreachedCredDoc` in the company creds view (and where domains are known).
- Show a `matched_domain` column in `admin/company_breached_creds.html` and in the email.

### 3. file_name
- Surface `BreachedCredDoc.file_name` in the notification email and the creds table.

### 4. Watchlist filter
- `admin/company_breached_creds.html`: dropdown of the company's watched domains (`?watchlist=<domain>`); when selected, search filters to that single domain. `matched_domain == domain` rows are clearly visible.

### 5. Notification triggers
- **Auto (new breach):** extend `_notify_new_breach` (fires from `breached_creds_add`) to email the company's users in addition to in-app notifications, including matched_domain + file_name. Email failure must not break the add flow (soft-fail, logged).
- **Manual (admin):** `POST /admin/companies/<id>/notify-breaches` + a "Notify company" button on the company creds page — emails the company's active users a summary of matched breaches.

### 6. Silent-failure fix
- Add `error=False` to `ESPagination`; set `error=True` in `search()`'s `except`.
- Views (`company_breached_creds`, `breached_creds_list`) check `pagination.error` and flash "Elasticsearch unavailable — check that ES is running" instead of showing a misleading empty table.

## Testing
- Unit tests: `compute_matched_domain` (suffix-aware, subdomain, email-host, url-host; `ibank.mn` must not match `nibank.mn`); email HTML builder with mocked `smtplib`; `ESPagination.error` propagation.
- App import / byte-compile clean.

## Security
- Resend API key must be stored only in `.env` (gitignored, confirmed untracked). The key shared in chat is considered exposed and should be rotated in the Resend dashboard.

## Out of scope
- match-ransomware CLI email (deferred; user chose auto + manual only).
- Resend HTTP SDK.
