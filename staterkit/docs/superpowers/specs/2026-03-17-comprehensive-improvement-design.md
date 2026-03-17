# Comprehensive Code Improvement — Design Spec

**Date:** 2026-03-17
**Target:** DSECLab Backend (staterkit) — Threat Intelligence & Breached Credentials Management System
**Stack:** Flask, SQLAlchemy, Bootstrap 5, SQLite (migrating to PostgreSQL)
**Users:** Client-facing (external organizations log in to see their breach data)

---

## 1. Security Hardening

### 1.1 Sanitize search input and escape LIKE wildcards
- **Current:** `search_routes.py` passes raw user input to `ilike()` without sanitization. `threat_intel.py` uses `html.escape` via `sanitize_input` but does not escape SQL LIKE wildcards (`%`, `_`).
- **Fix:** Create a shared `sanitize_input` in `api_utils.py` for HTML escaping. Add a separate `escape_like(value)` utility that escapes `%`, `_`, and `\` for safe use in LIKE/ILIKE queries. Apply both where needed.

### 1.2 Remove password from search and export search filters
- **Current:** `threat_intel.py:201` and `threat_intel.py:498` include `BreachedCredential.password` in search/export filters.
- **Fix:** Remove password field from all search query filters. Add a configurable option for whether exports include plaintext passwords (default: masked). For client-facing exports, passwords should be masked as `********` unless the admin explicitly opts in.

### 1.3 Validate `next` URL on login redirect
- **Current:** `auth.py:64-65` redirects to unvalidated `next` parameter — open redirect risk.
- **Fix:** Validate that `next` URL is relative (starts with `/` and not `//`).

### 1.4 Add rate limiting
- **Current:** No brute-force protection on login endpoints.
- **Fix:** Add `flask-limiter` with limits on `/login` (5/minute), `/api/auth/login` (10/minute), `/register` (3/minute). Use `memory://` storage for dev, configure Redis URI for production via `RATELIMIT_STORAGE_URI` env var.

### 1.5 Fail loudly on missing SECRET_KEY
- **Current:** Hardcoded fallback secret key in `__init__.py:21`.
- **Fix:** In production config, require `SECRET_KEY` env var (raise on missing). Keep fallback only for dev config.

### 1.6 Generic error messages for all endpoints
- **Current:** `admin_routes.py` (`add_company`, `delete_company`), `notification_routes.py` (get_notifications), and watchlist endpoints (`add_watchlist_entry`, `delete_watchlist_entry`) expose raw `str(e)` to users.
- **Fix:** Flash/return generic "An error occurred" message for all. Log full exception server-side via `logging`.

### 1.7 Fix missing OperationalError import
- **Current:** `threat_intel.py:411` references `OperationalError` without importing it.
- **Fix:** Add `from sqlalchemy.exc import OperationalError` import.

### 1.8 Disable open self-registration
- **Current:** `/register` is publicly accessible. A user registering with `user@existing-client.com` gets auto-linked to that client's company and can see their breached data.
- **Fix:** Disable self-registration by default. Add an admin "invite user" flow. Keep `/register` behind a feature flag (`ALLOW_SELF_REGISTRATION` env var, default `False`).

---

## 2. Code Quality & Deduplication

### 2.1 Consolidate `_build_domain_match_query`
- **Current:** Identical ~40-line function in `admin_routes.py:17-61`, `threat_intel.py:47-91`, and `services/breached_creds_service.py:10-47`.
- **Fix:** Keep only the one in `services/breached_creds_service.py`. Import it in `admin_routes.py` and `threat_intel.py`. (This also addresses the security concern of maintaining one correct implementation.)

### 2.2 Consolidate `get_user_company_domain`
- Delete the version in `routes.py:12-18`
- Import from `security.py` in `routes.py`

### 2.3 Fix duplicate imports in `threat_intel.py`
- Remove duplicate `from .security import (...)` block at lines 38-42

### 2.4 Add `is_admin_user` property to User model
```python
@property
def is_admin_user(self) -> bool:
    return self.role == 'admin' or self.isAdmin
```
- Replace all **Python-side** `current_user.role == 'admin' or current_user.isAdmin` checks with `current_user.is_admin_user`
- Update `can_edit()` and `can_delete()` to use `self.is_admin_user`
- Update `admin_required` decorator to use `current_user.is_admin_user`
- **Note:** SQLAlchemy query filter expressions (e.g., in `_notify_new_breach` at `threat_intel.py:108-135`) must keep using `User.role == 'admin'` and `User.isAdmin == True` since Python properties cannot be used in SQL queries.
- Also update `search_routes.py:33,49` to use `current_user.is_admin_user`

### 2.5 Fix CSV export indentation bug
- **Current:** `threat_intel.py:648-664` — the `for cred in breached_creds` loop runs outside the `else` block.
- **Fix:** Indent the loop to be inside the `else` block.

### 2.6 Remove unused `Todo` model
- Delete `Todo` class from `models.py`
- Remove `Todo` from import in `__init__.py:163`

### 2.7 Add audit logging to admin CRUD
- Add `log_audit` calls to: `add_user`, `edit_user`, `delete_user`, `add_company`, `edit_company`, `delete_company`
- Action types: `create_user`, `update_user`, `delete_user`, `create_company`, `update_company`, `delete_company`
- For update operations: capture `old_values` and `new_values` dicts (changed fields only)
- Log on both success and failure (with `status='failed'` and `error_message`)
- Use `db.session.begin_nested()` (savepoint) for audit writes to avoid interfering with the caller's transaction

### 2.8 Extract watchlist domain collection
- Add `Company.get_match_domains()` instance method that returns `[self.domain] + [entry.entry_value for entry in self.watchlist_entries]` (deduped, lowercased, non-empty)
- Use in admin routes (where a specific company object is available) and in security helpers (via `current_user.company.get_match_domains()`)

---

## 3. PostgreSQL Support & Configuration

### 3.1 Add `config.py`
```python
class BaseConfig:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600
    JWT_TOKEN_LOCATION = ['headers']
    JWT_HEADER_NAME = 'Authorization'
    JWT_HEADER_TYPE = 'Bearer'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')  # Falls back to SECRET_KEY if None
    CACHE_DEFAULT_TIMEOUT = 300

class DevelopmentConfig(BaseConfig):
    SECRET_KEY = 'dev-secret-key-change-me'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///cuba.db')
    SESSION_COOKIE_SECURE = False
    CACHE_TYPE = 'simple'
    DEBUG = True
    ALLOW_SELF_REGISTRATION = True

class ProductionConfig(BaseConfig):
    SECRET_KEY = os.environ['SECRET_KEY']  # Fails if not set
    SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']
    SESSION_COOKIE_SECURE = True
    CACHE_TYPE = os.environ.get('CACHE_TYPE', 'simple')
    CACHE_REDIS_URL = os.environ.get('CACHE_REDIS_URL')
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')
```

### 3.2 Database-agnostic date queries
- Replace `func.strftime('%Y-%m-%d', ...)` in `routes.py:98` with `func.date(BreachedCredential.created_at)` which works as a built-in function in both SQLite and PostgreSQL.

### 3.3 Update requirements.txt
- Add `psycopg2-binary>=2.9.0`
- Add `flask-limiter>=3.0.0`
- Remove `Flask-Admin>=1.6.0` (unused)

### 3.4 Timezone-aware datetimes
- Replace `datetime.datetime.utcnow` with `lambda: datetime.now(timezone.utc)` in model defaults.
- Update `datetime.utcnow()` calls in route handlers.
- **Note:** SQLite stores datetimes without timezone info. When running on SQLite (dev), ensure comparisons remain compatible by stripping tzinfo at the query boundary if needed. Test both backends.

---

## 4. UI/UX Polish

### 4.1 Standardize pagination
- Set default `per_page = 20` across all list views
- Add per-page selector dropdown (10/20/50) to all paginated pages

### 4.2 Loading states on forms
- Disable submit button on click, show spinner
- Add shared JavaScript utility for this pattern

### 4.3 Auto-dismiss flash messages
- Add JavaScript to auto-dismiss after 5 seconds
- Ensure close button works consistently

### 4.4 Fix search for non-admin users
- In `search_routes.py`, apply domain filter at DB query level instead of post-filtering in Python
- Use `apply_breached_domain_filter` from service layer
- Also use `current_user.is_admin_user` for admin checks

### 4.5 Empty states
- Add "No records found" message with appropriate icon for all tables
- Include action button where applicable (e.g., "Add first company")

### 4.6 Password masking
- Display passwords as `********` by default in breached creds list and detail views
- Add hover/click reveal toggle with eye icon

### 4.7 Fix breadcrumb order
- Standardize to: Section > Page (e.g., "Admin > Add User" not "Add User > Admin")

### 4.8 Delete confirmations
- Ensure all delete actions use SweetAlert confirmation dialog consistently

### 4.9 Notification polling (template change)
- Increase polling interval from 30 seconds to 60 seconds in the header template JavaScript

### 4.10 Dashboard domain filtering
- **Current:** `routes.py` dashboard uses simple `BreachedCredential.domain == user_domain` for non-admin users, while threat intel views use full watchlist matching.
- **Fix:** Use `apply_breached_domain_filter` from service layer in dashboard as well, so stats are consistent across views.

---

## 5. Cleanup

### 5.1 Remove dead code
- Delete commented-out Flask-Admin blocks in `__init__.py` (lines 109-132)
- Delete duplicate `load_user` comment block (lines 167-169)
- Delete SassMiddleware comment block (lines 96-106)

### 5.2 Update `.gitignore`
- Add `__pycache__/`, `*.pyc`, `instance/`, `venv/`, `*.db`

### 5.3 Replace `print()` with `logging`
- Add `import logging` and `logger = logging.getLogger(__name__)` to `audit_helpers.py`, `threat_intel.py`, and `notification_routes.py`
- Replace all `print()` calls with `logger.error()` / `logger.warning()`

### 5.4 Add `services/__init__.py`
- Create empty `__init__.py` for proper package resolution

### 5.5 Consolidate entry points
- Keep `app.py` as the single entry point
- Remove `run.py` or make it import from `app.py`

---

## Files Modified

| File | Changes |
|------|---------|
| `config.py` | **New** — configuration classes with JWT_SECRET_KEY, rate limit storage |
| `cuba/__init__.py` | Use config classes, remove dead code, remove inline config |
| `cuba/models.py` | Add `is_admin_user` property, `Company.get_match_domains()`, remove `Todo`, timezone-aware datetimes |
| `cuba/routes.py` | Import from security.py, fix date query with `func.date()`, use `apply_breached_domain_filter` |
| `cuba/auth.py` | Validate `next` URL, rate limiting, disable self-registration by default |
| `cuba/admin_routes.py` | Remove duplicate `_build_domain_match_query`, use service imports, add audit logging with savepoints, use `is_admin_user` |
| `cuba/threat_intel.py` | Remove duplicate function/imports, fix CSV bug, fix missing import, use `is_admin_user`, remove password from search/export filters, add password masking option for exports |
| `cuba/security.py` | Use `is_admin_user` property |
| `cuba/search_routes.py` | Add sanitization + LIKE escaping, fix DB-level filtering, use `is_admin_user` |
| `cuba/api_utils.py` | Add shared `sanitize_input` and `escape_like` utilities |
| `cuba/audit_helpers.py` | Replace print with logging, use savepoints |
| `cuba/notification_routes.py` | Generic error messages, replace print with logging |
| `cuba/services/__init__.py` | **New** — empty package init |
| `cuba/services/breached_creds_service.py` | Single source for domain match query |
| `requirements.txt` | Add psycopg2-binary, flask-limiter; remove Flask-Admin |
| `.gitignore` | Add pycache, instance, venv, *.db |
| Templates (multiple) | Pagination selector, loading states, empty states, password masking, flash auto-dismiss, breadcrumb fixes, notification polling interval |

---

## Out of Scope
- Full PostgreSQL migration (schema creation, data migration) — only adding support
- React/frontend rewrite
- Docker/deployment setup
- Automated test suite (would be a separate spec)
- Relationship between existing `migrate_*.py` scripts and Flask-Migrate (separate cleanup task)
