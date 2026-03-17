# Comprehensive Code Improvement — Design Spec

**Date:** 2026-03-17
**Target:** DSECLab Backend (staterkit) — Threat Intelligence & Breached Credentials Management System
**Stack:** Flask, SQLAlchemy, Bootstrap 5, SQLite (migrating to PostgreSQL)
**Users:** Client-facing (external organizations log in to see their breach data)

---

## 1. Security Hardening

### 1.1 Consolidate `_build_domain_match_query`
- **Current:** Identical ~40-line function in `admin_routes.py`, `threat_intel.py`, and `services/breached_creds_service.py`
- **Fix:** Keep only the one in `services/breached_creds_service.py`. Import it in `admin_routes.py` and `threat_intel.py`.

### 1.2 Sanitize search input
- **Current:** `search_routes.py` passes raw user input to `ilike()` without sanitization.
- **Fix:** Apply `sanitize_input` (from `threat_intel.py`) to search query. Move `sanitize_input` to a shared utility (e.g., `api_utils.py`).

### 1.3 Remove password from search
- **Current:** `threat_intel.py:201` includes `BreachedCredential.password` in search filter.
- **Fix:** Remove password field from search query filters.

### 1.4 Validate `next` URL on login redirect
- **Current:** `auth.py:64-65` redirects to unvalidated `next` parameter — open redirect risk.
- **Fix:** Validate that `next` URL is relative (starts with `/` and not `//`).

### 1.5 Add rate limiting
- **Current:** No brute-force protection on login endpoints.
- **Fix:** Add `flask-limiter` with limits on `/login` (5/minute), `/api/auth/login` (10/minute), `/register` (3/minute).

### 1.6 Fail loudly on missing SECRET_KEY
- **Current:** Hardcoded fallback secret key in `__init__.py:21`.
- **Fix:** In production config, require `SECRET_KEY` env var. Keep fallback only for dev config.

### 1.7 Generic error messages
- **Current:** `add_company`, `delete_company` expose raw `str(e)` to users.
- **Fix:** Flash generic "An error occurred" message. Log full exception server-side.

### 1.8 Fix missing OperationalError import
- **Current:** `threat_intel.py:411` references `OperationalError` without importing it.
- **Fix:** Add `from sqlalchemy.exc import OperationalError` import.

---

## 2. Code Quality & Deduplication

### 2.1 Consolidate domain match query
- Delete `_build_domain_match_query` from `admin_routes.py` and `threat_intel.py`
- Import from `services.breached_creds_service` in both files

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
- Replace all `current_user.role == 'admin' or current_user.isAdmin` checks (~15 occurrences) with `current_user.is_admin_user`
- Update `can_edit()` and `can_delete()` to use `self.is_admin_user`
- Update `admin_required` decorator to use `current_user.is_admin_user`

### 2.5 Fix CSV export indentation bug
- **Current:** `threat_intel.py:648-664` — the `for cred in breached_creds` loop runs outside the `else` block.
- **Fix:** Indent the loop to be inside the `else` block.

### 2.6 Remove unused `Todo` model
- Delete `Todo` class from `models.py`
- Remove `Todo` from import in `__init__.py:163`

### 2.7 Add audit logging to admin CRUD
- Add `log_audit` calls to: `add_user`, `edit_user`, `delete_user`, `add_company`, `edit_company`, `delete_company`

### 2.8 Extract watchlist domain collection
- Add `Company.get_match_domains()` method that returns `[company.domain] + [entry.entry_value for entry in watchlist_entries]`
- Use this method everywhere instead of repeating the collection logic

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
    CACHE_DEFAULT_TIMEOUT = 300

class DevelopmentConfig(BaseConfig):
    SECRET_KEY = 'dev-secret-key-change-me'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///cuba.db'
    SESSION_COOKIE_SECURE = False
    CACHE_TYPE = 'simple'
    DEBUG = True

class ProductionConfig(BaseConfig):
    SECRET_KEY = os.environ['SECRET_KEY']  # Fails if not set
    SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']
    SESSION_COOKIE_SECURE = True
    CACHE_TYPE = 'redis'
```

### 3.2 Database-agnostic date queries
- Replace `func.strftime('%Y-%m-%d', ...)` in `routes.py:98` with `func.cast(BreachedCredential.created_at, db.Date)` which works on both SQLite and PostgreSQL.

### 3.3 Update requirements.txt
- Add `psycopg2-binary>=2.9.0`
- Add `flask-limiter>=3.0.0`
- Remove `Flask-Admin>=1.6.0` (unused)

### 3.4 Timezone-aware datetimes
- Replace `datetime.datetime.utcnow` with `lambda: datetime.now(timezone.utc)` in model defaults.
- Update `datetime.utcnow()` calls in route handlers.

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

### 4.9 Notification polling
- Increase interval from 30 seconds to 60 seconds

---

## 5. Cleanup

### 5.1 Remove dead code
- Delete commented-out Flask-Admin blocks in `__init__.py` (lines 109-132)
- Delete duplicate `load_user` comment block (lines 167-169)
- Delete SassMiddleware comment block (lines 96-106)

### 5.2 Update `.gitignore`
- Add `__pycache__/`, `*.pyc`, `instance/`, `venv/`

### 5.3 Replace `print()` with `logging`
- Add `import logging` and `logger = logging.getLogger(__name__)` to `audit_helpers.py` and `threat_intel.py`
- Replace `print()` calls with `logger.error()` / `logger.warning()`

### 5.4 Add `services/__init__.py`
- Create empty `__init__.py` for proper package resolution

### 5.5 Consolidate entry points
- Keep `app.py` as the single entry point
- Remove `run.py` or make it import from `app.py`

---

## Files Modified

| File | Changes |
|------|---------|
| `config.py` | **New** — configuration classes |
| `cuba/__init__.py` | Use config classes, remove dead code, remove inline config |
| `cuba/models.py` | Add `is_admin_user` property, `Company.get_match_domains()`, remove `Todo`, timezone-aware datetimes |
| `cuba/routes.py` | Import from security.py, fix date query for PostgreSQL |
| `cuba/auth.py` | Validate `next` URL, rate limiting |
| `cuba/admin_routes.py` | Remove duplicate `_build_domain_match_query`, use service imports, add audit logging, use `is_admin_user` |
| `cuba/threat_intel.py` | Remove duplicate function/imports, fix CSV bug, fix missing import, use `is_admin_user` |
| `cuba/security.py` | Use `is_admin_user` property |
| `cuba/search_routes.py` | Add sanitization, fix DB-level filtering |
| `cuba/api_utils.py` | Add shared `sanitize_input` |
| `cuba/audit_helpers.py` | Replace print with logging |
| `cuba/notification_routes.py` | No backend changes |
| `cuba/services/__init__.py` | **New** — empty package init |
| `cuba/services/breached_creds_service.py` | Single source for domain match query |
| `requirements.txt` | Add psycopg2-binary, flask-limiter; remove Flask-Admin |
| `.gitignore` | Add pycache, instance, venv |
| Templates (multiple) | Pagination selector, loading states, empty states, password masking, flash auto-dismiss, breadcrumb fixes |

---

## Out of Scope
- Full PostgreSQL migration (schema creation, data migration) — only adding support
- React/frontend rewrite
- Docker/deployment setup
- Automated test suite (would be a separate spec)
