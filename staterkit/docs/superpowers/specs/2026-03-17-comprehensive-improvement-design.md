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

## 6. Elasticsearch Live Query Integration

### Overview
Replace local SQLite/PostgreSQL storage for breached credentials with live queries to Elasticsearch.

- **ES Cluster:** `https://localhost:9200` (Elasticsearch 8.x, TLS, basic auth)
- **Index:** `main` (392,804 documents)
- **Auth:** Basic auth (`elastic` user)

**Architecture split:**
- **Elasticsearch:** All breached credential data (search, list, stats, exports). Source of truth for breach data.
- **SQLite/PostgreSQL:** Users, companies, watchlists, audit logs, notifications, and breach metadata (marks/reviews).

### 6.1 ES Document Schema (from `main` index)

```json
{
  "type": "url",
  "source": "Telegram",
  "url": "https://accounts.mobicom.mn",
  "username": "94281723",
  "password": "mrgmss88L59L219f#@",
  "domain": "mobicom.mn",
  "timestamp": "2025-11-30T00:38:22.855026",
  "date_added": "2025-12-01T...",
  "file_hash": "...",
  "file_name": "...",
  "value": "..."
}
```

### 6.2 Field mapping: ES → App

| ES Field | App Usage | Notes |
|----------|-----------|-------|
| `_id` | Unique identifier | ES auto-generated, used to link local metadata |
| `type` | Credential type | `url`, etc. |
| `source` | Data source | `Telegram`, etc. |
| `url` | Associated URL | Full URL |
| `username` | Breached username | May be email, phone, or username |
| `password` | Breached password | Displayed masked, reveal on click |
| `domain` | Domain | May be null — extract from `url` or `username` if missing |
| `timestamp` | When breach occurred | Primary date field |
| `date_added` | When added to ES | Secondary date |
| `file_hash` | Source file hash | For provenance tracking |
| `file_name` | Source file name | For provenance tracking |
| `value` | Additional value | Context-dependent |

### 6.3 New service: `cuba/services/elasticsearch_service.py`

Create a centralized ES client service:

```python
class ElasticsearchService:
    """Handles all Elasticsearch queries for breached credentials."""

    def __init__(self, app=None):
        self.client = None
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize from Flask app config."""
        from elasticsearch import Elasticsearch
        self.client = Elasticsearch(
            app.config['ELASTICSEARCH_URL'],
            basic_auth=(
                app.config['ELASTICSEARCH_USER'],
                app.config['ELASTICSEARCH_PASSWORD']
            ),
            verify_certs=app.config.get('ELASTICSEARCH_VERIFY_CERTS', False),
            ssl_show_warn=False
        )
        self.index = app.config.get('ELASTICSEARCH_INDEX', 'main')

    def search(self, query_text, filters=None, page=1, per_page=20, sort='timestamp:desc'):
        """Search breached credentials with filters and pagination."""
        ...

    def get_by_id(self, doc_id):
        """Get single document by ES _id."""
        ...

    def get_stats(self, domain_filters=None):
        """Get aggregated statistics (by type, source, domain, trends)."""
        ...

    def get_daily_trends(self, days=30, domain_filters=None):
        """Get daily counts for chart data."""
        ...

    def export(self, filters=None, domain_filters=None, max_records=10000):
        """Scroll through all matching records for export."""
        ...

    def build_domain_filter(self, domains):
        """Build ES bool query for domain/watchlist matching."""
        ...
```

**Key methods explained:**

- `search()` — Uses ES `bool` query with `must`/`filter` clauses. Supports text search across `username`, `domain`, `url`, `source` fields. Pagination via `from`/`size`.
- `get_stats()` — Uses ES `aggregations` (terms agg on `type.keyword`, `source.keyword`, `domain.keyword`, date histogram on `timestamp`). Single query returns all stats.
- `build_domain_filter()` — Translates watchlist domains into ES `bool.should` with `wildcard`, `match`, and `term` queries (equivalent of current SQLAlchemy `ilike` logic).
- `export()` — Uses ES `search_after` or `scroll` API for large exports without loading all into memory.

### 6.4 Local metadata model: `BreachedCredMeta`

Replace `BreachedCredential` model with a lightweight metadata table:

```python
class BreachedCredMeta(db.Model):
    """Local metadata for ES breached credentials (marks, reviews)."""
    id = db.Column(db.Integer, primary_key=True)
    es_id = db.Column(db.String(200), unique=True, nullable=False, index=True)  # ES _id
    is_marked = db.Column(db.Boolean, default=False)
    marked_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    marked_at = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text, nullable=True)  # Analyst notes
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
```

- When a user marks/reviews a credential, create/update a `BreachedCredMeta` row keyed by `es_id`
- When listing credentials, batch-fetch metadata for the current page's ES `_id`s
- The old `BreachedCredential` model is removed

### 6.5 Config additions

```python
class BaseConfig:
    ...
    ELASTICSEARCH_URL = os.environ.get('ELASTICSEARCH_URL', 'https://localhost:9200')
    ELASTICSEARCH_USER = os.environ.get('ELASTICSEARCH_USER', 'elastic')
    ELASTICSEARCH_PASSWORD = os.environ.get('ELASTICSEARCH_PASSWORD', '')
    ELASTICSEARCH_INDEX = os.environ.get('ELASTICSEARCH_INDEX', 'main')
    ELASTICSEARCH_VERIFY_CERTS = os.environ.get('ELASTICSEARCH_VERIFY_CERTS', 'false').lower() == 'true'
```

### 6.6 Requirements addition

- Add `elasticsearch>=8.0.0` to `requirements.txt`

### 6.7 Route changes

All routes that currently query `BreachedCredential` via SQLAlchemy will be updated to use `ElasticsearchService`:

| Route | Current (SQLAlchemy) | New (ES) |
|-------|---------------------|----------|
| Dashboard (`routes.py`) | `BreachedCredential.query.count()`, date grouping | `es.get_stats()`, `es.get_daily_trends()` |
| Breached creds list (`threat_intel.py`) | `BreachedCredential.query.filter(...)` | `es.search()` with filters |
| Breached cred detail (`threat_intel.py`) | `BreachedCredential.query.get_or_404(id)` | `es.get_by_id(id)` + `BreachedCredMeta` lookup |
| Analysis (`threat_intel.py`) | Multiple aggregation queries | `es.get_stats()` with aggregations |
| Export (`threat_intel.py`) | `query.all()` | `es.export()` with scroll |
| Search (`search_routes.py`) | `BreachedCredential.query.filter(ilike)` | `es.search()` |
| Admin company breached creds (`admin_routes.py`) | `BreachedCredential.query.filter(domain)` | `es.search(domain_filters=...)` |
| Mark/unmark (`threat_intel.py`) | Update `BreachedCredential` row | Update `BreachedCredMeta` row |
| Add breached cred (`threat_intel.py`) | Insert into SQLite | Index into ES via `es.client.index()` |
| Edit/delete (`threat_intel.py`) | Update/delete SQLite row | Update/delete ES document |

### 6.8 Domain/watchlist filtering in ES

The current SQLAlchemy `_build_domain_match_query` translates to an ES query like:

```json
{
  "bool": {
    "should": [
      {"wildcard": {"domain.keyword": {"value": "*example.com*"}}},
      {"wildcard": {"username.keyword": {"value": "*@example.com"}}},
      {"wildcard": {"username.keyword": {"value": "*@*.example.com"}}},
      {"wildcard": {"url": {"value": "*example.com*"}}}
    ],
    "minimum_should_match": 1
  }
}
```

This is built by `ElasticsearchService.build_domain_filter()` using the same watchlist domains from `Company.get_match_domains()`.

### 6.9 Pagination with ES

ES uses `from`/`size` for pagination (not SQLAlchemy's `.paginate()`):
- Create a `ESPagination` helper class that mimics Flask-SQLAlchemy's pagination interface (`items`, `page`, `pages`, `total`, `has_prev`, `has_next`) so templates work without changes.

### 6.10 What gets removed

- `BreachedCredential` model from `models.py`
- All `_build_domain_match_query` functions (replaced by ES query builder)
- `apply_breached_domain_filter` from `breached_creds_service.py` (replaced by ES)
- `build_analysis_stats` rewritten to use ES aggregations
- SQLite-specific date queries in `routes.py` (replaced by ES date histogram)

---

## Files Modified (updated)

| File | Changes |
|------|---------|
| `config.py` | **New** — configuration classes with JWT_SECRET_KEY, rate limit storage, ES config |
| `cuba/__init__.py` | Use config classes, remove dead code, init ES service |
| `cuba/models.py` | Add `is_admin_user`, `Company.get_match_domains()`, remove `Todo`, remove `BreachedCredential`, add `BreachedCredMeta`, timezone-aware datetimes |
| `cuba/routes.py` | Import from security.py, use ES service for dashboard stats |
| `cuba/auth.py` | Validate `next` URL, rate limiting, disable self-registration by default |
| `cuba/admin_routes.py` | Remove duplicate functions, use ES for company breached creds, add audit logging, use `is_admin_user` |
| `cuba/threat_intel.py` | Rewrite to use ES service, fix CSV bug, use `is_admin_user`, password masking |
| `cuba/security.py` | Use `is_admin_user` property, keep watchlist helpers |
| `cuba/search_routes.py` | Use ES service for search, add sanitization, use `is_admin_user` |
| `cuba/api_utils.py` | Add shared `sanitize_input` and `escape_like` utilities |
| `cuba/audit_helpers.py` | Replace print with logging, use savepoints |
| `cuba/notification_routes.py` | Generic error messages, replace print with logging |
| `cuba/services/__init__.py` | **New** — empty package init |
| `cuba/services/elasticsearch_service.py` | **New** — ES client, search, stats, export, domain filtering, pagination helper |
| `cuba/services/breached_creds_service.py` | Rewrite: remove SQLAlchemy query builders, keep as thin adapter over ES service |
| `cuba/services/filters.py` | Keep for non-ES date filters (audit logs, etc.) |
| `requirements.txt` | Add elasticsearch, psycopg2-binary, flask-limiter; remove Flask-Admin |
| `.gitignore` | Add pycache, instance, venv, *.db |
| Templates (multiple) | Pagination selector, loading states, empty states, password masking, flash auto-dismiss, breadcrumb fixes, notification polling interval |

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
- ES cluster management, scaling, or index lifecycle policies
