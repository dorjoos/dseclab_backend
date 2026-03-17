# Comprehensive Code Improvement Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve the DSECLab threat intelligence platform with security hardening, code deduplication, Elasticsearch live query integration, and UI/UX polish.

**Architecture:** Replace SQLite-based breach storage with live Elasticsearch queries. Keep SQLite/PostgreSQL for relational data (users, companies, watchlists, audit). Add config management, rate limiting, and input sanitization.

**Tech Stack:** Flask, SQLAlchemy, Elasticsearch 8.x (`elasticsearch` Python client), Bootstrap 5, ApexCharts

**Spec:** `docs/superpowers/specs/2026-03-17-comprehensive-improvement-design.md`

**ES Connection:** `https://localhost:9200`, user `elastic`, index `main` (392K docs), TLS with self-signed cert

---

## Chunk 1: Foundation — Config, Requirements, Cleanup, Models

### Task 1: Create `config.py` and update requirements

**Files:**
- Create: `config.py`
- Modify: `requirements.txt`
- Modify: `cuba/__init__.py`

- [ ] **Step 1: Create `config.py`**

```python
# config.py
import os
from datetime import timedelta


class BaseConfig:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
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

    # Elasticsearch
    ELASTICSEARCH_URL = os.environ.get('ELASTICSEARCH_URL', 'https://localhost:9200')
    ELASTICSEARCH_USER = os.environ.get('ELASTICSEARCH_USER', 'elastic')
    ELASTICSEARCH_PASSWORD = os.environ.get('ELASTICSEARCH_PASSWORD', '')
    ELASTICSEARCH_INDEX = os.environ.get('ELASTICSEARCH_INDEX', 'main')
    ELASTICSEARCH_VERIFY_CERTS = os.environ.get('ELASTICSEARCH_VERIFY_CERTS', 'false').lower() == 'true'

    # Feature flags
    ALLOW_SELF_REGISTRATION = os.environ.get('ALLOW_SELF_REGISTRATION', 'false').lower() == 'true'


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', SECRET_KEY)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///cuba.db')
    SESSION_COOKIE_SECURE = False
    CACHE_TYPE = 'simple'
    ALLOW_SELF_REGISTRATION = True


class ProductionConfig(BaseConfig):
    SECRET_KEY = os.environ['SECRET_KEY']
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', os.environ['SECRET_KEY'])
    SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']
    SESSION_COOKIE_SECURE = True
    CACHE_TYPE = os.environ.get('CACHE_TYPE', 'simple')
    CACHE_REDIS_URL = os.environ.get('CACHE_REDIS_URL')
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig,
}
```

- [ ] **Step 2: Update `requirements.txt`**

```
Flask>=2.0.0
Flask-SQLAlchemy>=3.0.0
Flask-Login>=0.6.0
Flask-Assets>=2.0
Flask-WTF>=1.0.0
WTForms>=3.0.0
Flask-Caching>=2.0.0
libsass>=0.21.0
openpyxl>=3.1.0
reportlab>=4.0.0
Flask-Migrate>=4.0.0
flask-jwt-extended>=4.5.0
flask-limiter>=3.0.0
psycopg2-binary>=2.9.0
elasticsearch>=8.0.0
```

Remove `Flask-Admin>=1.6.0` (unused).

- [ ] **Step 3: Rewrite `cuba/__init__.py` to use app factory pattern**

Replace entire file. Key changes:
- Use `create_app()` factory function
- Load config from `config.py`
- Init all extensions via `init_app()`
- Init ES service
- Remove all commented-out Flask-Admin code
- Remove SassMiddleware comment block
- Remove duplicate `load_user` block
- Use `db.session.get()` instead of deprecated `Query.get()`

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_assets import Environment
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
cache = Cache()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)


def create_app(config_name=None):
    app = Flask(__name__)

    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'development')
    from config import config as config_dict
    app.config.from_object(config_dict[config_name])

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    cache.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    Environment(app)

    from .services.elasticsearch_service import es_service
    es_service.init_app(app)

    @app.context_processor
    def inject_csrf_token():
        from flask_wtf.csrf import generate_csrf
        return dict(csrf_token=generate_csrf)

    @app.context_processor
    def inject_default_breadcrumb():
        return dict(breadcrumb=None)

    @app.template_filter('format_number')
    def format_number_filter(value):
        try:
            return f"{int(value):,}"
        except (ValueError, TypeError):
            return value

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self';",
        )
        return response

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = "warning"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        from .models import User
        return db.session.get(User, int(user_id))

    from .routes import main as main_bp
    app.register_blueprint(main_bp)
    from .auth import auth as auth_bp
    app.register_blueprint(auth_bp)
    from .threat_intel import threat_intel as threat_intel_bp
    app.register_blueprint(threat_intel_bp)
    from .admin_routes import admin_bp
    app.register_blueprint(admin_bp)
    from .search_routes import search_bp
    app.register_blueprint(search_bp)
    from .notification_routes import notification_bp
    app.register_blueprint(notification_bp)

    @app.errorhandler(403)
    def forbidden_error(error):
        from flask import render_template
        return render_template('pages/error-pages/error-403.html'), 403

    @app.errorhandler(404)
    def not_found_error(error):
        from flask import render_template
        return render_template('pages/error-pages/error-404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        from flask import render_template
        db.session.rollback()
        return render_template('pages/error-pages/error-500.html'), 500

    return app
```

- [ ] **Step 4: Update `app.py` to use factory**

```python
from cuba import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, port=8003)
```

- [ ] **Step 5: Update `.gitignore`**

Append: `__pycache__/`, `*.pyc`, `instance/`, `venv/`, `*.db`, `.env`

- [ ] **Step 6: Install new dependencies**

Run: `cd /Users/jooy/Development/dseclab_backend/staterkit && pip install elasticsearch flask-limiter psycopg2-binary`

- [ ] **Step 7: Commit**

```bash
git add config.py requirements.txt cuba/__init__.py app.py .gitignore
git commit -m "feat: add config management, app factory, update dependencies"
```

---

### Task 2: Update models — `is_admin_user`, `Company.get_match_domains()`, `BreachedCredMeta`, remove `Todo`

**Files:**
- Modify: `cuba/models.py`

- [ ] **Step 1: Rewrite `cuba/models.py`**

Key changes:
- Add `is_admin_user` property to `User`
- Update `can_edit()` and `can_delete()` to use it
- Add `Company.get_match_domains()` method
- Remove `Todo` model
- Remove `BreachedCredential` model (replaced by ES)
- Add `BreachedCredMeta` model for local mark/review metadata
- Use timezone-aware `utcnow()` helper

Full replacement provided in spec section 6.4 and 2.4. See `cuba/models.py` in source for current state.

The new models file keeps: `Company`, `User`, `BreachedCredMeta` (new), `WatchlistEntry`, `Notification`, `AuditLog`, `UserActivity`.

Removes: `Todo`, `BreachedCredential`.

- [ ] **Step 2: Commit**

```bash
git add cuba/models.py
git commit -m "feat: update models - add is_admin_user, BreachedCredMeta, remove Todo and BreachedCredential"
```

---

### Task 3: Update shared utilities — `api_utils.py`, `security.py`, `audit_helpers.py`

**Files:**
- Modify: `cuba/api_utils.py`
- Modify: `cuba/security.py`
- Modify: `cuba/audit_helpers.py`
- Create: `cuba/services/__init__.py`

- [ ] **Step 1: Add `sanitize_input` and `escape_like` to `cuba/api_utils.py`**

Append to existing file:

```python
import html

def sanitize_input(text: str) -> str:
    if not text:
        return ""
    return html.escape(str(text).strip())

def escape_like(value: str) -> str:
    if not value:
        return ""
    return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
```

- [ ] **Step 2: Update `cuba/security.py` — use `is_admin_user`, simplify with `Company.get_match_domains()`**

Remove `can_user_access_breached_cred` and `requires_breached_cred_access` (no longer needed — ES handles access via domain filters). Keep `admin_required`, `get_user_company_domain`, `get_user_watchlist_domains`. Use `current_user.is_admin_user` instead of `current_user.role == 'admin' or current_user.isAdmin`. Replace `print()` with `logging`.

- [ ] **Step 3: Update `cuba/audit_helpers.py` — use logging, savepoints**

Replace `print()` with `logger.error()`. Use `db.session.begin_nested()` for audit writes.

- [ ] **Step 4: Create `cuba/services/__init__.py`**

Empty file for proper package resolution.

- [ ] **Step 5: Create `BreachedCredMeta` table**

Run `db.create_all()` early so the new model is available for all subsequent tasks:

```bash
cd /Users/jooy/Development/dseclab_backend/staterkit
python3 -c "
from app import app
from cuba import db
with app.app_context():
    db.create_all()
    print('Tables created successfully')
"
```

- [ ] **Step 6: Commit**

```bash
git add cuba/api_utils.py cuba/security.py cuba/audit_helpers.py cuba/services/__init__.py
git commit -m "feat: update utilities - sanitization, is_admin_user, logging, savepoints, create BreachedCredMeta table"
```

---

## Chunk 2: Elasticsearch Service

### Task 4: Create `cuba/services/elasticsearch_service.py`

**Files:**
- Create: `cuba/services/elasticsearch_service.py`
- Modify: `cuba/services/breached_creds_service.py`

- [ ] **Step 1: Create the ES service**

New file containing:
- `ESPagination` class — mimics Flask-SQLAlchemy pagination interface (`items`, `page`, `pages`, `total`, `has_prev`, `has_next`, `iter_pages()`)
- `BreachedCredDoc` class — wraps ES document with attribute access matching old `BreachedCredential` model interface. Field mapping:
  - `es_id` / `id` ← ES `_id`
  - `username` ← `source.username`
  - `domain` ← `source.domain`
  - `password` ← `source.password`
  - `source` (property alias `source_name`) ← `source.source`
  - `type` ← `source.type`
  - `url` ← `source.url`
  - `timestamp` ← `source.timestamp` (parsed to datetime)
  - `created_at` (property) ← returns `timestamp` or `date_added`
  - `date_added` ← `source.date_added`
  - `file_hash` ← `source.file_hash`
  - `file_name` ← `source.file_name`
  - `value` ← `source.value`
  - `type_color` (property) ← color mapping same as old model
  - `is_marked`, `marked_by`, `marked_at`, `marker`, `notes` ← populated from `BreachedCredMeta` via `_attach_metadata()`
- `ElasticsearchService` class with methods:
  - `init_app(app)` — connect to ES from Flask config
  - `search(query_text, filters, domain_filters, page, per_page)` — full-text search with pagination. **IMPORTANT: `multi_match` fields list MUST NOT include `password`** — only searches `username`, `domain`, `url`, `source`
  - `get_by_id(doc_id)` — single document lookup
  - `get_stats(domain_filters)` — aggregated stats (by_type, by_source, by_domain)
  - `get_daily_trends(days, domain_filters)` — date histogram for charts
  - `get_recent(limit, domain_filters)` — latest N documents
  - `export(filters, domain_filters, max_records)` — scroll API for exports
  - `index_document(doc)` — add new document
  - `update_document(doc_id, doc)` — update document
  - `delete_document(doc_id)` — delete document
  - `build_domain_filter(domains)` — watchlist matching as ES bool/should query
- `es_service` singleton instance

ES config keys: `ELASTICSEARCH_URL`, `ELASTICSEARCH_USER`, `ELASTICSEARCH_PASSWORD`, `ELASTICSEARCH_INDEX`, `ELASTICSEARCH_VERIFY_CERTS`

Full implementation in plan body (see spec section 6.3, 6.8, 6.9).

- [ ] **Step 2: Simplify `cuba/services/breached_creds_service.py`**

Replace with thin adapter that delegates to `es_service` and `get_user_watchlist_domains()`. Keep `build_analysis_stats()` function using ES.

- [ ] **Step 3: Commit**

```bash
git add cuba/services/elasticsearch_service.py cuba/services/breached_creds_service.py
git commit -m "feat: add Elasticsearch service with search, stats, export, domain filtering"
```

---

## Chunk 3: Route Rewrites

### Task 5: Rewrite `cuba/routes.py` (dashboard) to use ES

**Files:**
- Modify: `cuba/routes.py`

- [ ] **Step 1: Rewrite `routes.py`**

- Remove `get_user_company_domain` (import from `security.py`)
- Remove all `BreachedCredential` imports and SQLAlchemy queries
- Use `es_service.get_stats()` for stat cards
- Use `es_service.get_daily_trends()` for chart data
- Use `es_service.get_recent()` for latest events table

- [ ] **Step 2: Commit**

```bash
git add cuba/routes.py
git commit -m "feat: rewrite dashboard to use Elasticsearch for stats and trends"
```

---

### Task 6: Rewrite `cuba/threat_intel.py` to use ES

**Files:**
- Modify: `cuba/threat_intel.py`

- [ ] **Step 1: Rewrite `threat_intel.py`**

Major changes:
- Remove `_build_domain_match_query` (use ES `build_domain_filter`)
- Remove `sanitize_input` (import from `api_utils`)
- Remove duplicate imports
- All queries use `es_service` instead of SQLAlchemy
- Route URL params change from `<int:id>` to `<doc_id>` (ES string IDs)
- Mark/unmark uses `BreachedCredMeta` table
- Add/edit/delete go through ES API
- Export masks passwords as `********`
- Fix CSV indentation bug (was in old code)
- Use `is_admin_user` for permission checks
- Use `logging` instead of `print`
- Add `_attach_metadata()` helper to batch-load local marks for displayed items

- [ ] **Step 2: Commit**

```bash
git add cuba/threat_intel.py
git commit -m "feat: rewrite threat_intel to use Elasticsearch for all breach queries"
```

---

### Task 7: Update `cuba/auth.py` — security fixes

**Files:**
- Modify: `cuba/auth.py`

- [ ] **Step 1: Add `next` URL validation and rate limiting**

- Add `is_safe_url(target)` helper (check relative URL, no netloc)
- Add `@limiter.limit()` decorators on login/register
- Add registration gate checking `ALLOW_SELF_REGISTRATION` config
- Validate `next` param before redirect

- [ ] **Step 2: Commit**

```bash
git add cuba/auth.py
git commit -m "fix: add URL validation, rate limiting, registration gate to auth"
```

---

### Task 8: Update `cuba/admin_routes.py` — use ES, audit logging

**Files:**
- Modify: `cuba/admin_routes.py`

- [ ] **Step 1: Key changes**

- Remove `build_domain_match_query` function
- Remove `BreachedCredential` from imports
- Use `es_service` for `company_breached_creds` and `company_management` stats
- Use `company.get_match_domains()` for domain collection
- Use `current_user.is_admin_user` where applicable
- Add `log_audit` calls to all CRUD operations (create_user, update_user, delete_user, create_company, update_company, delete_company)
- Replace raw `str(e)` in flash/jsonify with generic "An error occurred"

- [ ] **Step 2: Commit**

```bash
git add cuba/admin_routes.py
git commit -m "feat: admin routes use ES, add audit logging, generic errors"
```

---

### Task 9: Update `cuba/search_routes.py` and `cuba/notification_routes.py`

**Files:**
- Modify: `cuba/search_routes.py`
- Modify: `cuba/notification_routes.py`

- [ ] **Step 1: Rewrite `search_routes.py` to use ES**

- Use `es_service.search()` instead of SQLAlchemy
- Apply domain filters at query level for non-admin users
- Use `sanitize_input` from `api_utils`
- Use `current_user.is_admin_user`
- Use `cred.es_id` in URLs

- [ ] **Step 2: Update `notification_routes.py` — generic errors, logging**

- Replace `traceback.print_exc()` with `logger.exception(...)`
- Replace `str(e)` in JSON responses with generic message

- [ ] **Step 3: Commit**

```bash
git add cuba/search_routes.py cuba/notification_routes.py
git commit -m "feat: search uses ES, generic error messages in notifications"
```

---

### Task 10: Update templates for ES identifiers

**Files:**
- Modify: `cuba/templates/threat_intel/breached_creds_list.html`
- Modify: `cuba/templates/threat_intel/breached_creds_view.html`
- Modify: `cuba/templates/threat_intel/breached_creds_form.html`
- Modify: `cuba/templates/general/index.html`

- [ ] **Step 1: Update breached_creds_list.html**

- Change `id=cred.id` to `doc_id=cred.es_id` in all `url_for()` calls
- Remove `Score` column (not applicable from ES)
- `cred.created_at` works via `BreachedCredDoc.created_at` property
- Add password reveal toggle: replace the existing password cell with a click-to-reveal using an eye icon button. Use `data-password` attribute and toggle visibility via JS class toggle (no innerHTML).
- Add per-page selector dropdown (10/20/50) next to the pagination controls
- Add empty state with icon when no results: `<td colspan="..." class="text-center p-4"><i data-feather="inbox"></i><p>No breached credentials found</p></td>`
- Replace `onsubmit="return confirm(...)"` on delete forms with SweetAlert confirmation

- [ ] **Step 2: Update breached_creds_view.html**

- Change `cred.id` to `cred.es_id` in all URL references
- Add password masking with click-to-reveal eye icon toggle

- [ ] **Step 3: Update index.html (dashboard)**

- Change `event.id` to `event.es_id` in `url_for()` calls

- [ ] **Step 4: Update admin templates**

- `admin/user_management.html` — add empty state, SweetAlert delete confirmation, per-page selector
- `admin/company_management.html` — add empty state, SweetAlert delete confirmation, per-page selector
- `admin/company_breached_creds.html` — change `cred.id` to `cred.es_id`, add empty state, per-page selector

- [ ] **Step 5: Fix breadcrumb order in route handlers**

Standardize across ALL pages to: `{"parent": "Section", "child": "Page"}`.
Routes to update:
- `admin_routes.py`: user_management, add_user, edit_user, company_management, add_company, edit_company, company_breached_creds, audit_logs, user_activities
- `threat_intel.py`: breached_creds_list, breached_creds_view, breached_creds_add, breached_creds_edit, analysis, reports
- `routes.py`: indexPage

- [ ] **Step 6: Add shared SweetAlert delete confirmation JS**

Add to `base.html` a reusable function for delete confirmations:
```javascript
document.querySelectorAll('form[data-confirm]').forEach(function(form) {
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        var msg = form.getAttribute('data-confirm') || 'Are you sure?';
        if (typeof Swal !== 'undefined') {
            Swal.fire({
                title: 'Confirm',
                text: msg,
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#dc3545',
                confirmButtonText: 'Yes, delete'
            }).then(function(result) {
                if (result.isConfirmed) form.submit();
            });
        } else if (confirm(msg)) {
            form.submit();
        }
    });
});
```
Then update all delete forms to use `data-confirm="..."` attribute and remove inline `onsubmit`.

- [ ] **Step 7: Commit**

```bash
git add cuba/templates/
git commit -m "feat: update templates - ES identifiers, breadcrumbs, empty states, password masking, delete confirmations, per-page selector"
```

---

## Chunk 4: UI/UX Polish & Final Verification

### Task 11: UI improvements — flash messages, loading states, notification polling

**Files:**
- Modify: `cuba/templates/base.html`
- Modify: `cuba/templates/layout/header.html`

- [ ] **Step 1: Add auto-dismiss flash messages and loading state JS to `base.html`**

Add a `<script>` block before `</body>` that:
- Selects all `.alert` elements and fades them out after 5 seconds using `style.opacity` and `setTimeout` with `element.remove()`
- On form submit, disables the submit button and shows a `.spinner-border` element

Note: Use DOM APIs (`element.textContent`, `element.classList`, `element.style`) for safe manipulation. Do not use `innerHTML` with user-provided content.

- [ ] **Step 2: Update notification polling interval in `header.html`**

Find the `setInterval` for notification polling and change from `30000` to `60000`.

- [ ] **Step 3: Commit**

```bash
git add cuba/templates/base.html cuba/templates/layout/header.html
git commit -m "feat: auto-dismiss flash messages, loading states, 60s notification poll"
```

---

### Task 12: Delete `run.py`, clean up

**Files:**
- Delete: `run.py`

- [ ] **Step 1: Remove `run.py`**

Delete the file. `app.py` is the sole entry point.

- [ ] **Step 2: Commit**

```bash
git rm run.py
git commit -m "chore: remove duplicate run.py entry point"
```

---

### Task 13: Verify ES connection and app startup

**Prerequisites:** Set `ELASTICSEARCH_PASSWORD` in your `.env` file or environment. Do NOT hardcode credentials in commands or plan documents.

- [ ] **Step 1: Verify ES connection**

```bash
cd /Users/jooy/Development/dseclab_backend/staterkit
python3 -c "
from app import app
with app.app_context():
    from cuba.services.elasticsearch_service import es_service
    stats = es_service.get_stats()
    print(f'ES connected. Total docs: {stats[\"total\"]}')
"
```

(Ensure `ELASTICSEARCH_PASSWORD` is set in your environment before running.)

- [ ] **Step 2: Commit any remaining changes**

```bash
git add -A
git commit -m "feat: verify ES integration"
```

---

### Task 14: End-to-end verification

- [ ] **Step 1: Start the app and verify all pages load**

```bash
cd /Users/jooy/Development/dseclab_backend/staterkit
python3 app.py
```

(Ensure `ELASTICSEARCH_PASSWORD` is set in your environment.)

Verify these URLs work (after logging in):
1. `http://localhost:8003/` — Dashboard loads with ES stats
2. `http://localhost:8003/threat-intelligence/breached-creds` — List shows ES data
3. `http://localhost:8003/threat-intelligence/analysis` — Analysis page works
4. `http://localhost:8003/admin/companies` — Company management with ES breach counts
5. `http://localhost:8003/api/search?q=mobicom` — Search returns ES results

- [ ] **Step 2: Fix any issues found during verification**

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "fix: address issues found during end-to-end verification"
```
