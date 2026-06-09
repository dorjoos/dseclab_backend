# Member Breached-Cred Password Reveal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let members reveal plaintext passwords for breached credentials owned by their company, via an audited AJAX endpoint. Server stops rendering plaintext into HTML for any role.

**Architecture:** GET `/threat-intelligence/breached-creds/<id>` always renders `********` (no plaintext for any role). New POST `/threat-intelligence/breached-creds/<id>/reveal-password` re-runs the existing `_check_cred_access` tenancy gate, writes an `AuditLog` row, and returns the plaintext as JSON. Click handler on the detail page does the fetch, injects plaintext into the DOM, and clears it on re-mask.

**Tech Stack:** Flask, Flask-WTF (CSRF via `X-CSRFToken` header), Flask-Login, Flask-Limiter, Werkzeug, vanilla JS `fetch`, pytest.

**Spec reference:** `docs/superpowers/specs/2026-06-09-member-breached-cred-password-reveal-design.md`

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `tests/__init__.py` | Create (empty) | Make `tests` a package |
| `tests/conftest.py` | Create | Pytest fixtures: app, client, DB, fake `es_service.get_by_id`, helper to log in users |
| `tests/test_breached_creds_reveal.py` | Create | All 9 behavioral tests for the reveal flow |
| `requirements.txt` | Modify | Add `pytest>=8.0`, `pytest-flask>=1.3` |
| `cuba/threat_intel.py` | Modify | Add `log_user_activity` import; change `breached_creds_view` to always mask; add `breached_creds_reveal_password` route |
| `cuba/templates/threat_intel/breached_creds_view.html` | Modify | Replace `{{ breached_cred.password }}` with hardcoded `********` placeholder; add `data-cred-id` |
| `cuba/templates/base.html` | Modify | Replace hover-based reveal with click-based AJAX reveal |

---

## Task 1: Scaffold test infrastructure

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`
- Modify: `requirements.txt`

- [ ] **Step 1: Add pytest deps to requirements**

Edit `requirements.txt`, append these two lines (preserving existing content):

```
pytest>=8.0
pytest-flask>=1.3
```

- [ ] **Step 2: Install the new deps**

```bash
source venv/bin/activate && pip install 'pytest>=8.0' 'pytest-flask>=1.3'
```

Expected: `Successfully installed pytest-... pytest-flask-...` (no errors).

- [ ] **Step 3: Create the empty package marker**

Create `tests/__init__.py` with no content (zero bytes).

- [ ] **Step 4: Create the conftest with fixtures**

Create `tests/conftest.py`:

```python
"""Pytest fixtures for dseclab tests.

Uses an in-memory SQLite DB and a monkey-patched es_service so tests
don't depend on Elasticsearch being available locally.
"""
import os
import pytest

os.environ.setdefault("FLASK_CONFIG", "development")
os.environ.setdefault("WTF_CSRF_ENABLED", "true")

from cuba import create_app, db as _db
from cuba.models import Company, User
from cuba.services.elasticsearch_service import BreachedCredDoc


@pytest.fixture()
def app():
    app = create_app()
    app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        WTF_CSRF_ENABLED=True,
        SERVER_NAME="localhost.localdomain",
        SECRET_KEY="test-secret",
    )
    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def db(app):
    return _db


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def company_acme(db):
    c = Company(name="Acme Co", domain="acme.com", company_type="customer")
    db.session.add(c)
    db.session.commit()
    return c


@pytest.fixture()
def company_other(db):
    c = Company(name="Other Co", domain="other.com", company_type="customer")
    db.session.add(c)
    db.session.commit()
    return c


def _make_user(db, *, email, role, company=None, password="Test@123"):
    u = User(username=email.split("@")[0], email=email, role=role,
             company_id=company.id if company else None, is_active=True)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture()
def member_acme(db, company_acme):
    return _make_user(db, email="alice@acme.com", role="member", company=company_acme)


@pytest.fixture()
def member_other(db, company_other):
    return _make_user(db, email="bob@other.com", role="member", company=company_other)


@pytest.fixture()
def analyst_user(db, company_acme):
    return _make_user(db, email="ana@acme.com", role="analyst", company=company_acme)


@pytest.fixture()
def admin_user(db):
    return _make_user(db, email="admin@dseclab.com", role="admin", company=None)


def login(client, email, password="Test@123"):
    """Helper: GET /login to grab CSRF, then POST credentials."""
    resp = client.get("/login")
    import re
    m = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', resp.data)
    assert m, "CSRF token not found on /login page"
    token = m.group(1).decode()
    return client.post("/login", data={
        "csrf_token": token,
        "email": email,
        "password": password,
    }, follow_redirects=False)


@pytest.fixture()
def fake_cred(monkeypatch):
    """Install a fake es_service.get_by_id and return a setter the test can call.

    Usage:
        fake_cred({"acme-1": {"username": "user@acme.com", "domain": "acme.com",
                              "password": "P@ssw0rd!"}})
    """
    from cuba.services import elasticsearch_service as es_mod
    from cuba import threat_intel as ti_mod

    store = {}

    def setter(mapping):
        store.update(mapping)

    def fake_get_by_id(doc_id):
        src = store.get(doc_id)
        if src is None:
            return None
        return BreachedCredDoc(doc_id, src)

    # Patch the binding the route actually uses.
    monkeypatch.setattr(ti_mod.es_service, "get_by_id", fake_get_by_id)
    monkeypatch.setattr(es_mod.es_service, "get_by_id", fake_get_by_id)
    return setter
```

- [ ] **Step 5: Verify pytest can collect**

```bash
source venv/bin/activate && python -m pytest tests/ --collect-only -q
```

Expected: `no tests ran in ...` (exit code 5) — fine, there are no test files yet. The important thing is no import errors / fixture errors.

- [ ] **Step 6: Commit**

```bash
git add tests/__init__.py tests/conftest.py requirements.txt
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
test: scaffold pytest infra with in-memory DB and fake es_service

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Failing test — detail page never renders plaintext

**Files:**
- Test: `tests/test_breached_creds_reveal.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_breached_creds_reveal.py`:

```python
"""Behavioral tests for the breached-cred password reveal flow.

Plan: docs/superpowers/plans/2026-06-09-member-breached-cred-password-reveal.md
"""
import pytest
from cuba.models import AuditLog, UserActivity


REAL_PASSWORD = "P@ssw0rd!Real"
CRED_ID = "acme-1"
CRED_SRC = {
    "username": "user@acme.com",
    "domain": "acme.com",
    "password": REAL_PASSWORD,
    "source": "test",
    "type": "combolist",
    "url": "https://acme.com/login",
    "timestamp": "2026-01-01T00:00:00",
}


def test_detail_page_never_contains_plaintext_member(client, member_acme, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})
    login(client, member_acme.email)
    resp = client.get(f"/threat-intelligence/breached-creds/{CRED_ID}")
    assert resp.status_code == 200
    assert REAL_PASSWORD.encode() not in resp.data, \
        "Plaintext password leaked into detail page HTML for member"


def test_detail_page_never_contains_plaintext_analyst(client, analyst_user, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})
    login(client, analyst_user.email)
    resp = client.get(f"/threat-intelligence/breached-creds/{CRED_ID}")
    assert resp.status_code == 200
    assert REAL_PASSWORD.encode() not in resp.data, \
        "Plaintext password leaked into detail page HTML for analyst"


def test_detail_page_never_contains_plaintext_admin(client, admin_user, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})
    login(client, admin_user.email)
    resp = client.get(f"/threat-intelligence/breached-creds/{CRED_ID}")
    assert resp.status_code == 200
    assert REAL_PASSWORD.encode() not in resp.data, \
        "Plaintext password leaked into detail page HTML for admin"


# `login` is defined in conftest.py — import it for use in tests.
from tests.conftest import login  # noqa: E402
```

- [ ] **Step 2: Run the test to verify it fails (admin path)**

```bash
source venv/bin/activate && python -m pytest tests/test_breached_creds_reveal.py::test_detail_page_never_contains_plaintext_admin -v
```

Expected: FAIL — admin currently sees plaintext (DATA_MASKING for admin is `[]`).

**Note:** The member and analyst tests may incidentally pass already because of `mask_value('password', ...)`. The admin test is the one that *must* fail before the fix.

---

## Task 3: Make detail page never render plaintext

**Files:**
- Modify: `cuba/threat_intel.py` (around line 321)
- Modify: `cuba/templates/threat_intel/breached_creds_view.html` (around lines 65-68)

- [ ] **Step 1: Update the route to always mask the password**

In `cuba/threat_intel.py`, replace the body of `breached_creds_view` starting from the comment `# Apply data masking to password field based on user role`. The current lines (around 320-321) are:

```python
    _attach_metadata([cred])
    # Apply data masking to password field based on user role
    cred.password = mask_value('password', cred.password)
    breadcrumb = {"parent": "Threat Intelligence", "child": "Credential Details"}
```

Replace with:

```python
    _attach_metadata([cred])
    # Server never renders plaintext password into HTML for any role.
    # Plaintext is delivered only via the reveal-password endpoint, which
    # re-runs _check_cred_access and writes an audit row per reveal.
    if cred.password:
        cred.password = '********'
    breadcrumb = {"parent": "Threat Intelligence", "child": "Credential Details"}
```

- [ ] **Step 2: Update the template to drop the Jinja interpolation**

In `cuba/templates/threat_intel/breached_creds_view.html`, find lines 64-68:

```html
            {% if breached_cred.password %}
            <div class="password-mask">
              <span class="masked-password">Click to reveal</span>
              <span class="revealed-password">{{ breached_cred.password }}</span>
            </div>
```

Replace with:

```html
            {% if breached_cred.password %}
            <div class="password-mask" data-cred-id="{{ breached_cred.es_id }}">
              <span class="masked-password">Click to reveal</span>
              <span class="revealed-password" data-placeholder="********">********</span>
              <span class="password-reveal-error" style="display:none;color:#c00;font-size:0.85em;"></span>
            </div>
```

Two changes: (a) `data-cred-id` so JS knows which endpoint to hit, (b) hardcoded `********` so plaintext is never templated in.

- [ ] **Step 3: Run all three detail-page tests**

```bash
source venv/bin/activate && python -m pytest tests/test_breached_creds_reveal.py -k "detail_page" -v
```

Expected: all three PASS.

- [ ] **Step 4: Smoke-test the running app**

If the dev server is still running (from earlier), it auto-reloads. Otherwise restart:

```bash
source venv/bin/activate && python -c "from cuba import create_app, socketio; app = create_app(); socketio.run(app, debug=True, port=8003, allow_unsafe_werkzeug=True)" &
sleep 3
```

Then verify a logged-in admin sees no plaintext on the detail page. (Skipping a curl-only check here because we'd need a real cred in ES — the pytest tests already cover the no-plaintext invariant.)

- [ ] **Step 5: Commit**

```bash
git add tests/test_breached_creds_reveal.py cuba/threat_intel.py cuba/templates/threat_intel/breached_creds_view.html
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
fix: stop rendering plaintext breached-cred passwords into HTML

Detail page now ships '********' for all roles. Plaintext will be
fetched on-demand via the reveal endpoint added in the next commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Failing tests — reveal endpoint behavior

**Files:**
- Modify: `tests/test_breached_creds_reveal.py` (append new tests)

- [ ] **Step 1: Append the endpoint tests**

Open `tests/test_breached_creds_reveal.py` and append (after the existing tests, before the `from tests.conftest import login` line — move that line to the top of the file if needed):

```python
REVEAL_PATH = f"/threat-intelligence/breached-creds/{CRED_ID}/reveal-password"


def _csrf_token(client):
    """Pull a CSRF token from the login page (sets the cookie too)."""
    import re
    r = client.get("/login")
    m = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', r.data)
    assert m, "CSRF token not found"
    return m.group(1).decode()


def test_reveal_owning_member_gets_plaintext(client, db, member_acme, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})
    login(client, member_acme.email)
    token = _csrf_token(client)
    resp = client.post(REVEAL_PATH, headers={"X-CSRFToken": token})
    assert resp.status_code == 200
    assert resp.is_json
    assert resp.get_json()["password"] == REAL_PASSWORD
    rows = AuditLog.query.filter_by(action_type="reveal_password").all()
    assert len(rows) == 1
    assert rows[0].resource_id == CRED_ID
    assert REAL_PASSWORD not in (rows[0].description or "")
    assert REAL_PASSWORD not in (rows[0].new_values or "")
    activities = UserActivity.query.filter_by(activity_type="reveal_password").all()
    assert len(activities) == 1


def test_reveal_cross_company_member_denied(client, db, member_other, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})  # cred belongs to acme.com
    login(client, member_other.email)  # user is at other.com
    token = _csrf_token(client)
    resp = client.post(REVEAL_PATH, headers={"X-CSRFToken": token})
    assert resp.status_code == 403
    assert REAL_PASSWORD.encode() not in resp.data
    granted = AuditLog.query.filter_by(action_type="reveal_password").all()
    denied = AuditLog.query.filter_by(action_type="reveal_password_denied").all()
    assert granted == [], "Denied reveal should not write a success audit row"
    assert len(denied) == 1, "Denied reveal should write a denial audit row"
    assert denied[0].resource_id == CRED_ID


def test_reveal_analyst_gets_plaintext(client, db, analyst_user, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})
    login(client, analyst_user.email)
    token = _csrf_token(client)
    resp = client.post(REVEAL_PATH, headers={"X-CSRFToken": token})
    assert resp.status_code == 200
    assert resp.get_json()["password"] == REAL_PASSWORD


def test_reveal_admin_gets_plaintext(client, db, admin_user, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})
    login(client, admin_user.email)
    token = _csrf_token(client)
    resp = client.post(REVEAL_PATH, headers={"X-CSRFToken": token})
    assert resp.status_code == 200
    assert resp.get_json()["password"] == REAL_PASSWORD
    rows = AuditLog.query.filter_by(action_type="reveal_password").all()
    assert len(rows) == 1


def test_reveal_missing_csrf_rejected(client, member_acme, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})
    login(client, member_acme.email)
    resp = client.post(REVEAL_PATH)
    assert resp.status_code == 400, f"Expected 400 without CSRF, got {resp.status_code}"


def test_reveal_unauthenticated_redirects_or_401(client, fake_cred):
    fake_cred({CRED_ID: CRED_SRC})
    resp = client.post(REVEAL_PATH)  # no login, no CSRF
    # @login_required redirects to /login when unauthenticated (302) or 401 — either is acceptable.
    assert resp.status_code in (302, 401), f"Expected 302/401, got {resp.status_code}"


def test_reveal_unknown_doc_returns_404(client, member_acme, fake_cred):
    fake_cred({})  # nothing in store
    login(client, member_acme.email)
    token = _csrf_token(client)
    resp = client.post(REVEAL_PATH, headers={"X-CSRFToken": token})
    assert resp.status_code == 404


def test_reveal_rate_limit_blocks_31st_call(client, member_acme, fake_cred):
    """The endpoint is decorated @limiter.limit('30/minute'); the 31st call returns 429."""
    from cuba import limiter
    # Reset limiter state so prior tests don't contaminate this one.
    try:
        limiter.reset()
    except Exception:
        pass
    fake_cred({CRED_ID: CRED_SRC})
    login(client, member_acme.email)
    token = _csrf_token(client)
    last_status = None
    for i in range(31):
        resp = client.post(REVEAL_PATH, headers={"X-CSRFToken": token})
        last_status = resp.status_code
        if last_status == 429:
            break
    assert last_status == 429, f"Expected 429 within 31 calls, got {last_status}"
```

- [ ] **Step 2: Run all reveal tests to verify they fail**

```bash
source venv/bin/activate && python -m pytest tests/test_breached_creds_reveal.py -k "reveal" -v
```

Expected: all FAIL with 404 (the endpoint doesn't exist yet).

---

## Task 5: Implement the reveal endpoint

**Files:**
- Modify: `cuba/threat_intel.py`

- [ ] **Step 1: Add `log_user_activity` to imports**

In `cuba/threat_intel.py` line 29, the current import is:

```python
from .audit_helpers import log_audit
```

Change to:

```python
from .audit_helpers import log_audit, log_user_activity
```

- [ ] **Step 2: Add the new route**

In `cuba/threat_intel.py`, immediately after the `breached_creds_view` function (which ends with `return render_template('threat_intel/breached_creds_view.html', breached_cred=cred, breadcrumb=breadcrumb)` around line 323-324), append a new route:

```python
@threat_intel.route('/threat-intelligence/breached-creds/<doc_id>/reveal-password', methods=['POST'])
@login_required
@limiter.limit("30/minute")
def breached_creds_reveal_password(doc_id):
    """Return the plaintext password for a breached cred the user is authorized to see.

    Gated by the same tenancy check as the detail view. Every successful and
    denied call is recorded in the audit log so reveals are accountable.
    """
    cred = es_service.get_by_id(doc_id)
    if not cred:
        return jsonify({"error": "not_found"}), 404
    if not _check_cred_access(cred):
        log_audit("reveal_password_denied", "breached_cred", doc_id,
                  f"User {current_user.username} denied reveal for cred {doc_id}",
                  status="failed")
        db.session.commit()
        return jsonify({"error": "access_denied"}), 403
    log_audit("reveal_password", "breached_cred", doc_id,
              f"User {current_user.username} revealed password for cred {doc_id} "
              f"(domain={cred.domain or 'unknown'})")
    log_user_activity("reveal_password", current_user.id, status="success")
    db.session.commit()
    return jsonify({"password": cred.password or ""})
```

Note: `db.session.commit()` after `log_audit` matches the existing pattern in `breached_creds_mark` (line ~395) — `log_audit` uses `begin_nested()` which only releases a savepoint; the outer transaction needs an explicit commit to persist the row.

- [ ] **Step 3: Run the reveal tests**

```bash
source venv/bin/activate && python -m pytest tests/test_breached_creds_reveal.py -k "reveal" -v
```

Expected: all 8 reveal tests PASS.

If `test_reveal_missing_csrf_rejected` is the only failure, double-check that `WTF_CSRF_ENABLED=True` is set in the test app config (it is in `conftest.py`). Flask-WTF returns 400 by default for missing CSRF on a POST; if the project has globally exempted the threat_intel blueprint, you may see 200 — fix by ensuring the endpoint is *not* CSRF-exempted.

- [ ] **Step 4: Run the full test file**

```bash
source venv/bin/activate && python -m pytest tests/test_breached_creds_reveal.py -v
```

Expected: all 11 tests PASS (3 detail + 8 reveal).

- [ ] **Step 5: Commit**

```bash
git add cuba/threat_intel.py tests/test_breached_creds_reveal.py
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: add audited reveal-password endpoint for breached creds

Members can fetch plaintext for creds owned by their company via
POST /threat-intelligence/breached-creds/<id>/reveal-password.
Gated by the existing _check_cred_access tenancy check. Each
success and denial writes an AuditLog row; successes also write
a UserActivity row. Rate-limited 30/min/user.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Frontend reveal handler

**Files:**
- Modify: `cuba/templates/base.html` (lines 124-134)

- [ ] **Step 1: Replace the hover-based reveal with click+AJAX reveal**

In `cuba/templates/base.html`, find lines 124-134 (the `// Password hover reveal` block):

```javascript
      // Password hover reveal
      document.querySelectorAll('.password-mask').forEach(function(mask) {
        var m = mask.querySelector('.masked-password');
        var r = mask.querySelector('.revealed-password');
        if (m && r) {
          m.style.display = 'inline';
          r.style.display = 'none';
          mask.addEventListener('mouseenter', function() { m.style.display='none'; r.style.display='inline'; });
          mask.addEventListener('mouseleave', function() { m.style.display='inline'; r.style.display='none'; });
        }
      });
```

Replace with:

```javascript
      // Password reveal: click to fetch plaintext via audited endpoint.
      // Server never sends plaintext on page load; we fetch only on demand.
      document.querySelectorAll('.password-mask').forEach(function(mask) {
        var m = mask.querySelector('.masked-password');
        var r = mask.querySelector('.revealed-password');
        var err = mask.querySelector('.password-reveal-error');
        var credId = mask.getAttribute('data-cred-id');
        if (!m || !r || !credId) return;

        m.style.display = 'inline';
        r.style.display = 'none';
        mask.style.cursor = 'pointer';

        function reMask() {
          var placeholder = r.getAttribute('data-placeholder') || '********';
          r.textContent = placeholder;
          r.style.display = 'none';
          m.style.display = 'inline';
          if (err) { err.style.display = 'none'; err.textContent = ''; }
        }

        function showError(msg) {
          if (err) {
            err.textContent = msg;
            err.style.display = 'inline';
          }
        }

        mask.addEventListener('click', function(e) {
          e.preventDefault();
          var isRevealed = r.style.display !== 'none';
          if (isRevealed) { reMask(); return; }

          if (err) { err.style.display = 'none'; err.textContent = ''; }
          fetch('/threat-intelligence/breached-creds/' + encodeURIComponent(credId) + '/reveal-password', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
              'X-CSRFToken': window.CSRF_TOKEN || '',
              'Accept': 'application/json'
            }
          }).then(function(resp) {
            if (resp.status === 401) { showError('Session expired. Please log in again.'); return null; }
            if (resp.status === 403) { showError('Access denied.'); return null; }
            if (resp.status === 404) { showError('Credential no longer exists.'); return null; }
            if (resp.status === 429) { showError('Too many reveal attempts. Try again in a minute.'); return null; }
            if (!resp.ok) { showError('Could not reveal password. Try again.'); return null; }
            return resp.json();
          }).then(function(data) {
            if (!data || typeof data.password !== 'string') return;
            r.textContent = data.password;
            r.style.display = 'inline';
            m.style.display = 'none';
          }).catch(function() {
            showError('Network error. Try again.');
          });
        });
      });
```

- [ ] **Step 2: Restart the dev server (if running) and load a detail page**

```bash
# Kill old server if needed:
lsof -ti:8003 | xargs -r kill
source venv/bin/activate && python -c "from cuba import create_app, socketio; app = create_app(); socketio.run(app, debug=True, port=8003, allow_unsafe_werkzeug=True)" &
sleep 4
```

- [ ] **Step 3: Manual smoke test in browser**

Open Chrome (or `mcp__claude-in-chrome__browser_navigate` if available) to `http://localhost:8003/login`, sign in as `admin@dseclab.com` / `Admin@123`, navigate to a breached-cred detail page that has a password, and verify:

1. Page source (View → Developer → View Source) shows `********`, NOT a real password — confirms server-side hardening.
2. Clicking the "Click to reveal" span fetches the password and displays it.
3. Clicking again re-masks to `********`.
4. `AuditLog` table shows a `reveal_password` row per click. Verify:

```bash
source venv/bin/activate && python -c "
from cuba import create_app, db
from cuba.models import AuditLog
app = create_app()
with app.app_context():
    rows = AuditLog.query.filter_by(action_type='reveal_password').order_by(AuditLog.created_at.desc()).limit(5).all()
    for r in rows:
        print(r.created_at, r.user_id, r.resource_id, r.description)
"
```

If no breached cred exists in your local ES yet, skip the click test and verify via the pytest suite only — but the page-source check (`********` in view-source) still applies for any detail page that *would* render a password.

- [ ] **Step 4: Commit**

```bash
git add cuba/templates/base.html
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: click-to-reveal password handler fetches via audited endpoint

Replaces hover-based reveal with click-based fetch to
/threat-intelligence/breached-creds/<id>/reveal-password. Plaintext
is injected into the DOM on success and cleared on re-mask. Errors
render inline below the field; plaintext never appears in an error path.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Final test sweep and cleanup

**Files:** (none — verification only)

- [ ] **Step 1: Run the full test suite**

```bash
source venv/bin/activate && python -m pytest tests/ -v
```

Expected: all 11 tests PASS, no warnings about deprecation or missing fixtures.

- [ ] **Step 2: Confirm no plaintext leak via grep**

```bash
grep -n "breached_cred.password\|cred\.password\b" cuba/templates/threat_intel/breached_creds_view.html
```

Expected output: only the `{% if breached_cred.password %}` guard line — no `{{ breached_cred.password }}` interpolation remains.

- [ ] **Step 3: Confirm the rate limit decorator is in place**

```bash
grep -B1 "def breached_creds_reveal_password" cuba/threat_intel.py
```

Expected: the line immediately above the function definition is `@limiter.limit("30/minute")`.

- [ ] **Step 4: Done — no further commit needed**

Plan complete. The work is on commits:
- Task 1: `test: scaffold pytest infra ...`
- Task 3: `fix: stop rendering plaintext breached-cred passwords ...`
- Task 5: `feat: add audited reveal-password endpoint ...`
- Task 6: `feat: click-to-reveal password handler ...`

---

## Risks & verification notes

- **Pre-existing substring-match bug in `_check_cred_access`** (`threat_intel.py:59`): a company at `co.com` can match creds at `evilco.com` via `"co.com" in "evilco.com"`. Out of scope for this plan — flagged in the spec for a separate hardening pass.
- **CSRF blueprint exemption:** if `csrf.exempt(threat_intel)` exists anywhere, the missing-CSRF test will fail (you'd get 200 instead of 400). Check `cuba/__init__.py` and `cuba/threat_intel.py` — only `flasgger.apispec` is exempted (confirmed at brainstorming time, but re-verify if Task 4 step 1 surprises).
- **ES dependency in manual smoke test (Task 6 step 3):** if the local ES has no breached creds with a password field, you can't click-test in the browser. The pytest suite covers the behavior end-to-end; the manual step is optional polish.
