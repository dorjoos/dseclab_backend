# D-SECLAB Flask Application Security Audit

**Date**: 2026-03-19
**Scope**: `/Users/jooy/Development/dseclab_backend/staterkit/cuba/`
**Methodology**: Manual source code review, OWASP Top 10 focus

---

## Summary

The D-SECLAB threat intelligence platform has a generally solid security posture for admin-guarded routes: CSRF protection is enabled globally, admin routes use decorators, and SQLAlchemy ORM prevents classic SQL injection. However, the audit identified **17 vulnerabilities** across multiple severity levels, with the most critical issues being mass assignment leading to privilege escalation, SSRF via the geolocation service, missing permission checks on export functionality, and a hardcoded development secret key that persists into production deployments.

---

## Findings

---

### 1. CRITICAL -- Mass Assignment: Self-Registration with Arbitrary Role/Permissions

**File**: `cuba/auth.py`, line 230
**CWE**: CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)

**Description**: The registration endpoint creates a `User` object with `role='member'` hardcoded on line 230, which is correct. However, the `permissions` field on the User model (line 69 of `models.py`) defaults to an empty string. The registration endpoint does NOT explicitly set `permissions=''`. While Flask-WTF CSRF is present, the real concern is the **profile update endpoint**.

**Actual Critical Path -- Profile Update**: In `auth.py` lines 266-320, the profile POST handler only processes `username`, `email`, and password fields. It does NOT process `role`, `isAdmin`, or `permissions` from the request form. This is SAFE.

**However**, the admin `edit_user` endpoint at `admin_routes.py:221-222 reads permissions directly from `request.form.getlist('permissions')` and sets `user.permissions = ','.join(permissions)`. This is admin-only and correct.

**Revised Assessment**: Registration and profile are safe against mass assignment. Downgrading.

**Severity**: LOW (design is actually safe for self-service endpoints)

---

### 2. HIGH -- SSRF via Geolocation Service (ip-api.com)

**File**: `cuba/services/geo_service.py`, lines 10-31
**CWE**: CWE-918 (Server-Side Request Forgery)

**Description**: The `get_location()` function constructs a URL by directly concatenating user-influenced data:
```python
GEO_API = "http://ip-api.com/json/"
resp = requests.get(GEO_API + ip_address, ...)
```

The `ip_address` comes from `request.remote_addr` (via `audit_helpers.py:15`), which is typically safe. However, if the application is deployed behind a reverse proxy and `request.remote_addr` is overridden by headers like `X-Forwarded-For` (a common Flask pattern), an attacker could inject arbitrary IP addresses or even path traversal characters to redirect the outbound HTTP request.

More critically, even with the current `request.remote_addr` source, the IP value is passed unsanitized into a URL. If `ip_address` contains characters like `/../` or query parameters, it could alter the target URL.

**Exploitation**: An attacker behind a proxy could set `X-Forwarded-For: 127.0.0.1/../../other-endpoint` or a hostname that resolves to internal infrastructure.

**Severity**: HIGH (SSRF to external service, potential for internal network probing if proxy misconfigured)

**Suggested Fix**: Validate that `ip_address` matches a strict IP regex (`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$` or valid IPv6) before making the request. Use `ipaddress` module for validation.

---

### 3. HIGH -- Hardcoded Development Secret Key

**File**: `config.py`, lines 47-48
**CWE**: CWE-798 (Use of Hard-coded Credentials)

**Description**: The development configuration uses a hardcoded fallback:
```python
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', SECRET_KEY)
```

The production config at line 59 falls back to an empty string:
```python
SECRET_KEY = os.environ.get('SECRET_KEY', '')
```

While `__init__.py:31-32` raises `RuntimeError` if `SECRET_KEY` is not set in production, the check is `not app.config.get('SECRET_KEY')` which means an empty string evaluates falsy and triggers the error. However, if someone deploys with `FLASK_CONFIG=development` in production (which is the default at line 27: `config_name = os.environ.get('FLASK_CONFIG', 'development')`), the hardcoded key `dev-secret-key-change-in-production` is used.

**Impact**: Anyone who knows this key (it is in the public source code) can forge session cookies and JWT tokens, achieving full authentication bypass and admin impersonation.

**Severity**: HIGH (authentication bypass in misconfigured deployments, which is the default)

**Suggested Fix**: Remove the hardcoded fallback; require SECRET_KEY via environment variable in all configurations. Change the default FLASK_CONFIG to `production`.

---

### 4. HIGH -- WebSocket Broadcast Leaks Breach Data to All Users

**File**: `cuba/ws_events.py`, lines 19-21; `cuba/threat_intel.py`, lines 344-351
**CWE**: CWE-200 (Exposure of Sensitive Information)

**Description**: When a new breached credential is added, `broadcast_new_breach()` emits the event to ALL connected WebSocket clients:
```python
def broadcast_new_breach(breach_data):
    socketio.emit('new_breach', breach_data, namespace='/')
```

This broadcasts `es_id`, `username`, `domain`, `source`, and `type` to every authenticated user, regardless of their company affiliation. A member of Company A will receive real-time notifications about breaches belonging to Company B, completely bypassing the domain-based access control enforced on all HTTP endpoints.

**Exploitation**: Any authenticated user connects via WebSocket and passively receives all new breach data in real time.

**Severity**: HIGH (cross-tenant data leak, breaks the entire multi-tenant isolation model)

**Suggested Fix**: Use SocketIO rooms per company/domain. On connect, join the user to their company's room. Emit breach events only to the relevant room(s).

---

### 5. HIGH -- SocketIO CORS Wildcard

**File**: `cuba/__init__.py`, line 40
**CWE**: CWE-942 (Permissive Cross-domain Policy)

**Description**:
```python
socketio.init_app(app, cors_allowed_origins="*")
```

The WebSocket server accepts connections from any origin. Combined with finding #4, any website can open a WebSocket connection to the D-SECLAB server (if the user has an active session) and receive breach data.

**Exploitation**: Attacker hosts a malicious page that opens a WebSocket to the D-SECLAB server. If a logged-in user visits the page, the attacker's JavaScript receives all `new_breach` and `stats_update` events.

**Severity**: HIGH (cross-origin WebSocket hijacking for data exfiltration)

**Suggested Fix**: Set `cors_allowed_origins` to the specific deployment domain(s).

---

### 6. HIGH -- Password Exposed in Breached Credential Detail View

**File**: `cuba/templates/threat_intel/breached_creds_view.html`, line 67
**CWE**: CWE-200 (Exposure of Sensitive Information)

**Description**: The credential detail template renders the raw password:
```html
<span class="revealed-password">{{ breached_cred.password }}</span>
```

The `data_masking.py` service exists but is never called in the view route (`breached_creds_view` at `threat_intel.py:306-319`). The `DATA_MASKING` config specifies that `member` role users should see masked passwords, but this masking is not enforced anywhere in the actual rendering path.

While the list API at line 289 hardcodes `'********'`, the detail view shows the real password to all authenticated users including members.

**Exploitation**: Any authenticated member can view the detail page for any credential they have domain access to and see the plaintext password.

**Severity**: HIGH (sensitive data exposure; the masking service exists but is dead code)

**Suggested Fix**: Apply `mask_value('password', cred.password)` in the view route before passing to the template, or call it in the template via a filter.

---

### 7. MEDIUM -- 2FA Setup Accepts Client-Supplied Secret (TOTP Secret Injection)

**File**: `cuba/auth.py`, lines 334-351
**CWE**: CWE-287 (Improper Authentication)

**Description**: During 2FA setup, the server generates a random TOTP secret and sends it to the client. On POST, the client sends back both the `token` and the `secret`:
```python
token = request.form.get("token", "").strip()
secret = request.form.get("secret", "").strip()
totp = pyotp.TOTP(secret)
if totp.verify(token):
    current_user.totp_secret = secret
```

The server trusts the client-supplied `secret` rather than storing it server-side (e.g., in the session). An attacker who can intercept or tamper with the form can set an arbitrary TOTP secret of their choosing.

**Exploitation**: An attacker who compromises a user's session (XSS, session fixation) can set a known TOTP secret, enabling persistent 2FA bypass even after the user changes their password.

**Severity**: MEDIUM (requires existing session compromise, but amplifies impact)

**Suggested Fix**: Store the generated secret in the server-side session during GET, and retrieve it from the session during POST verification instead of accepting it from the form.

---

### 8. MEDIUM -- 2FA Disable Has No Re-authentication

**File**: `cuba/auth.py`, lines 368-375
**CWE**: CWE-306 (Missing Authentication for Critical Function)

**Description**: The 2FA disable endpoint requires only `@login_required` and a POST request:
```python
@auth.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    current_user.totp_secret = None
    current_user.totp_enabled = False
```

There is no password confirmation or TOTP code verification before disabling 2FA. If an attacker gains access to an active session (e.g., via session fixation, XSS, or physical access to an unlocked browser), they can disable 2FA permanently.

**Severity**: MEDIUM (session hijack escalation, security downgrade without re-authentication)

**Suggested Fix**: Require the current password and/or a valid TOTP code before allowing 2FA to be disabled.

---

### 9. MEDIUM -- 2FA Brute-Force: No Rate Limiting on Verification

**File**: `cuba/auth.py`, lines 378-418
**CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts)

**Description**: The `verify_2fa` route has no `@limiter.limit()` decorator. TOTP codes are 6 digits (1,000,000 possibilities) with a 30-second window. The `pyotp.TOTP.verify()` method by default accepts the current and adjacent time windows, effectively giving a 90-second validity window.

An attacker who knows a user's password (from a breached credential, for example) can pass the first auth factor and then brute-force the 6-digit TOTP code without rate limiting.

**Exploitation**: After passing password auth, session gets `2fa_user_id`. Automated script sends POST requests to `/2fa/verify` with incrementing 6-digit codes. At 100 requests/second, the full keyspace can be exhausted in ~2.8 hours (within TOTP window overlap, many fewer are needed).

**Severity**: MEDIUM (2FA bypass via brute force)

**Suggested Fix**: Add `@limiter.limit("5/minute")` to the `verify_2fa` route. Add a lockout after N failed attempts.

---

### 10. MEDIUM -- No Permission Check on Export (Missing `export` Permission Enforcement)

**File**: `cuba/threat_intel.py`, lines 457-600
**CWE**: CWE-862 (Missing Authorization)

**Description**: The User model defines granular permissions including `export` (`models.py:69`). The `has_permission()` method and `permission_required` decorator exist in `security.py:24-37`. However, the `breached_creds_export` route at line 458 only requires `@login_required` -- it does NOT check `permission_required('export')`.

Any authenticated user (even a `member` with no explicit permissions) can export all breached credentials they have domain access to. The permissions system is defined but not enforced on the export endpoint.

**Exploitation**: A member user without the `export` permission can access `/threat-intelligence/breached-creds/export?format=json` and download all matching credentials.

**Severity**: MEDIUM (authorization bypass for data export)

**Suggested Fix**: Add `@permission_required('export')` decorator to the export route.

---

### 11. MEDIUM -- CSP Allows unsafe-inline and unsafe-eval

**File**: `cuba/__init__.py`, lines 103-111
**CWE**: CWE-79 (Cross-site Scripting)

**Description**: The Content Security Policy includes:
```
script-src 'self' 'unsafe-inline' 'unsafe-eval';
style-src 'self' 'unsafe-inline';
```

Both `unsafe-inline` and `unsafe-eval` are present in `script-src`, which effectively negates XSS protection from CSP. If any XSS vector exists (e.g., stored XSS through Elasticsearch data rendered in templates), CSP will not block execution.

**Severity**: MEDIUM (defense-in-depth weakness; no standalone exploit but removes a mitigation layer)

**Suggested Fix**: Replace inline scripts with nonce-based CSP (`'nonce-<random>'`). Remove `unsafe-eval` unless explicitly needed (e.g., for charting libraries).

---

### 12. MEDIUM -- Elasticsearch TLS Certificate Verification Disabled by Default

**File**: `config.py`, line 24; `cuba/services/elasticsearch_service.py`, line 133
**CWE**: CWE-295 (Improper Certificate Validation)

**Description**:
```python
ELASTICSEARCH_VERIFY_CERTS = os.environ.get('ELASTICSEARCH_VERIFY_CERTS', 'false').lower() == 'true'
```
Default is `false`, meaning TLS certificate verification is disabled. The ES client is initialized with `verify_certs=False`. This allows MITM attacks between the application and Elasticsearch, potentially exposing all breached credential data in transit.

**Severity**: MEDIUM (MITM on ES connection; depends on network topology)

**Suggested Fix**: Default to `true` and require explicit opt-out. Provide CA certificate configuration.

---

### 13. MEDIUM -- Session Not Invalidated on Password Change

**File**: `cuba/auth.py`, lines 296-308
**CWE**: CWE-613 (Insufficient Session Expiration)

**Description**: When a user changes their password via the profile page, the password is updated but the session is not regenerated or invalidated. If an attacker has stolen a session cookie, it remains valid even after the victim changes their password.

Similarly, when an admin deactivates a user (`is_active=False`) via `admin_routes.py:168,217`, existing sessions for that user are not invalidated. The deactivated user remains logged in until their session expires naturally.

**Severity**: MEDIUM (stolen sessions survive password changes and account deactivation)

**Suggested Fix**: After password change, call `session.regenerate()` or `logout_user()` + `login_user()`. For deactivation, implement a session version check in `load_user()`.

---

### 14. MEDIUM -- Production SECRET_KEY Can Be Empty String

**File**: `config.py`, lines 59-60
**CWE**: CWE-798 (Use of Hard-coded Credentials)

**Description**: The production config sets:
```python
SECRET_KEY = os.environ.get('SECRET_KEY', '')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', os.environ.get('SECRET_KEY', ''))
```

While `__init__.py:31` checks `not app.config.get('SECRET_KEY')`, an empty string is falsy and triggers the RuntimeError. However, `SESSION_COOKIE_SECURE` defaults to `false`:
```python
SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
```

In production, session cookies are NOT marked Secure by default, allowing them to be transmitted over HTTP.

**Severity**: MEDIUM (session cookie sent over plaintext HTTP in production if not explicitly configured)

**Suggested Fix**: Default `SESSION_COOKIE_SECURE` to `True` in production config.

---

### 15. LOW -- Notification Mark-Read Leaks Existence of Other Users' Notifications

**File**: `cuba/notification_routes.py`, lines 68-96
**CWE**: CWE-200 (Information Exposure Through Discrepancy)

**Description**: The `mark_read` endpoint first calls `get_or_404(id)` and then checks `notification.user_id != current_user.id`. This means:
- If a notification ID exists but belongs to another user: returns 403
- If a notification ID does not exist: returns 404

An attacker can enumerate valid notification IDs by distinguishing 403 from 404 responses. While the impact is limited (notification IDs are sequential integers), it leaks information about system activity.

**Severity**: LOW (information leakage, no direct data exposure)

**Suggested Fix**: Query with both `id` and `user_id` in a single query to always return 404 for unauthorized access.

---

### 16. LOW -- Error Handler Leaks Exception Details to Client

**File**: `cuba/notification_routes.py`, line 96
**CWE**: CWE-209 (Generation of Error Message Containing Sensitive Information)

**Description**:
```python
except Exception as e:
    return json_error(str(e), status_code=500)
```

The raw exception message is returned to the client. Depending on the exception, this could leak database schema information, file paths, or internal configuration details.

**Severity**: LOW (information leakage in error responses)

**Suggested Fix**: Return a generic error message; log the detailed exception server-side.

---

### 17. LOW -- IP Address from request.remote_addr is Unreliable Behind Proxies

**File**: `cuba/audit_helpers.py`, line 15; `cuba/__init__.py`, line 19
**CWE**: CWE-348 (Use of Less Trusted Source)

**Description**: The rate limiter uses `get_remote_address` and the audit logger uses `request.remote_addr`. Behind a reverse proxy (nginx, Cloudflare, etc.), `remote_addr` will be the proxy's IP, not the client's. This means:
1. Rate limiting is applied per-proxy-IP (ineffective; all users share the same limit)
2. Audit logs record the proxy IP, not the actual client IP

**Severity**: LOW (rate limit bypass and audit log corruption when behind a proxy)

**Suggested Fix**: Use `ProxyFix` middleware or configure `key_func` for the limiter to read `X-Forwarded-For` with proper trust chain validation.

---

## Positive Security Observations

The following areas are well-implemented:

1. **CSRF Protection**: Globally enabled via Flask-WTF, tokens present in forms, only Swagger endpoint exempted.
2. **SQL Injection Prevention**: All database queries use SQLAlchemy ORM with parameterized queries. The `escape_like()` helper properly escapes LIKE wildcards.
3. **Admin Route Protection**: All admin routes consistently use both `@login_required` and `@admin_required` decorators.
4. **Input Sanitization**: `sanitize_input()` uses `html.escape()` for user-facing text. Jinja2 auto-escaping prevents template XSS.
5. **Safe URL Redirect**: `is_safe_url()` validates redirect targets against open redirect attacks.
6. **Password Hashing**: Uses `werkzeug.security.generate_password_hash` (pbkdf2 by default).
7. **Login Rate Limiting**: `/login` is rate-limited to 5/minute.
8. **Notification Access Control**: `mark_read` correctly checks `notification.user_id != current_user.id`.
9. **Domain-Based Tenant Isolation**: ES queries consistently apply domain filters for non-admin users via `_get_domain_filters()`.
10. **Registration Guard**: Self-registration can be disabled via config flag `ALLOW_SELF_REGISTRATION`.

---

## Severity Summary

| Severity | Count | Findings |
|----------|-------|----------|
| CRITICAL | 0     | --       |
| HIGH     | 5     | #2 (SSRF), #3 (Hardcoded Secret), #4 (WebSocket Leak), #5 (CORS Wildcard), #6 (Password Exposure) |
| MEDIUM   | 8     | #7 (2FA Secret Injection), #8 (2FA No Re-auth), #9 (2FA Brute-force), #10 (Missing Export Permission), #11 (Weak CSP), #12 (ES TLS Disabled), #13 (Session Not Invalidated), #14 (Cookie Not Secure) |
| LOW      | 4     | #1 (Mass Assignment - Safe), #15 (Notification Enumeration), #16 (Error Leak), #17 (Proxy IP) |

---

## Priority Remediation Order

1. **Immediate**: Fix #3 (hardcoded secret key) and #5 (WebSocket CORS wildcard)
2. **Urgent**: Fix #4 (WebSocket broadcast leak) and #6 (password exposure in detail view)
3. **Short-term**: Fix #2 (SSRF), #7-#9 (2FA weaknesses), #10 (export permissions)
4. **Medium-term**: Fix #11-#14 (CSP, TLS, session management)
5. **Low priority**: Fix #15-#17 (information leakage, proxy issues)
