# CISA KEV Vulnerabilities Page — Design

**Date:** 2026-06-10
**Status:** Draft (awaiting user review)
**Owner:** dorjsambuu

## Problem

The platform has a `cisa-kev` Elasticsearch index (1,607 documents at time of writing) populated with the public CISA Known Exploited Vulnerabilities catalog. There is no UI for browsing it. Analysts and admins need a vulnerabilities page; members need a read-only summary so they can see what's relevant without operational controls.

## Goal

Add a Vulnerabilities page that reads from the `cisa-kev` ES index, with role-aware access:

- **Admin / Analyst:** full list + filters + detail page + CSV export.
- **Member:** list-only with a reduced set of columns and JSON fields; no detail page, no export.

Refactor the ES service layer to support multiple indices cleanly: extract a thin `ESIndexService` base, rename the existing `ElasticsearchService` to `BreachedCredsService`, and add a peer `CisaKevService`. Doing this now avoids accreting duplicated ES boilerplate as more indices come online.

## Non-goals (YAGNI)

- Per-company "mark" / notes table for vulnerabilities (no `CisaKevMeta` model).
- Vendor / product autocomplete dropdowns (v1 uses plain text inputs).
- Alerts on new KEV entries matching a company's tech stack (no tech-stack model exists).
- Live-poll / WebSocket updates for new CVEs.
- Ingestion / refresh job for the `cisa-kev` index (assumed to be loaded externally).
- A generalized "any-index" service abstraction beyond what the two real consumers need today.

## Architecture

```
cuba/
├── services/
│   ├── es_base.py                     ← new: ESIndexService (thin base)
│   ├── breached_creds_service.py      ← renamed from elasticsearch_service.py
│   └── cisa_kev_service.py            ← new: CisaKevService + CisaKevDoc
├── vulnerabilities.py                 ← new: blueprint
├── templates/threat_intel/
│   ├── vulnerabilities_list.html      ← new
│   └── vulnerabilities_view.html      ← new (admin/analyst only)
└── templates/layout/sidebar.html      ← modify: add nav link
```

### `ESIndexService` (base)

Holds shared, generic Elasticsearch behavior. Stays small on purpose — common patterns only, no domain knowledge.

```python
class ESIndexService:
    def __init__(self, index_name: str): ...
    @property
    def es(self) -> elasticsearch.Elasticsearch: ...
    @property
    def index(self) -> str: ...
    def _count(self, query: dict | None = None) -> int: ...
    def _search(self, body: dict) -> dict: ...
    def get_raw(self, doc_id: str) -> tuple[str, dict] | None: ...
    def index_document(self, doc: dict) -> str | None: ...
    def update_document(self, doc_id: str, doc: dict) -> bool: ...
    def delete_document(self, doc_id: str) -> bool: ...
```

Reads `ELASTICSEARCH_URL`, `ELASTICSEARCH_USER`, `ELASTICSEARCH_PASSWORD`, `ELASTICSEARCH_VERIFY_CERTS` from `current_app.config`. Lazy client init so import order doesn't matter.

### `BreachedCredsService(ESIndexService)` (renamed)

Same code as today's `ElasticsearchService`, with class renamed and the file moved. Hosts: `get_by_id`, `search`, `get_stats`, `get_*_trends`, `_build_query`, `build_domain_filter` (the suffix-aware version we shipped in `338b512`), `BreachedCredDoc`, `ESPagination`.

Module-level singleton: `breached_creds_service = BreachedCredsService()` exported alongside the legacy `es_service = breached_creds_service` alias for one release to keep external callers green.

### `CisaKevService(ESIndexService)` (new)

```python
class CisaKevService(ESIndexService):
    def __init__(self): super().__init__(
        current_app.config.get('CISA_KEV_INDEX', 'cisa-kev')
    )
    def get_by_id(self, doc_id: str) -> CisaKevDoc | None: ...
    def search(
        self,
        query_text: str | None = None,
        filters: dict | None = None,    # vendor, product, ransomware_use,
                                        # due_date_from, due_date_to,
                                        # date_added_from, date_added_to
        page: int = 1,
        per_page: int = 20,
    ) -> ESPagination[CisaKevDoc]: ...
    def get_stats(self) -> dict: ...    # {total, by_vendor [top 10],
                                        #  by_ransomware, due_this_week, overdue}
    def _build_query(self, query_text, filters) -> dict: ...
```

### `CisaKevDoc`

Wraps an ES source. Tolerates camelCase or snake_case field names in ES (CISA's published catalog uses camelCase; an ingestion pipeline may have rewritten them).

```python
class CisaKevDoc:
    def __init__(self, es_id: str, source: dict):
        self.es_id = es_id
        s = source or {}
        def get(camel, snake): return s.get(camel) if camel in s else s.get(snake)
        self.cve_id = get('cveID', 'cve_id') or es_id
        self.vendor = get('vendorProject', 'vendor_project')
        self.product = get('product', 'product')
        self.vulnerability_name = get('vulnerabilityName', 'vulnerability_name')
        self.date_added = _parse_date(get('dateAdded', 'date_added'))
        self.short_description = get('shortDescription', 'short_description')
        self.required_action = get('requiredAction', 'required_action')
        self.due_date = _parse_date(get('dueDate', 'due_date'))
        self.known_ransomware_use = get('knownRansomwareCampaignUse', 'known_ransomware_campaign_use')
        self.notes = get('notes', 'notes')
        self.cwes = get('cwes', 'cwes') or []
```

## Routes

New blueprint `vulnerabilities` registered in `cuba/__init__.py`.

| Method | Path | Allowed roles | Purpose |
|---|---|---|---|
| GET  | `/threat-intelligence/vulnerabilities`               | member, analyst, admin | SSR shell; data loaded via AJAX |
| POST | `/api/vulnerabilities/search`                        | member, analyst, admin | JSON rows + pagination |
| GET  | `/threat-intelligence/vulnerabilities/<cve_id>`      | analyst, admin         | Detail page |
| GET  | `/threat-intelligence/vulnerabilities/export.csv`    | analyst, admin         | CSV export |

Role enforcement is **server-side**, not just template-conditional. Member access to detail/export returns **403** with a flash redirect to the list.

### Member field allowlist on `/api/vulnerabilities/search`

For `current_user.role == 'member'`, the JSON row is restricted to:
```python
{'cve_id', 'vendor', 'product', 'vulnerability_name',
 'date_added', 'due_date', 'known_ransomware_use'}
```
The full role (admin/analyst) additionally gets:
```python
{'short_description', 'required_action', 'notes', 'cwes'}
```

This is enforced in the route by selecting fields before serialization, not by filtering in the template. The list template renders members' rows as **non-clickable** (no link to detail).

## Sidebar nav

Insert one item in `cuba/templates/layout/sidebar.html` under "Threat Intelligence", between Breached Credentials and Analysis:

```html
<a href="{{ url_for('vulnerabilities.list_page') }}" class="dsec-nav-item {% if 'vulnerabilities' in (request.endpoint or '') %}active{% endif %}">
  <i data-feather="alert-triangle"></i> Vulnerabilities
</a>
```

## Data flow

**List page:**
```
Browser  GET /threat-intelligence/vulnerabilities
         ↓
Server   render vulnerabilities_list.html (SSR shell, no data yet)
         ↓
Browser  JS POST /api/vulnerabilities/search {page, per_page, filters}
         ↓
Server   role gate → CisaKevService.search(...) → ESPagination[CisaKevDoc]
         → role-aware field projection → JSON
         ↓
Browser  table renders rows; member rows are non-clickable
```

**Detail page (admin/analyst):**
```
GET /threat-intelligence/vulnerabilities/<cve_id>
  → if role == 'member': 403 → flash + redirect to list
  → CisaKevService.get_by_id(cve_id) → CisaKevDoc
  → render vulnerabilities_view.html
```

## Error handling

| Condition | Response |
|---|---|
| ES unreachable | empty `ESPagination`, log error; UI shows "Could not load vulnerabilities. Try again." |
| Member hits detail or export | 403 + flash + redirect to `/threat-intelligence/vulnerabilities` |
| Unknown CVE on detail | 404 page |
| Unauthenticated POST search | 302 redirect to login (Flask-Login default) or 400 from CSRF — either is safe; never returns row data |
| Search input contains weird chars | `sanitize_input` (existing helper) applied to all query params |

## Audit logging

`log_audit` rows are written for:
- `vulnerabilities_export` on successful CSV export (resource_type `cisa_kev_index`)
- `vulnerabilities_view` on successful detail page render (resource_type `cisa_kev`, resource_id `cve_id`)

List-page views are NOT audited (high volume, low signal). Search queries are NOT audited unless we hit a real need later.

## Testing

New file: `tests/test_vulnerabilities.py`. Existing `tests/test_breached_creds_reveal.py` and `tests/conftest.py` need import-path updates for `BreachedCredDoc` (moves from `cuba.services.elasticsearch_service` to `cuba.services.breached_creds_service`).

### Behavioral tests (`tests/test_vulnerabilities.py`)
1. **Admin list shell** — GET `/threat-intelligence/vulnerabilities` as admin → 200, page contains the list shell markup
2. **Member list shell** — same as admin → 200 (members allowed)
3. **Admin search returns full fields** — POST `/api/vulnerabilities/search` as admin → 200, response rows contain `short_description`
4. **Member search omits sensitive fields** — POST as member → 200, rows do NOT contain `short_description`, `required_action`, `notes`, `cwes`
5. **Filter by vendor** — POST with `{vendor: "Microsoft"}` → only Microsoft CVEs in results
6. **Filter by ransomware_use** — POST with `{ransomware_use: "Known"}` → only ransomware-tagged CVEs
7. **Member denied on detail** — GET `/threat-intelligence/vulnerabilities/CVE-2024-1234` as member → 302 redirect to list, no detail markup
8. **Analyst on detail** — GET as analyst → 200, page shows CVE description + required action
9. **Member denied on export** — GET `/threat-intelligence/vulnerabilities/export.csv` as member → 302 redirect, no CSV bytes
10. **Admin export** — GET as admin → 200, `Content-Type: text/csv`, body contains header row
11. **Unknown CVE on detail** — GET as admin with non-existent ID → 404
12. **Unauthenticated search** — POST without session → status in (302, 400, 401), no row data

### Regression
- All 13 existing breached-creds tests still pass after `BreachedCredDoc` import path update.

### Test infra additions
- `fake_kev` fixture in `conftest.py`: monkey-patches `cisa_kev_service.get_by_id` and `cisa_kev_service.search` with an in-memory store, mirroring the existing `fake_cred` fixture.

## Open assumption (verify at implementation)

ES tunnel is down at design time, so I haven't directly inspected the `cisa-kev` index schema. The `CisaKevDoc` wrapper tolerates both CISA's published camelCase (`cveID`, `vendorProject`, etc.) and snake_case alternatives. First step of implementation: re-establish the tunnel, sample one document, confirm field names. If the index uses different names entirely, update the `get` mapping accordingly — design is otherwise unaffected.

## Migration / deployment notes

- No DB migration. No new model.
- Adds `cisa_kev_index = 'cisa-kev'` as a `BaseConfig` setting with env override `CISA_KEV_INDEX`.
- After deploy, sidebar shows new "Vulnerabilities" link for all logged-in users.
- The rename `elasticsearch_service.py` → `breached_creds_service.py` includes a one-release shim: a deprecated `cuba/services/elasticsearch_service.py` re-exports `BreachedCredDoc`, `BreachedCredsService as ElasticsearchService`, and the `es_service = breached_creds_service` alias. Remove the shim in a follow-up after dependent code is updated.
