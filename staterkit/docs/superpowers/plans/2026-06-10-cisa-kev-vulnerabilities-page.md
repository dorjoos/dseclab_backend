# CISA KEV Vulnerabilities Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Vulnerabilities page reading CISA KEV data from Elasticsearch with role-aware access (admin/analyst: full list + detail + export, member: list-only summary).

**Architecture:** Extract a thin `ESIndexService` base; rename `ElasticsearchService` → `BreachedCredsService`; add peer `CisaKevService` + `CisaKevDoc`. New `vulnerabilities` blueprint serves the list shell, AJAX search (with role-aware field projection), detail page (analyst+), and CSV export (analyst+).

**Tech Stack:** Flask, Flask-Login, elasticsearch-py 8.x, Jinja2, Bootstrap 5/Cuba, pytest.

**Spec reference:** `docs/superpowers/specs/2026-06-10-cisa-kev-vulnerabilities-page-design.md`

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `cuba/services/es_base.py` | Create | `ESIndexService` base class — client init, raw count/search/get/index/update/delete |
| `cuba/services/breached_creds_service.py` | Create (content moved from `elasticsearch_service.py`) | `BreachedCredsService`, `BreachedCredDoc`, `ESPagination`, `breached_creds_service` singleton |
| `cuba/services/elasticsearch_service.py` | Replace contents with shim | Re-exports for backward compat; one-release deprecation |
| `cuba/services/cisa_kev_service.py` | Create | `CisaKevService`, `CisaKevDoc`, `cisa_kev_service` singleton |
| `cuba/vulnerabilities.py` | Create | Blueprint with 4 routes |
| `cuba/templates/threat_intel/vulnerabilities_list.html` | Create | SSR shell + AJAX-loaded table |
| `cuba/templates/threat_intel/vulnerabilities_view.html` | Create | Detail page (admin/analyst only) |
| `cuba/templates/layout/sidebar.html` | Modify | Add "Vulnerabilities" nav item |
| `cuba/__init__.py` | Modify | Register `vulnerabilities` blueprint |
| `config.py` | Modify | Add `CISA_KEV_INDEX` config option |
| `tests/conftest.py` | Modify | Update `BreachedCredDoc` import path; add `fake_kev` fixture |
| `tests/test_breached_creds_reveal.py` | Modify (imports only) | Update `BreachedCredDoc` import path |
| `tests/test_vulnerabilities.py` | Create | 12 behavioral tests |

---

## Task 1: Verify ES schema (spike)

**Files:** none — read-only investigation.

This task confirms the actual field names in the `cisa-kev` index. If they don't match the camelCase / snake_case alternatives `CisaKevDoc` will handle, update the field-name map in Task 4 *before* writing the test fixtures.

- [ ] **Step 1: Confirm the SSH tunnel for ES is up**

```bash
curl -sk --max-time 5 -u "elastic:$REMOTE_ES_PASSWORD" -w '\nHTTP %{http_code}\n' https://localhost:9200/_cluster/health | tail -3
```

Expected: a JSON body and `HTTP 200`. If `HTTP 000`, restart the tunnel:
```bash
ssh -L 5601:localhost:5601 -L 9200:localhost:9200 -i /Users/jooy/Development/dsecblab dorjoo@213.163.197.81
```
Then retry.

- [ ] **Step 2: Sample one document**

```bash
curl -sk -u "elastic:$REMOTE_ES_PASSWORD" 'https://localhost:9200/cisa-kev/_search?size=1&pretty' | head -40
```

Expected: a JSON with `hits.hits[0]._source` showing the actual field names. Record them: cveID? cve_id? Mixed? They feed Task 4's `CisaKevDoc.__init__` map.

- [ ] **Step 3: Confirm total document count**

```bash
curl -sk -u "elastic:$REMOTE_ES_PASSWORD" https://localhost:9200/cisa-kev/_count
```

Expected: `{"count": 1607, ...}` (or similar). Use this number for sanity-checking the live smoke test in Task 9.

- [ ] **Step 4: No commit — this is a read-only spike**

Note the actual field names in your terminal scrollback. Plug them into the `_FIELD_MAP` in Task 4 if they differ from the assumed mapping.

---

## Task 2: `ESIndexService` base class

**Files:**
- Create: `cuba/services/es_base.py`

- [ ] **Step 1: Create the base class**

Create `cuba/services/es_base.py`:

```python
"""Thin Elasticsearch base — shared client init and raw operations.

Subclasses (BreachedCredsService, CisaKevService) own all domain logic:
query builders, doc wrappers, stats. This class only knows about clients
and indices.
"""
import logging
from typing import Optional, Tuple

from elasticsearch import Elasticsearch
from flask import current_app

logger = logging.getLogger(__name__)


class ESIndexService:
    def __init__(self, index_name: str):
        self._index = index_name
        self._es = None

    @property
    def index(self) -> str:
        return self._index

    @property
    def es(self) -> Elasticsearch:
        # Lazy: build the client on first use so import order doesn't matter
        # and tests can monkey-patch config before any connection is opened.
        if self._es is None:
            cfg = current_app.config
            self._es = Elasticsearch(
                cfg.get('ELASTICSEARCH_URL', 'https://localhost:9200'),
                basic_auth=(
                    cfg.get('ELASTICSEARCH_USER', 'elastic'),
                    cfg.get('ELASTICSEARCH_PASSWORD', ''),
                ),
                verify_certs=cfg.get('ELASTICSEARCH_VERIFY_CERTS', False),
                request_timeout=30,
            )
        return self._es

    def _count(self, query: Optional[dict] = None) -> int:
        try:
            body = {'query': query} if query else None
            resp = self.es.count(index=self._index, body=body)
            return int(resp.get('count', 0))
        except Exception:
            logger.exception('ES _count failed on %s', self._index)
            return 0

    def _search(self, body: dict) -> dict:
        try:
            return self.es.search(index=self._index, body=body)
        except Exception:
            logger.exception('ES _search failed on %s', self._index)
            return {'hits': {'hits': [], 'total': {'value': 0}}}

    def get_raw(self, doc_id: str) -> Optional[Tuple[str, dict]]:
        try:
            resp = self.es.get(index=self._index, id=doc_id)
            return resp['_id'], resp['_source']
        except Exception:
            logger.exception('ES get_raw failed on %s/%s', self._index, doc_id)
            return None

    def index_document(self, doc: dict) -> Optional[str]:
        try:
            resp = self.es.index(index=self._index, document=doc, refresh=True)
            return resp.get('_id')
        except Exception:
            logger.exception('ES index_document failed on %s', self._index)
            return None

    def update_document(self, doc_id: str, doc: dict) -> bool:
        try:
            self.es.update(index=self._index, id=doc_id, doc=doc, refresh=True)
            return True
        except Exception:
            logger.exception('ES update_document failed on %s/%s', self._index, doc_id)
            return False

    def delete_document(self, doc_id: str) -> bool:
        try:
            self.es.delete(index=self._index, id=doc_id, refresh=True)
            return True
        except Exception:
            logger.exception('ES delete_document failed on %s/%s', self._index, doc_id)
            return False
```

- [ ] **Step 2: Verify import works**

```bash
source venv/bin/activate && python -c "from cuba.services.es_base import ESIndexService; print(ESIndexService.__name__)"
```

Expected output: `ESIndexService` (no traceback).

- [ ] **Step 3: Commit**

```bash
git add staterkit/cuba/services/es_base.py
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
refactor: extract ESIndexService base for ES-backed services

Pure infrastructure: lazy client init, raw count/search/get/index/
update/delete. No domain knowledge — subclasses own query builders
and doc wrappers.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Rename `elasticsearch_service.py` → `breached_creds_service.py`

**Files:**
- Rename: `cuba/services/elasticsearch_service.py` → `cuba/services/breached_creds_service.py`
- Replace `cuba/services/elasticsearch_service.py` content with a shim
- Modify: `cuba/threat_intel.py` — update import
- Modify: `tests/conftest.py` — update import
- Modify: `tests/test_breached_creds_reveal.py` — no change needed (uses `from cuba.services.elasticsearch_service`? Actually verify in step 4)

- [ ] **Step 1: Git-rename the file**

```bash
cd /Users/jooy/Development/dseclab_backend
git mv staterkit/cuba/services/elasticsearch_service.py staterkit/cuba/services/breached_creds_service.py
```

- [ ] **Step 2: Update class name and module docstring**

In `staterkit/cuba/services/breached_creds_service.py`, change:
- Docstring (line 1): `"""Elasticsearch service for breached credential searches."""` → `"""Breached credentials service backed by the 'main' ES index."""`
- Class declaration: `class ElasticsearchService:` → `class BreachedCredsService(ESIndexService):`
- Add this import near the top (after the existing `from elasticsearch import Elasticsearch`):

```python
from .es_base import ESIndexService
```

- Rewrite the class `__init__` to call `super().__init__('main')` (or read from config). Replace the existing `__init__` body **plus** the property/private helper that builds `self.es` (look for `self.url`, `self.user`, `self.password`, `self.es = Elasticsearch(...)`) with:

```python
    def __init__(self):
        from flask import current_app
        index = current_app.config.get('ELASTICSEARCH_INDEX', 'main') if current_app else 'main'
        super().__init__(index)
```

- The existing `self.es` attribute access in the rest of the class is preserved because `ESIndexService` exposes `es` as a property.
- At the bottom of the file, change the singleton:

```python
# Before:
# es_service = ElasticsearchService()
# After:
breached_creds_service = BreachedCredsService()
```

- [ ] **Step 3: Create a shim at the old path**

Create a new `staterkit/cuba/services/elasticsearch_service.py` (the old name) with this content only:

```python
"""DEPRECATED shim — import from cuba.services.breached_creds_service instead.

Kept for one release so external callers (deploy scripts, notebooks)
don't break across the rename. Remove after dependent code is updated.
"""
import warnings

from .breached_creds_service import (
    BreachedCredsService,
    BreachedCredDoc,
    ESPagination,
    breached_creds_service,
)

warnings.warn(
    "cuba.services.elasticsearch_service is deprecated; "
    "import from cuba.services.breached_creds_service instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Old singleton + class name alias for backward compat.
es_service = breached_creds_service
ElasticsearchService = BreachedCredsService

__all__ = [
    'BreachedCredsService',
    'BreachedCredDoc',
    'ESPagination',
    'breached_creds_service',
    'es_service',
    'ElasticsearchService',
]
```

- [ ] **Step 4: Update first-party imports**

Update `staterkit/cuba/threat_intel.py`. Find the existing line (around line 31):

```python
from .services.elasticsearch_service import es_service
```

Replace with:

```python
from .services.breached_creds_service import breached_creds_service as es_service
```

(Keeping the local `es_service` name keeps the rest of the file's call sites unchanged.)

Update `staterkit/tests/conftest.py`. Find:

```python
from cuba.services.elasticsearch_service import BreachedCredDoc
```

Replace with:

```python
from cuba.services.breached_creds_service import BreachedCredDoc
```

In the same file, find the `fake_cred` fixture body. Replace:

```python
    from cuba.services import elasticsearch_service as es_mod
```

with:

```python
    from cuba.services import breached_creds_service as es_mod
```

- [ ] **Step 5: Run existing breached-creds tests — must stay green**

```bash
source venv/bin/activate && python -m pytest tests/test_breached_creds_reveal.py -v 2>&1 | tail -15
```

Expected: **13 passed**. If any fail, you missed an import — grep the codebase: `grep -rn "from cuba.services.elasticsearch_service\|services.elasticsearch_service" cuba/ tests/`.

- [ ] **Step 6: Commit**

```bash
git add staterkit/cuba/services/breached_creds_service.py staterkit/cuba/services/elasticsearch_service.py staterkit/cuba/threat_intel.py staterkit/tests/conftest.py
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
refactor: rename ElasticsearchService to BreachedCredsService

Inherits from ESIndexService base. Old import path kept as a
deprecated shim that re-exports the new names and emits a
DeprecationWarning. All 13 existing tests pass.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `CisaKevDoc` + `CisaKevService`

**Files:**
- Create: `cuba/services/cisa_kev_service.py`
- Modify: `staterkit/config.py` — add `CISA_KEV_INDEX`

- [ ] **Step 1: Add config**

In `staterkit/config.py`, find the existing `ELASTICSEARCH_INDEX = ...` line in `BaseConfig` (around line 23). Immediately below it, add:

```python
    CISA_KEV_INDEX = os.environ.get('CISA_KEV_INDEX', 'cisa-kev')
```

- [ ] **Step 2: Create the service module**

Create `staterkit/cuba/services/cisa_kev_service.py`:

```python
"""CISA KEV (Known Exploited Vulnerabilities) service backed by ES."""
import logging
from datetime import datetime
from typing import Optional

from flask import current_app

from .es_base import ESIndexService
from .breached_creds_service import ESPagination

logger = logging.getLogger(__name__)


def _parse_date(val):
    if val is None or val == '':
        return None
    if isinstance(val, datetime):
        return val
    try:
        return datetime.fromisoformat(str(val).replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return None


def _clean(val):
    if val is None:
        return None
    if isinstance(val, str) and val.strip().lower() in ('none', 'null', 'n/a', ''):
        return None
    return val


class CisaKevDoc:
    """Wraps a cisa-kev ES document. Tolerates camelCase or snake_case fields.

    CISA publishes camelCase (cveID, vendorProject, ...); an ingestion
    pipeline may have rewritten them. Either form works.
    """

    def __init__(self, es_id: str, source: dict):
        self.es_id = es_id
        s = source or {}
        get = lambda camel, snake: s.get(camel) if camel in s else s.get(snake)

        self.cve_id = _clean(get('cveID', 'cve_id')) or es_id
        self.vendor = _clean(get('vendorProject', 'vendor_project'))
        self.product = _clean(get('product', 'product'))
        self.vulnerability_name = _clean(get('vulnerabilityName', 'vulnerability_name'))
        self.date_added = _parse_date(get('dateAdded', 'date_added'))
        self.short_description = _clean(get('shortDescription', 'short_description'))
        self.required_action = _clean(get('requiredAction', 'required_action'))
        self.due_date = _parse_date(get('dueDate', 'due_date'))
        self.known_ransomware_use = _clean(
            get('knownRansomwareCampaignUse', 'known_ransomware_campaign_use')
        )
        self.notes = _clean(get('notes', 'notes'))
        self.cwes = get('cwes', 'cwes') or []


class CisaKevService(ESIndexService):
    def __init__(self):
        # Read index name on first use, not at import (no app context yet).
        super().__init__('cisa-kev')

    @property
    def index(self) -> str:
        try:
            return current_app.config.get('CISA_KEV_INDEX', 'cisa-kev')
        except Exception:
            return self._index

    def get_by_id(self, doc_id: str) -> Optional[CisaKevDoc]:
        raw = self.get_raw(doc_id)
        if raw is None:
            return None
        es_id, source = raw
        return CisaKevDoc(es_id, source)

    def _build_query(self, query_text=None, filters=None) -> dict:
        must = []
        filter_clauses = []

        if query_text and query_text.strip():
            q = query_text.strip().lower()
            must.append({
                'bool': {
                    'should': [
                        {'wildcard': {'cveID': {'value': f'*{q}*', 'case_insensitive': True}}},
                        {'wildcard': {'cve_id': {'value': f'*{q}*', 'case_insensitive': True}}},
                        {'wildcard': {'vulnerabilityName': {'value': f'*{q}*', 'case_insensitive': True}}},
                        {'wildcard': {'vulnerability_name': {'value': f'*{q}*', 'case_insensitive': True}}},
                        {'wildcard': {'shortDescription': {'value': f'*{q}*', 'case_insensitive': True}}},
                        {'wildcard': {'short_description': {'value': f'*{q}*', 'case_insensitive': True}}},
                    ],
                    'minimum_should_match': 1,
                }
            })

        if filters:
            v = filters.get('vendor')
            if v:
                filter_clauses.append({
                    'bool': {
                        'should': [
                            {'term': {'vendorProject.keyword': v}},
                            {'term': {'vendor_project.keyword': v}},
                        ],
                        'minimum_should_match': 1,
                    }
                })
            p = filters.get('product')
            if p:
                filter_clauses.append({
                    'bool': {
                        'should': [
                            {'term': {'product.keyword': p}},
                        ],
                        'minimum_should_match': 1,
                    }
                })
            ru = filters.get('ransomware_use')
            if ru:
                filter_clauses.append({
                    'bool': {
                        'should': [
                            {'term': {'knownRansomwareCampaignUse.keyword': ru}},
                            {'term': {'known_ransomware_campaign_use.keyword': ru}},
                        ],
                        'minimum_should_match': 1,
                    }
                })

        query = {'bool': {}}
        if must:
            query['bool']['must'] = must
        if filter_clauses:
            query['bool']['filter'] = filter_clauses
        if not query['bool']:
            query = {'match_all': {}}
        return query

    def search(
        self,
        query_text: Optional[str] = None,
        filters: Optional[dict] = None,
        page: int = 1,
        per_page: int = 20,
    ) -> ESPagination:
        page = max(1, int(page))
        per_page = max(1, min(100, int(per_page)))
        body = {
            'query': self._build_query(query_text, filters),
            'from': (page - 1) * per_page,
            'size': per_page,
            'sort': [{'dateAdded': {'order': 'desc', 'unmapped_type': 'date'}}],
            'track_total_hits': True,
        }
        resp = self._search(body)
        hits = resp.get('hits', {}).get('hits', [])
        total = resp.get('hits', {}).get('total', {})
        if isinstance(total, dict):
            total = total.get('value', 0)
        items = [CisaKevDoc(h['_id'], h.get('_source', {})) for h in hits]
        return ESPagination(items=items, page=page, per_page=per_page, total=int(total))

    def get_stats(self) -> dict:
        body = {
            'query': {'match_all': {}},
            'size': 0,
            'track_total_hits': True,
            'aggs': {
                'by_vendor': {
                    'terms': {'field': 'vendorProject.keyword', 'size': 10}
                },
                'by_ransomware': {
                    'terms': {'field': 'knownRansomwareCampaignUse.keyword', 'size': 5}
                },
            },
        }
        resp = self._search(body)
        total = resp.get('hits', {}).get('total', {})
        if isinstance(total, dict):
            total = total.get('value', 0)
        aggs = resp.get('aggregations', {})
        return {
            'total': int(total),
            'by_vendor': [
                (b['key'], b['doc_count'])
                for b in aggs.get('by_vendor', {}).get('buckets', [])
            ],
            'by_ransomware': {
                b['key']: b['doc_count']
                for b in aggs.get('by_ransomware', {}).get('buckets', [])
            },
        }


cisa_kev_service = CisaKevService()
```

- [ ] **Step 3: Verify import works**

```bash
source venv/bin/activate && python -c "from cuba.services.cisa_kev_service import CisaKevDoc, CisaKevService, cisa_kev_service; print('OK')"
```

Expected: `OK`.

- [ ] **Step 4: Commit**

```bash
git add staterkit/cuba/services/cisa_kev_service.py staterkit/config.py
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: add CisaKevService + CisaKevDoc for the cisa-kev ES index

Service mirrors the breached-creds pattern: search with text + filters
(vendor, product, ransomware_use), stats aggregations, get_by_id.
CisaKevDoc tolerates both CISA camelCase and snake_case field names.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Failing tests for the vulnerabilities blueprint

**Files:**
- Modify: `tests/conftest.py` — add `fake_kev` fixture
- Create: `tests/test_vulnerabilities.py`

- [ ] **Step 1: Add `fake_kev` fixture**

In `staterkit/tests/conftest.py`, after the existing `fake_cred` fixture, append:

```python
@pytest.fixture()
def fake_kev(monkeypatch):
    """Mirror of fake_cred but for cisa_kev_service.

    Usage:
        fake_kev({"CVE-2024-1": {"cveID": "CVE-2024-1", "vendorProject": "Microsoft",
                                  "product": "Windows", "vulnerabilityName": "RCE",
                                  "shortDescription": "blah", "knownRansomwareCampaignUse": "Known"}})
    """
    from cuba.services import cisa_kev_service as svc_mod
    from cuba.services.cisa_kev_service import CisaKevDoc, cisa_kev_service
    from cuba.services.breached_creds_service import ESPagination

    store = {}

    def setter(mapping):
        store.update(mapping)

    def fake_get_by_id(doc_id):
        src = store.get(doc_id)
        if src is None:
            return None
        return CisaKevDoc(doc_id, src)

    def fake_search(query_text=None, filters=None, page=1, per_page=20):
        items = [CisaKevDoc(k, v) for k, v in store.items()]
        if filters:
            if filters.get('vendor'):
                v = filters['vendor'].lower()
                items = [i for i in items if (i.vendor or '').lower() == v]
            if filters.get('product'):
                p = filters['product'].lower()
                items = [i for i in items if (i.product or '').lower() == p]
            if filters.get('ransomware_use'):
                ru = filters['ransomware_use']
                items = [i for i in items if (i.known_ransomware_use or '') == ru]
        if query_text:
            q = query_text.lower()
            items = [
                i for i in items
                if q in (i.cve_id or '').lower()
                or q in (i.vulnerability_name or '').lower()
                or q in (i.short_description or '').lower()
            ]
        total = len(items)
        start = (page - 1) * per_page
        end = start + per_page
        return ESPagination(items=items[start:end], page=page, per_page=per_page, total=total)

    monkeypatch.setattr(svc_mod.cisa_kev_service, 'get_by_id', fake_get_by_id)
    monkeypatch.setattr(svc_mod.cisa_kev_service, 'search', fake_search)
    monkeypatch.setattr(cisa_kev_service, 'get_by_id', fake_get_by_id)
    monkeypatch.setattr(cisa_kev_service, 'search', fake_search)
    return setter
```

- [ ] **Step 2: Create the test file with all 12 tests**

Create `staterkit/tests/test_vulnerabilities.py` (14 tests total):

```python
"""Behavioral tests for the CISA KEV Vulnerabilities page.

Plan: docs/superpowers/plans/2026-06-10-cisa-kev-vulnerabilities-page.md
"""
import re
import pytest
from tests.conftest import login


LIST_PATH = '/threat-intelligence/vulnerabilities'
SEARCH_PATH = '/api/vulnerabilities/search'
EXPORT_PATH = '/threat-intelligence/vulnerabilities/export.csv'

CVE_A = 'CVE-2024-0001'
CVE_B = 'CVE-2024-0002'
SAMPLE = {
    CVE_A: {
        'cveID': CVE_A,
        'vendorProject': 'Microsoft',
        'product': 'Windows',
        'vulnerabilityName': 'Win32k EoP',
        'dateAdded': '2024-01-15',
        'shortDescription': 'Use-after-free in Win32k leading to privilege escalation.',
        'requiredAction': 'Apply MS-24-XXX',
        'dueDate': '2024-02-05',
        'knownRansomwareCampaignUse': 'Known',
        'notes': 'https://msrc.microsoft.com/CVE-2024-0001',
        'cwes': ['CWE-416'],
    },
    CVE_B: {
        'cveID': CVE_B,
        'vendorProject': 'Apache',
        'product': 'Struts',
        'vulnerabilityName': 'OGNL Injection',
        'dateAdded': '2024-02-01',
        'shortDescription': 'Remote code execution via crafted Content-Type header.',
        'requiredAction': 'Upgrade to 2.5.33',
        'dueDate': '2024-02-22',
        'knownRansomwareCampaignUse': 'Unknown',
        'notes': 'https://cve.mitre.org/CVE-2024-0002',
        'cwes': ['CWE-917'],
    },
}


def _csrf_token(client):
    r = client.get('/threat-intelligence/breached-creds', follow_redirects=True)
    m = re.search(rb'window\.CSRF_TOKEN\s*=\s*"([^"]+)"', r.data)
    assert m, f'CSRF token not found (status={r.status_code})'
    return m.group(1).decode()


# --- shell access (all roles allowed) ---

def test_admin_can_get_list_shell(client, admin_user, fake_kev):
    fake_kev(SAMPLE)
    login(client, admin_user.email)
    r = client.get(LIST_PATH)
    assert r.status_code == 200
    assert b'Vulnerabilities' in r.data or b'CISA' in r.data


def test_member_can_get_list_shell(client, member_acme, fake_kev):
    fake_kev(SAMPLE)
    login(client, member_acme.email)
    r = client.get(LIST_PATH)
    assert r.status_code == 200


# --- AJAX search: role-aware field projection ---

def test_admin_search_returns_full_fields(client, admin_user, fake_kev):
    fake_kev(SAMPLE)
    login(client, admin_user.email)
    token = _csrf_token(client)
    r = client.post(SEARCH_PATH, headers={'X-CSRFToken': token},
                    json={'page': 1, 'per_page': 10})
    assert r.status_code == 200
    rows = r.get_json()['rows']
    assert len(rows) == 2
    sample_row = rows[0]
    assert 'short_description' in sample_row
    assert 'required_action' in sample_row
    assert 'notes' in sample_row
    assert 'cwes' in sample_row


def test_member_search_omits_sensitive_fields(client, member_acme, fake_kev):
    fake_kev(SAMPLE)
    login(client, member_acme.email)
    token = _csrf_token(client)
    r = client.post(SEARCH_PATH, headers={'X-CSRFToken': token},
                    json={'page': 1, 'per_page': 10})
    assert r.status_code == 200
    rows = r.get_json()['rows']
    assert len(rows) == 2
    sample_row = rows[0]
    assert 'cve_id' in sample_row
    assert 'vendor' in sample_row
    assert 'product' in sample_row
    assert 'short_description' not in sample_row
    assert 'required_action' not in sample_row
    assert 'notes' not in sample_row
    assert 'cwes' not in sample_row


def test_filter_by_vendor(client, admin_user, fake_kev):
    fake_kev(SAMPLE)
    login(client, admin_user.email)
    token = _csrf_token(client)
    r = client.post(SEARCH_PATH, headers={'X-CSRFToken': token},
                    json={'page': 1, 'per_page': 10, 'vendor': 'Microsoft'})
    assert r.status_code == 200
    rows = r.get_json()['rows']
    assert len(rows) == 1
    assert rows[0]['cve_id'] == CVE_A


def test_filter_by_ransomware_use(client, admin_user, fake_kev):
    fake_kev(SAMPLE)
    login(client, admin_user.email)
    token = _csrf_token(client)
    r = client.post(SEARCH_PATH, headers={'X-CSRFToken': token},
                    json={'page': 1, 'per_page': 10, 'ransomware_use': 'Known'})
    assert r.status_code == 200
    rows = r.get_json()['rows']
    assert len(rows) == 1
    assert rows[0]['cve_id'] == CVE_A


# --- detail page ---

def test_member_denied_on_detail(client, member_acme, fake_kev):
    fake_kev(SAMPLE)
    login(client, member_acme.email)
    r = client.get(f'{LIST_PATH}/{CVE_A}', follow_redirects=False)
    # Implementation may return 302 (redirect+flash) or 403; both keep the
    # body free of the CVE description. Accept either.
    assert r.status_code in (302, 403)
    assert b'Use-after-free' not in r.data


def test_analyst_can_view_detail(client, analyst_user, fake_kev):
    fake_kev(SAMPLE)
    login(client, analyst_user.email)
    r = client.get(f'{LIST_PATH}/{CVE_A}')
    assert r.status_code == 200
    assert b'Use-after-free' in r.data
    assert b'Apply MS-24-XXX' in r.data


def test_unknown_cve_returns_404(client, admin_user, fake_kev):
    fake_kev({})
    login(client, admin_user.email)
    r = client.get(f'{LIST_PATH}/CVE-9999-9999')
    assert r.status_code == 404


# --- export ---

def test_member_denied_on_export(client, member_acme, fake_kev):
    fake_kev(SAMPLE)
    login(client, member_acme.email)
    r = client.get(EXPORT_PATH, follow_redirects=False)
    assert r.status_code in (302, 403)
    assert b'CVE-2024-0001' not in r.data


def test_admin_can_export(client, admin_user, fake_kev):
    fake_kev(SAMPLE)
    login(client, admin_user.email)
    r = client.get(EXPORT_PATH)
    assert r.status_code == 200
    assert r.mimetype.startswith('text/csv')
    body = r.data.decode()
    assert 'cve_id' in body.lower() or 'cveid' in body.lower()
    assert CVE_A in body


# --- audit ---

def test_detail_view_writes_audit_row(client, db, analyst_user, fake_kev):
    from cuba.models import AuditLog
    fake_kev(SAMPLE)
    login(client, analyst_user.email)
    r = client.get(f'{LIST_PATH}/{CVE_A}')
    assert r.status_code == 200
    rows = AuditLog.query.filter_by(action_type='vulnerabilities_view').all()
    assert len(rows) == 1
    assert rows[0].resource_id == CVE_A


def test_export_writes_audit_row(client, db, admin_user, fake_kev):
    from cuba.models import AuditLog
    fake_kev(SAMPLE)
    login(client, admin_user.email)
    r = client.get(EXPORT_PATH)
    assert r.status_code == 200
    rows = AuditLog.query.filter_by(action_type='vulnerabilities_export').all()
    assert len(rows) == 1


# --- unauthenticated ---

def test_unauthenticated_search_does_not_leak(client, fake_kev):
    fake_kev(SAMPLE)
    r = client.post(SEARCH_PATH)
    assert r.status_code in (302, 400, 401)
    assert b'Use-after-free' not in r.data
```

- [ ] **Step 3: Run the tests — they should fail (no blueprint yet)**

```bash
source venv/bin/activate && python -m pytest tests/test_vulnerabilities.py -v 2>&1 | tail -25
```

Expected: all 14 FAIL (most with 404 since the blueprint isn't registered).

---

## Task 6: Implement the `vulnerabilities` blueprint

**Files:**
- Create: `cuba/vulnerabilities.py`
- Modify: `cuba/__init__.py` — register the blueprint

- [ ] **Step 1: Create the blueprint module**

Create `staterkit/cuba/vulnerabilities.py`:

```python
"""Vulnerabilities blueprint — CISA KEV browser."""
import csv
import io
import logging

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash, Response,
    jsonify, abort,
)
from flask_login import login_required, current_user

from . import db, limiter
from .api_utils import sanitize_input
from .audit_helpers import log_audit
from .services.cisa_kev_service import cisa_kev_service

logger = logging.getLogger(__name__)

vulnerabilities = Blueprint('vulnerabilities', __name__)


MEMBER_FIELDS = {
    'cve_id', 'vendor', 'product', 'vulnerability_name',
    'date_added', 'due_date', 'known_ransomware_use',
}
FULL_FIELDS = MEMBER_FIELDS | {
    'short_description', 'required_action', 'notes', 'cwes',
}


def _is_full_access():
    return current_user.role in ('admin', 'analyst')


def _serialize(doc, fields):
    def fmt_date(d):
        return d.strftime('%Y-%m-%d') if d else ''
    payload = {
        'cve_id': doc.cve_id or '',
        'vendor': doc.vendor or '',
        'product': doc.product or '',
        'vulnerability_name': doc.vulnerability_name or '',
        'date_added': fmt_date(doc.date_added),
        'due_date': fmt_date(doc.due_date),
        'known_ransomware_use': doc.known_ransomware_use or '',
        'short_description': doc.short_description or '',
        'required_action': doc.required_action or '',
        'notes': doc.notes or '',
        'cwes': doc.cwes or [],
    }
    return {k: v for k, v in payload.items() if k in fields}


@vulnerabilities.route('/threat-intelligence/vulnerabilities')
@login_required
def list_page():
    breadcrumb = {'parent': 'Threat Intelligence', 'child': 'Vulnerabilities'}
    return render_template('threat_intel/vulnerabilities_list.html',
                          breadcrumb=breadcrumb,
                          full_access=_is_full_access())


@vulnerabilities.route('/api/vulnerabilities/search', methods=['POST'])
@login_required
@limiter.limit('60/minute')
def search_api():
    data = request.get_json(silent=True) or {}
    page = int(data.get('page', 1) or 1)
    per_page = int(data.get('per_page', 20) or 20)
    per_page = min(max(per_page, 1), 100)
    query_text = sanitize_input(data.get('search', '') or None)
    filters = {}
    for k in ('vendor', 'product', 'ransomware_use'):
        v = sanitize_input(data.get(k, '') or None)
        if v:
            filters[k] = v
    pagination = cisa_kev_service.search(
        query_text=query_text,
        filters=filters or None,
        page=page,
        per_page=per_page,
    )
    fields = FULL_FIELDS if _is_full_access() else MEMBER_FIELDS
    rows = [_serialize(d, fields) for d in pagination.items]
    return jsonify({
        'rows': rows,
        'page': pagination.page,
        'pages': pagination.pages,
        'total': pagination.total,
        'has_prev': pagination.has_prev,
        'has_next': pagination.has_next,
    })


@vulnerabilities.route('/threat-intelligence/vulnerabilities/<cve_id>')
@login_required
def detail_page(cve_id):
    if not _is_full_access():
        flash('Detail view is available for analysts and administrators only.', 'warning')
        return redirect(url_for('vulnerabilities.list_page'))
    doc = cisa_kev_service.get_by_id(cve_id)
    if not doc:
        abort(404)
    log_audit('vulnerabilities_view', 'cisa_kev', doc.cve_id,
              f'User {current_user.username} viewed {doc.cve_id} detail')
    db.session.commit()
    breadcrumb = {'parent': 'Vulnerabilities', 'child': doc.cve_id}
    return render_template('threat_intel/vulnerabilities_view.html',
                          vuln=doc, breadcrumb=breadcrumb)


@vulnerabilities.route('/threat-intelligence/vulnerabilities/export.csv')
@login_required
def export_csv():
    if not _is_full_access():
        flash('Export is available for analysts and administrators only.', 'warning')
        return redirect(url_for('vulnerabilities.list_page'))
    pagination = cisa_kev_service.search(page=1, per_page=10000)
    log_audit('vulnerabilities_export', 'cisa_kev_index', None,
              f'User {current_user.username} exported {pagination.total} CISA KEV rows as CSV')
    db.session.commit()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        'cve_id', 'vendor', 'product', 'vulnerability_name',
        'date_added', 'due_date', 'known_ransomware_use',
        'short_description', 'required_action', 'notes',
    ])
    for d in pagination.items:
        writer.writerow([
            d.cve_id or '',
            d.vendor or '',
            d.product or '',
            d.vulnerability_name or '',
            d.date_added.strftime('%Y-%m-%d') if d.date_added else '',
            d.due_date.strftime('%Y-%m-%d') if d.due_date else '',
            d.known_ransomware_use or '',
            d.short_description or '',
            d.required_action or '',
            d.notes or '',
        ])
    return Response(
        buf.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=cisa-kev.csv'},
    )
```

- [ ] **Step 2: Register the blueprint**

In `staterkit/cuba/__init__.py`, find the existing block (around lines 134-141):

```python
    from .threat_intel import threat_intel as threat_intel_bp
    app.register_blueprint(threat_intel_bp)
    from .admin_routes import admin_bp
    app.register_blueprint(admin_bp)
```

Insert immediately after `app.register_blueprint(threat_intel_bp)` and before the next blueprint:

```python
    from .vulnerabilities import vulnerabilities as vulnerabilities_bp
    app.register_blueprint(vulnerabilities_bp)
```

- [ ] **Step 3: Create the list and detail templates**

Create `staterkit/cuba/templates/threat_intel/vulnerabilities_list.html`:

```html
{% extends "base.html" %}
{% block title %}D-SECLAB | Vulnerabilities{% endblock %}
{% block content %}
<div class="av-page" id="vulns-page">
  <div class="av-page-header">
    <h1 class="av-page-title">Vulnerabilities (CISA KEV)</h1>
    <p class="av-page-subtitle">Known Exploited Vulnerabilities catalog</p>
  </div>

  <div class="av-toolbar">
    <div class="av-toolbar-left">
      <span class="av-count" id="vulns-total">Loading...</span>
    </div>
    <div class="av-toolbar-right">
      <div class="av-search">
        <input type="text" id="vulns-search" placeholder="Search CVE / name / description...">
      </div>
      <select id="vulns-vendor" class="av-filter">
        <option value="">All vendors</option>
      </select>
      <select id="vulns-ransomware" class="av-filter">
        <option value="">Any ransomware-use</option>
        <option value="Known">Known</option>
        <option value="Unknown">Unknown</option>
      </select>
      {% if full_access %}
      <a href="{{ url_for('vulnerabilities.export_csv') }}" class="av-btn">Export CSV</a>
      {% endif %}
    </div>
  </div>

  <div class="av-table-wrap">
    <table class="av-table" id="vulns-table">
      <thead>
        <tr>
          <th>#</th>
          <th>CVE ID</th>
          <th>Vendor</th>
          <th>Product</th>
          <th>Vulnerability</th>
          <th>Added</th>
          <th>Due</th>
          <th>Ransomware</th>
        </tr>
      </thead>
      <tbody id="vulns-body"></tbody>
    </table>
    <div class="av-empty" id="vulns-empty" style="display:none;">No results found</div>
  </div>

  <div class="av-pagination" id="vulns-pagination"></div>
</div>

<script>
(function() {
  var FULL_ACCESS = {{ 'true' if full_access else 'false' }};
  var state = { page: 1, per_page: 20 };

  function fmt(s) { return s == null ? '' : String(s); }

  function load() {
    var body = {
      page: state.page,
      per_page: state.per_page,
      search: document.getElementById('vulns-search').value,
      vendor: document.getElementById('vulns-vendor').value,
      ransomware_use: document.getElementById('vulns-ransomware').value
    };
    fetch('/api/vulnerabilities/search', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': window.CSRF_TOKEN || '',
        'Accept': 'application/json'
      },
      body: JSON.stringify(body)
    }).then(function(r) { return r.ok ? r.json() : null; })
      .then(function(data) {
        if (!data) { document.getElementById('vulns-empty').style.display = ''; return; }
        document.getElementById('vulns-total').textContent = data.total + ' total';
        var tbody = document.getElementById('vulns-body');
        tbody.innerHTML = '';
        if (!data.rows.length) {
          document.getElementById('vulns-empty').style.display = '';
          return;
        }
        document.getElementById('vulns-empty').style.display = 'none';
        data.rows.forEach(function(row, i) {
          var tr = document.createElement('tr');
          var cveCell = FULL_ACCESS
            ? '<a href="/threat-intelligence/vulnerabilities/' + encodeURIComponent(row.cve_id) + '">' + fmt(row.cve_id) + '</a>'
            : fmt(row.cve_id);
          tr.innerHTML =
            '<td>' + ((state.page - 1) * state.per_page + i + 1) + '</td>' +
            '<td>' + cveCell + '</td>' +
            '<td>' + fmt(row.vendor) + '</td>' +
            '<td>' + fmt(row.product) + '</td>' +
            '<td>' + fmt(row.vulnerability_name) + '</td>' +
            '<td>' + fmt(row.date_added) + '</td>' +
            '<td>' + fmt(row.due_date) + '</td>' +
            '<td>' + fmt(row.known_ransomware_use) + '</td>';
          tbody.appendChild(tr);
        });
      });
  }

  document.getElementById('vulns-search').addEventListener('input', function() {
    state.page = 1; load();
  });
  document.getElementById('vulns-vendor').addEventListener('change', function() {
    state.page = 1; load();
  });
  document.getElementById('vulns-ransomware').addEventListener('change', function() {
    state.page = 1; load();
  });
  load();
})();
</script>
{% endblock %}
```

Create `staterkit/cuba/templates/threat_intel/vulnerabilities_view.html`:

```html
{% extends "base.html" %}
{% block title %}D-SECLAB | {{ vuln.cve_id }}{% endblock %}
{% block content %}
<div class="av-page">
  <div class="av-page-header">
    <h1 class="av-page-title">{{ vuln.cve_id }}</h1>
    <p class="av-page-subtitle">{{ vuln.vulnerability_name or '' }}</p>
  </div>

  <div class="av-detail-grid">
    <div class="av-detail-cell">
      <div class="av-detail-label">Vendor</div>
      <div class="av-detail-value">{{ vuln.vendor or '—' }}</div>
    </div>
    <div class="av-detail-cell">
      <div class="av-detail-label">Product</div>
      <div class="av-detail-value">{{ vuln.product or '—' }}</div>
    </div>
    <div class="av-detail-cell">
      <div class="av-detail-label">Date Added</div>
      <div class="av-detail-value">
        {{ vuln.date_added.strftime('%Y-%m-%d') if vuln.date_added else '—' }}
      </div>
    </div>
    <div class="av-detail-cell">
      <div class="av-detail-label">Due Date</div>
      <div class="av-detail-value">
        {{ vuln.due_date.strftime('%Y-%m-%d') if vuln.due_date else '—' }}
      </div>
    </div>
    <div class="av-detail-cell">
      <div class="av-detail-label">Ransomware Use</div>
      <div class="av-detail-value">{{ vuln.known_ransomware_use or '—' }}</div>
    </div>
    <div class="av-detail-cell av-detail-cell--wide">
      <div class="av-detail-label">Description</div>
      <div class="av-detail-value">{{ vuln.short_description or '—' }}</div>
    </div>
    <div class="av-detail-cell av-detail-cell--wide">
      <div class="av-detail-label">Required Action</div>
      <div class="av-detail-value">{{ vuln.required_action or '—' }}</div>
    </div>
    <div class="av-detail-cell av-detail-cell--wide">
      <div class="av-detail-label">Notes / References</div>
      <div class="av-detail-value">{{ vuln.notes or '—' }}</div>
    </div>
    <div class="av-detail-cell">
      <div class="av-detail-label">CWEs</div>
      <div class="av-detail-value">{{ (vuln.cwes or []) | join(', ') or '—' }}</div>
    </div>
  </div>

  <div class="av-actions">
    <a href="{{ url_for('vulnerabilities.list_page') }}" class="av-btn">← Back to list</a>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 4: Run the tests**

```bash
source venv/bin/activate && python -m pytest tests/test_vulnerabilities.py -v 2>&1 | tail -20
```

Expected: all 14 PASS. If any fail, the most likely causes:
- 404 on `LIST_PATH`: blueprint not registered. Re-check Task 6 Step 2.
- 405 on `SEARCH_PATH`: missing `methods=['POST']` decorator.
- Member sees `short_description`: field projection logic in `_serialize` is wrong.
- CSV body missing CVE_A: export route not iterating all items.

- [ ] **Step 5: Confirm breached-creds tests still pass (regression)**

```bash
source venv/bin/activate && python -m pytest tests/ -v 2>&1 | tail -8
```

Expected: 27 passed (13 breached-creds + 14 vulnerabilities).

- [ ] **Step 6: Commit**

```bash
git add staterkit/cuba/vulnerabilities.py staterkit/cuba/__init__.py staterkit/cuba/templates/threat_intel/vulnerabilities_list.html staterkit/cuba/templates/threat_intel/vulnerabilities_view.html staterkit/tests/conftest.py staterkit/tests/test_vulnerabilities.py
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: CISA KEV vulnerabilities page with role-aware access

GET /threat-intelligence/vulnerabilities serves an SSR shell that loads
rows via POST /api/vulnerabilities/search. Members get a reduced field
set (no short_description / required_action / notes / cwes) and no
detail or export links. Analysts and admins get the full list,
detail page (CVE-keyed), and CSV export.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Sidebar navigation

**Files:**
- Modify: `cuba/templates/layout/sidebar.html`

- [ ] **Step 1: Add the new nav item**

In `staterkit/cuba/templates/layout/sidebar.html`, find the existing block:

```html
      <a href="{{ url_for('threat_intel.breached_creds_list') }}" class="dsec-nav-item {% if 'breached_creds' in (request.endpoint or '') %}active{% endif %}">
        <i data-feather="shield"></i> Breached Credentials
      </a>
```

Immediately after that line, insert:

```html
      <a href="{{ url_for('vulnerabilities.list_page') }}" class="dsec-nav-item {% if 'vulnerabilities' in (request.endpoint or '') %}active{% endif %}">
        <i data-feather="alert-triangle"></i> Vulnerabilities
      </a>
```

- [ ] **Step 2: Smoke-test the link renders**

If the dev server is running (auto-reload picks up templates), refresh any logged-in page in the browser. Otherwise:

```bash
source venv/bin/activate && python -c "from cuba import create_app, socketio; app = create_app(); socketio.run(app, debug=True, port=8003, allow_unsafe_werkzeug=True)" &
sleep 4
```

Then `curl` to confirm the rendered sidebar has the new link:

```bash
csrf=$(curl -s -c /tmp/c.txt http://localhost:8003/login | grep -oE 'name="csrf_token"[^>]*value="[^"]+"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -b /tmp/c.txt -c /tmp/c.txt -o /dev/null -X POST http://localhost:8003/login -d "csrf_token=$csrf&email=admin@dseclab.com&password=Admin@123"
curl -s -b /tmp/c.txt http://localhost:8003/threat-intelligence/breached-creds | grep -oE 'href="[^"]*vulnerabilities[^"]*"' | head -2
```

Expected: at least one `href="/threat-intelligence/vulnerabilities"` line.

- [ ] **Step 3: Commit**

```bash
git add staterkit/cuba/templates/layout/sidebar.html
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
feat: add Vulnerabilities link to Threat Intelligence nav

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Live ES smoke test

**Files:** none — verification only.

- [ ] **Step 1: Confirm the ES tunnel is up (from Task 1)**

```bash
curl -sk -u "elastic:$REMOTE_ES_PASSWORD" -o /dev/null -w "%{http_code}\n" https://localhost:9200/cisa-kev/_count
```

Expected: `200`.

- [ ] **Step 2: Probe the service end-to-end against live ES**

```bash
source venv/bin/activate && python -c "
from cuba import create_app
app = create_app()
with app.app_context():
    from cuba.services.cisa_kev_service import cisa_kev_service
    p = cisa_kev_service.search(page=1, per_page=3)
    print('total:', p.total)
    for d in p.items:
        print(' -', d.cve_id, '|', d.vendor, '|', d.product, '|', d.vulnerability_name)
    s = cisa_kev_service.get_stats()
    print('stats.total:', s['total'])
    print('top vendors:', s['by_vendor'][:5])
"
```

Expected: `total: 1607` (or close), 3 CVE rows printed with vendor/product/name populated. If fields print as `None`, the field-name map in `CisaKevDoc` doesn't match the live schema — adjust the `get(...)` keys per what you recorded in Task 1.

- [ ] **Step 3: Browser check (manual)**

1. Open http://localhost:8003 as `admin@dseclab.com` / `Admin@123`.
2. Click the new "Vulnerabilities" link in the sidebar.
3. Confirm: the table loads with real CVEs, total count matches Step 2, vendor/ransomware filters work.
4. Click any CVE row → detail page renders.
5. Click "Export CSV" → CSV downloads.
6. Log out, log in as `dorjoo@test.com` / `Test@123` (member).
7. Confirm: list loads, rows are NOT clickable, no Export button.

- [ ] **Step 4: No commit — verification only**

If anything is off, fix in the appropriate task and re-run the pytest suite plus this manual sweep.

---

## Task 9: Final verification

**Files:** none — verification only.

- [ ] **Step 1: Full test suite**

```bash
source venv/bin/activate && python -m pytest tests/ -q 2>&1 | tail -5
```

Expected: `25 passed` (13 breached-creds + 12 vulnerabilities).

- [ ] **Step 2: Lint / typecheck (if configured — confirm none added by this work)**

```bash
git -C /Users/jooy/Development/dseclab_backend status --short staterkit/
```

Expected: clean working tree apart from pre-existing dirty paths (`.DS_Store`, `payload.txt`).

- [ ] **Step 3: Done**

Work is on the following commits (in order):
- Task 2: `refactor: extract ESIndexService base for ES-backed services`
- Task 3: `refactor: rename ElasticsearchService to BreachedCredsService`
- Task 4: `feat: add CisaKevService + CisaKevDoc for the cisa-kev ES index`
- Task 6: `feat: CISA KEV vulnerabilities page with role-aware access`
- Task 7: `feat: add Vulnerabilities link to Threat Intelligence nav`

Push when ready:

```bash
git -C /Users/jooy/Development/dseclab_backend push origin main
```

---

## Risks & notes

- **CSRF on JSON endpoint**: Flask-WTF requires `X-CSRFToken` on POST. The list-page JS already passes `window.CSRF_TOKEN`. Tests pass the token explicitly. If the project ever moves `threat_intel` behind `csrf.exempt`, the vulnerabilities blueprint must NOT inherit that — it stays protected.
- **`CisaKevDoc` field-name assumptions**: explicitly verified at implementation time in Task 1 (live ES sample). Mapping is dual camelCase/snake_case at construction so a future ingestion rewrite doesn't break.
- **Pagination math**: `ESPagination(items, page, per_page, total)` — positional order must match. Don't reorder.
- **Rate limit**: `60/minute` on `/api/vulnerabilities/search` — generous enough for live filtering as the user types, slow enough to dampen abuse.
- **Deprecation shim**: the `elasticsearch_service.py` shim emits `DeprecationWarning`. Remove it in a follow-up PR after dependent code (deploy scripts, notebooks) updates its imports.
