"""CISA KEV (Known Exploited Vulnerabilities) service backed by ES."""
import logging
from datetime import datetime, timedelta
from typing import Any

from flask import current_app

from .breached_creds_service import ESPagination
from .es_base import ESIndexService

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


def _today_iso():
    """Return today at 00:00 UTC as ISO8601 — boundary for due_soon/overdue ranges."""
    return datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()


class CisaKevDoc:
    """Wraps a cisa-kev ES document. Tolerates camelCase or snake_case fields.

    CISA publishes camelCase (cveID, vendorProject, ...); an ingestion
    pipeline may have rewritten them. Either form works.
    """

    def __init__(self, es_id: str, source: dict):
        self.es_id = es_id
        s = source or {}
        def get(camel, snake):
            """Feeds disagree on casing; accept either spelling."""
            return s.get(camel) if camel in s else s.get(snake)

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
        super().__init__('cisa-kev')

    @property
    def index(self) -> str:
        try:
            return current_app.config.get('CISA_KEV_INDEX', 'cisa-kev')
        except Exception:
            return self._index

    def get_by_id(self, doc_id: str) -> CisaKevDoc | None:
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

        query: dict[str, Any] = {'bool': {}}
        if must:
            query['bool']['must'] = must
        if filter_clauses:
            query['bool']['filter'] = filter_clauses
        if not query['bool']:
            query = {'match_all': {}}
        return query

    def search(
        self,
        query_text: str | None = None,
        filters: dict | None = None,
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
        today = _today_iso()
        in_7d = (datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                 + timedelta(days=7)).isoformat()

        due_soon = self._count({
            'bool': {
                'should': [
                    {'range': {'dueDate': {'gte': today, 'lt': in_7d}}},
                    {'range': {'due_date': {'gte': today, 'lt': in_7d}}},
                ],
                'minimum_should_match': 1,
            }
        })
        overdue = self._count({
            'bool': {
                'should': [
                    {'range': {'dueDate': {'lt': today}}},
                    {'range': {'due_date': {'lt': today}}},
                ],
                'minimum_should_match': 1,
            }
        })

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
            'due_soon': int(due_soon or 0),
            'overdue': int(overdue or 0),
        }


cisa_kev_service = CisaKevService()
