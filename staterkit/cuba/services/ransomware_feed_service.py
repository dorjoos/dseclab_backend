"""Ransomware-feed service backed by the ransomware-feed ES index.

Returns data shaped exactly the way templates/threat_intel/ransomware.html
expects:
- get_groups()             -> list[{name, victims, last_seen, status, color}]
- get_recent(limit=10)     -> list[{group, victim, country, sector, date, data_size}]
- get_dashboard_stats()    -> {total_attacks, active_groups, countries_affected,
                               data_leaked_tb, attacks_this_month, sectors,
                               monthly_trend, monthly_labels}

Field-name tolerance: ransomware-feed indices in the wild use slightly
different conventions (ransomware.live, ransomwatch, etc). The doc wrapper
accepts the most common spellings; if the live index uses something else
entirely, just extend the `get(...)` calls.
"""
import hashlib
import logging
from collections import Counter, OrderedDict
from datetime import datetime, timedelta
from typing import Optional

from flask import current_app

from .es_base import ESIndexService

logger = logging.getLogger(__name__)


# Palette used to colour group cards; deterministic per-name so the same
# group always gets the same colour across page loads.
_PALETTE = [
    '#dc2626', '#d97706', '#7c3aed', '#4f46e5', '#0891b2',
    '#059669', '#ec4899', '#f59e0b', '#10b981', '#3b82f6',
    '#ef4444', '#a855f7', '#14b8a6', '#f97316', '#6366f1',
]


def _color_for(name: str) -> str:
    if not name:
        return '#6b7280'
    h = int(hashlib.md5(name.encode('utf-8')).hexdigest()[:8], 16)
    return _PALETTE[h % len(_PALETTE)]


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


def _fmt_date(d):
    if not d:
        return ''
    return d.strftime('%Y-%m-%d')


def _fmt_size(val):
    """Format whatever the feed gives for data size. Accepts a raw byte int,
    a string like '2.5 TB', or None."""
    if val is None or val == '':
        return ''
    if isinstance(val, (int, float)):
        # rough bytes -> human readable
        units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
        size = float(val)
        for u in units:
            if size < 1024:
                return f'{size:.1f} {u}'
            size /= 1024
        return f'{size:.1f} EB'
    return str(val)


class RansomwareDoc:
    """Wraps a ransomware-feed document with field-name tolerance."""

    def __init__(self, es_id: str, source: dict):
        self.es_id = es_id
        s = source or {}

        def get(*keys):
            for k in keys:
                if k in s and s[k] not in (None, ''):
                    return s[k]
            return None

        self.group = _clean(get('group_name', 'group', 'gang', 'actor'))
        self.victim = _clean(get('victim', 'victim_name', 'post_title', 'title'))
        self.country = _clean(get('country', 'country_code', 'victim_country'))
        self.sector = _clean(get('sector', 'activity', 'industry', 'victim_sector'))
        self.discovered = _parse_date(
            get('discovered', 'published', 'date', 'attack_date',
                'date_added', 'timestamp', 'created_at')
        )
        self.description = _clean(get('description', 'summary', 'post'))
        self.url = _clean(get('post_url', 'url', 'leak_site', 'screenshot'))
        self.data_size = get('data_size', 'size', 'leak_size', 'bytes')


class RansomwareFeedService(ESIndexService):
    def __init__(self):
        super().__init__('ransomware-feed')

    @property
    def index(self) -> str:
        try:
            return current_app.config.get('RANSOMWARE_FEED_INDEX', 'ransomware-feed')
        except Exception:
            return self._index

    # ------------------------------------------------------------------
    # Group summaries
    # ------------------------------------------------------------------

    def get_groups(self, top_n: int = 8) -> list:
        """Top `top_n` groups by victim count, with last-seen date and colour."""
        body = {
            'size': 0,
            'query': {'match_all': {}},
            'aggs': {
                'by_group': {
                    'terms': {
                        # Try both spellings via runtime field fallback isn't
                        # available pre-7.10; use whichever the index uses.
                        'field': 'group_name.keyword',
                        'size': top_n,
                        'missing': 'unknown',
                    },
                    'aggs': {
                        'last_seen': {
                            'max': {
                                'field': 'discovered',
                                'missing': 0,
                            }
                        }
                    }
                }
            }
        }
        resp = self._search(body)
        buckets = resp.get('aggregations', {}).get('by_group', {}).get('buckets', [])
        if not buckets:
            # Fall back to alternate field naming.
            body2 = {
                'size': 0,
                'query': {'match_all': {}},
                'aggs': {
                    'by_group': {
                        'terms': {'field': 'group.keyword', 'size': top_n, 'missing': 'unknown'},
                        'aggs': {'last_seen': {'max': {'field': 'date'}}}
                    }
                }
            }
            resp = self._search(body2)
            buckets = resp.get('aggregations', {}).get('by_group', {}).get('buckets', [])

        out = []
        for b in buckets:
            name = b.get('key') or 'unknown'
            last_seen_ms = b.get('last_seen', {}).get('value')
            last_seen = ''
            if last_seen_ms:
                try:
                    last_seen = datetime.utcfromtimestamp(last_seen_ms / 1000).strftime('%Y-%m-%d')
                except (TypeError, ValueError):
                    last_seen = ''
            out.append({
                'name': name,
                'victims': b.get('doc_count', 0),
                'last_seen': last_seen,
                'status': 'active',
                'color': _color_for(name),
            })
        return out

    # ------------------------------------------------------------------
    # Recent posts
    # ------------------------------------------------------------------

    def get_recent(self, limit: int = 10) -> list:
        body = {
            'size': limit,
            'sort': [{'discovered': {'order': 'desc', 'unmapped_type': 'date'}}],
            'query': {'match_all': {}},
            'track_total_hits': True,
        }
        resp = self._search(body)
        hits = resp.get('hits', {}).get('hits', [])
        out = []
        for h in hits:
            doc = RansomwareDoc(h['_id'], h.get('_source', {}))
            out.append({
                'group': doc.group or '—',
                'victim': doc.victim or '—',
                'country': doc.country or '',
                'sector': doc.sector or '',
                'date': _fmt_date(doc.discovered),
                'data_size': _fmt_size(doc.data_size),
            })
        return out

    # ------------------------------------------------------------------
    # Dashboard aggregates
    # ------------------------------------------------------------------

    def get_dashboard_stats(self) -> dict:
        now = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        month_start = now.replace(day=1).isoformat()
        twelve_months_ago = (now - timedelta(days=365)).isoformat()

        body = {
            'size': 0,
            'query': {'match_all': {}},
            'track_total_hits': True,
            'aggs': {
                'groups':    {'cardinality': {'field': 'group_name.keyword'}},
                'countries': {'cardinality': {'field': 'country.keyword'}},
                'by_sector': {
                    'terms': {'field': 'sector.keyword', 'size': 10, 'missing': 'Other'}
                },
                'monthly': {
                    'date_histogram': {
                        'field': 'discovered',
                        'calendar_interval': 'month',
                        'min_doc_count': 0,
                        'extended_bounds': {
                            'min': twelve_months_ago,
                            'max': now.isoformat(),
                        },
                    }
                },
            },
        }
        resp = self._search(body)

        total = resp.get('hits', {}).get('total', {})
        if isinstance(total, dict):
            total = total.get('value', 0)
        aggs = resp.get('aggregations', {})

        # Try alternate field names if primary returned empty.
        if not aggs.get('by_sector', {}).get('buckets'):
            body2 = {**body}
            body2['aggs'] = {
                'groups':    {'cardinality': {'field': 'group.keyword'}},
                'countries': {'cardinality': {'field': 'country.keyword'}},
                'by_sector': {'terms': {'field': 'activity.keyword', 'size': 10, 'missing': 'Other'}},
                'monthly':   body['aggs']['monthly'].copy(),
            }
            body2['aggs']['monthly']['date_histogram'] = dict(
                body['aggs']['monthly']['date_histogram'],
                field='date',
            )
            resp = self._search(body2)
            aggs = resp.get('aggregations', {})

        sectors = OrderedDict()
        for b in aggs.get('by_sector', {}).get('buckets', []):
            sectors[b.get('key', 'Other')] = b.get('doc_count', 0)

        monthly = aggs.get('monthly', {}).get('buckets', [])
        # Take the last 12 buckets
        monthly = monthly[-12:]
        monthly_labels = []
        monthly_trend = []
        for b in monthly:
            ts = b.get('key', 0)
            try:
                label = datetime.utcfromtimestamp(ts / 1000).strftime('%b')
            except (TypeError, ValueError):
                label = ''
            monthly_labels.append(label)
            monthly_trend.append(b.get('doc_count', 0))

        attacks_this_month_resp = self._count({
            'range': {'discovered': {'gte': month_start}}
        })
        if not attacks_this_month_resp:
            attacks_this_month_resp = self._count({
                'range': {'date': {'gte': month_start}}
            })

        return {
            'total_attacks': int(total),
            'active_groups': int(aggs.get('groups', {}).get('value') or 0),
            'countries_affected': int(aggs.get('countries', {}).get('value') or 0),
            'data_leaked_tb': 0,  # Not reliably present in feeds.
            'attacks_this_month': int(attacks_this_month_resp or 0),
            'sectors': dict(sectors) or {'Unknown': 0},
            'monthly_trend': monthly_trend or [0] * 12,
            'monthly_labels': monthly_labels or ['', '', '', '', '', '', '', '', '', '', '', ''],
        }


ransomware_feed_service = RansomwareFeedService()
