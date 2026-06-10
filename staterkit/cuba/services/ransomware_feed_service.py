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
import math
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


def _short(text, n=140):
    """Truncate text to roughly `n` characters, ending on a word boundary."""
    if not text:
        return ''
    t = ' '.join(str(text).split())  # collapse whitespace
    if len(t) <= n:
        return t
    cut = t[:n].rsplit(' ', 1)[0]
    return cut.rstrip(',.;:!? ') + '…'


def _safe_http_url(val):
    """Return val only if it is an http(s) URL — strip javascript:, data:,
    file:, etc. to neutralise XSS via attacker-controlled href in the feed."""
    if not val:
        return ''
    s = str(val).strip()
    low = s.lower()
    if low.startswith('http://') or low.startswith('https://'):
        return s
    return ''


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

        # Real prod fields first, then common fallbacks for portability.
        self.group = _clean(get('ransomware_group', 'group_name', 'group', 'gang', 'actor'))
        self.victim = _clean(get('victim_name', 'victim', 'post_title', 'title'))
        self.country = _clean(get('victim_country', 'country', 'country_code'))
        self.sector = _clean(get('sector', 'activity', 'industry', 'victim_sector'))
        self.discovered = _parse_date(
            get('@timestamp', 'published_date', 'discovered', 'published',
                'date', 'attack_date', 'date_added', 'timestamp', 'created_at')
        )
        self.description = _clean(get('raw_description', 'description', 'summary', 'post'))
        self.url = _clean(get('source_url', 'post_url', 'url', 'leak_site', 'screenshot'))
        self.victim_website = _clean(get('victim_website', 'website'))
        self.feed_source = _clean(get('feed_source', 'source'))
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
                        'field': 'ransomware_group',
                        'size': top_n,
                        'missing': 'unknown',
                    },
                    'aggs': {
                        'last_seen': {'max': {'field': '@timestamp'}}
                    }
                }
            }
        }
        resp = self._search(body)
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

    def get_recent(self, page: int = 1, per_page: int = 10) -> dict:
        """Paginated recent attacks. Returns {items, page, per_page, total,
        pages, has_prev, has_next}."""
        page = max(1, int(page or 1))
        per_page = max(1, min(100, int(per_page or 10)))
        body = {
            'size': per_page,
            'from': (page - 1) * per_page,
            'sort': [{'@timestamp': {'order': 'desc', 'unmapped_type': 'date'}}],
            'query': {'match_all': {}},
            'track_total_hits': True,
        }
        resp = self._search(body)
        hits = resp.get('hits', {}).get('hits', [])
        total = resp.get('hits', {}).get('total', {})
        if isinstance(total, dict):
            total = total.get('value', 0)
        total = int(total)
        out = []
        for h in hits:
            doc = RansomwareDoc(h['_id'], h.get('_source', {}))
            group = doc.group or 'unknown'
            description_full = doc.description or ''
            out.append({
                'group': group,
                'group_color': _color_for(group),
                'victim': doc.victim or '—',
                'victim_website': doc.victim_website or '',
                'country': doc.country or '',
                'sector': doc.sector or '',
                'date': _fmt_date(doc.discovered),
                'data_size': _fmt_size(doc.data_size),
                # Scheme-validated: an attacker-controlled feed row with
                # source_url='javascript:...' is stripped to '' here so it
                # never reaches a template href.
                'source_url': _safe_http_url(doc.url),
                'feed_source': doc.feed_source or '',
                'description': description_full,
                'description_short': _short(description_full, 120),
            })
        pages = max(1, math.ceil(total / per_page)) if per_page else 1
        return {
            'items': out,
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': pages,
            'has_prev': page > 1,
            'has_next': page < pages,
        }

    # ------------------------------------------------------------------
    # Dashboard aggregates
    # ------------------------------------------------------------------

    def get_dashboard_stats(self) -> dict:
        now = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        month_start = now.replace(day=1).isoformat()
        week_ago = (now - timedelta(days=7)).isoformat()
        twelve_months_ago = (now - timedelta(days=365)).isoformat()

        body = {
            'size': 0,
            'query': {'match_all': {}},
            'track_total_hits': True,
            'aggs': {
                'groups':    {'cardinality': {'field': 'ransomware_group'}},
                'countries': {'cardinality': {'field': 'victim_country'}},
                # The feed has no sector/industry — group by country instead so
                # the bar chart still tells the user something useful (top
                # affected countries). Renamed externally but keeps the same
                # template variable name to avoid a template churn.
                'by_country': {
                    'terms': {'field': 'victim_country', 'size': 10, 'missing': 'Unknown'}
                },
                'monthly': {
                    'date_histogram': {
                        'field': '@timestamp',
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

        sectors = OrderedDict()
        for b in aggs.get('by_country', {}).get('buckets', []):
            sectors[b.get('key', 'Unknown')] = b.get('doc_count', 0)

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
            'range': {'@timestamp': {'gte': month_start}}
        })

        # Distinct groups that posted in the last 7 days — operational signal
        # for 'who is currently active'. More useful than the hardcoded
        # 'Data Leaked: 0TB' since the feed has no size field.
        active_week_resp = self._search({
            'size': 0,
            'query': {'range': {'@timestamp': {'gte': week_ago}}},
            'aggs': {'g': {'cardinality': {'field': 'ransomware_group'}}},
        })
        active_this_week = int(
            active_week_resp.get('aggregations', {}).get('g', {}).get('value') or 0
        )

        return {
            'total_attacks': int(total),
            'active_groups': int(aggs.get('groups', {}).get('value') or 0),
            'countries_affected': int(aggs.get('countries', {}).get('value') or 0),
            'data_leaked_tb': 0,  # DEPRECATED — kept for back-compat.
            'active_this_week': active_this_week,
            'attacks_this_month': int(attacks_this_month_resp or 0),
            'sectors': dict(sectors) or {'Unknown': 0},
            'monthly_trend': monthly_trend or [0] * 12,
            'monthly_labels': monthly_labels or ['', '', '', '', '', '', '', '', '', '', '', ''],
        }


ransomware_feed_service = RansomwareFeedService()
