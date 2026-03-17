"""Elasticsearch service for breached credential searches."""
import logging
import math
from datetime import datetime, timedelta

from elasticsearch import Elasticsearch

logger = logging.getLogger(__name__)


class ESPagination:
    """Mimics Flask-SQLAlchemy pagination so templates work unchanged."""

    def __init__(self, items, page, per_page, total):
        self.items = items
        self.page = page
        self.per_page = per_page
        self.total = total
        self.pages = max(1, math.ceil(total / per_page)) if per_page else 1
        self.has_prev = page > 1
        self.has_next = page < self.pages
        self.prev_num = page - 1 if self.has_prev else None
        self.next_num = page + 1 if self.has_next else None

    def iter_pages(self, left_edge=2, left_current=2, right_current=5, right_edge=2):
        last = 0
        for num in range(1, self.pages + 1):
            if (
                num <= left_edge
                or (self.page - left_current - 1 < num < self.page + right_current)
                or num > self.pages - right_edge
            ):
                if last + 1 != num:
                    yield None
                yield num
                last = num


class BreachedCredDoc:
    """Wraps an ES document to look like the old SQLAlchemy model."""

    TYPE_COLORS = {
        "combolist": "primary",
        "stealer": "danger",
        "malware": "warning",
        "pastebin": "info",
        "breach": "secondary",
        "phishing": "danger",
        "darkweb": "dark",
        "url": "info",
    }

    def __init__(self, es_id, source):
        self.es_id = es_id
        self.id = es_id
        self._source = source or {}

        self.username = self._clean(self._source.get("username"))
        self.domain = self._clean(self._source.get("domain"))
        self.password = self._source.get("password")
        self.source_name = self._clean(self._source.get("source"))
        self.source = self.source_name
        self.type = self._clean(self._source.get("type"))
        self.url = self._clean(self._source.get("url"))
        self.file_hash = self._clean(self._source.get("file_hash"))
        self.file_name = self._clean(self._source.get("file_name"))
        self.value = self._clean(self._source.get("value"))

        self.timestamp = self._parse_date(self._source.get("timestamp"))
        self.date_added = self._parse_date(self._source.get("date_added"))

        # Metadata fields (populated externally)
        self.is_marked = False
        self.marked_by = None
        self.marked_at = None
        self.marker = None
        self.notes = None

    @staticmethod
    def _clean(val):
        """Return None for empty/sentinel values like 'None', 'null', ''."""
        if val is None:
            return None
        if isinstance(val, str) and val.strip().lower() in ("none", "null", "n/a", ""):
            return None
        return val

    @property
    def created_at(self):
        return self.timestamp or self.date_added

    @property
    def type_color(self):
        return self.TYPE_COLORS.get((self.type or "").lower(), "secondary")

    @property
    def _score(self):
        return None

    @staticmethod
    def _parse_date(val):
        if val is None:
            return None
        if isinstance(val, datetime):
            return val
        try:
            # Handle ISO format with optional microseconds
            return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None


class ElasticsearchService:
    """High-level ES operations for breached credentials."""

    def __init__(self, app=None):
        self.es = None
        self.index = "main"
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        es_url = app.config.get("ELASTICSEARCH_URL", "https://localhost:9200")
        es_password = app.config.get(
            "ELASTICSEARCH_PASSWORD",
            ""
        )
        self.index = app.config.get("ELASTICSEARCH_INDEX", "main")

        self.es = Elasticsearch(
            es_url,
            basic_auth=("elastic", es_password),
            verify_certs=False,
            ssl_show_warn=False,
        )
        logger.info("Elasticsearch client initialised for %s / index=%s", es_url, self.index)

    # ------------------------------------------------------------------
    # Query building
    # ------------------------------------------------------------------

    def build_domain_filter(self, domains):
        """Build ES bool/should matching domains across multiple fields."""
        if not domains:
            return None

        should = []
        for domain in domains:
            if not domain:
                continue
            domain = domain.lower().strip()
            if not domain:
                continue

            # domain.keyword — exact or contains
            should.append({"wildcard": {"domain.keyword": {"value": f"*{domain}*", "case_insensitive": True}}})
            should.append({"term": {"domain.keyword": domain}})

            # username.keyword — email patterns and contains
            should.append({"wildcard": {"username.keyword": {"value": f"*@{domain}", "case_insensitive": True}}})
            should.append({"wildcard": {"username.keyword": {"value": f"*@*.{domain}", "case_insensitive": True}}})
            should.append({"term": {"username.keyword": domain}})
            should.append({"wildcard": {"username.keyword": {"value": f"*{domain}*", "case_insensitive": True}}})

            # url — contains domain
            should.append({"wildcard": {"url": {"value": f"*{domain}*", "case_insensitive": True}}})

        if not should:
            return None
        return {"bool": {"should": should, "minimum_should_match": 1}}

    def _build_query(self, query_text=None, filters=None, domain_filters=None):
        """Build an ES bool query from search text, filters, and domain filters."""
        must = []
        filter_clauses = []

        # Free-text search (never on password)
        if query_text and query_text.strip():
            q = query_text.strip().lower()
            must.append({
                "bool": {
                    "should": [
                        {"wildcard": {"username": {"value": f"*{q}*", "case_insensitive": True}}},
                        {"wildcard": {"domain": {"value": f"*{q}*", "case_insensitive": True}}},
                        {"wildcard": {"url": {"value": f"*{q}*", "case_insensitive": True}}},
                        {"wildcard": {"source": {"value": f"*{q}*", "case_insensitive": True}}},
                    ],
                    "minimum_should_match": 1
                }
            })

        # Structured filters
        if filters:
            if filters.get("type"):
                filter_clauses.append({"term": {"type.keyword": filters["type"]}})
            if filters.get("source"):
                filter_clauses.append({"wildcard": {"source.keyword": {"value": f"*{filters['source']}*", "case_insensitive": True}}})
            if filters.get("domain"):
                filter_clauses.append({"wildcard": {"domain.keyword": {"value": f"*{filters['domain']}*", "case_insensitive": True}}})

            date_filter = filters.get("date_filter")
            if date_filter:
                now = datetime.utcnow()
                if date_filter == "today":
                    gte = now.replace(hour=0, minute=0, second=0, microsecond=0)
                elif date_filter == "week":
                    gte = now - timedelta(days=7)
                elif date_filter == "month":
                    gte = now - timedelta(days=30)
                else:
                    gte = None
                if gte:
                    filter_clauses.append({"range": {"timestamp": {"gte": gte.isoformat()}}})

        # Domain-based access control
        if domain_filters:
            domain_q = self.build_domain_filter(domain_filters)
            if domain_q:
                filter_clauses.append(domain_q)

        if not must and not filter_clauses:
            return {"match_all": {}}

        query = {"bool": {}}
        if must:
            query["bool"]["must"] = must
        if filter_clauses:
            query["bool"]["filter"] = filter_clauses
        return query

    # ------------------------------------------------------------------
    # Search / read
    # ------------------------------------------------------------------

    def search(self, query_text=None, filters=None, domain_filters=None,
               page=1, per_page=20, sort="timestamp:desc"):
        """Search and paginate. Returns ESPagination."""
        try:
            query = self._build_query(query_text, filters, domain_filters)
            from_offset = (page - 1) * per_page

            # Parse sort
            sort_parts = sort.split(":")
            sort_field = sort_parts[0]
            sort_order = sort_parts[1] if len(sort_parts) > 1 else "desc"

            body = {
                "query": query,
                "from": from_offset,
                "size": per_page,
                "sort": [{sort_field: {"order": sort_order}}],
                "track_total_hits": True,
            }

            resp = self.es.search(index=self.index, body=body)
            total = resp["hits"]["total"]["value"]
            items = [
                BreachedCredDoc(hit["_id"], hit["_source"])
                for hit in resp["hits"]["hits"]
            ]
            return ESPagination(items, page, per_page, total)
        except Exception:
            logger.exception("ES search failed")
            return ESPagination([], page, per_page, 0)

    def get_by_id(self, doc_id):
        """Fetch a single document by _id."""
        try:
            resp = self.es.get(index=self.index, id=doc_id)
            return BreachedCredDoc(resp["_id"], resp["_source"])
        except Exception:
            logger.exception("ES get_by_id failed for %s", doc_id)
            return None

    def get_stats(self, domain_filters=None):
        """Return aggregate stats: total, by_type, by_source, by_domain."""
        try:
            query = self._build_query(domain_filters=domain_filters)
            body = {
                "query": query,
                "size": 0,
                "track_total_hits": True,
                "aggs": {
                    "by_type": {"terms": {"field": "type.keyword", "size": 50}},
                    "by_source": {"terms": {"field": "source.keyword", "size": 50}},
                    "by_domain": {"terms": {"field": "domain.keyword", "size": 10}},
                },
            }
            resp = self.es.search(index=self.index, body=body)
            total = resp["hits"]["total"]["value"]

            by_type = {
                b["key"]: b["doc_count"]
                for b in resp["aggregations"]["by_type"]["buckets"]
            }
            by_source = {
                b["key"]: b["doc_count"]
                for b in resp["aggregations"]["by_source"]["buckets"]
            }
            by_domain = {
                b["key"]: b["doc_count"]
                for b in resp["aggregations"]["by_domain"]["buckets"]
            }
            return {
                "total": total,
                "by_type": by_type,
                "by_source": by_source,
                "by_domain": by_domain,
            }
        except Exception:
            logger.exception("ES get_stats failed")
            return {"total": 0, "by_type": {}, "by_source": {}, "by_domain": {}}

    def get_daily_trends(self, days=30, domain_filters=None):
        """Return (labels, data) for a daily date_histogram."""
        try:
            query = self._build_query(domain_filters=domain_filters)
            gte = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
            body = {
                "query": query,
                "size": 0,
                "aggs": {
                    "daily": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "day",
                            "min_doc_count": 0,
                            "extended_bounds": {
                                "min": gte,
                                "max": datetime.utcnow().strftime("%Y-%m-%d"),
                            },
                        }
                    }
                },
                "post_filter": {"range": {"timestamp": {"gte": gte}}},
            }
            resp = self.es.search(index=self.index, body=body)
            buckets = resp["aggregations"]["daily"]["buckets"]
            labels = [b["key_as_string"][:10] for b in buckets]
            data = [b["doc_count"] for b in buckets]
            return labels, data
        except Exception:
            logger.exception("ES get_daily_trends failed")
            return [], []

    def get_monthly_trends(self, months=12, domain_filters=None):
        """Return (labels, data) for a monthly date_histogram."""
        try:
            query = self._build_query(domain_filters=domain_filters)
            gte = (datetime.utcnow() - timedelta(days=months * 30)).strftime("%Y-%m-%d")
            body = {
                "query": query,
                "size": 0,
                "aggs": {
                    "monthly": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "month",
                            "format": "yyyy-MM",
                            "min_doc_count": 0,
                            "extended_bounds": {
                                "min": gte,
                                "max": datetime.utcnow().strftime("%Y-%m-%d"),
                            },
                        }
                    }
                },
                "post_filter": {"range": {"timestamp": {"gte": gte}}},
            }
            resp = self.es.search(index=self.index, body=body)
            buckets = resp["aggregations"]["monthly"]["buckets"]
            labels = [b["key_as_string"] for b in buckets]
            data = [b["doc_count"] for b in buckets]
            return labels, data
        except Exception:
            logger.exception("ES get_monthly_trends failed")
            return [], []

    def get_recent(self, limit=10, domain_filters=None):
        """Return the most recent documents."""
        try:
            query = self._build_query(domain_filters=domain_filters)
            body = {
                "query": query,
                "size": limit,
                "sort": [{"timestamp": {"order": "desc"}}],
            }
            resp = self.es.search(index=self.index, body=body)
            return [
                BreachedCredDoc(hit["_id"], hit["_source"])
                for hit in resp["hits"]["hits"]
            ]
        except Exception:
            logger.exception("ES get_recent failed")
            return []

    def export(self, filters=None, domain_filters=None, max_records=10000):
        """Scroll through results for export. Returns list of BreachedCredDoc."""
        try:
            query = self._build_query(filters=filters, domain_filters=domain_filters)
            body = {
                "query": query,
                "size": min(1000, max_records),
                "sort": [{"timestamp": {"order": "desc"}}],
            }
            resp = self.es.search(index=self.index, body=body, scroll="2m")
            scroll_id = resp.get("_scroll_id")
            hits = resp["hits"]["hits"]
            results = [BreachedCredDoc(h["_id"], h["_source"]) for h in hits]

            while len(results) < max_records and len(hits) > 0:
                resp = self.es.scroll(scroll_id=scroll_id, scroll="2m")
                scroll_id = resp.get("_scroll_id")
                hits = resp["hits"]["hits"]
                if not hits:
                    break
                for h in hits:
                    results.append(BreachedCredDoc(h["_id"], h["_source"]))
                    if len(results) >= max_records:
                        break

            # Clean up scroll
            if scroll_id:
                try:
                    self.es.clear_scroll(scroll_id=scroll_id)
                except Exception:
                    pass

            return results
        except Exception:
            logger.exception("ES export failed")
            return []

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def index_document(self, doc):
        """Index a new document. Returns the new _id or None."""
        try:
            resp = self.es.index(index=self.index, document=doc)
            return resp["_id"]
        except Exception:
            logger.exception("ES index_document failed")
            return None

    def update_document(self, doc_id, doc):
        """Partial update. Returns True on success."""
        try:
            self.es.update(index=self.index, id=doc_id, doc=doc)
            return True
        except Exception:
            logger.exception("ES update_document failed for %s", doc_id)
            return False

    def delete_document(self, doc_id):
        """Delete a document. Returns True on success."""
        try:
            self.es.delete(index=self.index, id=doc_id)
            return True
        except Exception:
            logger.exception("ES delete_document failed for %s", doc_id)
            return False


# Module-level singleton
es_service = ElasticsearchService()
