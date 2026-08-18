"""Breached credentials service backed by the 'main' ES index."""
import contextlib
import logging
import math
from datetime import datetime, timedelta

from elasticsearch import Elasticsearch

from .es_base import ESIndexService

logger = logging.getLogger(__name__)


class ESPagination:
    """Mimics Flask-SQLAlchemy pagination so templates work unchanged."""

    def __init__(self, items, page, per_page, total, error=False, max_pages=None):
        self.items = items
        self.page = page
        self.per_page = per_page
        self.total = total
        # True when the search backend (Elasticsearch) was unreachable or
        # errored. Lets views distinguish "no matches" from "backend down"
        # instead of silently showing an empty table.
        self.error = error
        self.pages = max(1, math.ceil(total / per_page)) if per_page else 1
        # Don't offer pages the backend cannot serve. A 900k-hit search has
        # 45,000 nominal pages but ES will only page through the first 10,000
        # results, so links past that would come back as a fake outage.
        if max_pages:
            self.pages = min(self.pages, max_pages)
            self.truncated = math.ceil(total / per_page) > self.pages if per_page else False
        else:
            self.truncated = False
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
        # Which watched domain this credential matched (set by callers that
        # know the relevant watchlist). None when unknown / no match.
        self.matched_domain = None

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


class BreachedCredsService(ESIndexService):
    """High-level ES operations for breached credentials."""

    def __init__(self, app=None):
        super().__init__("main")
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        es_url = app.config.get("ELASTICSEARCH_URL", "https://localhost:9200")
        es_password = app.config.get(
            "ELASTICSEARCH_PASSWORD",
            ""
        )
        # Note: storing on self._index so the base class's @property index returns it.
        self._index = app.config.get("ELASTICSEARCH_INDEX", "main")

        self._es = Elasticsearch(
            es_url,
            basic_auth=("elastic", es_password),
            verify_certs=app.config.get('ELASTICSEARCH_VERIFY_CERTS', False),
            ssl_show_warn=False,
        )
        logger.info("Elasticsearch client initialised for %s / index=%s", es_url, self._index)

    # ------------------------------------------------------------------
    # Query building
    # ------------------------------------------------------------------

    def build_domain_filter(self, domains):
        """Build ES bool/should matching domains across multiple fields.

        Matches a credential's domain/username-email-host/URL-host when it
        equals the watched domain or is a subdomain of it. Substring matches
        like 'ibank.mn' against 'nibank.mn' must not pass.
        """
        if not domains:
            return None

        should = []
        for domain in domains:
            if not domain:
                continue
            domain = domain.lower().strip().lstrip(".").rstrip(".")
            if not domain or len(domain) < 4:
                continue

            # domain.keyword — exact match or subdomain (anchored on a dot)
            should.append({"term": {"domain.keyword": domain}})
            should.append({"wildcard": {"domain.keyword": {"value": f"*.{domain}", "case_insensitive": True}}})

            # username.keyword — email whose host is the domain or a subdomain
            should.append({"wildcard": {"username.keyword": {"value": f"*@{domain}", "case_insensitive": True}}})
            should.append({"wildcard": {"username.keyword": {"value": f"*@*.{domain}", "case_insensitive": True}}})

            # url — host portion equals domain or a subdomain. Wildcards on the
            # raw URL string can't distinguish 'nibank.mn' from 'ibank.mn'
            # safely, so use a regexp anchored on the scheme/host boundary.
            host_re = domain.replace(".", "\\.")
            should.append({
                "regexp": {
                    "url": {
                        "value": f".*://([^/?#:@]+\\.)?{host_re}(:[0-9]+)?(/.*)?",
                        "case_insensitive": True,
                    }
                }
            })

        if not should:
            return None
        return {"bool": {"should": should, "minimum_should_match": 1}}

    # Each employee costs two bool/should clauses (see build_employee_filter),
    # so the list can't grow past ES's max_clause_count — 4096 on the ES 8
    # client this app pins — and turn the tab into an error. Well above any
    # real payroll; truncation is logged, never silent.
    MAX_EMPLOYEES = 1000

    # ES refuses from+size beyond index.max_result_window (10,000 by default).
    # search() clamps to this rather than letting the rejection surface as a
    # backend-down error.
    MAX_RESULT_WINDOW = 10000

    def build_employee_filter(self, emails):
        """Match credentials belonging to these exact people.

        Two shapes are matched, because feeds disagree on how they store an
        address:

        1. `username` is the whole address — b.otgon@khanbank.mn.
        2. `username` is only the local part and the host sits in `domain` —
           b.otgon + khanbank.mn. Both halves are required, so this stays as
           precise as the first: it cannot reach a different person at the
           same domain.

        Every clause is an exact term. Nothing here is a suffix or substring
        match: an employee filter answers "was *this person* breached", so
        b.otgon@khanbank.mn must not pull in every other address at the
        domain — the unfiltered tab already does that. It also rules out
        `on@acme.com` quietly matching inside `otgon@acme.com`.

        Not matched: the raw dump line. It usually contains the same address
        the pipeline already extracted into `username`, so scanning it would
        be mostly redundant, and doing so precisely needs an anchored regexp
        per employee — too slow at this clause count to pay for the narrow
        case of a feed that failed to parse its own row.

        An empty list yields a match-nothing clause. The caller asked to see
        one specific set of people; a company with nobody on file has no
        employee breaches, which is not the same as having no filter.
        """
        wanted = sorted({e.strip().lower() for e in (emails or []) if e and e.strip()})
        if not wanted:
            return {"bool": {"must_not": {"match_all": {}}}}

        if len(wanted) > self.MAX_EMPLOYEES:
            logger.warning(
                "employee filter truncated to %d of %d addresses; the rest are "
                "not searched", self.MAX_EMPLOYEES, len(wanted))
            wanted = wanted[:self.MAX_EMPLOYEES]

        # case_insensitive throughout: dumps are inconsistent about casing,
        # while the stored watchlist entry is normalised to lowercase.
        def _term(field, value):
            return {"term": {field: {"value": value, "case_insensitive": True}}}

        should = []
        for address in wanted:
            should.append(_term("username.keyword", address))
            local, _, host = address.partition("@")
            if local and host:
                should.append({"bool": {"filter": [
                    _term("username.keyword", local),
                    _term("domain.keyword", host),
                ]}})

        return {"bool": {"minimum_should_match": 1, "should": should}}

    @staticmethod
    def compute_match_detail(doc, domains):
        """Return (matched_domain, match_path), or (None, None) if nothing matched.

        Mirrors build_domain_filter's suffix-aware logic in Python so callers
        can label each result. A domain matches when the credential's domain,
        the host of its email username, or the host of its URL equals the
        watched domain or is a subdomain of it. Substring collisions such as
        'ibank.mn' vs 'nibank.mn' must not match.
        """
        if not domains:
            return None, None

        def _host_matches(value, domain):
            return bool(value) and (value == domain or value.endswith("." + domain))

        domain_val = (getattr(doc, "domain", None) or "").lower().strip()
        username = (getattr(doc, "username", None) or "").lower().strip()
        email_host = username.split("@", 1)[1] if "@" in username else ""

        url_host = ""
        url = getattr(doc, "url", None)
        if url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url if "://" in url else "//" + url)
                url_host = (parsed.hostname or "").lower().strip()
            except Exception:
                url_host = ""

        for domain in domains:
            if not domain:
                continue
            domain = domain.lower().strip().lstrip(".").rstrip(".")
            if not domain or len(domain) < 4:
                continue
            # Username first: an account *at* the watched domain is a stronger
            # statement than one merely harvested from its site.
            if _host_matches(email_host, domain):
                return domain, "username"
            if _host_matches(domain_val, domain) or _host_matches(url_host, domain):
                return domain, "site"
        return None, None

    @staticmethod
    def compute_matched_domain(doc, domains):
        """Return the watched domain this credential matched, else None."""
        return BreachedCredsService.compute_match_detail(doc, domains)[0]

    def attach_matched_domain(self, items, domains):
        """Set .matched_domain and .match_path on each item.

        match_path is what separates an organisation's own staff from its
        customers: 'username' means the account lives at the watched domain,
        'site' means the credential was captured against it.
        """
        for item in items:
            item.matched_domain, item.match_path = self.compute_match_detail(item, domains)
        return items

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
                # Treat domain and matched_domain as equivalent: match the
                # domain field, the email-username host, or the URL host — the
                # same fields matched_domain is derived from. A leading '@'
                # (e.g. "@khanbank.mn") is stripped so it still matches.
                dv = filters["domain"].strip().lstrip("@")
                filter_clauses.append({"bool": {"should": [
                    {"wildcard": {"domain.keyword": {"value": f"*{dv}*", "case_insensitive": True}}},
                    {"wildcard": {"username.keyword": {"value": f"*@*{dv}*", "case_insensitive": True}}},
                    {"wildcard": {"url": {"value": f"*{dv}*", "case_insensitive": True}}},
                ], "minimum_should_match": 1}})

            if filters.get("employees") is not None:
                # An explicit list, and an EMPTY one means "this company has no
                # employees on file" — which must match nothing, not everything.
                # Same trap as domain_filters below.
                filter_clauses.append(self.build_employee_filter(filters["employees"]))

            date_filter = filters.get("date_filter")
            if date_filter:
                now = datetime.utcnow()
                if date_filter == "24h":
                    # Rolling 24 hours, which is what the notification reports on;
                    # "today" resets at midnight and would report a different set.
                    gte = now - timedelta(hours=24)
                elif date_filter == "today":
                    gte = now.replace(hour=0, minute=0, second=0, microsecond=0)
                elif date_filter == "week":
                    gte = now - timedelta(days=7)
                elif date_filter == "month":
                    gte = now - timedelta(days=30)
                else:
                    gte = None
                if gte:
                    filter_clauses.append({"range": {"timestamp": {"gte": gte.isoformat()}}})

        # Domain-based access control.
        #
        # None means unrestricted, and only an admin may pass it. A list means
        # restrict to those domains — and an EMPTY list means the caller may
        # see nothing, not everything. Treating [] as "no filter" would turn a
        # user with no assigned scope into a user with total access, so the
        # empty case gets an explicit match-nothing clause.
        if domain_filters is not None:
            domain_q = self.build_domain_filter(domain_filters)
            filter_clauses.append(
                domain_q if domain_q else {"bool": {"must_not": {"match_all": {}}}})

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
        """Search and paginate. Returns ESPagination.

        Pages past the index's result window are clamped to the last reachable
        page rather than being sent to ES, which would reject them and surface
        as `error=True` — telling the user the search backend is down when it
        is fine. Reaching further needs search_after, not a bigger offset.
        """
        page = max(1, int(page or 1))
        per_page = max(1, int(per_page or 20))
        last_reachable = max(1, self.MAX_RESULT_WINDOW // per_page)
        if page > last_reachable:
            logger.info("page %d is past the %d-result window; clamped to %d",
                        page, self.MAX_RESULT_WINDOW, last_reachable)
            page = last_reachable
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
            return ESPagination(items, page, per_page, total,
                                max_pages=last_reachable)
        except Exception:
            logger.exception("ES search failed")
            return ESPagination([], page, per_page, 0, error=True)

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

    def get_daily_trends(self, days=7, domain_filters=None):
        """Return (labels, data) for a daily date_histogram."""
        try:
            query = self._build_query(domain_filters=domain_filters)
            gte = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
            # Add date range to the query itself
            if "bool" not in query:
                query = {"bool": {"filter": [{"range": {"timestamp": {"gte": gte}}}]}}
            elif "filter" in query["bool"]:
                query["bool"]["filter"].append({"range": {"timestamp": {"gte": gte}}})
            else:
                query["bool"]["filter"] = [{"range": {"timestamp": {"gte": gte}}}]
            body = {
                "query": query,
                "size": 0,
                "aggs": {
                    "daily": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "day",
                            "format": "yyyy-MM-dd",
                            "min_doc_count": 0,
                        }
                    }
                },
            }
            resp = self.es.search(index=self.index, body=body)
            buckets = resp["aggregations"]["daily"]["buckets"]
            day_names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
            labels = []
            for b in buckets:
                try:
                    dt = datetime.strptime(b["key_as_string"], "%Y-%m-%d")
                    labels.append(day_names[dt.weekday()] + " " + b["key_as_string"][5:])
                except Exception:
                    labels.append(b["key_as_string"][:10])
            data = [b["doc_count"] for b in buckets]
            return labels, data
        except Exception:
            logger.exception("ES get_daily_trends failed")
            return [], []

    def get_weekly_trends(self, weeks=12, domain_filters=None):
        """Return (labels, data) for a weekly date_histogram."""
        try:
            query = self._build_query(domain_filters=domain_filters)
            gte = (datetime.utcnow() - timedelta(weeks=weeks)).strftime("%Y-%m-%d")
            body = {
                "query": query,
                "size": 0,
                "aggs": {
                    "weekly": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "week",
                            "format": "yyyy-MM-dd",
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
            buckets = resp["aggregations"]["weekly"]["buckets"]
            labels = ["W" + str(i + 1) for i in range(len(buckets))]
            data = [b["doc_count"] for b in buckets]
            return labels, data
        except Exception:
            logger.exception("ES get_weekly_trends failed")
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
                            "format": "yyyy-MM-dd",
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
            # Convert to short month names: Jan, Feb...
            month_names = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
            labels = []
            for b in buckets:
                try:
                    dt = datetime.strptime(b["key_as_string"][:10], "%Y-%m-%d")
                    labels.append(month_names[dt.month - 1] + " " + str(dt.year)[2:])
                except Exception:
                    labels.append(b["key_as_string"][:7])
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
                # Best effort: the scroll expires on its own, and failing to
                # release it must not fail the export the caller asked for.
                with contextlib.suppress(Exception):
                    self.es.clear_scroll(scroll_id=scroll_id)

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
breached_creds_service = BreachedCredsService()
# Legacy alias — most call sites use `es_service` (kept for backward compat).
es_service = breached_creds_service
