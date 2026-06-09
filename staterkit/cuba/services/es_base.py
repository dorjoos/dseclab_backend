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
