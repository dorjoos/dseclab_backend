"""DEPRECATED shim — import from cuba.services.breached_creds_service instead.

Kept for one release so external callers (deploy scripts, notebooks)
don't break across the rename. Remove after dependent code is updated.
"""
import warnings

from .breached_creds_service import (
    BreachedCredDoc,
    BreachedCredsService,
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
