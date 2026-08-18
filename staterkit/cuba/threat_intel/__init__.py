"""Threat-intelligence views.

Was a single 1,200-line module carrying breached credentials, reports,
ransomware and analysis; every change to one area touched the same file. Split
into one module per area, all registering onto the same blueprint so no
endpoint name — and so no template url_for() — changed.

Submodules are imported for their side effect of registering routes. The
re-exports below are the module-level names callers and tests already reach
for through `cuba.threat_intel`.
"""
from ..services.breached_creds_service import breached_creds_service as es_service
from . import analysis, breached_creds, ransomware, reports  # noqa: F401  (route registration)
from ._blueprint import threat_intel
from ._shared import (  # noqa: F401  (re-exported, see __all__)
    _attach_metadata,
    _check_cred_access,
    _cred_matches_domain,
    _get_domain_filters,
    _get_employee_emails,
    _get_match_domains,
    _host_belongs_to,
    _notify_new_breach,
    _send_breach_emails,
)

__all__ = [
    'threat_intel',
    'es_service',
    '_attach_metadata',
    '_check_cred_access',
    '_cred_matches_domain',
    '_get_domain_filters',
    '_get_employee_emails',
    '_get_match_domains',
    '_host_belongs_to',
    '_notify_new_breach',
    '_send_breach_emails',
]
