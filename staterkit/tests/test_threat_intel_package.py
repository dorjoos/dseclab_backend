"""The threat_intel package must keep looking like the module it replaced.

It was one 1,200-line file; it is now one module per area, all registering onto
a single blueprint. The split is only safe while every endpoint name survives —
templates reference url_for('threat_intel.*') throughout, and a missing
endpoint is a BuildError at render time, not an import error.
"""
import pytest

# Every endpoint the split had to preserve. A rename here is a broken template.
EXPECTED_ENDPOINTS = {
    'threat_intel.add_alert',
    'threat_intel.add_schedule',
    'threat_intel.analysis',
    'threat_intel.breach_summary',
    'threat_intel.breached_creds_add',
    'threat_intel.breached_creds_api',
    'threat_intel.breached_creds_delete',
    'threat_intel.breached_creds_edit',
    'threat_intel.breached_creds_employees',
    'threat_intel.breached_creds_export',
    'threat_intel.breached_creds_list',
    'threat_intel.breached_creds_mark',
    'threat_intel.breached_creds_reveal_password',
    'threat_intel.breached_creds_view',
    'threat_intel.delete_alert',
    'threat_intel.delete_schedule',
    'threat_intel.edit_schedule',
    'threat_intel.generate_report',
    'threat_intel.ransomware_dashboard',
    'threat_intel.reports',
    'threat_intel.timeline_api',
    'threat_intel.toggle_alert',
    'threat_intel.toggle_schedule',
}


def test_every_threat_intel_endpoint_is_registered(app):
    """A submodule that stops being imported drops its routes silently:
    __init__ imports them purely for the side effect of registration."""
    registered = {e for e in app.view_functions if e.startswith('threat_intel.')}
    assert registered == EXPECTED_ENDPOINTS


def test_all_areas_are_represented(app):
    """Guards the specific failure of one submodule import being dropped."""
    for probe in ('breached_creds_list', 'reports', 'ransomware_dashboard',
                  'analysis'):
        assert f'threat_intel.{probe}' in app.view_functions, (
            f'{probe} is missing — is its submodule still imported in '
            'cuba/threat_intel/__init__.py?')


@pytest.mark.parametrize('name', [
    'threat_intel', 'es_service', '_get_domain_filters', '_get_employee_emails',
    '_check_cred_access', '_attach_metadata', '_notify_new_breach',
])
def test_package_still_exposes_module_level_names(name):
    """Callers and tests reach these through `cuba.threat_intel`; the package
    has to keep answering to them or the split is a breaking change."""
    from cuba import threat_intel
    assert hasattr(threat_intel, name), f'cuba.threat_intel.{name} is gone'


def test_one_blueprint_not_several():
    """Several blueprints would have renamed every endpoint."""
    from cuba.threat_intel import analysis, breached_creds, ransomware, reports, threat_intel
    for module in (analysis, breached_creds, ransomware, reports):
        assert module.threat_intel is threat_intel
