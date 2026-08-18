"""`flask dseclab audit-scope` — who was exposed by the tenancy bug.

The code path is fixed, but the fix cannot tell you retrospectively whether
any account was ever in a position to use it. This command answers that, and
exits non-zero on findings so a deploy check or cron can act on it.
"""
import pytest

from cuba.cli import audit_scope
from tests.conftest import _make_user


def _run(app, runner_args=()):
    """Invoke the command and return (exit_code, output)."""
    runner = app.test_cli_runner()
    result = runner.invoke(audit_scope, list(runner_args))
    return result.exit_code, result.output


def test_clean_estate_reports_nothing_and_exits_zero(app, db, admin_user,
                                                     member_acme, company_acme):
    """An admin has no company by design; a member has one. Neither counts."""
    with app.app_context():
        code, out = _run(app)
    assert code == 0, out
    assert 'No company-less non-admin accounts' in out


def test_company_less_member_is_reported(app, db, company_acme):
    with app.app_context():
        _make_user(db, email='orphan@nowhere.example', role='member', company=None)
        code, out = _run(app)
    assert code == 1, 'a finding must fail the check, not just print'
    assert 'orphan@nowhere.example' in out
    assert '1 account(s)' in out


def test_admins_are_not_reported(app, db, admin_user):
    """Admins legitimately have no company — reporting them is noise that
    would train people to ignore the command."""
    with app.app_context():
        code, out = _run(app)
    assert code == 0, out
    assert admin_user.email not in out


def test_members_with_a_company_are_not_reported(app, db, member_acme,
                                                 company_acme):
    with app.app_context():
        code, out = _run(app)
    assert code == 0, out
    assert member_acme.email not in out


@pytest.mark.parametrize('role', ['member', 'analyst', 'viewer'])
def test_every_non_admin_role_counts(app, db, role):
    """The scope bug did not care which non-admin role you held."""
    with app.app_context():
        _make_user(db, email=f'{role}@nowhere.example', role=role, company=None)
        code, out = _run(app)
    assert code == 1
    assert f'{role}@nowhere.example' in out


def test_command_is_registered(app):
    """It is referenced in the deploy notes; a rename must break a test, not
    a runbook."""
    assert 'dseclab' in app.cli.commands
    assert 'audit-scope' in app.cli.commands['dseclab'].commands
