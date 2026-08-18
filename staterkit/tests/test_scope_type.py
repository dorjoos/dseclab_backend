"""The scope type itself: unrestricted is a value, not an absence.

Spelling "unrestricted" as None made it indistinguishable from the other
things None means around here — "no company", "not logged in", "argument
omitted". Two views crossed those wires and served a company-less member every
tenant's credentials.

Unrestricted is its own type now, so the mistake is a type error rather than
something a reviewer has to spot. These tests pin the runtime half of that
contract; mypy enforces the rest, and test_mypy_rejects_the_old_spelling below
checks the enforcement is actually switched on.
"""
import shutil
import subprocess
import textwrap

import pytest

from cuba.security import UNRESTRICTED, DomainScope, Unrestricted
from cuba.services.breached_creds_service import breached_creds_service as es

MATCH_NOTHING = {"bool": {"must_not": {"match_all": {}}}}


# --- the sentinel ---

def test_unrestricted_is_truthy():
    """`scope or fallback` must keep the unrestricted scope. The None spelling
    collapsed to the fallback, which is how "see everything" became
    "see nothing" at one call site and vice versa at another."""
    assert UNRESTRICTED
    assert (UNRESTRICTED or frozenset({'fallback.com'})) is UNRESTRICTED


def test_unrestricted_is_not_none_and_not_empty():
    """The three states must be mutually distinguishable."""
    assert UNRESTRICTED is not None
    assert frozenset() != UNRESTRICTED
    assert frozenset() is not None


def test_unrestricted_reads_well_in_a_traceback():
    assert repr(UNRESTRICTED) == 'UNRESTRICTED'


def test_unrestricted_carries_no_state():
    """__slots__ keeps it a marker; a sentinel that can hold attributes
    invites someone to smuggle scope through it."""
    with pytest.raises(AttributeError):
        UNRESTRICTED.domains = frozenset({'sneaky.com'})


def test_scope_alias_admits_exactly_the_two_shapes():
    assert isinstance(UNRESTRICTED, Unrestricted)
    assert DomainScope is not None  # imported and usable at runtime


# --- what the query builder does with each ---

def test_unrestricted_adds_no_domain_clause():
    assert es._build_query(domain_filters=UNRESTRICTED) == {"match_all": {}}


def test_empty_scope_matches_nothing():
    """Not "no filter" — a caller with no scope must see no rows."""
    query = es._build_query(domain_filters=frozenset())
    assert query["bool"]["filter"] == [MATCH_NOTHING]


def test_none_fails_closed():
    """A forgotten scope arrives as None. It must show too little, never too
    much — the old builder read None as unrestricted."""
    query = es._build_query(domain_filters=None)
    assert query["bool"]["filter"] == [MATCH_NOTHING]


def test_populated_scope_restricts():
    query = es._build_query(domain_filters=frozenset({'acme.com'}))
    clauses = query["bool"]["filter"]
    assert MATCH_NOTHING not in clauses
    assert clauses


# --- the scope cannot be omitted ---

@pytest.mark.parametrize('method', [
    'search', 'get_stats', 'get_recent', 'export',
    'get_daily_trends', 'get_weekly_trends', 'get_monthly_trends',
])
def test_every_query_method_demands_a_scope(method):
    """Keyword-only and required. A default would let a new call site inherit
    whatever the default happened to mean."""
    with pytest.raises(TypeError, match='domain_filters'):
        getattr(es, method)()


# --- and the enforcement is switched on ---

MYPY = shutil.which('mypy')


@pytest.mark.skipif(MYPY is None, reason='mypy is not installed')
def test_mypy_rejects_the_old_spelling(tmp_path):
    """The point of the whole change: the shape of the original bug must not
    type-check. A green suite with mypy disabled would be a false comfort."""
    probe = tmp_path / 'probe.py'
    probe.write_text(textwrap.dedent('''
        from cuba.security import get_user_watchlist_domains
        from cuba.services.breached_creds_service import (
            breached_creds_service as es,
        )

        def dashboard(user_domain: str | None) -> None:
            # The exact line that leaked one tenant's data to another.
            scope = get_user_watchlist_domains() if user_domain else None
            es.get_stats(domain_filters=scope)
    '''))
    result = subprocess.run(
        [MYPY, '--no-error-summary', '--follow-imports=silent', str(probe)],
        capture_output=True, text=True, cwd='.')
    assert result.returncode != 0, (
        'the old None-means-unrestricted spelling still type-checks:\n'
        f'{result.stdout}{result.stderr}')
    assert 'domain_filters' in result.stdout
