"""A schedule with no company must still label the rows it reports on.

collect_creds resolves `domains` to None for an unrestricted admin schedule —
correct for *scoping*, since such a report spans every tenant. It was then
passed straight to attach_matched_domain as `domains or []`, and labelling
against no domains leaves every credential with matched_domain=None and
match_path=None.

That is not merely a blank column in the PDF. classify_creds reads those two
fields to split staff / customer / third-party, and an unmatched credential
falls through to "customer" — so the email told a client that its own staff
were its customers.
"""
import pytest

from cuba.models import Company, ScheduledReport, WatchlistEntry
from cuba.services import report_scheduler as rs
from cuba.services.breached_creds_service import BreachedCredDoc, ESPagination

STAFF = {'username': 'b.otgon@acme.com', 'domain': '', 'password': 'x',
         'source': 'Telegram', 'type': 'combolist'}
CUSTOMER = {'username': 'shopper@gmail.com', 'domain': 'acme.com',
            'password': 'x', 'source': 'Telegram', 'type': 'url'}
SUPPLIER = {'username': 'rep@supplier.mn', 'domain': 'supplier.mn',
            'password': 'x', 'source': 'Telegram', 'type': 'url'}


@pytest.fixture()
def es_returns(monkeypatch):
    """Point the scheduler's ES at a fixed set of documents."""
    def _install(sources):
        from cuba.services.breached_creds_service import breached_creds_service as es
        docs = [BreachedCredDoc(f'd{i}', s) for i, s in enumerate(sources)]
        monkeypatch.setattr(es, 'search', lambda **kw: ESPagination(docs, 1, 200, len(docs)))
    return _install


def _admin_schedule(admin_user):
    """A schedule with no company — 'all I can see'.

    Unpersisted, like _sched_for in test_report_scheduler: collect_creds only
    reads .company and .creator, and adding a fixture User to a second session
    raises InvalidRequestError.
    """
    return ScheduledReport(name='All tenants', frequency='daily', format='pdf',
                           run_time='09:00', company=None,
                           creator=admin_user, created_by=admin_user.id,
                           is_active=True)


# --- the model helpers ---

def test_all_match_domains_spans_every_company(app, db, company_acme, company_other):
    db.session.add(WatchlistEntry(company_id=company_acme.id, entry_type='domain',
                                  entry_value='Mail.Acme.com'))
    db.session.add(WatchlistEntry(company_id=company_acme.id,
                                  entry_type='third_party',
                                  entry_value='supplier.mn'))
    db.session.commit()
    with app.app_context():
        domains = Company.all_match_domains()
    assert 'acme.com' in domains and 'other.com' in domains
    assert 'mail.acme.com' in domains, 'watchlist entries are missing'
    assert 'supplier.mn' in domains, 'third-party domains are watched too'


def test_all_third_party_domains_excludes_own_domains(app, db, company_acme):
    db.session.add(WatchlistEntry(company_id=company_acme.id, entry_type='domain',
                                  entry_value='mail.acme.com'))
    db.session.add(WatchlistEntry(company_id=company_acme.id,
                                  entry_type='third_party',
                                  entry_value='supplier.mn'))
    db.session.commit()
    with app.app_context():
        assert Company.all_third_party_domains() == ['supplier.mn']


# --- the regression ---

def test_admin_schedule_labels_its_rows(app, db, admin_user, company_acme,
                                        es_returns):
    es_returns([STAFF, CUSTOMER])
    with app.app_context():
        schedule = _admin_schedule(admin_user)
        creds, domains, _ = rs.collect_creds(schedule)

    assert domains == [], 'scoping must stay unrestricted for an admin schedule'
    matched = [c.matched_domain for c in creds]
    assert matched == ['acme.com', 'acme.com'], (
        f'rows went out unlabelled: {matched}')


def test_admin_schedule_does_not_file_staff_as_customers(app, db, admin_user,
                                                         company_acme, es_returns):
    """The consequence that actually reaches the client."""
    from cuba.services.email_service import classify_creds

    es_returns([STAFF, CUSTOMER])
    with app.app_context():
        schedule = _admin_schedule(admin_user)
        creds, _, third_party = rs.collect_creds(schedule)
        buckets = classify_creds(creds, third_party)

    assert [c.username for c in buckets['staff']] == ['b.otgon@acme.com']
    assert [c.username for c in buckets['customer']] == ['shopper@gmail.com']


def test_admin_schedule_still_recognises_a_supplier(app, db, admin_user,
                                                    company_acme, es_returns):
    """third_party was [] for a company-less schedule, so nothing could ever
    be classified as a supplier's."""
    from cuba.services.email_service import classify_creds

    db.session.add(WatchlistEntry(company_id=company_acme.id,
                                  entry_type='third_party',
                                  entry_value='supplier.mn'))
    db.session.commit()

    es_returns([SUPPLIER])
    with app.app_context():
        schedule = _admin_schedule(admin_user)
        creds, _, third_party = rs.collect_creds(schedule)
        buckets = classify_creds(creds, third_party)

    assert [c.username for c in buckets['third_party']] == ['rep@supplier.mn']


def test_company_schedule_is_unchanged(app, db, member_acme, company_acme,
                                       es_returns):
    """A schedule that names a company was never broken; keep it scoped to
    that company rather than to every watched domain."""
    es_returns([CUSTOMER])
    with app.app_context():
        row = ScheduledReport(name='Acme only', frequency='daily', format='pdf',
                              run_time='09:00', company=company_acme,
                              creator=member_acme, created_by=member_acme.id,
                              is_active=True)
        creds, domains, _ = rs.collect_creds(row)

    assert domains == ['acme.com']
    assert creds[0].matched_domain == 'acme.com'


# --- the PDF ---

def test_pdf_has_one_domain_column():
    """Same merge as the list page: Domain and Matched named one value."""
    import inspect
    src = inspect.getsource(rs.build_pdf)
    assert '"Matched"' not in src, 'the PDF still has a separate Matched column'
    assert 'or getattr(cred, "matched_domain", "")' in src, 'no fallback'
