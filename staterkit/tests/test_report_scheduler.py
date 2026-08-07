"""Scheduled report execution: due detection, claiming, scoping, delivery."""
from datetime import datetime, timedelta

import pytest

from cuba.models import ScheduledReport, ReportHistory, WatchlistEntry
from cuba.services import report_scheduler as rs


@pytest.fixture()
def schedule(db, admin_user):
    def _make(**kw):
        kw.setdefault("name", "Daily Report")
        kw.setdefault("frequency", "daily")
        kw.setdefault("format", "pdf")
        kw.setdefault("email_to", "a@example.com")
        kw.setdefault("is_active", True)
        kw.setdefault("next_run", datetime.utcnow() - timedelta(minutes=1))
        kw.setdefault("created_by", admin_user.id)
        row = ScheduledReport(**kw)
        db.session.add(row)
        db.session.commit()
        return row
    return _make


# --- time handling ---

@pytest.mark.parametrize("raw,expected", [
    # Parsed times snap to a slot boundary; 13:59 belongs to 14:00.
    ("2026-08-07T13:59", datetime(2026, 8, 7, 14, 0)),
    ("2026-08-07T13:59:30", datetime(2026, 8, 7, 14, 0)),
    ("2026-08-07 13:59", datetime(2026, 8, 7, 14, 0)),
    ("2026-08-07T13:00", datetime(2026, 8, 7, 13, 0)),
    ("", None),
    (None, None),
    ("not a date", None),
])
def test_parse_schedule_time(raw, expected):
    assert rs.parse_schedule_time(raw) == expected


@pytest.mark.parametrize("freq,max_days", [
    ("daily", 1),
    ("weekly", 7),
    ("monthly", 31),
])
def test_compute_next_run_advances_within_its_period(app, freq, max_days):
    """Times are wall-clock now, so assert the period rather than a fixed delta."""
    with app.app_context():
        base = datetime(2026, 8, 7, 13, 0)
        nxt = rs.compute_next_run(freq, base, "09:00",
                                  "" if freq == "daily" else "1")
        assert nxt > base
        assert (nxt - base).days <= max_days


def test_compute_next_run_unknown_frequency_is_none():
    assert rs.compute_next_run("fortnightly", datetime(2026, 8, 7)) is None


# --- due detection ---

def test_due_schedules_finds_past_next_run(app, schedule):
    with app.app_context():
        row = schedule()
        assert row.id in [s.id for s in rs.due_schedules()]


def test_future_and_inactive_schedules_are_not_due(app, schedule):
    with app.app_context():
        schedule(next_run=datetime.utcnow() + timedelta(hours=2))
        schedule(is_active=False)
        assert rs.due_schedules() == []


def test_schedule_without_next_run_is_never_due(app, schedule):
    with app.app_context():
        schedule(next_run=None)
        assert rs.due_schedules() == []


# --- claiming (the multi-worker guard) ---

def test_claim_moves_next_run_forward(app, schedule):
    with app.app_context():
        row = schedule(frequency="daily")
        before = row.next_run
        assert rs.claim_schedule(row) is True
        assert row.next_run > before
        assert row.last_run is not None


def test_only_one_worker_can_claim_a_due_run(app, schedule):
    """gunicorn runs many workers, each with its own scheduler; a second claim
    on the same due run must lose, or the report sends twice."""
    from types import SimpleNamespace

    with app.app_context():
        row = schedule()
        original_next_run = row.next_run

        assert rs.claim_schedule(row) is True

        # A second worker that read the row before the winner committed still
        # holds the old next_run. Modelled as a detached stand-in so it isn't
        # the same identity-mapped object the winner just mutated.
        other_worker = SimpleNamespace(id=row.id, frequency=row.frequency,
                                       run_time=row.run_time, run_days=row.run_days,
                                       next_run=original_next_run)
        assert rs.claim_schedule(other_worker) is False


# --- scoping ---

def test_company_schedule_uses_that_company_domains(app, db, admin_user, company_acme):
    with app.app_context():
        row = ScheduledReport(name="Acme", frequency="daily", format="pdf",
                              company_id=company_acme.id, created_by=admin_user.id,
                              next_run=datetime.utcnow())
        db.session.add(row)
        db.session.commit()
        captured = {}

        class _Page:
            error = False
            items = []

        def fake_search(**kw):
            captured.update(kw)
            return _Page()

        from cuba.services import breached_creds_service as mod
        original = mod.breached_creds_service.search
        mod.breached_creds_service.search = fake_search
        try:
            rs.collect_creds(row)
        finally:
            mod.breached_creds_service.search = original
        assert "acme.com" in captured["domain_filters"]


def test_third_party_watchlist_domains_are_returned(app, db, admin_user, company_acme):
    with app.app_context():
        db.session.add(WatchlistEntry(company_id=company_acme.id,
                                      entry_type="third_party",
                                      entry_value="supplier.mn"))
        db.session.commit()
        row = ScheduledReport(name="Acme", frequency="daily", format="pdf",
                              company_id=company_acme.id, created_by=admin_user.id,
                              next_run=datetime.utcnow())
        db.session.add(row)
        db.session.commit()

        class _Page:
            error = False
            items = []

        from cuba.services import breached_creds_service as mod
        original = mod.breached_creds_service.search
        mod.breached_creds_service.search = lambda **kw: _Page()
        try:
            _, domains, third_party = rs.collect_creds(row)
        finally:
            mod.breached_creds_service.search = original
        assert "supplier.mn" in domains        # searched...
        assert third_party == ["supplier.mn"]  # ...and labelled third-party


def test_member_creator_cannot_report_on_another_company(app, db, member_acme,
                                                         company_other):
    """A schedule pointed at a company the creator can't see yields nothing."""
    with app.app_context():
        row = ScheduledReport(name="Other", frequency="daily", format="pdf",
                              company_id=company_other.id, created_by=member_acme.id,
                              next_run=datetime.utcnow())
        db.session.add(row)
        db.session.commit()
        creds, domains, _ = rs.collect_creds(row)
        assert creds == [] and domains == []


# --- recipient policy (the exfiltration guard) ---

def _sched_for(company, creator, email_to):
    return ScheduledReport(name="R", frequency="daily", format="pdf",
                           email_to=email_to, company=company,
                           creator=creator, created_by=creator.id,
                           next_run=datetime.utcnow())


def test_recipients_must_sit_on_the_company_domain(app, company_acme, admin_user):
    with app.app_context():
        row = _sched_for(company_acme, admin_user,
                         "alice@acme.com,attacker@golomtbank.com")
        allowed, rejected = rs.validate_recipients(row)
        assert allowed == ["alice@acme.com"]
        assert [a for a, _ in rejected] == ["attacker@golomtbank.com"]


def test_subdomain_of_company_domain_is_allowed(app, company_acme, admin_user):
    with app.app_context():
        row = _sched_for(company_acme, admin_user, "ops@mail.acme.com")
        allowed, _ = rs.validate_recipients(row)
        assert allowed == ["ops@mail.acme.com"]


def test_lookalike_domain_is_refused(app, company_ibank, admin_user):
    """Suffix matching must not let nibank.mn satisfy ibank.mn."""
    with app.app_context():
        row = _sched_for(company_ibank, admin_user, "attacker@nibank.mn")
        allowed, rejected = rs.validate_recipients(row)
        assert allowed == []
        assert rejected


def test_third_party_domain_is_not_a_valid_recipient(app, db, company_acme, admin_user):
    """Watching a supplier doesn't entitle them to the client's findings."""
    with app.app_context():
        from cuba.models import Company
        db.session.add(WatchlistEntry(company_id=company_acme.id,
                                      entry_type="third_party",
                                      entry_value="supplier.mn"))
        db.session.commit()
        # Re-fetch in this session: the fixture object belongs to the outer
        # app context's session and would not see the new entry.
        company = db.session.get(Company, company_acme.id)
        assert "supplier.mn" not in company.get_own_domains()
        row = _sched_for(company, admin_user, "someone@supplier.mn")
        allowed, rejected = rs.validate_recipients(row)
        assert allowed == []
        assert rejected


def test_without_a_company_only_the_creator_may_be_mailed(app, admin_user):
    """Covers the live 'company=None → external address' schedules."""
    with app.app_context():
        row = _sched_for(None, admin_user,
                         f"{admin_user.email},dorjsambuu@golomtbank.com")
        allowed, rejected = rs.validate_recipients(row)
        assert allowed == [admin_user.email]
        assert [a for a, _ in rejected] == ["dorjsambuu@golomtbank.com"]


def test_malformed_addresses_are_refused(app, company_acme, admin_user):
    with app.app_context():
        row = _sched_for(company_acme, admin_user, "not-an-email,a b@acme.com")
        allowed, rejected = rs.validate_recipients(row)
        assert allowed == []
        assert len(rejected) == 2


def test_recipient_count_is_capped(app, company_acme, admin_user):
    with app.app_context():
        many = ",".join(f"u{i}@acme.com" for i in range(rs.MAX_RECIPIENTS + 5))
        row = _sched_for(company_acme, admin_user, many)
        allowed, rejected = rs.validate_recipients(row)
        assert len(allowed) == rs.MAX_RECIPIENTS
        assert len(rejected) == 5


def test_send_time_revalidation_drops_a_now_invalid_recipient(app, db, schedule,
                                                              company_acme, monkeypatch):
    """A row edited straight in the database must not deliver anyway."""
    with app.app_context():
        row = schedule(company_id=company_acme.id, email_to="alice@acme.com")
        app.config.update(MAIL_USERNAME="resend", MAIL_PASSWORD="key")
        # Bypass the create-time check the way a direct DB edit would.
        row.email_to = "attacker@golomtbank.com"
        db.session.commit()

        sent = []

        class _Page:
            error = False
            items = []

        from cuba.services import breached_creds_service as mod
        monkeypatch.setattr(mod.breached_creds_service, "search", lambda **kw: _Page())
        import cuba.services.email_service as es
        monkeypatch.setattr(es, "send_email",
                            lambda to, s, b, a=None, an=None, text=None: sent.append(to) or True)

        rs.run_due(app)
        assert sent == []


def test_send_writes_an_audit_row(app, db, schedule, company_acme, member_acme,
                                  monkeypatch):
    with app.app_context():
        from cuba.models import AuditLog
        row = schedule(company_id=company_acme.id, email_to=member_acme.email,
                       created_by=member_acme.id)
        app.config.update(MAIL_USERNAME="resend", MAIL_PASSWORD="key")

        class _Page:
            error = False
            items = []

        from cuba.services import breached_creds_service as mod
        monkeypatch.setattr(mod.breached_creds_service, "search", lambda **kw: _Page())
        import cuba.services.email_service as es
        monkeypatch.setattr(es, "send_email",
                            lambda to, s, b, a=None, an=None, text=None: True)

        rs.run_due(app)
        audit = AuditLog.query.filter_by(action_type="scheduled_report_sent").all()
        assert len(audit) == 1
        assert member_acme.email in audit[0].description


def test_inactive_creator_disables_the_schedule(app, db, schedule, member_acme,
                                                monkeypatch):
    """An offboarded account must not keep exporting on its own schedule."""
    from cuba.models import User

    with app.app_context():
        row = schedule(created_by=member_acme.id, email_to=member_acme.email)
        # Deactivate through this session, so the change actually reaches the
        # database that run_due's own session will read.
        db.session.get(User, member_acme.id).is_active = False
        db.session.commit()

        sent = []
        import cuba.services.email_service as es
        monkeypatch.setattr(es, "send_email",
                            lambda to, s, b, a=None, an=None, text=None: sent.append(to) or True)

        assert rs.run_due(app) == 0
        assert sent == []
        assert db.session.get(ScheduledReport, row.id).is_active is False


def test_pdf_never_contains_a_password(app):
    """The attachment leaves our control entirely once mailed."""
    from types import SimpleNamespace
    with app.app_context():
        cred = SimpleNamespace(username="a@acme.com", domain="acme.com",
                               matched_domain="acme.com", source="Telegram",
                               created_at=None, password="SuperSecret123!")
        pdf = rs.build_pdf("Report", [cred], "tester")
        assert pdf and b"SuperSecret123!" not in pdf


def test_admin_allowlisted_address_bypasses_the_domain_rule(app, db, company_acme,
                                                            admin_user):
    """An admin can approve one exact off-domain address per company."""
    from cuba.models import Company
    from cuba.models import ReportRecipient
    db.session.add(ReportRecipient(company_id=company_acme.id,
                                   email="ciso@consultancy.example"))
    db.session.commit()
    with app.app_context():
        company = db.session.get(Company, company_acme.id)
        row = _sched_for(company, admin_user,
                         "ciso@consultancy.example,other@consultancy.example")
        allowed, rejected = rs.validate_recipients(row)
        assert allowed == ["ciso@consultancy.example"]
        assert [a for a, _ in rejected] == ["other@consultancy.example"]


def test_allowlist_is_per_company(app, db, company_acme, company_other, admin_user):
    """Approving an address for one client must not approve it for another."""
    from cuba.models import Company
    from cuba.models import ReportRecipient
    db.session.add(ReportRecipient(company_id=company_acme.id,
                                   email="ciso@consultancy.example"))
    db.session.commit()
    with app.app_context():
        other = db.session.get(Company, company_other.id)
        row = _sched_for(other, admin_user, "ciso@consultancy.example")
        allowed, _ = rs.validate_recipients(row)
        assert allowed == []


# --- delivery ---

def test_run_due_sends_and_records_history(app, db, schedule, company_acme, monkeypatch):
    with app.app_context():
        # Recipients must sit on the target company's domain to be delivered.
        row = schedule(company_id=company_acme.id, format="pdf",
                       email_to="one@acme.com,two@acme.com")
        app.config.update(MAIL_USERNAME="resend", MAIL_PASSWORD="key")
        sent = []

        class _Page:
            error = False
            items = []

        from cuba.services import breached_creds_service as mod
        monkeypatch.setattr(mod.breached_creds_service, "search", lambda **kw: _Page())

        import cuba.services.email_service as es
        monkeypatch.setattr(es, "send_email",
                            lambda to, s, b, a=None, an=None, text=None: sent.append(to) or True)

        assert rs.run_due(app) == 1
        assert sent == ["one@acme.com", "two@acme.com"]
        history = ReportHistory.query.filter_by(schedule_id=row.id).all()
        assert len(history) == 1
        assert history[0].source == "scheduled"


def test_run_due_survives_a_failing_schedule(app, db, schedule, monkeypatch):
    """One broken schedule must not stop the others from running."""
    with app.app_context():
        schedule(name="broken")
        from cuba.services import breached_creds_service as mod

        def boom(**kw):
            raise RuntimeError("ES down")

        monkeypatch.setattr(mod.breached_creds_service, "search", boom)
        assert rs.run_due(app) == 0  # did not raise


# --- slot alignment ---

@pytest.mark.parametrize("raw,expected", [
    ("2026-08-07T20:09", datetime(2026, 8, 7, 20, 0)),   # down to :00
    ("2026-08-07T20:20", datetime(2026, 8, 7, 20, 30)),  # up to :30
    ("2026-08-07T20:30", datetime(2026, 8, 7, 20, 30)),  # already a slot
    ("2026-08-07T20:59", datetime(2026, 8, 7, 21, 0)),   # rolls the hour
])
def test_parsed_times_snap_to_a_slot(raw, expected):
    """Second-level precision buys nothing and costs a wake-up per minute."""
    assert rs.parse_schedule_time(raw) == expected


def test_next_run_lands_on_a_slot(app):
    with app.app_context():
        nxt = rs.compute_next_run("daily", datetime(2026, 8, 7, 20, 9), "09:30", "")
        assert nxt.minute in (0, 30) and nxt.second == 0


def test_claim_advances_from_the_slot_not_from_now(app, schedule):
    """Advancing from the moment we happen to run would drift the time later
    on every execution."""
    with app.app_context():
        slot = datetime.utcnow().replace(second=0, microsecond=0) - timedelta(days=1)
        slot = rs.round_to_slot(slot)
        row = schedule(frequency="daily", next_run=slot)
        assert rs.claim_schedule(row) is True
        assert row.next_run > datetime.utcnow()      # never leaves it in the past
        assert row.next_run.minute in (0, 30)        # still on a slot
        assert row.next_run.second == 0


# --- local wall-clock scheduling ---

from zoneinfo import ZoneInfo

UB = ZoneInfo("Asia/Ulaanbaatar")   # UTC+8


def test_daily_time_is_local_not_utc(app):
    """09:00 means 09:00 in Ulaanbaatar, which is 01:00 UTC."""
    with app.app_context():
        nxt = rs.next_occurrence("daily", "09:00", "",
                                 datetime(2026, 8, 7, 0, 0), tz=UB)
        assert nxt == datetime(2026, 8, 7, 1, 0)      # 09:00 +08 == 01:00Z
        assert rs.to_local(nxt, UB).hour == 9


def test_daily_rolls_to_tomorrow_once_past(app):
    with app.app_context():
        nxt = rs.next_occurrence("daily", "09:00", "",
                                 datetime(2026, 8, 7, 2, 0), tz=UB)
        assert nxt == datetime(2026, 8, 8, 1, 0)


def test_weekly_picks_the_next_selected_weekday(app):
    """Mon+Fri from a Wednesday should land on Friday."""
    with app.app_context():
        wednesday = datetime(2026, 8, 5, 0, 0)       # 08:00 local Wed
        nxt = rs.next_occurrence("weekly", "09:00", "1,5", wednesday, tz=UB)
        assert rs.to_local(nxt, UB).isoweekday() == 5


def test_weekly_wraps_to_next_week(app):
    """Monday-only, asked on a Monday afternoon, goes to next Monday."""
    with app.app_context():
        monday_late = datetime(2026, 8, 3, 6, 0)     # 14:00 local Mon
        nxt = rs.next_occurrence("weekly", "09:00", "1", monday_late, tz=UB)
        local = rs.to_local(nxt, UB)
        assert local.isoweekday() == 1 and local.day == 10


def test_monthly_uses_the_chosen_day(app):
    with app.app_context():
        nxt = rs.next_occurrence("monthly", "09:00", "15",
                                 datetime(2026, 8, 7, 0, 0), tz=UB)
        assert rs.to_local(nxt, UB).day == 15


def test_monthly_31st_clamps_to_a_short_month(app):
    """A 31st must land on the last day rather than skipping the month."""
    with app.app_context():
        nxt = rs.next_occurrence("monthly", "09:00", "31",
                                 datetime(2026, 9, 5, 0, 0), tz=UB)
        local = rs.to_local(nxt, UB)
        assert (local.month, local.day) == (9, 30)


def test_unknown_frequency_has_no_occurrence(app):
    with app.app_context():
        assert rs.next_occurrence("hourly", "09:00", "", datetime(2026, 8, 7), tz=UB) is None
