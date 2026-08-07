"""Execution of ScheduledReport rows: due detection, claiming, delivery.

The scheduler runs in-process (APScheduler) rather than as a cron-driven CLI,
which means every gunicorn worker starts one — gunicorn.conf.py runs
`cpu_count() * 2 + 1` of them. Nothing here may assume it is the only runner:
a due schedule is claimed with a conditional UPDATE that exactly one worker can
win, and the loser simply moves on. See claim_schedule().
"""
import io
import logging
import re
from datetime import datetime, timedelta

from .. import db

logger = logging.getLogger(__name__)

# How often the background job looks for due schedules.
POLL_SECONDS = 60

_FREQUENCY_DELTAS = {
    "daily": timedelta(days=1),
    "weekly": timedelta(weeks=1),
    "monthly": timedelta(days=30),
}


def compute_next_run(frequency, after):
    """Next occurrence strictly after `after`, or None for unknown frequency."""
    delta = _FREQUENCY_DELTAS.get((frequency or "").lower())
    return (after + delta) if delta else None


def parse_schedule_time(raw):
    """Parse the form's datetime-local value ('2026-08-07T13:59')."""
    if not raw:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
    return None


def due_schedules(now=None):
    """Active schedules whose next_run has arrived."""
    from ..models import ScheduledReport
    now = now or datetime.utcnow()
    return (ScheduledReport.query
            .filter(ScheduledReport.is_active.is_(True),
                    ScheduledReport.next_run.isnot(None),
                    ScheduledReport.next_run <= now)
            .all())


def claim_schedule(schedule, now=None):
    """Atomically take ownership of a due run. True if this process won it.

    The UPDATE is conditional on next_run still holding the value we read, so
    concurrent workers racing on the same row produce exactly one winner: the
    first commit moves next_run forward and every other UPDATE matches zero
    rows. Without this, each worker would send the same report.
    """
    from ..models import ScheduledReport
    now = now or datetime.utcnow()
    expected = schedule.next_run
    if expected is None:
        return False

    following = compute_next_run(schedule.frequency, now)
    updated = (db.session.query(ScheduledReport)
               .filter(ScheduledReport.id == schedule.id,
                       ScheduledReport.next_run == expected)
               .update({"next_run": following, "last_run": now},
                       synchronize_session=False))
    db.session.commit()
    if updated:
        db.session.refresh(schedule)
        return True
    return False


_EMAIL_RE = re.compile(r"^[^@\s,;:<>\"']+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# A single schedule fanning out to dozens of addresses is a distribution list,
# not a report; cap it so one row can't become a broadcast channel.
MAX_RECIPIENTS = 20


def _host_of(address):
    return address.rsplit("@", 1)[1].lower() if "@" in address else ""


def _domain_allows(host, domain):
    """Suffix-aware, matching the rest of the app: a subdomain of a watched
    domain counts, but 'nibank.mn' must never satisfy 'ibank.mn'."""
    return bool(host) and (host == domain or host.endswith("." + domain))


def allowed_recipient_domains(schedule):
    """Domains a schedule may mail to.

    Bound to the target company's own domains: a Statebank report reaches
    @statebank.mn addresses and nothing else. A schedule with no company has no
    such anchor, so it gets none — see validate_recipients for that case.
    """
    company = getattr(schedule, "company", None)
    return company.get_own_domains() if company is not None else []


def validate_recipients(schedule, addresses=None):
    """Split a schedule's recipients into (allowed, rejected).

    Enforced when the schedule is created *and* again at send time: a company's
    domains, its users, and the creator's standing can all change after a
    schedule is saved, and a stale row must not keep delivering.
    """
    raw = addresses if addresses is not None else (schedule.email_to or "")
    if isinstance(raw, str):
        candidates = [a.strip() for a in raw.split(",") if a.strip()]
    else:
        candidates = [str(a).strip() for a in raw if str(a).strip()]

    allowed, rejected = [], []
    company = getattr(schedule, "company", None)
    domains = allowed_recipient_domains(schedule)
    allowlist = set(company.get_report_recipient_allowlist()) if company else set()
    creator_email = (getattr(schedule.creator, "email", "") or "").lower()

    for address in candidates:
        low = address.lower()
        if not _EMAIL_RE.match(address):
            rejected.append((address, "not a valid email address"))
        elif low in allowlist:
            # Admin-approved exception to the domain rule.
            allowed.append(address)
        elif domains:
            if any(_domain_allows(_host_of(low), d) for d in domains):
                allowed.append(address)
            else:
                rejected.append(
                    (address, "not on " + ", ".join(domains)
                     + ", and not on the company's approved recipient list"))
        elif low == creator_email and creator_email:
            # No company to anchor to: the creator may still mail themselves.
            allowed.append(address)
        else:
            rejected.append(
                (address, "schedule has no company, so only the creator's own "
                          "address is permitted"))

    if len(allowed) > MAX_RECIPIENTS:
        for extra in allowed[MAX_RECIPIENTS:]:
            rejected.append((extra, f"exceeds the {MAX_RECIPIENTS}-recipient limit"))
        allowed = allowed[:MAX_RECIPIENTS]
    return allowed, rejected


def domains_for_user(user):
    """Watched domains this user may see. None means unrestricted (admin)."""
    if user is None:
        return []
    if getattr(user, "is_admin_user", False):
        return None
    company = getattr(user, "company", None)
    return company.get_match_domains() if company else []


def build_pdf(name, creds, generated_for):
    """Render creds to a PDF, or None when reportlab isn't available."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
    except ImportError:
        logger.warning("reportlab unavailable; sending report without attachment")
        return None

    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = [
        Paragraph("D-SECLAB", styles["Title"]),
        Paragraph(name, styles["Heading2"]),
        Spacer(1, 12),
        Paragraph(
            f"Prepared for: {generated_for}<br/>"
            f"Records: {len(creds)}<br/>"
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            styles["Normal"]),
        Spacer(1, 12),
    ]

    # Passwords are deliberately absent — this file leaves our control the
    # moment it is attached to an email.
    rows = [["Username", "Domain", "Matched", "Source", "Date"]]
    for cred in creds[:200]:
        rows.append([
            (getattr(cred, "username", "") or "")[:34],
            (getattr(cred, "domain", "") or "")[:26],
            (getattr(cred, "matched_domain", "") or "")[:26],
            (getattr(cred, "source", "") or "")[:24],
            cred.created_at.strftime("%Y-%m-%d") if getattr(cred, "created_at", None) else "",
        ])
    table = Table(rows)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#26359C")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D8DEE6")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
    ]))
    elements.append(table)
    if len(creds) > 200:
        elements += [Spacer(1, 10),
                     Paragraph(f"Showing first 200 of {len(creds)} records.",
                               styles["Normal"])]
    doc.build(elements)
    return output.getvalue()


def collect_creds(schedule):
    """Fetch the credentials a schedule reports on.

    A schedule targeting a company reports on that company's watched domains.
    Without one it falls back to whatever its creator may see. Returns
    (creds, domains, third_party_domains).
    """
    from .breached_creds_service import breached_creds_service as es

    company = getattr(schedule, "company", None)
    third_party = []
    if company is not None:
        domains = company.get_match_domains()
        third_party = company.get_third_party_domains()
        creator_scope = domains_for_user(schedule.creator)
        if creator_scope is not None:
            # Non-admin creator: never let a schedule reach past their own scope.
            allowed = set(creator_scope)
            domains = [d for d in domains if d in allowed]
    else:
        domains = domains_for_user(schedule.creator)

    if domains is not None and not domains:
        # Nothing this schedule is allowed to report on.
        return [], [], []

    window = "24h" if (schedule.frequency or "").lower() == "daily" else "week"
    page = es.search(domain_filters=domains or None,
                     filters={"date_filter": window},
                     page=1, per_page=200)
    if page.error:
        raise RuntimeError("Elasticsearch unavailable")
    creds = es.attach_matched_domain(page.items, domains or [])
    return creds, (domains or []), third_party


def run_schedule(schedule):
    """Generate and deliver one claimed schedule. Returns records sent."""
    from ..models import ReportHistory
    from .email_service import build_breach_email, send_email, is_email_configured
    from flask import current_app

    creds, domains, third_party = collect_creds(schedule)

    # Re-check every recipient now, not just when the row was saved: company
    # domains change, and a schedule edited straight in the database would
    # otherwise deliver whatever it was given.
    recipients, rejected = validate_recipients(schedule)
    for address, reason in rejected:
        logger.warning("Schedule %s: refusing recipient %s — %s",
                       schedule.id, address, reason)

    company = getattr(schedule, "company", None)
    subject, body, text = build_breach_email(
        company.name if company else schedule.name, creds,
        base_url=current_app.config.get("APP_BASE_URL"),
        company_domain=(company.domain if company
                        else (domains[0] if len(domains) == 1 else None)),
        third_party_domains=third_party,
    )

    attachment = attachment_name = None
    if (schedule.format or "").lower() == "pdf":
        attachment = build_pdf(schedule.name, creds,
                               getattr(schedule.creator, "username", "—"))
        if attachment:
            stamp = datetime.utcnow().strftime("%Y%m%d")
            attachment_name = f"dseclab_report_{stamp}.pdf"

    sent = 0
    if recipients and is_email_configured():
        for address in recipients:
            # One message per recipient: a shared To would disclose the
            # distribution list to everyone on it.
            if send_email(address, subject, body, attachment, attachment_name, text=text):
                sent += 1
    elif not is_email_configured():
        logger.warning("Email not configured; schedule %s produced no mail", schedule.id)

    db.session.add(ReportHistory(
        name=schedule.name,
        format=schedule.format or "pdf",
        file_size=len(attachment or b""),
        record_count=len(creds),
        status="completed" if sent or not recipients else "failed",
        source="scheduled",
        schedule_id=schedule.id,
        generated_by=schedule.created_by,
    ))

    # Breach data leaving the platform is an auditable event: who, for whom,
    # how much, and to exactly which addresses. Built directly rather than via
    # log_audit(), which reads current_user — there is no request here.
    try:
        from ..models import AuditLog
        db.session.add(AuditLog(
            user_id=schedule.created_by,
            action_type="scheduled_report_sent",
            resource_type="scheduled_report",
            resource_id=schedule.id,
            description=(
                f"{schedule.name}: {len(creds)} record(s) for "
                f"{getattr(schedule.company, 'name', None) or 'creator scope'} "
                f"to {', '.join(recipients) or 'nobody'}"
                + (f"; refused {', '.join(a for a, _ in rejected)}" if rejected else "")
            ),
            status="success" if sent or not recipients else "failed",
        ))
    except Exception as exc:  # auditing must not sink the run
        logger.error("Could not write audit row for schedule %s: %s", schedule.id, exc)

    db.session.commit()
    logger.info("Schedule %r ran: %d records, %d/%d emails sent, %d refused",
                schedule.name, len(creds), sent, len(recipients), len(rejected))
    return len(creds)


def run_due(app, now=None):
    """Claim and run every due schedule. Never raises."""
    ran = 0
    with app.app_context():
        try:
            schedules = due_schedules(now)
        except Exception as exc:
            logger.error("Could not query due schedules: %s", exc)
            return 0
        for schedule in schedules:
            try:
                # Authorisation is re-checked here, not trusted from creation
                # time: an offboarded account's schedules must stop delivering
                # rather than keep exporting on their behalf indefinitely.
                creator = schedule.creator
                if creator is None or not getattr(creator, "is_active", False):
                    schedule.is_active = False
                    db.session.commit()
                    logger.warning("Schedule %s disabled: creator missing or inactive",
                                   schedule.id)
                    continue
                if not claim_schedule(schedule, now):
                    continue  # another worker got it
                run_schedule(schedule)
                ran += 1
            except Exception as exc:
                db.session.rollback()
                logger.error("Schedule %s failed: %s", schedule.id, exc)
    return ran


def start_scheduler(app):
    """Start the in-process poller. Returns the scheduler, or None if disabled.

    Never starts under the `flask` CLI: `flask db upgrade` and friends build an
    app too, and a migration should not also be mailing reports.
    """
    import os

    if not app.config.get("SCHEDULER_ENABLED", True) or app.config.get("TESTING"):
        return None
    if os.environ.get("FLASK_RUN_FROM_CLI") == "true":
        logger.info("Running under the Flask CLI; report scheduler not started")
        return None
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        logger.warning("APScheduler not installed; scheduled reports will not run")
        return None

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(lambda: run_due(app), "interval", seconds=POLL_SECONDS,
                      id="dseclab-run-due-reports", max_instances=1,
                      coalesce=True, replace_existing=True)
    scheduler.start()
    app.extensions["report_scheduler"] = scheduler
    logger.info("Report scheduler started (every %ss)", POLL_SECONDS)
    return scheduler
