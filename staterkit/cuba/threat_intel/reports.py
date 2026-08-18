"""Reports hub: scheduled reports, alert rules and on-demand generation."""
from flask import render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from datetime import datetime, timezone

from .. import db, limiter
from ..api_utils import sanitize_input
from ..audit_helpers import log_audit
from ..services.breached_creds_service import breached_creds_service as es_service
from ._blueprint import threat_intel
from ._shared import _get_domain_filters

@threat_intel.route('/threat-intelligence/reports')
@login_required
def reports():
    from ..models import ScheduledReport, AlertRule, ReportHistory

    schedules = ScheduledReport.query.filter_by(created_by=current_user.id).order_by(ScheduledReport.created_at.desc()).all()
    if current_user.is_admin_user:
        schedules = ScheduledReport.query.order_by(ScheduledReport.created_at.desc()).all()

    alerts = AlertRule.query.filter_by(created_by=current_user.id).order_by(AlertRule.created_at.desc()).all()
    if current_user.is_admin_user:
        alerts = AlertRule.query.order_by(AlertRule.created_at.desc()).all()

    history = ReportHistory.query.filter_by(generated_by=current_user.id).order_by(ReportHistory.created_at.desc()).limit(20).all()
    if current_user.is_admin_user:
        history = ReportHistory.query.order_by(ReportHistory.created_at.desc()).limit(20).all()

    # Companies a schedule may target: admins pick any client, everyone else is
    # limited to their own so a schedule can't be pointed at another company.
    from ..models import Company
    if current_user.is_admin_user:
        companies = Company.query.order_by(Company.name).all()
    elif current_user.company:
        companies = [current_user.company]
    else:
        companies = []

    breadcrumb = {"parent": "Threat Intelligence", "child": "Reports"}
    return render_template('threat_intel/reports.html',
                          schedules=schedules, alerts=alerts, history=history,
                          companies=companies, breadcrumb=breadcrumb)


def _parse_schedule_form(form):
    """Validate the schedule fields shared by the create and edit forms.

    Returns (values, error): `values` is a dict ready to apply to a
    ScheduledReport, `error` a (message, category) pair when the form can't be
    accepted. Both routes go through here so their rules cannot drift apart —
    the recipient binding below is the only thing that guards a client's breach
    data, and it must hold on edit exactly as it does on create.
    """
    from ..models import Company
    from ..services.report_scheduler import compute_next_run
    from datetime import datetime as _dt

    name = sanitize_input(form.get('name', ''))
    if not name:
        return None, ('Report name is required.', 'warning')

    frequency = form.get('frequency', 'weekly')

    # Never trust the posted company: a non-admin may only target their own.
    company_id = (form.get('company_id') or '').strip() or None
    if company_id:
        company = db.session.get(Company, company_id)
        if company is None or (not current_user.is_admin_user
                               and current_user.company_id != company.id):
            return None, ('Invalid company selection.', 'danger')

    # Local wall-clock time of day plus which days it applies to. run_days is
    # ISO weekdays for weekly ("1,5"), a day of the month for monthly ("15"),
    # and unused for daily.
    run_time = (form.get('run_time') or '').strip()
    if frequency == 'weekly':
        run_days = ','.join(d for d in form.getlist('run_days')
                            if d.isdigit() and 1 <= int(d) <= 7)
        if not run_days:
            # Silently falling back to "whatever day it is now" would make the
            # schedule run on a day nobody chose.
            return None, ('Pick at least one day of the week.', 'warning')
    elif frequency == 'monthly':
        day = (form.get('run_day_of_month') or '').strip()
        run_days = day if day.isdigit() and 1 <= int(day) <= 31 else ''
    else:
        run_days = ''

    return {
        'name': name,
        'frequency': frequency,
        'format': form.get('format', 'pdf'),
        'email_to': sanitize_input(form.get('email_to', '')),
        'company_id': company_id,
        'run_time': run_time,
        'run_days': run_days,
        'next_run': compute_next_run(frequency, _dt.utcnow(), run_time, run_days),
    }, None


def _bind_recipients(schedule, email_to):
    """Set schedule.email_to from a submitted address list, or return an error.

    Recipients are bound to the target company's own domains, so a client's
    breach data cannot be scheduled out to an unrelated address. Rejected here
    rather than silently dropped at send time, so the mistake is visible.
    """
    if not email_to:
        schedule.email_to = None
        return None
    from ..services.report_scheduler import validate_recipients
    allowed, rejected = validate_recipients(schedule, email_to)
    if rejected:
        return 'Cannot send to ' + '; '.join(f'{a} ({why})' for a, why in rejected)
    schedule.email_to = ','.join(allowed)
    return None


def _schedule_saved_message(verb, run_label, values):
    """Flash text shared by create and edit."""
    name, frequency, next_run = values['name'], values['frequency'], values['next_run']
    if next_run:
        from ..services.report_scheduler import to_local
        local = to_local(next_run)
        return (f'Scheduled report "{name}" {verb} — {run_label} '
                f'{local.strftime("%Y-%m-%d %H:%M")} ({local.tzname()}).', 'success')
    return (f'Scheduled report "{name}" {verb}, but "{frequency}" is not a '
            f'known frequency so it has no run time.', 'warning')


@threat_intel.route('/threat-intelligence/reports/schedule/add', methods=['POST'])
@login_required
def add_schedule():
    from ..models import ScheduledReport, Company

    values, error = _parse_schedule_form(request.form)
    if error:
        flash(*error)
        return redirect(url_for('threat_intel.reports'))

    schedule = ScheduledReport(
        name=values['name'], frequency=values['frequency'], format=values['format'],
        run_time=values['run_time'] or None, run_days=values['run_days'] or None,
        next_run=values['next_run'], company_id=values['company_id'],
        created_by=current_user.id, is_active=True
    )
    # validate_recipients reads .creator and .company, which aren't populated
    # from the id columns until a flush — set them by hand first.
    schedule.creator = current_user
    schedule.company = (db.session.get(Company, values['company_id'])
                        if values['company_id'] else None)

    recipient_error = _bind_recipients(schedule, values['email_to'])
    if recipient_error:
        db.session.rollback()
        flash(recipient_error, 'danger')
        return redirect(url_for('threat_intel.reports'))

    db.session.add(schedule)
    db.session.commit()
    log_audit('scheduled_report_create', 'scheduled_report', schedule.id,
              f'{schedule.name} → {schedule.email_to or "no recipients"} '
              f'({"company " + schedule.company.name if schedule.company else "creator scope"})')
    flash(*_schedule_saved_message('created', 'first run', values))
    return redirect(url_for('threat_intel.reports'))


@threat_intel.route('/threat-intelligence/reports/schedule/<sid>/edit', methods=['POST'])
@login_required
def edit_schedule(sid):
    from ..models import ScheduledReport, Company
    schedule = ScheduledReport.query.get_or_404(sid)
    if schedule.created_by != current_user.id and not current_user.is_admin_user:
        flash('Access denied.', 'danger')
        return redirect(url_for('threat_intel.reports'))

    values, error = _parse_schedule_form(request.form)
    if error:
        flash(*error)
        return redirect(url_for('threat_intel.reports'))

    schedule.name = values['name']
    schedule.frequency = values['frequency']
    schedule.format = values['format']
    schedule.run_time = values['run_time'] or None
    schedule.run_days = values['run_days'] or None
    schedule.company_id = values['company_id']
    schedule.company = (db.session.get(Company, values['company_id'])
                        if values['company_id'] else None)
    # Recomputed from the new cadence. last_run stays as it was: editing a
    # schedule doesn't undo the runs it already had. is_active isn't here
    # either — Pause/Enable owns that.
    schedule.next_run = values['next_run']

    recipient_error = _bind_recipients(schedule, values['email_to'])
    if recipient_error:
        db.session.rollback()
        flash(recipient_error, 'danger')
        return redirect(url_for('threat_intel.reports'))

    db.session.commit()
    log_audit('scheduled_report_update', 'scheduled_report', schedule.id,
              f'{schedule.name} → {schedule.email_to or "no recipients"} '
              f'({"company " + schedule.company.name if schedule.company else "creator scope"})')
    flash(*_schedule_saved_message('updated', 'next run', values))
    return redirect(url_for('threat_intel.reports'))


@threat_intel.route('/threat-intelligence/reports/schedule/<sid>/toggle', methods=['POST'])
@login_required
def toggle_schedule(sid):
    from ..models import ScheduledReport
    schedule = ScheduledReport.query.get_or_404(sid)
    if schedule.created_by != current_user.id and not current_user.is_admin_user:
        flash('Access denied.', 'danger')
        return redirect(url_for('threat_intel.reports'))
    schedule.is_active = not schedule.is_active
    db.session.commit()
    flash(f'Schedule {"enabled" if schedule.is_active else "disabled"}.', 'info')
    return redirect(url_for('threat_intel.reports'))


@threat_intel.route('/threat-intelligence/reports/schedule/<sid>/delete', methods=['POST'])
@login_required
def delete_schedule(sid):
    from ..models import ScheduledReport
    schedule = ScheduledReport.query.get_or_404(sid)
    if schedule.created_by != current_user.id and not current_user.is_admin_user:
        flash('Access denied.', 'danger')
        return redirect(url_for('threat_intel.reports'))
    db.session.delete(schedule)
    db.session.commit()
    flash('Schedule deleted.', 'info')
    return redirect(url_for('threat_intel.reports'))


@threat_intel.route('/threat-intelligence/reports/alert/add', methods=['POST'])
@login_required
def add_alert():
    from ..models import AlertRule
    name = sanitize_input(request.form.get('name', ''))
    condition_type = request.form.get('condition_type', 'new_breach')
    condition_value = sanitize_input(request.form.get('condition_value', ''))
    notify_method = request.form.get('notify_method', 'in_app')
    notify_target = sanitize_input(request.form.get('notify_target', ''))

    if not name or not condition_value:
        flash('Alert name and condition are required.', 'warning')
        return redirect(url_for('threat_intel.reports') + '#alerts')

    # Validate webhook URL if notify_method is webhook
    if notify_method == 'webhook' and notify_target:
        if not notify_target.startswith('https://'):
            flash('Webhook URL must use HTTPS.', 'danger')
            return redirect(url_for('threat_intel.reports') + '#alerts')
        # Block private/internal IPs in webhook URLs
        from urllib.parse import urlparse
        parsed = urlparse(notify_target)
        hostname = parsed.hostname or ''
        # Reject localhost, internal hostnames, and private IP ranges
        if hostname in ('localhost', '127.0.0.1', '::1', '0.0.0.0') or hostname.startswith('10.') or hostname.startswith('192.168.') or hostname.startswith('172.16.') or hostname.endswith('.local') or hostname.endswith('.internal'):
            flash('Webhook URL must not point to a private/internal address.', 'danger')
            return redirect(url_for('threat_intel.reports') + '#alerts')

    alert = AlertRule(
        name=name, condition_type=condition_type, condition_value=condition_value,
        notify_method=notify_method, notify_target=notify_target or None,
        created_by=current_user.id, is_active=True
    )
    db.session.add(alert)
    db.session.commit()
    flash(f'Alert rule "{name}" created.', 'success')
    return redirect(url_for('threat_intel.reports') + '#alerts')


@threat_intel.route('/threat-intelligence/reports/alert/<aid>/toggle', methods=['POST'])
@login_required
def toggle_alert(aid):
    from ..models import AlertRule
    alert = AlertRule.query.get_or_404(aid)
    if alert.created_by != current_user.id and not current_user.is_admin_user:
        flash('Access denied.', 'danger')
        return redirect(url_for('threat_intel.reports') + '#alerts')
    alert.is_active = not alert.is_active
    db.session.commit()
    flash(f'Alert {"enabled" if alert.is_active else "disabled"}.', 'info')
    return redirect(url_for('threat_intel.reports') + '#alerts')


@threat_intel.route('/threat-intelligence/reports/alert/<aid>/delete', methods=['POST'])
@login_required
def delete_alert(aid):
    from ..models import AlertRule
    alert = AlertRule.query.get_or_404(aid)
    if alert.created_by != current_user.id and not current_user.is_admin_user:
        flash('Access denied.', 'danger')
        return redirect(url_for('threat_intel.reports') + '#alerts')
    db.session.delete(alert)
    db.session.commit()
    flash('Alert rule deleted.', 'info')
    return redirect(url_for('threat_intel.reports') + '#alerts')


@threat_intel.route('/threat-intelligence/reports/generate', methods=['POST'])
@login_required
@limiter.limit("3/minute")
def generate_report():
    """Generate a report now and save to history."""
    from ..models import ReportHistory
    fmt = request.form.get('format', 'csv')

    domain_filters = _get_domain_filters()
    creds = es_service.export(domain_filters=domain_filters, max_records=5000)

    # Estimate file size (rough: ~100 bytes per record for CSV)
    size_map = {'csv': 100, 'xlsx': 150, 'json': 200, 'pdf': 80}
    estimated_size = len(creds) * size_map.get(fmt, 100)

    history = ReportHistory(
        name=f'Breach Report {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")}',
        format=fmt, record_count=len(creds), file_size=estimated_size, status='completed',
        source='manual', generated_by=current_user.id
    )
    db.session.add(history)
    db.session.commit()

    # Redirect to actual export
    return redirect(url_for('threat_intel.breached_creds_export', format=fmt))
