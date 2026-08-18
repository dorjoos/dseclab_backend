"""dseclab CLI commands — register on the Flask app in cuba.__init__.

Run via:  flask --app wsgi:app dseclab <subcommand>
or:       /opt/dseclab/venv/bin/flask dseclab <subcommand>

Designed for cron / systemd-timer driven housekeeping. Keep each command
idempotent so a missed run never corrupts state.
"""
import logging
from datetime import datetime, timedelta

import click
from flask.cli import AppGroup

from . import db
from .models import AuditLog, Company, Notification, User, UserActivity, WatchlistEntry

logger = logging.getLogger(__name__)

dseclab = AppGroup('dseclab', help='dseclab operational commands.')


@dseclab.command('cleanup-audit')
@click.option('--days', default=90, show_default=True, type=int,
              help='Delete audit rows older than this many days.')
@click.option('--dry-run', is_flag=True, help='Count rows but do not delete.')
def cleanup_audit(days, dry_run):
    """Delete AuditLog rows older than --days. Idempotent: safe to re-run."""
    if days < 1:
        raise click.UsageError('--days must be >= 1')
    cutoff = datetime.utcnow() - timedelta(days=days)
    q = AuditLog.query.filter(AuditLog.created_at < cutoff)
    count = q.count()
    click.echo(f'AuditLog rows older than {days}d (cutoff={cutoff.isoformat()}): {count}')
    if dry_run:
        click.echo('--dry-run set, nothing deleted.')
        return
    deleted = q.delete(synchronize_session=False)
    db.session.commit()
    click.echo(f'Deleted {deleted} AuditLog rows.')


@dseclab.command('cleanup-activity')
@click.option('--days', default=90, show_default=True, type=int,
              help='Delete user_activity rows older than this many days.')
@click.option('--dry-run', is_flag=True, help='Count rows but do not delete.')
def cleanup_activity(days, dry_run):
    """Delete UserActivity rows older than --days. Idempotent."""
    if days < 1:
        raise click.UsageError('--days must be >= 1')
    cutoff = datetime.utcnow() - timedelta(days=days)
    q = UserActivity.query.filter(UserActivity.created_at < cutoff)
    count = q.count()
    click.echo(f'UserActivity rows older than {days}d (cutoff={cutoff.isoformat()}): {count}')
    if dry_run:
        click.echo('--dry-run set, nothing deleted.')
        return
    deleted = q.delete(synchronize_session=False)
    db.session.commit()
    click.echo(f'Deleted {deleted} UserActivity rows.')


def _host_belongs_to(host: str, domain: str) -> bool:
    """Suffix-aware host match — same logic as threat_intel._host_belongs_to."""
    if not host or not domain:
        return False
    host = host.lower().strip().rstrip('.')
    domain = domain.lower().strip().lstrip('.').rstrip('.')
    if not host or not domain:
        return False
    return host == domain or host.endswith('.' + domain)


def _victim_matches_watchlist(victim_website: str, victim_name: str,
                              entry_value: str, entry_type: str) -> bool:
    """True if a ransomware-feed row's victim should trigger an alert for
    a given watchlist entry. Handles domain entries (suffix match) and
    plain-text entries (case-insensitive substring in victim_name)."""
    value = (entry_value or '').strip()
    if not value:
        return False
    etype = (entry_type or 'domain').lower()
    if etype == 'domain':
        if _host_belongs_to(victim_website or '', value):
            return True
        # Some feeds put the website in the victim_name field as the title.
        return bool(victim_name and value.lower() in victim_name.lower())
    # Non-domain entries (keyword watch, etc.) — substring on victim name.
    return value.lower() in (victim_name or '').lower()


@dseclab.command('match-ransomware')
@click.option('--since-hours', default=24, show_default=True, type=int,
              help='Look back this many hours for new ransomware-feed docs.')
@click.option('--dry-run', is_flag=True, help='Show matches without writing notifications.')
def match_ransomware(since_hours, dry_run):
    """Scan recent ransomware-feed docs, create Notifications when a victim
    matches any company's WatchlistEntry. Idempotent: deduplicates on the
    link URL so re-runs don't spam users."""
    from .services.ransomware_feed_service import ransomware_feed_service

    if since_hours < 1:
        raise click.UsageError('--since-hours must be >= 1')

    cutoff = datetime.utcnow() - timedelta(hours=since_hours)
    cutoff_iso = cutoff.isoformat()

    # Pull every doc in the window. The feed lands ~tens/day so even a
    # 7-day backfill is small — no pagination needed for the scan.
    body = {
        'size': 1000,
        'query': {'range': {'@timestamp': {'gte': cutoff_iso}}},
        'sort': [{'@timestamp': {'order': 'desc', 'unmapped_type': 'date'}}],
        'track_total_hits': True,
    }
    resp = ransomware_feed_service._search(body)
    hits = resp.get('hits', {}).get('hits', [])
    click.echo(f'Scanning {len(hits)} ransomware docs since {cutoff_iso}.')

    # All watchlist entries up-front; we have O(few hundred) of them, so the
    # cartesian product against ~tens of docs is cheap.
    watch_rows = (
        db.session.query(WatchlistEntry, Company)
        .join(Company, Company.id == WatchlistEntry.company_id)
        .all()
    )
    if not watch_rows:
        click.echo('No WatchlistEntry rows configured — nothing to match.')
        return

    matched = 0
    created = 0
    for h in hits:
        src = h.get('_source', {}) or {}
        victim_website = (src.get('victim_website') or '').strip()
        victim_name = (src.get('victim_name') or '').strip()
        ransomware_group = (src.get('ransomware_group') or 'unknown').strip()
        link = (src.get('source_url') or '').strip()

        for entry, company in watch_rows:
            if not _victim_matches_watchlist(
                victim_website, victim_name, entry.entry_value, entry.entry_type
            ):
                continue
            matched += 1

            # Notify every active user of the matching company.
            users = User.query.filter(
                User.company_id == company.id,
                User.is_active == True,
            ).all()
            for u in users:
                # Dedup: skip if this user already has a notification for the
                # same source link (the feed's unique post URL).
                if link:
                    existing = Notification.query.filter_by(
                        user_id=u.id, link=link,
                    ).first()
                    if existing:
                        continue
                if dry_run:
                    click.echo(
                        f'  WOULD notify {u.email}: {ransomware_group} → '
                        f'{victim_name or victim_website} (company={company.name})'
                    )
                    continue
                n = Notification(
                    user_id=u.id,
                    notification_type='warning',
                    title=f'Ransomware: {ransomware_group} claims attack',
                    message=f'{victim_name or victim_website} '
                            f'(matched watchlist entry: {entry.entry_value})',
                    link=link or None,
                )
                db.session.add(n)
                created += 1

    if not dry_run:
        db.session.commit()
        click.echo(f'Matched {matched} watchlist hits; wrote {created} notifications.')
    else:
        click.echo(f'Matched {matched} watchlist hits; --dry-run set, no notifications written.')


# Additive schema changes applied by `ensure-schema`, oldest first.
# (table, column, type) — the type must be valid on both SQLite and
# PostgreSQL, and the column must be nullable so existing rows stay valid.
#
# This exists because deploys run `flask db upgrade`, which applies revisions
# but never generates them, so a new model column reaches no server. Autogen
# on a live database is worse: it diffs models against the schema and will
# emit DROPs for any drift. Listing changes explicitly keeps deploys additive
@dseclab.command('audit-scope')
def audit_scope():
    """List accounts whose tenancy scope is undefined.

    A non-admin with no company has no scope. Until the get_scope_domains()
    fix, the dashboard and the analysis view handed exactly those accounts an
    *unrestricted* view — every tenant's totals, trends and ten most recent
    credentials — because the helper they branched on returns None both for an
    admin and for a company-less member.

    The code path is fixed. This reports whether any account was in a position
    to have used it, which the fix cannot tell you retrospectively.

    Read-only. Exits non-zero when it finds something, so a cron or a deploy
    check can act on it.
    """
    orphans = (User.query
               .filter(User.company_id.is_(None), User.role != 'admin')
               .order_by(User.email)
               .all())

    if not orphans:
        click.echo('No company-less non-admin accounts. Nothing was exposed '
                   'through the scope bug.')
        return

    click.echo(f'{len(orphans)} account(s) with no company and a non-admin role:')
    click.echo('')
    click.echo(f'  {"EMAIL":<38} {"USERNAME":<20} {"ROLE":<8} ACTIVE  LAST LOGIN')
    for user in orphans:
        last = getattr(user, 'last_login', None)
        click.echo(
            f'  {(user.email or ""):<38} {(user.username or ""):<20} '
            f'{(user.role or ""):<8} '
            f'{"yes" if getattr(user, "is_active", False) else "no":<7} '
            f'{last.strftime("%Y-%m-%d %H:%M") if last else "never"}')
    click.echo('')
    click.echo('Each of these could reach every tenant\'s dashboard and analysis '
               'data before the fix.')
    click.echo('Assign a company, deactivate the account, or confirm it is a '
               'service account that never signs in.')
    raise SystemExit(1)


# and re-runnable.
_ADDITIVE_COLUMNS = [
    ('scheduled_report', 'company_id', 'VARCHAR(36) REFERENCES company(id)'),
    ('scheduled_report', 'run_time', 'VARCHAR(5)'),
    ('scheduled_report', 'run_days', 'VARCHAR(50)'),
]


@dseclab.command('ensure-schema')
@click.option('--dry-run', is_flag=True, help='Report what is missing but change nothing.')
def ensure_schema(dry_run):
    """Create missing tables and add missing columns. Idempotent."""
    from sqlalchemy import inspect, text

    created = []
    inspector = inspect(db.engine)
    before = set(inspector.get_table_names())
    if not dry_run:
        # create_all only ever creates; it never drops or alters.
        db.create_all()
        inspector = inspect(db.engine)
        created = sorted(set(inspector.get_table_names()) - before)
    else:
        missing = {t.name for t in db.metadata.sorted_tables} - before
        created = sorted(missing)

    for table in created:
        click.echo(f'{"would create" if dry_run else "created"} table: {table}')

    inspector = inspect(db.engine)
    tables = set(inspector.get_table_names())
    changed = 0
    for table, column, coltype in _ADDITIVE_COLUMNS:
        if table not in tables:
            continue  # create_all will have built it with the column already
        columns = {c['name'] for c in inspector.get_columns(table)}
        if column in columns:
            continue
        changed += 1
        if dry_run:
            click.echo(f'would add column: {table}.{column}')
            continue
        db.session.execute(text(f'ALTER TABLE {table} ADD COLUMN {column} {coltype}'))
        db.session.commit()
        click.echo(f'added column: {table}.{column}')

    if not created and not changed:
        click.echo('Schema already up to date.')
    elif dry_run:
        click.echo(f'{len(created)} table(s) and {changed} column(s) pending.')
    else:
        click.echo(f'Schema updated: {len(created)} table(s), {changed} column(s).')


def register_cli(app):
    app.cli.add_command(dseclab)
