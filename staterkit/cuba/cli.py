"""dseclab CLI commands — register on the Flask app in cuba.__init__.

Run via:  flask --app wsgi:app dseclab <subcommand>
or:       /opt/dseclab/venv/bin/flask dseclab <subcommand>

Designed for cron / systemd-timer driven housekeeping. Keep each command
idempotent so a missed run never corrupts state.
"""
import logging
from datetime import datetime, timedelta

import click
from flask import current_app
from flask.cli import AppGroup

from . import db
from .models import AuditLog, UserActivity

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


def register_cli(app):
    app.cli.add_command(dseclab)
