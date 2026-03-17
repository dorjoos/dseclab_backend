"""Audit logging helper functions."""
import json
import logging
from flask import request
from flask_login import current_user
from datetime import datetime, timezone
from . import db
from .models import AuditLog, UserActivity

logger = logging.getLogger(__name__)


def get_client_ip():
    """Get client IP address from request."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr


def get_user_agent():
    """Get user agent from request."""
    return request.headers.get('User-Agent', '')[:500]


def log_audit(action_type, resource_type, resource_id=None, description="",
              old_values=None, new_values=None, status="success", error_message=None):
    """Log an audit event using a savepoint to avoid interfering with caller's transaction."""
    try:
        user_id = current_user.id if current_user.is_authenticated else None
        audit_log = AuditLog(
            user_id=user_id,
            action_type=action_type,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            ip_address=get_client_ip(),
            user_agent=get_user_agent(),
            old_values=json.dumps(old_values) if old_values else None,
            new_values=json.dumps(new_values) if new_values else None,
            status=status,
            error_message=error_message
        )
        nested = db.session.begin_nested()
        db.session.add(audit_log)
        nested.commit()
    except Exception as e:
        logger.error("Failed to log audit: %s", e)
        db.session.rollback()


def log_user_activity(activity_type, user_id=None, status="success", failure_reason=None):
    """Log user activity using a savepoint."""
    try:
        if user_id is None and current_user.is_authenticated:
            user_id = current_user.id
        activity = UserActivity(
            user_id=user_id,
            activity_type=activity_type,
            ip_address=get_client_ip(),
            user_agent=get_user_agent(),
            status=status,
            failure_reason=failure_reason
        )
        nested = db.session.begin_nested()
        db.session.add(activity)
        nested.commit()
    except Exception as e:
        logger.error("Failed to log user activity: %s", e)
        db.session.rollback()
