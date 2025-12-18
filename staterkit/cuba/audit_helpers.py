"""
Audit logging helper functions for tracking system actions
"""
from flask import request
from flask_login import current_user
from datetime import datetime
import json
from . import db
from .models import AuditLog, UserActivity


def get_client_ip():
    """Get client IP address from request"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr


def get_user_agent():
    """Get user agent from request"""
    return request.headers.get('User-Agent', '')[:500]  # Limit length


def log_audit(action_type, resource_type, resource_id=None, description="", 
               old_values=None, new_values=None, status="success", error_message=None):
    """
    Log an audit event
    
    Args:
        action_type: Type of action (create, update, delete, export, etc.)
        resource_type: Type of resource (user, company, breached_credential, etc.)
        resource_id: ID of the affected resource
        description: Human-readable description
        old_values: Dictionary of old values (for updates)
        new_values: Dictionary of new values (for updates)
        status: success, failed, or error
        error_message: Error message if status is failed/error
    """
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
        
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        # Don't break the application if audit logging fails
        db.session.rollback()
        print(f"Failed to log audit: {e}")


def log_user_activity(activity_type, user_id=None, status="success", failure_reason=None):
    """
    Log user activity (login, logout, etc.)
    
    Args:
        activity_type: Type of activity (login, logout, login_failed, password_change, etc.)
        user_id: User ID (None for failed login attempts)
        status: success or failed
        failure_reason: Reason for failure (invalid_password, user_inactive, etc.)
    """
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
        
        db.session.add(activity)
        db.session.commit()
    except Exception as e:
        # Don't break the application if activity logging fails
        db.session.rollback()
        print(f"Failed to log user activity: {e}")

