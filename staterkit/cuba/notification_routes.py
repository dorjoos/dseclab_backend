from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from datetime import datetime
from . import db
from .models import Notification
from .api_utils import json_error, json_success

notification_bp = Blueprint('notifications', __name__)


@notification_bp.route('/api/notifications')
@login_required
def get_notifications():
    """Get recent notifications for current user"""
    try:
        limit = int(request.args.get('limit', 5))
        unread_only = request.args.get('unread_only', '').lower() in ('1', 'true', 'yes', 'on')
        
        q = Notification.query.filter_by(user_id=current_user.id)
        if unread_only:
            q = q.filter_by(is_read=False)

        notifications = q.order_by(Notification.created_at.desc()).limit(limit).all()
        
        unread_count = Notification.query.filter_by(
            user_id=current_user.id,
            is_read=False
        ).count()
        
        notifications_data = [{
            'id': n.id,
            'type': n.notification_type or 'info',
            'title': n.title or 'Notification',
            'message': n.message or '',
            'link': n.link or '#',
            'is_read': bool(n.is_read),
            'created_at': n.created_at.strftime('%Y-%m-%d %H:%M:%S') if n.created_at else '',
            'time_ago': _time_ago(n.created_at) if n.created_at else ''
        } for n in notifications]
        
        return jsonify({
            'notifications': notifications_data,
            'unread_count': unread_count
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return json_error(str(e), status_code=500, notifications=[], unread_count=0)


@notification_bp.route('/api/notifications/<int:id>/read', methods=['POST'])
@login_required
def mark_read(id):
    """Mark notification as read"""
    try:
        notification = Notification.query.get_or_404(id)
        
        if notification.user_id != current_user.id:
            return json_error('Unauthorized', status_code=403)
        
        notification.is_read = True
        notification.read_at = datetime.utcnow()
        db.session.commit()
        
        return json_success()
    except Exception as e:
        return json_error(str(e), status_code=500)


@notification_bp.route('/api/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_read():
    """Mark all notifications as read"""
    Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).update({'is_read': True, 'read_at': datetime.utcnow()})
    db.session.commit()
    
    return json_success()


def _time_ago(dt):
    """Calculate time ago string"""
    if not dt:
        return ''
    
    now = datetime.utcnow()
    diff = now - dt
    
    if diff.days > 0:
        return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    else:
        return "Just now"

