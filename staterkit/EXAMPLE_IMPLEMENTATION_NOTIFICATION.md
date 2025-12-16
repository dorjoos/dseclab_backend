# Example Implementation: Notification System

This is a quick example of how to implement the Notification system (High Priority Feature).

## 1. Add Notification Model (already in improvements doc)

## 2. Create Notification Routes

```python
# cuba/notifications.py
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from . import db
from .models import Notification, BreachedCredential

notifications_bp = Blueprint('notifications', __name__)

@notifications_bp.route('/notifications')
@login_required
def notifications_list():
    """List all notifications for current user"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    notifications = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    unread_count = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).count()
    
    return render_template('notifications/list.html',
                         notifications=notifications.items,
                         pagination=notifications,
                         unread_count=unread_count)

@notifications_bp.route('/notifications/<int:id>/read', methods=['POST'])
@login_required
def mark_read(id):
    """Mark notification as read"""
    notification = Notification.query.get_or_404(id)
    
    if notification.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    notification.is_read = True
    notification.read_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'success': True})

@notifications_bp.route('/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_read():
    """Mark all notifications as read"""
    Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).update({'is_read': True, 'read_at': datetime.utcnow()})
    db.session.commit()
    
    return jsonify({'success': True})

@notifications_bp.route('/api/notifications/unread-count')
@login_required
def unread_count():
    """Get unread notification count (for header badge)"""
    count = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).count()
    
    return jsonify({'count': count})
```

## 3. Helper Function to Create Notifications

```python
# cuba/utils.py
from .models import Notification, User
from . import db
from datetime import datetime

def create_notification(user_id, notification_type, title, message, link=None):
    """Create a new notification"""
    notification = Notification(
        user_id=user_id,
        notification_type=notification_type,
        title=title,
        message=message,
        link=link
    )
    db.session.add(notification)
    db.session.commit()
    return notification

def notify_new_breach(credential_id, company_domain):
    """Notify all users in a company about a new breach"""
    # Get all active users for the company
    users = User.query.filter_by(
        company_id=Company.query.filter_by(domain=company_domain).first().id,
        is_active=True
    ).all()
    
    credential = BreachedCredential.query.get(credential_id)
    
    for user in users:
        create_notification(
            user_id=user.id,
            notification_type='warning',
            title=f'New Breach Detected: {credential.company_name}',
            message=f'Email: {credential.email}',
            link=f'/threat-intelligence/breached-creds/{credential_id}'
        )
```

## 4. Update Breached Credentials Add Route

```python
# In cuba/threat_intel.py - breached_creds_add()
# After creating the credential:
from .utils import notify_new_breach

breached_cred = BreachedCredential(...)
db.session.add(breached_cred)
db.session.commit()

# Notify users
notify_new_breach(breached_cred.id, email_domain)
```

## 5. Add Notification Badge to Header

```html
<!-- In cuba/templates/layout/header.html -->
<li class="onhover-dropdown">
  <div class="notification-box">
    <svg>
      <use href="{{ url_for('static', filename= 'assets/svg/icon-sprite.svg' )}}#notification"></use>
    </svg>
    <span class="badge rounded-pill badge-danger" id="notification-count">0</span>
  </div>
  <div class="onhover-show-div notification-dropdown">
    <h6 class="f-18 mb-0 dropdown-title">Notifications</h6>
    <div id="notification-list">
      <!-- Loaded via AJAX -->
    </div>
    <div class="text-center p-2">
      <a href="{{ url_for('notifications.notifications_list') }}" class="btn btn-sm btn-primary">View All</a>
    </div>
  </div>
</li>
```

## 6. JavaScript to Update Notification Count

```javascript
// In base.html
function updateNotificationCount() {
  fetch('/api/notifications/unread-count')
    .then(response => response.json())
    .then(data => {
      const badge = document.getElementById('notification-count');
      if (badge) {
        badge.textContent = data.count;
        badge.style.display = data.count > 0 ? 'inline' : 'none';
      }
    });
}

// Update every 30 seconds
setInterval(updateNotificationCount, 30000);
updateNotificationCount(); // Initial load
```

This is a basic implementation. You can expand it with:
- Email notifications
- Real-time updates (WebSockets)
- Notification preferences
- Notification categories
- Sound alerts
- Desktop notifications

