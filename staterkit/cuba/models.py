from . import db
import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import re


class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    domain = db.Column(db.String(200), nullable=False, unique=True, index=True)  # e.g., test.com, bank.com
    company_type = db.Column(db.String(50), nullable=False)  # bank, operator, government, other
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    users = db.relationship('User', backref='company', lazy=True)
    breached_credentials = db.relationship('BreachedCredential', backref='company', lazy=True)
    watchlist_entries = db.relationship('WatchlistEntry', backref='company', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f"Company('{self.name}', '{self.domain}')"

    @staticmethod
    def extract_domain(email: str) -> str:
        """Extract domain from email address"""
        if '@' in email:
            return email.split('@')[1].lower()
        return ""

    @staticmethod
    def get_or_create_by_domain(domain: str, company_type: str = 'other', allow_create: bool = False):
        """
        Get existing company by domain, optionally create new one
        
        Args:
            domain: Domain string (e.g., 'example.com')
            company_type: Type of company (default: 'other')
            allow_create: If True, create company if it doesn't exist. If False, only return existing company.
        
        Returns:
            Company object if found or created, None if not found and allow_create=False
        """
        domain = domain.lower().strip()
        company = Company.query.filter_by(domain=domain).first()
        if not company and allow_create:
            company = Company(
                name=domain,
                domain=domain,
                company_type=company_type
            )
            db.session.add(company)
            db.session.commit()
        return company


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='member', nullable=False)  # admin, member
    isAdmin = db.Column(db.Boolean, default=False)  # Legacy field, use role instead
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def __repr__(self):
        return f"User('{self.username}','{self.email}','{self.role}')"

    @property
    def company_domain(self) -> str:
        """Get company domain from email or company relationship"""
        if self.company and self.company.domain:
            return self.company.domain
        return Company.extract_domain(self.email)

    def can_edit(self) -> bool:
        """Check if user can edit records"""
        return self.role == 'admin' or self.isAdmin

    def can_delete(self) -> bool:
        """Check if user can delete records"""
        return self.role == 'admin' or self.isAdmin

    def can_mark(self) -> bool:
        """Check if user can mark/update status"""
        return True  # All authenticated users can mark

    # Credential helpers
    def set_password(self, raw_password: str) -> None:
        """Hash and store the password."""
        self.password = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        """Return True if the provided password matches the stored hash."""
        return check_password_hash(self.password, raw_password)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(500), unique=True, nullable=False)
    completed = db.Column(db.Boolean, default=False)
    timeStamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    notification_type = db.Column(db.String(50), default='info')  # alert, info, warning, success
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text)
    link = db.Column(db.String(500))  # URL to related item
    is_read = db.Column(db.Boolean, default=False)
    read_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)
    
    # Relationships
    user = db.relationship('User', backref='notifications')
    
    def __repr__(self):
        return f"Notification('{self.title}', '{self.user_id}', '{self.is_read}')"


class BreachedCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    _id = db.Column(db.String(200), nullable=True, index=True)  # External ID
    _ignored = db.Column(db.Boolean, default=False)  # Ignored flag
    _index = db.Column(db.String(200), nullable=True)  # Index reference
    _score = db.Column(db.Float, nullable=True)  # Score value
    domain = db.Column(db.String(200), nullable=True, index=True)  # Domain
    password = db.Column(db.String(500), nullable=True)  # Password (plain text)
    source = db.Column(db.String(200), nullable=True)  # Source
    type = db.Column(db.String(50), nullable=True, index=True)  # Type
    url = db.Column(db.String(500), nullable=True)  # URL
    username = db.Column(db.String(200), nullable=True, index=True)  # Username
    
    # Metadata fields (kept for system functionality)
    is_marked = db.Column(db.Boolean, default=False)  # Marked by member for review
    marked_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    marked_at = db.Column(db.DateTime, nullable=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    creator = db.relationship('User', foreign_keys=[created_by], backref='breached_credentials')
    marker = db.relationship('User', foreign_keys=[marked_by])

    def __repr__(self):
        return f"BreachedCredential('{self.username}', '{self.domain}', '{self.type}')"
    
    @property
    def type_color(self):
        """Get color class for type tag"""
        if not self.type:
            return 'secondary'
        type_colors = {
            'combolist': 'primary',
            'stealer': 'danger',
            'malware': 'warning',
            'pastebin': 'info',
            'breach': 'secondary',
            'phishing': 'danger',
            'darkweb': 'dark'
        }
        return type_colors.get(self.type.lower(), 'secondary')


class WatchlistEntry(db.Model):
    """Watchlist entries for companies - supports multiple entries per company"""
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    entry_type = db.Column(db.String(20), nullable=False)  # domain, url, email, slug, ip_address
    entry_value = db.Column(db.String(500), nullable=False)  # The actual value
    description = db.Column(db.Text, nullable=True)  # Optional description
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    def __repr__(self):
        return f"WatchlistEntry('{self.entry_type}', '{self.entry_value}')"


class AuditLog(db.Model):
    """Audit log for tracking all important system actions"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Nullable for system actions
    action_type = db.Column(db.String(50), nullable=False, index=True)  # create, update, delete, login, logout, export, etc.
    resource_type = db.Column(db.String(50), nullable=False, index=True)  # user, company, breached_credential, watchlist, etc.
    resource_id = db.Column(db.Integer, nullable=True)  # ID of the affected resource
    description = db.Column(db.Text, nullable=False)  # Human-readable description
    ip_address = db.Column(db.String(45), nullable=True)  # IPv4 or IPv6
    user_agent = db.Column(db.String(500), nullable=True)  # Browser/user agent
    old_values = db.Column(db.Text, nullable=True)  # JSON string of old values (for updates)
    new_values = db.Column(db.Text, nullable=True)  # JSON string of new values (for updates)
    status = db.Column(db.String(20), default='success', nullable=False)  # success, failed, error
    error_message = db.Column(db.Text, nullable=True)  # Error message if status is failed/error
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)
    
    # Relationships
    user = db.relationship('User', backref='audit_logs')
    
    def __repr__(self):
        return f"AuditLog('{self.action_type}', '{self.resource_type}', '{self.user_id}', '{self.created_at}')"


class UserActivity(db.Model):
    """User activity tracking - login history, failed attempts, etc."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Nullable for failed login attempts
    activity_type = db.Column(db.String(50), nullable=False, index=True)  # login, logout, login_failed, password_change, etc.
    ip_address = db.Column(db.String(45), nullable=True, index=True)  # IPv4 or IPv6
    user_agent = db.Column(db.String(500), nullable=True)  # Browser/user agent
    location = db.Column(db.String(200), nullable=True)  # Geographic location (if available)
    status = db.Column(db.String(20), default='success', nullable=False)  # success, failed
    failure_reason = db.Column(db.String(200), nullable=True)  # Reason for failure (invalid_password, user_inactive, etc.)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)
    
    # Relationships
    user = db.relationship('User', backref='activities')
    
    def __repr__(self):
        return f"UserActivity('{self.activity_type}', '{self.user_id}', '{self.status}', '{self.created_at}')"