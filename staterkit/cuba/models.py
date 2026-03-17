from . import db
from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


def utcnow():
    return datetime.now(timezone.utc)


class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    domain = db.Column(db.String(200), nullable=False, unique=True, index=True)
    company_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    users = db.relationship('User', backref='company', lazy=True)
    watchlist_entries = db.relationship('WatchlistEntry', backref='company', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f"Company('{self.name}', '{self.domain}')"

    def get_match_domains(self):
        """Return deduped, lowercased list of domains from company domain + watchlist entries."""
        domains = set()
        if self.domain:
            domains.add(self.domain.lower().strip())
        for entry in self.watchlist_entries:
            if entry.entry_value:
                val = entry.entry_value.strip().lower()
                if val:
                    domains.add(val)
        return list(domains)

    @staticmethod
    def extract_domain(email: str) -> str:
        if '@' in email:
            return email.split('@')[1].lower()
        return ""

    @staticmethod
    def get_or_create_by_domain(domain: str, company_type: str = 'other', allow_create: bool = False):
        domain = domain.lower().strip()
        company = Company.query.filter_by(domain=domain).first()
        if not company and allow_create:
            company = Company(name=domain, domain=domain, company_type=company_type)
            db.session.add(company)
            db.session.commit()
        return company


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='member', nullable=False)
    isAdmin = db.Column(db.Boolean, default=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    def __repr__(self):
        return f"User('{self.username}','{self.email}','{self.role}')"

    @property
    def is_admin_user(self) -> bool:
        return self.role == 'admin' or self.isAdmin

    @property
    def company_domain(self) -> str:
        if self.company and self.company.domain:
            return self.company.domain
        return Company.extract_domain(self.email)

    def can_edit(self) -> bool:
        return self.is_admin_user

    def can_delete(self) -> bool:
        return self.is_admin_user

    def can_mark(self) -> bool:
        return True

    def set_password(self, raw_password: str) -> None:
        self.password = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password, raw_password)


class BreachedCredMeta(db.Model):
    """Local metadata for ES breached credentials (marks, reviews)."""
    id = db.Column(db.Integer, primary_key=True)
    es_id = db.Column(db.String(200), unique=True, nullable=False, index=True)
    is_marked = db.Column(db.Boolean, default=False)
    marked_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    marked_at = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)

    marker = db.relationship('User', foreign_keys=[marked_by])

    def __repr__(self):
        return f"BreachedCredMeta('{self.es_id}', marked={self.is_marked})"


class WatchlistEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    entry_type = db.Column(db.String(20), nullable=False)
    entry_value = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    def __repr__(self):
        return f"WatchlistEntry('{self.entry_type}', '{self.entry_value}')"


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    notification_type = db.Column(db.String(50), default='info')
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text)
    link = db.Column(db.String(500))
    is_read = db.Column(db.Boolean, default=False)
    read_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)

    user = db.relationship('User', backref='notifications')

    def __repr__(self):
        return f"Notification('{self.title}', '{self.user_id}', '{self.is_read}')"


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action_type = db.Column(db.String(50), nullable=False, index=True)
    resource_type = db.Column(db.String(50), nullable=False, index=True)
    resource_id = db.Column(db.Integer, nullable=True)
    description = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    old_values = db.Column(db.Text, nullable=True)
    new_values = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='success', nullable=False)
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)

    user = db.relationship('User', backref='audit_logs')

    def __repr__(self):
        return f"AuditLog('{self.action_type}', '{self.resource_type}', '{self.user_id}')"


class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    activity_type = db.Column(db.String(50), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True, index=True)
    user_agent = db.Column(db.String(500), nullable=True)
    location = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(20), default='success', nullable=False)
    failure_reason = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)

    user = db.relationship('User', backref='activities')

    def __repr__(self):
        return f"UserActivity('{self.activity_type}', '{self.user_id}', '{self.status}')"
