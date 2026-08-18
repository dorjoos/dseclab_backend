import uuid

from . import db
from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


def utcnow():
    return datetime.now(timezone.utc)


class Company(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
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

    # Watchlist entries of this type hold a supplier's domain rather than the
    # company's own, so matches against them are counted as third-party rather
    # than as the company's staff or customers.
    THIRD_PARTY_ENTRY_TYPE = 'third_party'

    def get_match_domains(self):
        """Return deduped, lowercased list of domains from company domain + watchlist entries."""
        domains = set()
        if self.domain:
            domains.add(self.domain.lower().strip())
        for entry in self.watchlist_entries:
            if entry.entry_type in ('domain', self.THIRD_PARTY_ENTRY_TYPE) and entry.entry_value:
                val = entry.entry_value.strip().lower()
                if val:
                    domains.add(val)
        return list(domains)

    def get_third_party_domains(self):
        """Watched domains belonging to vendors/contractors rather than to us."""
        return [
            entry.entry_value.strip().lower()
            for entry in self.watchlist_entries
            if entry.entry_type == self.THIRD_PARTY_ENTRY_TYPE and entry.entry_value
        ]

    def get_employee_emails(self):
        """Staff addresses to watch, from the 'email' watchlist entries.

        Distinct from get_report_recipient_allowlist: an employee is someone
        whose credentials we hunt for, a recipient is someone we mail findings
        to. The two lists overlap in practice but must not be conflated — a
        CISO is a recipient, the whole payroll is not.
        """
        return sorted({
            entry.entry_value.strip().lower()
            for entry in self.watchlist_entries
            if entry.entry_type == 'email' and entry.entry_value
            and entry.entry_value.strip()
        })

    def get_report_recipient_allowlist(self):
        """Exact addresses an admin approved for this company's reports."""
        return [r.email.strip().lower() for r in self.report_recipients if r.email]

    @staticmethod
    def all_match_domains():
        """Every watched domain across every company, deduped and lowercased.

        For anything that spans all tenants — an admin's credential list, or a
        schedule with no company selected. There is no single company whose
        domains can label those rows, and labelling against none of them is
        not a neutral choice: matched_domain and match_path stay unset, which
        downstream code reads as "not staff, not a supplier".

        Two queries, not one per company: walking Company.watchlist_entries
        per row is an N+1 over the client roster.
        """
        domains = {c.domain.strip().lower()
                   for c in Company.query.with_entities(Company.domain).all()
                   if c.domain and c.domain.strip()}
        rows = WatchlistEntry.query.filter(
            WatchlistEntry.entry_type.in_(('domain', Company.THIRD_PARTY_ENTRY_TYPE))
        ).with_entities(WatchlistEntry.entry_value).all()
        domains.update(r.entry_value.strip().lower() for r in rows
                       if r.entry_value and r.entry_value.strip())
        return sorted(domains)

    @staticmethod
    def all_third_party_domains():
        """Every supplier domain across every company.

        Kept apart from all_match_domains for the same reason
        get_third_party_domains is kept apart from get_match_domains: a
        credential matched against a supplier is classified third-party rather
        than as the client's own, and that distinction drives what a breach
        email says about it.
        """
        rows = WatchlistEntry.query.filter_by(
            entry_type=Company.THIRD_PARTY_ENTRY_TYPE
        ).with_entities(WatchlistEntry.entry_value).all()
        return sorted({r.entry_value.strip().lower() for r in rows
                       if r.entry_value and r.entry_value.strip()})

    def get_own_domains(self):
        """Domains this company itself owns — never a supplier's.

        Report recipients are bound to these: a company's breach data may only
        be mailed to addresses at that company. Third-party watchlist domains
        are deliberately excluded, since a supplier being watched does not make
        them entitled to the client's findings.
        """
        domains = set()
        if self.domain:
            domains.add(self.domain.lower().strip())
        for entry in self.watchlist_entries:
            if entry.entry_type == 'domain' and entry.entry_value:
                val = entry.entry_value.strip().lower()
                if val:
                    domains.add(val)
        return sorted(domains)

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
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='member', nullable=False)
    isAdmin = db.Column(db.Boolean, default=False)
    company_id = db.Column(db.String(36), db.ForeignKey('company.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)
    totp_secret = db.Column(db.String(32), nullable=True)  # TOTP secret for 2FA
    totp_enabled = db.Column(db.Boolean, default=False)
    permissions = db.Column(db.String(500), default='')  # comma-separated: view,analyze,export,manage_users,manage_companies,manage_alerts

    def __repr__(self):
        return f"User('{self.username}','{self.email}','{self.role}')"

    @property
    def is_admin_user(self) -> bool:
        return self.role == 'admin'

    @property
    def company_domain(self) -> str:
        if self.company and self.company.domain:
            return self.company.domain
        return Company.extract_domain(self.email)

    def can_edit(self) -> bool:
        return self.is_admin_user

    def can_delete(self) -> bool:
        return self.is_admin_user

    def has_permission(self, perm):
        """Check if user has a specific permission."""
        if self.is_admin_user:
            return True  # Admins have all permissions
        return perm in (self.permissions or '').split(',')

    def get_permissions(self):
        """Get list of permissions."""
        if self.is_admin_user:
            return ['view', 'analyze', 'export', 'manage_users', 'manage_companies', 'manage_alerts', 'manage_reports']
        return [p.strip() for p in (self.permissions or '').split(',') if p.strip()]

    def can_mark(self) -> bool:
        return True

    def set_password(self, raw_password: str) -> None:
        self.password = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password, raw_password)


class BreachedCredMeta(db.Model):
    """Local metadata for ES breached credentials (marks, reviews)."""
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    es_id = db.Column(db.String(200), unique=True, nullable=False, index=True)
    is_marked = db.Column(db.Boolean, default=False)
    marked_by = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    marked_at = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)

    marker = db.relationship('User', foreign_keys=[marked_by])

    def __repr__(self):
        return f"BreachedCredMeta('{self.es_id}', marked={self.is_marked})"


class WatchlistEntry(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    company_id = db.Column(db.String(36), db.ForeignKey('company.id'), nullable=False)
    entry_type = db.Column(db.String(20), nullable=False)
    entry_value = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    def __repr__(self):
        return f"WatchlistEntry('{self.entry_type}', '{self.entry_value}')"


class ReportRecipient(db.Model):
    """An address approved to receive a company's reports.

    Distinct from WatchlistEntry on purpose. A watchlist entry is a *domain we
    monitor for breaches* (statebank.mn and its subdomains); a report recipient
    is a *person we send findings to*. Conflating them pollutes the watchlist
    with addresses that were never meant to be searched.

    Reports are normally bound to the company's own domains; rows here are the
    admin-approved exceptions, so they are always exact addresses and never
    domains — a domain here would reopen the hole that binding closes.
    """
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    company_id = db.Column(db.String(36), db.ForeignKey('company.id'), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    created_by = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)

    company = db.relationship('Company', backref=db.backref(
        'report_recipients', lazy=True, cascade='all, delete-orphan'))

    __table_args__ = (
        db.UniqueConstraint('company_id', 'email', name='uq_report_recipient'),
    )

    def __repr__(self):
        return f"ReportRecipient('{self.email}')"


class Notification(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
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
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    action_type = db.Column(db.String(50), nullable=False, index=True)
    resource_type = db.Column(db.String(50), nullable=False, index=True)
    resource_id = db.Column(db.String(36), nullable=True)
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
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
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


class ScheduledReport(db.Model):
    """Scheduled automatic report generation."""
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(200), nullable=False)
    frequency = db.Column(db.String(20), nullable=False)  # daily, weekly, monthly
    # Local wall-clock time of day, "HH:MM". Stored as the operator typed it —
    # next_run holds the UTC instant it resolves to, so a schedule keeps its
    # local time rather than shifting when the offset changes.
    run_time = db.Column(db.String(5), nullable=True)
    # weekly: ISO weekdays, "1,5" = Mon and Fri. monthly: day of month, "15".
    run_days = db.Column(db.String(50), nullable=True)
    format = db.Column(db.String(10), default='pdf')  # csv, xlsx, pdf, json
    filters = db.Column(db.Text, nullable=True)  # JSON filters
    email_to = db.Column(db.String(500), nullable=True)  # comma-separated emails
    is_active = db.Column(db.Boolean, default=True)
    last_run = db.Column(db.DateTime, nullable=True)
    next_run = db.Column(db.DateTime, nullable=True)
    # Scopes the report to one client's watched domains. NULL means "whatever
    # the creator may see", which is how schedules behaved before per-company
    # reporting existed.
    company_id = db.Column(db.String(36), db.ForeignKey('company.id'), nullable=True)
    created_by = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)

    creator = db.relationship('User', foreign_keys=[created_by])
    company = db.relationship('Company', foreign_keys=[company_id])

    def __repr__(self):
        return f"ScheduledReport('{self.name}', '{self.frequency}')"


class AlertRule(db.Model):
    """Alert rules for breach monitoring."""
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(200), nullable=False)
    condition_type = db.Column(db.String(50), nullable=False)  # new_breach, threshold, domain_match
    condition_value = db.Column(db.String(500), nullable=False)  # domain pattern, threshold number, etc.
    notify_method = db.Column(db.String(20), default='in_app')  # in_app, email, webhook
    notify_target = db.Column(db.String(500), nullable=True)  # email or webhook URL
    is_active = db.Column(db.Boolean, default=True)
    trigger_count = db.Column(db.Integer, default=0)
    last_triggered = db.Column(db.DateTime, nullable=True)
    created_by = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)

    creator = db.relationship('User', foreign_keys=[created_by])

    def __repr__(self):
        return f"AlertRule('{self.name}', '{self.condition_type}')"


class ReportHistory(db.Model):
    """Generated report history for download."""
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(200), nullable=False)
    format = db.Column(db.String(10), nullable=False)
    file_size = db.Column(db.Integer, default=0)  # bytes
    record_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='completed')  # pending, generating, completed, failed
    source = db.Column(db.String(50), default='manual')  # manual, scheduled
    schedule_id = db.Column(db.String(36), db.ForeignKey('scheduled_report.id'), nullable=True)
    generated_by = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)

    generator = db.relationship('User', foreign_keys=[generated_by])
    schedule = db.relationship('ScheduledReport', foreign_keys=[schedule_id])

    def __repr__(self):
        return f"ReportHistory('{self.name}', '{self.status}')"
