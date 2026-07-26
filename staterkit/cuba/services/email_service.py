"""Simple email service for report and breach-notification delivery.

Delivery is over SMTP; configured for Resend's SMTP relay by default
(smtp.resend.com:587, username 'resend', password = Resend API key).
"""
import html
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from flask import current_app

logger = logging.getLogger(__name__)


def send_email(to, subject, body, attachment=None, attachment_name=None):
    """Send an email. Returns True on success."""
    try:
        config = current_app.config
        server = config.get('MAIL_SERVER', 'smtp.gmail.com')
        port = config.get('MAIL_PORT', 587)
        use_tls = config.get('MAIL_USE_TLS', True)
        username = config.get('MAIL_USERNAME', '')
        password = config.get('MAIL_PASSWORD', '')
        sender = config.get('MAIL_DEFAULT_SENDER', 'noreply@dseclab.com')

        if not username or not password:
            logger.warning("Email not configured (MAIL_USERNAME/MAIL_PASSWORD not set)")
            return False

        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = to
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))

        if attachment and attachment_name:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment)
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename={attachment_name}')
            msg.attach(part)

        with smtplib.SMTP(server, port) as smtp:
            if use_tls:
                smtp.starttls()
            smtp.login(username, password)
            smtp.sendmail(sender, to.split(','), msg.as_string())

        logger.info("Email sent to %s: %s", to, subject)
        return True
    except Exception as e:
        logger.error("Failed to send email: %s", e)
        return False


def is_email_configured():
    """True when SMTP credentials are present so send_email can deliver."""
    config = current_app.config
    return bool(config.get('MAIL_USERNAME') and config.get('MAIL_PASSWORD'))


def _row(label, value):
    if not value:
        return ""
    return (
        f'<tr><td style="padding:4px 12px 4px 0;color:#6b7280;'
        f'white-space:nowrap;">{html.escape(str(label))}</td>'
        f'<td style="padding:4px 0;color:#111827;font-family:monospace;">'
        f'{html.escape(str(value))}</td></tr>'
    )


def build_breach_email(company_name, creds, base_url=None):
    """Build (subject, html_body) for a breach-notification email.

    `creds` is an iterable of BreachedCredDoc-like objects. Each may expose
    username, domain, matched_domain, file_name, source, type, created_at and
    es_id. matched_domain and file_name are surfaced per the design.
    """
    creds = list(creds)
    count = len(creds)
    subject = f"[DSECLab] {count} breached credential(s) — {company_name}"

    base_url = (base_url or "").rstrip("/")
    blocks = []
    for c in creds:
        link = ""
        es_id = getattr(c, "es_id", None)
        if base_url and es_id:
            url = f"{base_url}/threat-intelligence/breached-creds/{es_id}"
            link = (f'<tr><td colspan="2" style="padding:6px 0 0;">'
                    f'<a href="{html.escape(url)}" '
                    f'style="color:#2563eb;">View credential &rsaquo;</a></td></tr>')
        date_val = getattr(c, "created_at", None)
        date_str = date_val.strftime("%Y-%m-%d") if hasattr(date_val, "strftime") else (date_val or "")
        rows = "".join([
            _row("Username", getattr(c, "username", None)),
            _row("Domain", getattr(c, "domain", None)),
            _row("Matched domain", getattr(c, "matched_domain", None)),
            _row("File name", getattr(c, "file_name", None)),
            _row("Source", getattr(c, "source", None)),
            _row("Type", getattr(c, "type", None)),
            _row("Date", date_str),
            link,
        ])
        blocks.append(
            f'<table style="border-collapse:collapse;margin:0 0 16px;'
            f'border-left:3px solid #dc2626;padding-left:12px;">{rows}</table>'
        )

    body = (
        f'<div style="font-family:Arial,Helvetica,sans-serif;max-width:640px;">'
        f'<h2 style="color:#111827;">Breach alert — {html.escape(company_name)}</h2>'
        f'<p style="color:#374151;">{count} breached credential(s) matched your '
        f'watchlist. Details below.</p>'
        f'{"".join(blocks)}'
        f'<p style="color:#9ca3af;font-size:12px;">Sent by DSECLab Threat '
        f'Intelligence Platform.</p></div>'
    )
    return subject, body
