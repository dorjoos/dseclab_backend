"""Simple email service for report and breach-notification delivery.

Delivery is over SMTP; configured for Resend's SMTP relay by default
(smtp.resend.com:587, username 'resend', password = Resend API key).

Messages go out as multipart/alternative — an HTML-only breach alert reads as
spam to most corporate filters, and the text part is what shows up in clients
that refuse HTML at all.
"""
import html
import logging
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from urllib.parse import quote
from flask import current_app

logger = logging.getLogger(__name__)

# Brand palette, sampled from static/assets/images/logo/logo.png.
BRAND = "#8424F0"
BRAND_ALT = "#249CFC"
INK = "#111827"
MUTED = "#6B7280"
BORDER = "#E5E7EB"
PAGE_BG = "#F4F5F7"
CARD_BG = "#FFFFFF"
ALERT = "#DC2626"

# The only credential fields that ever reach a message body. Anything a
# BreachedCredDoc grows later — a password, most of all — stays out by
# construction rather than by us remembering not to render it.
_CARD_FIELDS = (
    ("Domain", "domain"),
    ("Matched domain", "matched_domain"),
    ("Type", "type"),
)


def _esc(value):
    """Escape for HTML text *and* attribute contexts."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _clean_header(value):
    """Collapse all whitespace, so caller text can't inject mail headers.

    Subjects are built from company names, which are admin-supplied; a bare
    CR/LF in one would otherwise start a new header line.
    """
    return " ".join(str(value or "").split())


def _fmt_date(value):
    return value.strftime("%Y-%m-%d") if hasattr(value, "strftime") else (value or "")


def _cred_url(base_url, es_id):
    """URL for a credential's detail page, or None if we can't build a safe one.

    es_id comes from Elasticsearch, so it's quoted before it joins the path.
    """
    if not base_url or not es_id:
        return None
    return (f"{str(base_url).rstrip('/')}/threat-intelligence/breached-creds/"
            f"{quote(str(es_id), safe='')}")


def _as_text(value, link=None):
    """Render a value inside an anchor we own.

    Gmail autolinks anything that looks like an address or a domain and paints
    it with its own blue underline — but it leaves text that is already inside
    an <a> alone. An anchor with no href renders as plain text, which is what
    we want everywhere except the credential heading.
    """
    href = f' href="{_esc(link)}"' if link else ""
    return (f'<a{href} style="color:{INK};text-decoration:none;">'
            f'{_esc(value)}</a>')


def _row(label, value):
    if not value:
        return ""
    return (
        f'<tr>'
        f'<td style="padding:3px 16px 3px 0;background-color:{CARD_BG};color:{MUTED};'
        f'font-size:13px;white-space:nowrap;vertical-align:top;">{_esc(label)}</td>'
        f'<td style="padding:3px 0;background-color:{CARD_BG};color:{INK};font-size:13px;'
        f'font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;'
        f'word-break:break-all;">{_as_text(value)}</td>'
        f'</tr>'
    )


def _card(cred, base_url):
    """One credential, as a bordered card with a red accent edge."""
    link = _cred_url(base_url, getattr(cred, "es_id", None))
    username = getattr(cred, "username", None) or "(unknown username)"

    rows = "".join(_row(label, getattr(cred, attr, None))
                   for label, attr in _CARD_FIELDS)
    rows += _row("Date", _fmt_date(getattr(cred, "created_at", None)))

    cta = ""
    if link:
        cta = (f'<div style="margin:12px 0 0;">'
               f'<a href="{_esc(link)}" style="color:{BRAND};text-decoration:none;'
               f'font-size:13px;font-weight:600;">View credential &rarr;</a></div>')

    return (
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
        f'width="100%" style="width:100%;border-collapse:separate;border-spacing:0;'
        f'margin:0 0 12px;">'
        f'<tr>'
        f'<td width="3" style="width:3px;background-color:{ALERT};font-size:0;'
        f'line-height:0;border-radius:6px 0 0 6px;">&nbsp;</td>'
        f'<td style="padding:14px 16px;background-color:{CARD_BG};'
        f'border:1px solid {BORDER};border-left:0;border-radius:0 6px 6px 0;">'
        f'<div style="margin:0 0 10px;font-size:15px;font-weight:600;color:{INK};'
        f'word-break:break-all;">{_as_text(username, link)}</div>'
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0">'
        f'{rows}</table>{cta}</td>'
        f'</tr></table>'
    )


def _shell(inner, preheader=""):
    """Wrap card content in the branded 600px document."""
    return (
        '<!DOCTYPE html>'
        '<html lang="en"><head>'
        '<meta charset="utf-8"/>'
        '<meta name="viewport" content="width=device-width,initial-scale=1"/>'
        '<meta name="x-apple-disable-message-reformatting"/>'
        '<meta name="color-scheme" content="light dark"/>'
        '<meta name="supported-color-schemes" content="light dark"/>'
        '<title>Breach alert</title>'
        '<style>@media (max-width:620px){'
        '.dsec-wrap{width:100%!important;}'
        '.dsec-pad{padding-left:16px!important;padding-right:16px!important;}}'
        '</style>'
        '</head>'
        f'<body style="margin:0;padding:0;background-color:{PAGE_BG};">'
        f'<div style="display:none;max-height:0;overflow:hidden;font-size:0;'
        f'line-height:0;color:{PAGE_BG};">{_esc(preheader)}</div>'
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
        f'width="100%" style="width:100%;background-color:{PAGE_BG};">'
        f'<tr><td align="center" style="padding:24px 12px;background-color:{PAGE_BG};">'
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
        f'width="600" class="dsec-wrap" style="width:600px;max-width:600px;'
        f'border-collapse:separate;border-spacing:0;">'
        # header
        f'<tr><td class="dsec-pad" style="padding:22px 28px;background-color:{BRAND};'
        f'background-image:linear-gradient(90deg,{BRAND},{BRAND_ALT});'
        f'border-radius:10px 10px 0 0;">'
        f'<div style="font-size:19px;font-weight:700;letter-spacing:.06em;'
        f'color:#FFFFFF;">D-SECLAB</div>'
        f'<div style="font-size:12px;color:#EDE4FB;letter-spacing:.04em;">'
        f'Threat Intelligence</div>'
        f'</td></tr>'
        # body
        f'<tr><td class="dsec-pad" style="padding:28px;background-color:{CARD_BG};'
        f'border:1px solid {BORDER};border-top:0;border-radius:0 0 10px 10px;">'
        f'{inner}'
        f'</td></tr>'
        # footer
        f'<tr><td class="dsec-pad" style="padding:18px 28px;background-color:{PAGE_BG};">'
        f'<div style="font-size:12px;color:{MUTED};line-height:1.6;">'
        f'Sent by DSECLab Threat Intelligence Platform.<br/>'
        f'You received this because your organization&rsquo;s domains are on watch.'
        f'</div></td></tr>'
        '</table></td></tr></table></body></html>'
    )


def _text_body(company_name, creds, base_url):
    """The text/plain alternative — same data, no markup."""
    lines = [
        "D-SECLAB — Threat Intelligence",
        "",
        f"Breach alert — {company_name}",
        f"{len(creds)} breached credential(s) matched your watchlist.",
        "",
    ]
    for cred in creds:
        lines.append(f"* {getattr(cred, 'username', None) or '(unknown username)'}")
        for label, attr in _CARD_FIELDS:
            value = getattr(cred, attr, None)
            if value:
                lines.append(f"    {label}: {value}")
        date_str = _fmt_date(getattr(cred, "created_at", None))
        if date_str:
            lines.append(f"    Date: {date_str}")
        url = _cred_url(base_url, getattr(cred, "es_id", None))
        if url:
            lines.append(f"    {url}")
        lines.append("")
    lines.append("Sent by DSECLab Threat Intelligence Platform.")
    return "\n".join(lines)


def _strip_tags(markup):
    """Crude HTML→text, used only when a caller supplies no text part."""
    text = re.sub(r"<br\s*/?>", "\n", markup or "", flags=re.I)
    text = re.sub(r"</(p|div|tr|h[1-6]|table)>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\n{3,}", "\n\n", html.unescape(text)).strip()


def _recipients(to):
    """Split and validate recipients, dropping anything header-unsafe."""
    out = []
    for addr in str(to or "").split(","):
        addr = addr.strip()
        if not addr or "@" not in addr or "\r" in addr or "\n" in addr:
            continue
        out.append(addr)
    return out


def build_breach_email(company_name, creds, base_url=None):
    """Build (subject, html_body, text_body) for a breach-notification email.

    `creds` is an iterable of BreachedCredDoc-like objects. Only the fields in
    _CARD_FIELDS (plus username, created_at and es_id) are read; see that
    tuple's comment for why the allowlist matters.
    """
    creds = list(creds)
    count = len(creds)
    company_name = _clean_header(company_name)
    subject = _clean_header(
        f"[DSECLab] {count} breached credential(s) — {company_name}")

    base_url = (str(base_url or "")).rstrip("/")
    cards = "".join(_card(c, base_url) for c in creds)

    button = ""
    if base_url:
        listing = f"{base_url}/threat-intelligence/breached-creds"
        button = (
            f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
            f'style="margin:22px auto 4px;"><tr>'
            f'<td align="center" style="background-color:{BRAND};border-radius:6px;">'
            f'<a href="{_esc(listing)}" style="display:inline-block;padding:11px 22px;'
            f'color:#FFFFFF;font-size:14px;font-weight:600;text-decoration:none;">'
            f'Open in D-SECLAB &rarr;</a>'
            f'</td></tr></table>'
        )

    inner = (
        f'<div style="margin:0 0 4px;font-size:12px;font-weight:600;'
        f'letter-spacing:.08em;color:{ALERT};">&#9679; BREACH ALERT</div>'
        f'<div style="margin:0 0 4px;font-size:26px;font-weight:700;color:{INK};'
        f'line-height:1.25;">{count} breached credential{"" if count == 1 else "s"}</div>'
        f'<div style="margin:0 0 22px;font-size:15px;color:{MUTED};">'
        f'matched {_esc(company_name)}</div>'
        f'{cards}{button}'
    )

    preheader = f"{count} breached credential(s) matched {company_name}"
    return subject, _shell(inner, preheader), _text_body(company_name, creds, base_url)


def send_email(to, subject, body, attachment=None, attachment_name=None, *, text=None):
    """Send an email. Returns True on success.

    `text` is keyword-only so existing positional calls keep working; when it's
    omitted the plain part is derived from the HTML.
    """
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

        recipients = _recipients(to)
        if not recipients:
            logger.error("No valid recipient in %r; not sending", to)
            return False

        alternative = MIMEMultipart('alternative')
        alternative.attach(MIMEText(text or _strip_tags(body), 'plain', 'utf-8'))
        alternative.attach(MIMEText(body, 'html', 'utf-8'))

        if attachment and attachment_name:
            msg = MIMEMultipart('mixed')
            msg.attach(alternative)
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment)
            encoders.encode_base64(part)
            part.add_header('Content-Disposition',
                            f'attachment; filename={_clean_header(attachment_name)}')
            msg.attach(part)
        else:
            msg = alternative

        msg['From'] = sender
        msg['To'] = ", ".join(recipients)
        msg['Subject'] = _clean_header(subject)

        with smtplib.SMTP(server, port) as smtp:
            if use_tls:
                smtp.starttls()
            smtp.login(username, password)
            smtp.sendmail(sender, recipients, msg.as_string())

        logger.info("Email sent to %s: %s", msg['To'], msg['Subject'])
        return True
    except Exception as e:
        logger.error("Failed to send email: %s", e)
        return False


def is_email_configured():
    """True when SMTP credentials are present so send_email can deliver."""
    config = current_app.config
    return bool(config.get('MAIL_USERNAME') and config.get('MAIL_PASSWORD'))
