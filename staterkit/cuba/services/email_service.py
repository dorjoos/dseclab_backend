"""Simple email service for report and breach-notification delivery.

Delivery is over SMTP; configured for Resend's SMTP relay by default
(smtp.resend.com:587, username 'resend', password = Resend API key).

Messages go out as multipart/alternative — an HTML-only breach alert reads as
spam to most corporate filters, and the text part is what shows up in clients
that refuse HTML at all.

Body copy is Mongolian; subject lines stay English so they remain scannable in
a mixed inbox and in our own logs.
"""
import html
import logging
import re
import smtplib
from datetime import date
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from urllib.parse import quote
from flask import current_app

logger = logging.getLogger(__name__)

# Palette taken from the report design.
PAGE_BG = "#EEF1F5"
CARD_BG = "#FFFFFF"
HEADER_BG = "#12161C"
STRIPE_BG = "#1A1012"
STRIPE_FG = "#EF6B6B"
MARK_BG = "#E5533D"
INK = "#111827"
MUTED = "#98A2B3"
BODY = "#4A5568"
LINE = "#E5E8EC"
PANEL_BG = "#F7F9FC"
LINK = "#3B5BDB"
CTA_BG = "#26359C"

# Tile accents, in the order the tiles are laid out.
TOTAL_FG = "#E5484D"
STAFF_FG = "#3B5BDB"
CUSTOMER_FG = "#E8912D"
THIRD_PARTY_FG = "#8B3DD9"

# Mongolian body copy. Subjects stay English by design.
MN = {
    "header_sub": "Өнөөдрийн Аюулгүй Байдлын Тайлан",
    "stripe": "Алдагдсан нэвтрэх нэр нууц үгүүд",
    "window": ("Сүүлийн 24 цагт", "илэрсэн бүртгэл"),
    "tile_total": ("НИЙТ АЛДАГДСАН", "бүртгэл"),
    "tile_staff": ("АЖИЛЧИД", "ажилтан"),
    "tile_customer": ("ХЭРЭГЛЭГЧИД", "хэрэглэгч"),
    "tile_third_party": ("3RD PARTY", "vendor / contractor"),
    "recent": "СҮҮЛИЙН ИЛЭРСЭН БҮРТГЭЛҮҮД",
    "total_records": "нийт бүртгэл",
    "actions": "АВАХ АРГА ХЭМЖЭЭ",
    "steps": [
        "Нөлөөлсөн бүх акаунтын нууц үгийг нэн даруй шинэчлэх",
        "Сэжигтэй нэвтрэлт, IP логийг дараагийн 48 цагт хянах",
        "Алдагдсан session / token-ийг хүчингүй болгох",
        "Бүх эрхтэй акаунтад MFA идэвхжүүлэх",
        "Гуравдагч талын хандалтыг шалгаж, шаардлагагүй эрхийг хасах",
    ],
    "cta": "Бүтэн тайлан харах",
    "footer_org": "Кибер Аюулгүй Байдлын Судалгааны Лаборатори",
    "unknown_user": "(тодорхойгүй)",
}

# The only credential attributes any renderer reads. A BreachedCredDoc carries
# a plaintext password; keeping the reads funnelled through here is what makes
# leaking it impossible rather than merely unlikely.
_READ_FIELDS = ("username", "matched_domain", "match_path", "source", "type", "es_id")


def _esc(value):
    """Escape for HTML text *and* attribute contexts."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _clean_header(value):
    """Collapse all whitespace, so caller text can't inject mail headers."""
    return " ".join(str(value or "").split())


def _cred_url(base_url, es_id):
    """URL for a credential's detail page, or None if we can't build a safe one."""
    if not base_url or not es_id:
        return None
    return (f"{str(base_url).rstrip('/')}/threat-intelligence/breached-creds/"
            f"{quote(str(es_id), safe='')}")


def _as_text(value, link=None, color=INK, underline=False):
    """Render a value inside an anchor we own.

    Gmail autolinks anything resembling an address or domain and paints it with
    its own styling, but leaves text already inside an <a> alone. An anchor with
    no href renders as plain text.
    """
    href = f' href="{_esc(link)}"' if link else ""
    decoration = "underline" if underline else "none"
    return (f'<a{href} style="color:{color};text-decoration:{decoration};">'
            f'{_esc(value)}</a>')


def classify_creds(creds, third_party_domains=None):
    """Split credentials into staff / customer / third-party buckets.

    A credential whose *username* sits at a watched domain belongs to the
    organisation's own people. One matched through the site — its domain or
    URL — belongs to somebody who used that site, i.e. a customer. Anything
    matched against a supplier's watched domain is third-party regardless.
    """
    third_party = {str(d).lower().strip() for d in (third_party_domains or []) if d}
    buckets = {"staff": [], "customer": [], "third_party": []}
    for cred in creds:
        matched = (getattr(cred, "matched_domain", None) or "").lower()
        if matched and matched in third_party:
            buckets["third_party"].append(cred)
        elif getattr(cred, "match_path", None) == "username":
            buckets["staff"].append(cred)
        else:
            buckets["customer"].append(cred)
    return buckets


def _chip_label(cred):
    """Provenance chip, e.g. 'Telegram/Stealerlog'.

    Live documents already carry a compound source ("Telegram/Stealerlog")
    while `type` holds a separate technical label ("url"), so source alone is
    the chip; type is only a fallback for documents lacking one.
    """
    return getattr(cred, "source", None) or getattr(cred, "type", None) or ""


def _tile(label, value, sublabel, color):
    return (
        f'<td width="25%" valign="top" style="width:25%;padding:0 5px;">'
        f'<div style="background-color:{CARD_BG};border:1px solid {LINE};'
        f'border-radius:10px;padding:14px 14px 16px;">'
        f'<div style="font-size:10px;font-weight:700;letter-spacing:.07em;'
        f'color:{MUTED};">{_esc(label)}</div>'
        f'<div style="margin-top:8px;font-size:28px;font-weight:700;line-height:1;'
        f'color:{color};">{_esc(value)}</div>'
        f'<div style="margin-top:7px;font-size:12px;color:{BODY};">'
        f'{_esc(sublabel)}</div>'
        f'</div></td>'
    )


def _cred_row(cred, base_url, is_first):
    """One credential: identifier on the left, provenance chip on the right."""
    link = _cred_url(base_url, getattr(cred, "es_id", None))
    username = getattr(cred, "username", None) or MN["unknown_user"]
    chip = _chip_label(cred)
    border = "" if is_first else f"border-top:1px solid {LINE};"

    chip_cell = ""
    if chip:
        chip_cell = (
            f'<td align="right" valign="middle" style="padding:13px 16px;{border}">'
            f'<span style="display:inline-block;background-color:{PANEL_BG};'
            f'border:1px solid {LINE};border-radius:6px;padding:4px 9px;'
            f'font-size:11px;color:{BODY};white-space:nowrap;">{_esc(chip)}</span>'
            f'</td>'
        )

    return (
        f'<tr>'
        f'<td valign="middle" style="padding:13px 16px;{border}'
        f'font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;'
        f'font-size:13px;word-break:break-all;">'
        f'{_as_text(username, link, color=LINK if link else INK, underline=bool(link))}'
        f'</td>{chip_cell}</tr>'
    )


def _step(number, text):
    return (
        f'<tr>'
        f'<td width="26" valign="top" style="width:26px;padding:0 10px 9px 0;">'
        f'<div style="width:24px;height:24px;border:1px solid #D8DEE6;'
        f'border-radius:12px;background-color:{CARD_BG};color:{BODY};'
        f'font-size:12px;line-height:24px;text-align:center;">{number}</div></td>'
        f'<td valign="middle" style="padding:0 0 9px;font-size:14px;color:{INK};'
        f'line-height:24px;">{_esc(text)}</td>'
        f'</tr>'
    )


def build_breach_email(company_name, creds, base_url=None, company_domain=None,
                       third_party_domains=None, report_date=None):
    """Build (subject, html_body, text_body) for a breach-notification email.

    `creds` is an iterable of BreachedCredDoc-like objects; only the attributes
    in _READ_FIELDS are ever read. `third_party_domains` comes from
    Company.get_third_party_domains() and decides the third-party tile.
    """
    creds = list(creds)
    count = len(creds)
    company_name = _clean_header(company_name)
    subject = _clean_header(
        f"[DSECLab] {count} breached credential(s) — {company_name}")

    base_url = str(base_url or "").rstrip("/")
    buckets = classify_creds(creds, third_party_domains)
    stamp = (report_date or date.today()).strftime("%Y-%m-%d")
    listing = f"{base_url}/threat-intelligence/breached-creds" if base_url else None

    rows = "".join(_cred_row(c, base_url, i == 0) for i, c in enumerate(creds))
    steps = "".join(_step(i, s) for i, s in enumerate(MN["steps"], start=1))
    window_top, window_bottom = MN["window"]

    tiles = "".join([
        _tile(MN["tile_total"][0], count, MN["tile_total"][1], TOTAL_FG),
        _tile(MN["tile_staff"][0], len(buckets["staff"]), MN["tile_staff"][1], STAFF_FG),
        _tile(MN["tile_customer"][0], len(buckets["customer"]),
              MN["tile_customer"][1], CUSTOMER_FG),
        _tile(MN["tile_third_party"][0], len(buckets["third_party"]),
              MN["tile_third_party"][1], THIRD_PARTY_FG),
    ])

    cta = ""
    if listing:
        cta = (
            f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
            f'align="center" style="margin:26px auto 4px;"><tr>'
            f'<td style="background-color:{CTA_BG};border-radius:8px;">'
            f'<a href="{_esc(listing)}" style="display:inline-block;padding:14px 28px;'
            f'font-size:15px;font-weight:700;color:#FFFFFF;text-decoration:none;">'
            f'{_esc(MN["cta"])} &rarr;</a></td></tr></table>'
        )

    domain_line = ""
    if company_domain:
        domain_line = (
            f'<div style="margin-top:6px;font-family:ui-monospace,SFMono-Regular,'
            f'Menlo,Consolas,monospace;font-size:14px;">'
            f'{_as_text(company_domain, listing, color=LINK, underline=True)}</div>'
        )

    body = (
        '<!DOCTYPE html>'
        '<html lang="mn"><head>'
        '<meta charset="utf-8"/>'
        '<meta name="viewport" content="width=device-width,initial-scale=1"/>'
        '<meta name="x-apple-disable-message-reformatting"/>'
        '<meta name="color-scheme" content="light"/>'
        '<title>DSECLab</title></head>'
        f'<body style="margin:0;padding:0;background-color:{PAGE_BG};">'
        f'<div style="display:none;max-height:0;overflow:hidden;font-size:0;'
        f'line-height:0;color:{PAGE_BG};">'
        f'{_esc(company_name)} — {count} {_esc(MN["total_records"])}</div>'

        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
        f'width="100%" style="width:100%;background-color:{PAGE_BG};">'
        f'<tr><td align="center" style="padding:26px 12px 34px;">'

        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
        f'width="640" style="width:640px;max-width:640px;border-collapse:collapse;">'

        # ---- dark header ----
        f'<tr><td style="padding:22px 26px;background-color:{HEADER_BG};'
        f'border-radius:12px 12px 0 0;">'
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
        f'width="100%" style="width:100%;"><tr>'
        f'<td width="46" valign="middle" style="width:46px;">'
        f'<div style="width:44px;height:44px;background-color:{MARK_BG};'
        f'border-radius:11px;color:#FFFFFF;font-size:20px;font-weight:700;'
        f'line-height:44px;text-align:center;">D</div></td>'
        f'<td valign="middle" style="padding-left:13px;">'
        f'<div style="font-size:19px;font-weight:700;color:#FFFFFF;">Dseclab</div>'
        f'<div style="margin-top:2px;font-size:12px;color:#9AA3B0;">'
        f'{_esc(MN["header_sub"])}</div></td>'
        f'<td align="right" valign="middle">'
        f'<span style="display:inline-block;border:1px solid #2C323C;'
        f'border-radius:7px;padding:6px 11px;font-size:12px;color:#C7CDD6;">'
        f'{_esc(stamp)}</span></td>'
        f'</tr></table></td></tr>'

        # ---- alert stripe ----
        f'<tr><td style="padding:11px 26px;background-color:{STRIPE_BG};">'
        f'<span style="font-size:13px;font-weight:700;color:{STRIPE_FG};">'
        f'&#9679;&nbsp; {_esc(MN["stripe"])}</span></td></tr>'

        # ---- company + window ----
        f'<tr><td style="padding:28px 26px 0;background-color:{CARD_BG};">'
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
        f'width="100%" style="width:100%;"><tr>'
        f'<td valign="top">'
        f'<div style="font-size:27px;font-weight:700;color:{INK};line-height:1.2;">'
        f'{_esc(company_name)}</div>{domain_line}</td>'
        f'<td align="right" valign="top" style="font-size:13px;color:{MUTED};'
        f'line-height:1.5;">{_esc(window_top)}<br/>{_esc(window_bottom)}</td>'
        f'</tr></table>'
        f'<div style="border-top:1px solid {LINE};margin-top:20px;"></div>'
        f'</td></tr>'

        # ---- tiles ----
        f'<tr><td style="padding:20px 21px 0;background-color:{CARD_BG};">'
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
        f'width="100%" style="width:100%;"><tr>{tiles}</tr></table></td></tr>'

        # ---- recent records ----
        f'<tr><td style="padding:26px 26px 0;background-color:{CARD_BG};">'
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
        f'width="100%" style="width:100%;"><tr>'
        f'<td valign="middle" style="border-left:4px solid {LINK};padding-left:11px;'
        f'font-size:13px;font-weight:700;letter-spacing:.03em;color:{INK};">'
        f'{_esc(MN["recent"])}</td>'
        f'<td align="right" valign="middle" style="font-size:12px;color:{MUTED};">'
        f'{count} {_esc(MN["total_records"])}</td>'
        f'</tr></table>'
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
        f'width="100%" style="width:100%;margin-top:12px;border:1px solid {LINE};'
        f'border-radius:10px;background-color:{CARD_BG};">{rows}</table>'
        f'</td></tr>'

        # ---- actions ----
        f'<tr><td style="padding:24px 26px 0;background-color:{CARD_BG};">'
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
        f'width="100%" style="width:100%;background-color:{PANEL_BG};'
        f'border-left:4px solid {LINK};"><tr>'
        f'<td style="padding:20px 22px;">'
        f'<div style="margin-bottom:14px;font-size:13px;font-weight:700;'
        f'letter-spacing:.03em;color:{INK};">{_esc(MN["actions"])}</div>'
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0">'
        f'{steps}</table></td></tr></table></td></tr>'

        # ---- cta ----
        f'<tr><td align="center" style="padding:0 26px 34px;'
        f'background-color:{CARD_BG};border-radius:0 0 12px 12px;">{cta}</td></tr>'

        # ---- footer ----
        f'<tr><td style="padding:22px 0 0;"></td></tr>'
        f'<tr><td style="padding:20px 24px;background-color:#F5F7FA;'
        f'border:1px solid {LINE};border-radius:12px;">'
        f'<div style="font-size:14px;font-weight:700;color:{INK};">Dseclab</div>'
        f'<div style="margin-top:4px;font-size:12px;color:{MUTED};">'
        f'{_esc(MN["footer_org"])} &middot; '
        f'{_as_text("dseclab.mn", listing, color=LINK, underline=True)}</div>'
        f'</td></tr>'

        '</table></td></tr></table></body></html>'
    )

    return subject, body, _text_body(company_name, creds, base_url, buckets, stamp)


def _text_body(company_name, creds, base_url, buckets, stamp):
    """The text/plain alternative — same data, no markup."""
    lines = [
        "DSECLAB — " + MN["header_sub"],
        stamp,
        "",
        company_name,
        f"{MN['stripe']}: {len(creds)}",
        "",
        f"{MN['tile_total'][0]}: {len(creds)}",
        f"{MN['tile_staff'][0]}: {len(buckets['staff'])}",
        f"{MN['tile_customer'][0]}: {len(buckets['customer'])}",
        f"{MN['tile_third_party'][0]}: {len(buckets['third_party'])}",
        "",
        MN["recent"],
    ]
    for cred in creds:
        username = getattr(cred, "username", None) or MN["unknown_user"]
        chip = _chip_label(cred)
        lines.append(f"  * {username}" + (f"  [{chip}]" if chip else ""))
        url = _cred_url(base_url, getattr(cred, "es_id", None))
        if url:
            lines.append(f"      {url}")
    lines += ["", MN["actions"]]
    lines += [f"  {i}. {s}" for i, s in enumerate(MN["steps"], start=1)]
    if base_url:
        lines += ["", f"{MN['cta']}: {base_url}/threat-intelligence/breached-creds"]
    lines += ["", f"Dseclab — {MN['footer_org']} · dseclab.mn"]
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
