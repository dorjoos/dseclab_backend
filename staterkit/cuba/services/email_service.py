"""Simple email service for report delivery."""
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
