"""Outbound email (currently: password reset).

Two honest modes:

* MAIL_HOST configured -> the message is handed to that SMTP server (STARTTLS by
  default, or implicit TLS with MAIL_USE_SSL). send_email() returns True only
  when the server ACCEPTED the message.
* MAIL_HOST unset -> nothing is sent. The message, including any link in it, is
  written to the server log at WARNING and send_email() returns False. That is a
  deliberate fallback so an operator can still recover an account when no mail
  provider exists, and it is never reported as delivery.

send_email() never raises into a request handler: an SMTP outage must not turn
"I forgot my password" into a 500 (or, worse, an error that reveals whether the
address exists). Failures are logged and reported as False.
"""

import smtplib
import ssl
from email.message import EmailMessage

from flask import current_app


def mail_configured():
    return bool(current_app.config.get('MAIL_HOST'))


def send_email(to_address, subject, body):
    """Send one plain-text email. Returns True if an SMTP server accepted it,
    False if it was only logged or delivery failed."""
    cfg = current_app.config
    host = cfg.get('MAIL_HOST')

    if not host:
        current_app.logger.warning(
            'MAIL_HOST is not configured, so no email was sent. Message for %s -- subject: %s\n%s',
            to_address, subject, body)
        return False

    message = EmailMessage()
    message['From'] = cfg.get('MAIL_FROM') or 'no-reply@localhost'
    message['To'] = to_address
    message['Subject'] = subject
    message.set_content(body)

    port = cfg.get('MAIL_PORT') or 587
    try:
        if cfg.get('MAIL_USE_SSL'):
            smtp = smtplib.SMTP_SSL(host, port, timeout=10, context=ssl.create_default_context())
        else:
            smtp = smtplib.SMTP(host, port, timeout=10)
        with smtp:
            if not cfg.get('MAIL_USE_SSL') and cfg.get('MAIL_USE_TLS'):
                smtp.starttls(context=ssl.create_default_context())
            if cfg.get('MAIL_USERNAME'):
                smtp.login(cfg['MAIL_USERNAME'], cfg.get('MAIL_PASSWORD') or '')
            smtp.send_message(message)
        return True
    except Exception as exc:  # network, TLS, auth, refused recipient...
        current_app.logger.error('email to %s could not be delivered via %s:%s: %s',
                                 to_address, host, port, exc)
        return False
