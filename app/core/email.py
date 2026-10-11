"""
Email sender using aiosmtplib.
Sends verification, password reset, and notification emails.
"""
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
import structlog

try:
    import aiosmtplib
    HAS_SMTP = True
except ImportError:
    HAS_SMTP = False

from app.core.config import get_settings

log = structlog.get_logger()


async def send_email(
    to: str,
    subject: str,
    html_body: str,
    text_body: Optional[str] = None,
) -> bool:
    """
    Send an email. Returns True on success, False on failure (never raises).
    In development (no SMTP config), logs the email content.
    """
    s = get_settings()
    if not s.smtp_host:
        log.info("email_dev_mode", to=to, subject=subject)
        log.debug("email_body", html=html_body[:200])
        return True

    if not HAS_SMTP:
        log.error("aiosmtplib_not_installed")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{s.from_name} <{s.from_email}>"
    msg["To"] = to

    if text_body:
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        await aiosmtplib.send(
            msg,
            hostname=s.smtp_host,
            port=s.smtp_port,
            username=s.smtp_user or None,
            password=s.smtp_password or None,
            use_tls=s.smtp_use_tls,
            start_tls=not s.smtp_use_tls,
        )
        log.info("email_sent", to=to, subject=subject)
        return True
    except Exception as e:
        log.error("email_send_failed", to=to, subject=subject, error=str(e))
        return False


async def send_verification_email(to: str, username: str, verify_token: str) -> bool:
    s = get_settings()
    verify_url = f"{s.web_base_url}/verify-email?token={verify_token}"
    subject = "Verify your email address"
    html = f"""
    <html><body style="font-family: Arial, sans-serif; background: #0a0f1e; color: #e2e8f0; padding: 40px;">
      <div style="max-width: 480px; margin: 0 auto; background: #0f172a; border-radius: 12px; padding: 32px;">
        <h2 style="color: #60a5fa;">Welcome, {username}!</h2>
        <p>Please verify your email address to activate your account.</p>
        <a href="{verify_url}" style="display: inline-block; margin: 20px 0; padding: 12px 28px;
           background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: white;
           text-decoration: none; border-radius: 8px; font-weight: bold;">Verify Email</a>
        <p style="color: #64748b; font-size: 12px;">This link expires in {s.email_verify_ttl_hours} hours.<br>
        If you did not create an account, ignore this email.</p>
      </div>
    </body></html>
    """
    return await send_email(to, subject, html)


async def send_password_reset_email(to: str, username: str, reset_token: str) -> bool:
    s = get_settings()
    reset_url = f"{s.web_base_url}/reset-password?token={reset_token}"
    subject = "Reset your password"
    html = f"""
    <html><body style="font-family: Arial, sans-serif; background: #0a0f1e; color: #e2e8f0; padding: 40px;">
      <div style="max-width: 480px; margin: 0 auto; background: #0f172a; border-radius: 12px; padding: 32px;">
        <h2 style="color: #60a5fa;">Password Reset</h2>
        <p>Hi {username}, you requested a password reset.</p>
        <a href="{reset_url}" style="display: inline-block; margin: 20px 0; padding: 12px 28px;
           background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: white;
           text-decoration: none; border-radius: 8px; font-weight: bold;">Reset Password</a>
        <p style="color: #64748b; font-size: 12px;">This link expires in {s.password_reset_ttl_minutes} minutes.<br>
        If you did not request this, ignore this email.</p>
      </div>
    </body></html>
    """
    return await send_email(to, subject, html)
