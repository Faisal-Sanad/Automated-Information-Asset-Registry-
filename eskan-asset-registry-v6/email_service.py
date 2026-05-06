"""
email_service.py — Gmail SMTP email service (SSL port 465)
Used for 2FA one-time codes and account notifications.
"""
import smtplib
import ssl
import os
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "465"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
FROM_NAME     = "Eskan Bank — Asset Registry"


def send_email(to_email: str, subject: str, body_html: str) -> bool:
    """Send an email via SSL SMTP. Returns True on success."""
    if not SMTP_USER or not SMTP_PASSWORD:
        print(f"  [EMAIL] SMTP not configured — would send to {to_email}: {subject}")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"{FROM_NAME} <{SMTP_USER}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(body_html, "html"))

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=10) as server:
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to_email, msg.as_string())
        print(f"  [EMAIL] Sent to {to_email}: {subject}")
        return True
    except Exception as e:
        print(f"  [EMAIL ERROR] {e}")
        return False


def generate_otp() -> str:
    """Generate a 6-digit numeric one-time code."""
    return ''.join(random.choices(string.digits, k=6))


def send_2fa_code(to_email: str, code: str, username: str) -> bool:
    subject = "Eskan Bank Asset Registry — Your verification code"
    body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto">
      <h2 style="color:#1F3864">Two-Factor Verification</h2>
      <p>Hello <strong>{username}</strong>,</p>
      <p>Your one-time verification code for the Eskan Bank Information Asset Registry is:</p>
      <div style="font-size:36px;font-weight:bold;letter-spacing:8px;
                  color:#1F3864;background:#f0f4f8;padding:20px;
                  text-align:center;border-radius:8px;margin:20px 0">
        {code}
      </div>
      <p>This code expires in <strong>5 minutes</strong>. Do not share it with anyone.</p>
      <hr style="border:none;border-top:1px solid #e2e8f0">
      <p style="font-size:12px;color:#94a3b8">
        Eskan Bank Information Asset Registry System — CBB OM-5.5 Compliant
      </p>
    </div>
    """
    return send_email(to_email, subject, body)


def send_registration_received(to_email: str, username: str) -> bool:
    """Email to user confirming their registration request was received."""
    subject = "Eskan Bank Asset Registry — Registration Request Received"
    body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto">
      <h2 style="color:#1F3864">Registration Request Received</h2>
      <p>Hello <strong>{username}</strong>,</p>
      <p>Your registration request for the Eskan Bank Information Asset Registry
         has been received successfully.</p>
      <p>An administrator will review your request shortly. You will receive
         another email once a decision has been made.</p>
      <hr style="border:none;border-top:1px solid #e2e8f0">
      <p style="font-size:12px;color:#94a3b8">
        Eskan Bank Information Asset Registry System — CBB OM-5.5 Compliant
      </p>
    </div>
    """
    return send_email(to_email, subject, body)


def send_registration_approval(to_email: str, username: str) -> bool:
    subject = "Eskan Bank Asset Registry — Account Approved"
    body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto">
      <h2 style="color:#1F3864">Account Approved</h2>
      <p>Hello <strong>{username}</strong>,</p>
      <p>Your account registration for the Eskan Bank Information Asset Registry
         has been approved by an administrator.</p>
      <p>You may now log in at <strong>http://localhost:5000</strong></p>
      <hr style="border:none;border-top:1px solid #e2e8f0">
      <p style="font-size:12px;color:#94a3b8">
        Eskan Bank Information Asset Registry System — CBB OM-5.5 Compliant
      </p>
    </div>
    """
    return send_email(to_email, subject, body)


def send_registration_rejection(to_email: str, username: str, reason: str = "") -> bool:
    subject = "Eskan Bank Asset Registry — Registration Update"
    body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto">
      <h2 style="color:#1F3864">Registration Update</h2>
      <p>Hello <strong>{username}</strong>,</p>
      <p>Your account registration request has not been approved at this time.</p>
      {f'<p><strong>Reason:</strong> {reason}</p>' if reason else ''}
      <p>Please contact the Information Security team for further assistance.</p>
      <hr style="border:none;border-top:1px solid #e2e8f0">
      <p style="font-size:12px;color:#94a3b8">
        Eskan Bank Information Asset Registry System — CBB OM-5.5 Compliant
      </p>
    </div>
    """
    return send_email(to_email, subject, body)


def send_admin_registration_notification(admin_email: str, username: str,
                                          full_name: str, email: str) -> bool:
    """Email to admin when a new registration request is submitted."""
    subject = "Eskan Bank Asset Registry — New Registration Request"
    body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto">
      <h2 style="color:#1F3864">New Registration Request</h2>
      <p>A new user has requested access to the Eskan Bank Information Asset Registry.</p>
      <table style="border-collapse:collapse;width:100%;margin:16px 0">
        <tr><td style="padding:8px;background:#f0f4f8;font-weight:bold">Username</td>
            <td style="padding:8px">{username}</td></tr>
        <tr><td style="padding:8px;background:#f0f4f8;font-weight:bold">Full Name</td>
            <td style="padding:8px">{full_name or '—'}</td></tr>
        <tr><td style="padding:8px;background:#f0f4f8;font-weight:bold">Email</td>
            <td style="padding:8px">{email}</td></tr>
      </table>
      <p>Please log in to the system to review and approve or reject this request.</p>
      <hr style="border:none;border-top:1px solid #e2e8f0">
      <p style="font-size:12px;color:#94a3b8">
        Eskan Bank Information Asset Registry System — CBB OM-5.5 Compliant
      </p>
    </div>
    """
    return send_email(admin_email, subject, body)


def send_pending_change_notification(admin_email: str, submitted_by: str,
                                      action: str, asset_id: str) -> bool:
    subject = "Eskan Bank Asset Registry — Pending Change Requires Review"
    body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto">
      <h2 style="color:#1F3864">Pending Change Awaiting Review</h2>
      <p>A change submitted by <strong>{submitted_by}</strong> requires administrator approval.</p>
      <table style="border-collapse:collapse;width:100%;margin:16px 0">
        <tr><td style="padding:8px;background:#f0f4f8;font-weight:bold">Action</td>
            <td style="padding:8px">{action}</td></tr>
        <tr><td style="padding:8px;background:#f0f4f8;font-weight:bold">Asset ID</td>
            <td style="padding:8px">{asset_id}</td></tr>
      </table>
      <p>Please log in to review and approve or reject this change.</p>
      <hr style="border:none;border-top:1px solid #e2e8f0">
      <p style="font-size:12px;color:#94a3b8">
        Eskan Bank Information Asset Registry System — CBB OM-5.5 Compliant
      </p>
    </div>
    """
    return send_email(admin_email, subject, body)


def send_password_reset_code(to_email: str, username: str, code: str) -> bool:
    """Email reset code to user."""
    subject = "Eskan Bank Asset Registry — Password Reset Code"
    body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto">
      <h2 style="color:#1F3864">Password Reset</h2>
      <p>Hello <strong>{username}</strong>,</p>
      <p>A password reset was requested for your account. Your reset code is:</p>
      <div style="font-size:36px;font-weight:bold;letter-spacing:8px;
                  color:#1F3864;background:#f0f4f8;padding:20px;
                  text-align:center;border-radius:8px;margin:20px 0">
        {code}
      </div>
      <p>This code expires in <strong>15 minutes</strong>.</p>
      <p>If you did not request this reset, please contact your administrator immediately.</p>
      <hr style="border:none;border-top:1px solid #e2e8f0">
      <p style="font-size:12px;color:#94a3b8">
        Eskan Bank Information Asset Registry System — CBB OM-5.5 Compliant
      </p>
    </div>
    """
    return send_email(to_email, subject, body)


def send_admin_password_reset_notification(admin_email: str, username: str, email: str) -> bool:
    """Notify admin when a user requests a password reset."""
    subject = "Eskan Bank Asset Registry — Password Reset Requested"
    body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto">
      <h2 style="color:#1F3864">Password Reset Activity</h2>
      <p>A password reset was requested for the following account:</p>
      <table style="border-collapse:collapse;width:100%;margin:16px 0">
        <tr><td style="padding:8px;background:#f0f4f8;font-weight:bold">Username</td>
            <td style="padding:8px">{username}</td></tr>
        <tr><td style="padding:8px;background:#f0f4f8;font-weight:bold">Email</td>
            <td style="padding:8px">{email}</td></tr>
      </table>
      <p>No action is required unless this activity appears suspicious.</p>
      <hr style="border:none;border-top:1px solid #e2e8f0">
      <p style="font-size:12px;color:#94a3b8">
        Eskan Bank Information Asset Registry System — CBB OM-5.5 Compliant
      </p>
    </div>
    """
    return send_email(admin_email, subject, body)


def send_account_deleted_notification(admin_email: str, deleted_username: str, 
                                       deleted_by: str) -> bool:
    """Notify admin when a user account is deleted."""
    subject = "Eskan Bank Asset Registry — User Account Deleted"
    body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto">
      <h2 style="color:#1F3864">Account Deleted</h2>
      <p>The following user account has been permanently deleted from the system:</p>
      <table style="border-collapse:collapse;width:100%;margin:16px 0">
        <tr><td style="padding:8px;background:#f0f4f8;font-weight:bold">Username</td>
            <td style="padding:8px">{deleted_username}</td></tr>
        <tr><td style="padding:8px;background:#f0f4f8;font-weight:bold">Deleted by</td>
            <td style="padding:8px">{deleted_by}</td></tr>
      </table>
      <hr style="border:none;border-top:1px solid #e2e8f0">
      <p style="font-size:12px;color:#94a3b8">
        Eskan Bank Information Asset Registry System — CBB OM-5.5 Compliant
      </p>
    </div>
    """
    return send_email(admin_email, subject, body)