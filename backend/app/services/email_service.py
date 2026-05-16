"""SMTP email delivery for verification OTPs with branded HTML template.

The template follows the SentinelX brand bible:

  • Brand wordmark — white "SENTINEL" + gold "X" (#F5A623) in the navy header
  • Body palette — light surface for maximum legibility on every email client
  • Code block — large monospace gold OTP on a navy panel
  • Security notice — amber-bordered call-out warning the recipient about
    unsolicited verification requests
  • Plain-text fallback so accessibility tools and minimalist clients
    (e.g. mutt) still render the OTP correctly

`send_otp_email` falls back to logging the code at WARN level when SMTP is
not configured so local-dev / CI runs can still complete a registration
flow without a real mail server.
"""
from __future__ import annotations

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib

from app.core.config import settings

logger = logging.getLogger(__name__)

BRAND_NAVY = "#0F1D3A"
BRAND_NAVY_LIGHT = "#1c3b7a"
BRAND_GOLD = "#F5A623"
BRAND_BG = "#F5F6F8"

OTP_EXPIRY_DISPLAY = "15 minutes"


def _build_otp_html(code: str, username: str) -> str:
    """Build a professional branded HTML email for OTP verification."""
    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="color-scheme" content="light" />
  <meta name="supported-color-schemes" content="light" />
  <title>SentinelX Security Verification Code</title>
  <!--[if mso]>
  <noscript>
    <xml>
      <o:OfficeDocumentSettings>
        <o:PixelsPerInch>96</o:PixelsPerInch>
      </o:OfficeDocumentSettings>
    </xml>
  </noscript>
  <![endif]-->
</head>
<body style="margin:0;padding:0;background-color:{BRAND_BG};font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:{BRAND_BG};padding:40px 0;">
    <tr>
      <td align="center">
        <table role="presentation" width="560" cellspacing="0" cellpadding="0" style="max-width:560px;width:100%;background-color:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(15,29,58,0.08);">
          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,{BRAND_NAVY} 0%,{BRAND_NAVY_LIGHT} 100%);padding:32px 40px;text-align:center;">
              <table role="presentation" cellspacing="0" cellpadding="0" style="margin:0 auto;">
                <tr>
                  <td style="vertical-align:middle;padding-right:12px;">
                    <div style="width:44px;height:44px;border-radius:50%;border:3px solid {BRAND_GOLD};display:inline-block;text-align:center;line-height:38px;position:relative;">
                      <div style="width:30px;height:30px;border-radius:50%;border:2px solid {BRAND_GOLD};opacity:0.7;position:absolute;top:4px;left:4px;"></div>
                      <div style="width:18px;height:18px;border-radius:50%;border:1.5px solid {BRAND_GOLD};opacity:0.5;position:absolute;top:10px;left:10px;"></div>
                      <div style="width:6px;height:6px;border-radius:50%;background-color:{BRAND_GOLD};display:inline-block;margin-top:16px;"></div>
                    </div>
                  </td>
                  <td style="vertical-align:middle;">
                    <div style="font-size:28px;font-weight:900;letter-spacing:-0.5px;line-height:1;">
                      <span style="color:#ffffff;">SENTINEL</span><span style="color:{BRAND_GOLD};">X</span>
                    </div>
                    <div style="font-size:9px;font-weight:700;letter-spacing:3px;color:rgba(255,255,255,0.55);margin-top:4px;text-transform:uppercase;">
                      Detect &middot; Prioritize &middot; Remediate
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:40px;">
              <h1 style="margin:0 0 8px;font-size:22px;font-weight:800;color:{BRAND_NAVY};">
                Security Verification Code
              </h1>
              <div style="width:60px;height:3px;background-color:{BRAND_GOLD};border-radius:2px;margin-bottom:24px;"></div>

              <p style="margin:0 0 20px;font-size:15px;color:#334155;line-height:1.6;">
                Dear <strong>{username}</strong>,
              </p>
              <p style="margin:0 0 24px;font-size:15px;color:#334155;line-height:1.6;">
                Your SentinelX verification code is:
              </p>

              <!-- OTP Code Box -->
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr>
                  <td align="center">
                    <div style="display:inline-block;background:linear-gradient(135deg,{BRAND_NAVY} 0%,{BRAND_NAVY_LIGHT} 100%);border-radius:12px;padding:22px 52px;margin:0 auto;border:2px solid rgba(245,166,35,0.25);">
                      <span style="font-family:'Courier New',monospace;font-size:38px;font-weight:900;letter-spacing:14px;color:{BRAND_GOLD};">
                        {code}
                      </span>
                    </div>
                  </td>
                </tr>
              </table>

              <p style="margin:24px 0 0;font-size:13px;color:#64748b;line-height:1.6;text-align:center;">
                This code will expire in <strong style="color:{BRAND_NAVY};">{OTP_EXPIRY_DISPLAY}</strong>.
              </p>

              <!-- Divider -->
              <hr style="border:none;border-top:1px solid #e2e8f0;margin:28px 0;" />

              <!-- Security Notice -->
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#FEF3C7;border-radius:8px;border:1px solid #FDE68A;">
                <tr>
                  <td style="padding:14px 18px;">
                    <p style="margin:0;font-size:13px;color:#92400E;line-height:1.5;">
                      <strong>Security Notice:</strong> If you did not request this login,
                      please ignore this email or contact our security team immediately.
                      Never share this code with anyone &mdash; SentinelX staff will never
                      ask you for it.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color:{BRAND_BG};padding:24px 40px;border-top:1px solid #e2e8f0;">
              <p style="margin:0;font-size:12px;color:#94a3b8;line-height:1.5;text-align:center;">
                Best Regards,<br />
                <strong style="color:{BRAND_NAVY};">SentinelX Security Team</strong>
              </p>
              <p style="margin:12px 0 0;font-size:11px;color:#cbd5e1;line-height:1.5;text-align:center;">
                This is an automated message from the SentinelX Vulnerability Intelligence Platform.
                <br />Please do not reply to this email.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def _build_otp_text(code: str, username: str) -> str:
    """Plain-text fallback for the OTP email."""
    return (
        f"SentinelX Security Verification Code\n"
        f"{'=' * 40}\n\n"
        f"Dear {username},\n\n"
        f"Your SentinelX verification code is:\n\n"
        f"    {code}\n\n"
        f"This code will expire in {OTP_EXPIRY_DISPLAY}.\n\n"
        f"If you did not request this login, please ignore this email\n"
        f"or contact our security team immediately. SentinelX staff\n"
        f"will never ask you for this code.\n\n"
        f"Best Regards,\n"
        f"SentinelX Security Team\n"
    )


async def send_otp_email(to_email: str, code: str, username: str) -> None:
    """Send a branded OTP email. Falls back to logging if SMTP is not configured."""
    subject = "SentinelX Security Verification Code"

    if not settings.smtp_host or not settings.smtp_host.strip():
        logger.warning(
            "SMTP not configured; OTP for %s (%s) is: %s",
            to_email,
            username,
            code,
        )
        return

    from_addr = (settings.smtp_from or settings.smtp_user or "noreply@sentinelx.local").strip()
    smtp_host = settings.smtp_host.strip()
    smtp_user = (settings.smtp_user or "").strip() or None
    smtp_pass = (settings.smtp_password or "").strip() or None

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_email

    text_part = MIMEText(_build_otp_text(code, username), "plain", "utf-8")
    html_part = MIMEText(_build_otp_html(code, username), "html", "utf-8")
    msg.attach(text_part)
    msg.attach(html_part)

    try:
        await aiosmtplib.send(
            msg,
            hostname=smtp_host,
            port=settings.smtp_port,
            username=smtp_user,
            password=smtp_pass,
            start_tls=bool(settings.smtp_use_tls),
            timeout=30,
        )
        logger.info("Sent verification email to %s from %s via %s", to_email, from_addr, smtp_host)
    except Exception:
        logger.exception("SMTP send failed for %s (host=%s, user=%s)", to_email, smtp_host, smtp_user)
        raise
