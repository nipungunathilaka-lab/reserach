import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

class EmailService:
    @staticmethod
    def send_otp_email(email: str, otp: str):
        # Fallback to os.getenv in case Settings fails to load the .env
        mail_username = settings.mail_username or os.getenv("MAIL_USERNAME")
        mail_password = settings.mail_password or os.getenv("MAIL_PASSWORD")
        mail_server = settings.mail_server or os.getenv("MAIL_SERVER") or "smtp.gmail.com"
        mail_port = settings.mail_port or int(os.getenv("MAIL_PORT", 587))
        mail_from = settings.mail_from or os.getenv("MAIL_FROM") or mail_username

        if not mail_username or not mail_password:
            logger.warning(f"Email credentials not configured. OTP for {email} is: {otp}")
            return

        html_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #333;">
                <h2 style="color: #06b6d4;">SecureFT Verification</h2>
                <p>Hello,</p>
                <p>Your one-time verification code is:</p>
                <h1 style="letter-spacing: 5px; background: #f8fafc; padding: 15px; border-radius: 8px; display: inline-block;">{otp}</h1>
                <p>This code will expire in 5 minutes.</p>
                <p>If you didn't request this, you can safely ignore this email.</p>
            </body>
        </html>
        """
        
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Your Verification Code"
        msg["From"] = mail_from
        msg["To"] = email

        part1 = MIMEText("Your verification code is: " + otp, "plain")
        part2 = MIMEText(html_content, "html")
        msg.attach(part1)
        msg.attach(part2)
        
        try:
            # Connect to SMTP server
            if mail_port == 465:
                server = smtplib.SMTP_SSL(mail_server, mail_port)
            else:
                server = smtplib.SMTP(mail_server, mail_port)
                server.starttls()
                
            server.login(mail_username, mail_password)
            server.sendmail(mail_from, email, msg.as_string())
            server.quit()
            logger.info(f"OTP email successfully sent to {email} via {mail_server}:{mail_port}")
            print(f"✅ OTP email successfully sent to {email}!")
        except Exception as e:
            logger.error(f"Failed to send email to {email}: {str(e)}")
            print(f"❌ Failed to send OTP email: {str(e)}")
            raise e

