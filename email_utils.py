import random
import smtplib
from email.mime.text import MIMEText

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(receiver_email, otp_code):
    sender_email = "YOUR_EMAIL@gmail.com"
    sender_password = "YOUR_APP_PASSWORD"

    subject = "Your OTP Verification Code"
    body = f"Your verification code is: {otp_code}"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())