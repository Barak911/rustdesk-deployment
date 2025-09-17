#!/usr/bin/env python3
import smtplib
import sys
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
import json
import subprocess

def get_secret_value(secret_name, region):
    try:
        result = subprocess.run([
            'aws', 'secretsmanager', 'get-secret-value',
            '--secret-id', secret_name,
            '--region', region,
            '--query', 'SecretString',
            '--output', 'text'
        ], capture_output=True, text=True, check=True)

        secret_data = json.loads(result.stdout)
        return secret_data.get('password', '')
    except Exception as e:
        print(f'Error retrieving secret: {e}', file=sys.stderr)
        return None

def send_email(smtp_server, smtp_port, username, password, from_addr, to_addr, subject, message):
    try:
        msg = MIMEMultipart()
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Subject'] = subject
        msg['Date'] = formatdate(localtime=True)
        msg.attach(MIMEText(message, 'plain'))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(username, password)
        server.sendmail(from_addr, to_addr, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f'Error sending email: {e}', file=sys.stderr)
        return False

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('Usage: send_email.py <priority> <subject> <message>')
        sys.exit(1)

    priority = sys.argv[1]
    subject = sys.argv[2]
    message = sys.argv[3]

    # Get environment variables
    smtp_server = os.getenv('SMTP_SERVER', 'smtp.office365.com')
    smtp_port = int(os.getenv('SMTP_PORT', '587'))
    username = os.getenv('EMAIL_USER', '')
    to_addr = os.getenv('ALERT_EMAIL', '')
    secret_name = os.getenv('EMAIL_PASSWORD_SECRET_NAME', '')
    aws_region = os.getenv('AWS_REGION', 'il-central-1')

    if not all([username, to_addr, secret_name]):
        print('Missing required environment variables', file=sys.stderr)
        sys.exit(1)

    # Get password from AWS Secrets Manager
    password = get_secret_value(secret_name, aws_region)
    if not password:
        print('Failed to get email password from Secrets Manager', file=sys.stderr)
        sys.exit(1)

    # Format subject with priority
    full_subject = f'[{priority}] RustDesk Server Alert: {subject}'

    # Send email
    success = send_email(smtp_server, smtp_port, username, password, username, to_addr, full_subject, message)
    sys.exit(0 if success else 1)