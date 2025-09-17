#!/bin/bash
set -eo pipefail

# Load environment variables
source /opt/rustdesk/env-loader.sh

# Use environment variables for configuration
BACKUP_DIR="$BACKUP_DIR"
S3_BUCKET="$S3_BUCKET"
AWS_REGION="$AWS_REGION"
FILE="rustdesk_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
cd "$BASE_DIR"

# Create backup status file to signal monitoring system (prevents false alerts)
echo "BACKUP_IN_PROGRESS" > /opt/rustdesk/monitoring/backup_status.txt
echo "$(date): Backup started" >> /opt/rustdesk/logs/backup.log

# Function to send backup notification
send_backup_notification() {
    local status="$1"
    local message="$2"

    # Get email password dynamically
    local email_password=""
    if [ -n "$EMAIL_PASSWORD_SECRET_NAME" ] && [ "$EMAIL_PASSWORD_SECRET_NAME" != "PLACEHOLDER" ]; then
        email_password=$(aws secretsmanager get-secret-value \
            --secret-id "$EMAIL_PASSWORD_SECRET_NAME" \
            --region "$AWS_REGION" \
            --query SecretString --output text 2>/dev/null | jq -r .password 2>/dev/null)
    elif [ -n "$EMAIL_PASSWORD" ]; then
        email_password="$EMAIL_PASSWORD"
    fi

    if [ -n "$email_password" ]; then
        python3 -c "
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    msg = MIMEMultipart()
    msg['From'] = '$EMAIL_USER'
    msg['To'] = '$ALERT_EMAIL'
    msg['Subject'] = 'RustDesk Backup: $status'
    msg.attach(MIMEText('$message', 'plain'))

    server = smtplib.SMTP('$SMTP_SERVER', $SMTP_PORT)
    server.starttls()
    server.login('$EMAIL_USER', '$email_password')

    text = msg.as_string()
    server.sendmail('$EMAIL_USER', '$ALERT_EMAIL', text)
    server.quit()
    print('Backup notification sent successfully')

except Exception as e:
    print(f'Backup notification failed: {e}')
    logger 'RustDesk Backup: $status - $message'
" || {
            logger "RustDesk Backup: $status - $message"
            echo "$(date): $status - $message" >> /opt/rustdesk/logs/backup.log
        }
    fi
}

# Send backup start notification
send_backup_notification "Started" "Daily backup process initiated at $(date)"

# Stop containers gracefully with timeout
echo "Stopping RustDesk containers for backup..."
if timeout 60 docker compose -f $BASE_DIR/compose.yml down; then
    echo "Containers stopped successfully"
else
    echo "Warning: Container stop timed out, forcing stop"
    docker compose -f $BASE_DIR/compose.yml down --timeout 0
fi

# Wait a moment to ensure containers are fully stopped
sleep 5

# Verify containers are stopped
if docker ps --filter name=hbbs --format '{{.Status}}' | grep -q "Up"; then
    echo "Error: HBBS container still running, cannot proceed with backup"
    send_backup_notification "Failed" "Cannot stop containers for backup"
    exit 1
fi

echo "Creating backup archive..."
# Archive volumes and monitoring data
if /bin/tar -czf "$BACKUP_DIR/$FILE" data monitoring web; then
    echo "Backup archive created: $FILE"
    BACKUP_SIZE=$(du -h "$BACKUP_DIR/$FILE" | cut -f1)
    echo "Backup size: $BACKUP_SIZE"
else
    echo "Error: Failed to create backup archive"
    send_backup_notification "Failed" "Backup archive creation failed"
    exit 1
fi

echo "Uploading $FILE to S3..."
if /usr/bin/aws s3 cp "$BACKUP_DIR/$FILE" "s3://$S3_BUCKET/Backups/" --region "$AWS_REGION"; then
    echo "Backup uploaded to S3 successfully"
else
    echo "Error: Failed to upload backup to S3"
    send_backup_notification "Failed" "S3 upload failed for backup $FILE"
    exit 1
fi

# Start containers
echo "Starting RustDesk containers..."
if docker compose -f $BASE_DIR/compose.yml up -d; then
    echo "Containers started successfully"
else
    echo "Error: Failed to start containers"
    send_backup_notification "Failed" "Container restart failed after backup"
    exit 1
fi

# Wait for containers to be healthy
echo "Waiting for containers to be healthy..."
HEALTHY=false
for i in {1..30}; do
    if docker ps --filter name=hbbs --format '{{.Status}}' | grep -q "Up"; then
        if docker ps --filter name=hbbr --format '{{.Status}}' | grep -q "Up"; then
            HEALTHY=true
            break
        fi
    fi
    echo "Waiting for containers... attempt $i/30"
    sleep 2
done

if [ "$HEALTHY" = true ]; then
    echo "All containers are healthy"

    # Verify RustDesk service is responding
    echo "Verifying RustDesk service health..."
    if timeout 10 curl -s "http://localhost:$RUSTDESK_PORT" > /dev/null 2>&1; then
        echo "RustDesk service is responding"
    else
        echo "Warning: RustDesk service not responding on port $RUSTDESK_PORT"
    fi

    # Send successful backup notification
    send_backup_notification "Completed" "Daily backup completed successfully\n- File: $FILE\n- Size: $BACKUP_SIZE\n- S3 Location: s3://$S3_BUCKET/Backups/$FILE\n- Service Status: Healthy"

    # Clean up old backups (keep last 7)
    echo "Cleaning up old backups..."
    cd "$BACKUP_DIR" && ls -t | tail -n +8 | xargs -r rm -f
    echo "Old backups cleaned up"

else
    echo "Error: Containers failed to become healthy after restart"
    send_backup_notification "Failed" "Containers unhealthy after backup restart"
    exit 1
fi

# Remove backup status file
rm -f /opt/rustdesk/monitoring/backup_status.txt

# Log completion
echo "$(date): Backup completed successfully" >> /opt/rustdesk/logs/backup.log

echo "Backup process completed successfully!"