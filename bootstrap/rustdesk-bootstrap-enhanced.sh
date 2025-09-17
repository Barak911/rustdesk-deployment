#!/bin/bash
# -----------------------------------------------------------------------------
# Enhanced RustDesk Docker bootstrap with monitoring
#   Installs Docker & Compose, restores (or generates) RustDesk encryption keys,
#   launches HBBS/HBBR containers, sets up monitoring, web UI, and daily backups.
# -----------------------------------------------------------------------------
# This script is intended to be downloaded from S3 and executed as root by
# EC2 UserData, but it can also be run manually on a clean Ubuntu 22.04 host.
# -----------------------------------------------------------------------------
set -eo pipefail

# Set TEST_SERVER to true to skip key‑restore
TEST_SERVER=false


# Check for backup environment files and restore if they exist
echo "Checking for backup environment files..."

# Restore environment file if backup exists
if [ -f "/tmp/rustdesk.env.backup" ]; then
    echo "✓ Found backup environment file, restoring to original location..."
    cp /tmp/rustdesk.env.backup /opt/rustdesk/rustdesk.env
    rm /tmp/rustdesk.env.backup
    echo "✓ Original environment file restored from backup"
else
    echo "ℹ No backup environment file found, will use CloudFormation defaults"
fi

# Restore environment loader if backup exists
if [ -f "/tmp/env-loader.sh.backup" ]; then
    echo "✓ Found backup environment loader, restoring to original location..."
    cp /tmp/env-loader.sh.backup /opt/rustdesk/env-loader.sh
    chmod 500 /opt/rustdesk/env-loader.sh
    rm /tmp/env-loader.sh.backup
    echo "✓ Original environment loader restored from backup"
    
    USING_RESTORED_LOADER=true
else
    echo "ℹ No backup environment loader found, will create new one"
    USING_RESTORED_LOADER=false
fi

# Create environment loader script only if we don't have a restored one
if [ "$USING_RESTORED_LOADER" = "false" ]; then
    echo "Creating new environment loader script..."
    cat > /opt/rustdesk/env-loader.sh << 'ENV_LOADER_EOF'
#!/bin/bash
# ==============================================================================
# RustDesk Environment Loader
# This script provides a standardized way to load environment variables
# for all RustDesk scripts and services
# ==============================================================================

# Function to load environment variables
load_rustdesk_environment() {
    local env_file="/opt/rustdesk/rustdesk.env"
    local script_name="${0##*/}"
    
    echo "[$script_name] Loading RustDesk environment..."
    
    # Check if environment file exists
    if [ ! -f "$env_file" ]; then
        echo "[$script_name] ERROR: Environment file not found at $env_file"
        return 1
    fi
    
    # Load environment variables
    set -a
    source "$env_file"
    set +a
    
    # Dynamically retrieve email password from Secrets Manager
    if [ -n "$EMAIL_PASSWORD_SECRET_NAME" ] && [ "$EMAIL_PASSWORD_SECRET_NAME" != "PLACEHOLDER" ]; then
        echo "[$script_name] Retrieving email password from Secrets Manager..."
        EMAIL_PASSWORD=$(aws secretsmanager get-secret-value \
            --secret-id "$EMAIL_PASSWORD_SECRET_NAME" \
            --region "$AWS_REGION" \
            --query SecretString --output text 2>/dev/null | jq -r .password 2>/dev/null)
        
        if [ $? -eq 0 ] && [ -n "$EMAIL_PASSWORD" ] && [ "$EMAIL_PASSWORD" != "null" ]; then
            export EMAIL_PASSWORD
            echo "[$script_name] ✓ Email password retrieved from Secrets Manager"
        else
            echo "[$script_name] WARNING: Failed to retrieve email password from Secrets Manager"
            echo "[$script_name] WARNING: Email alerts may not work properly"
            EMAIL_PASSWORD=""
        fi
    elif [ -z "$EMAIL_PASSWORD" ]; then
        echo "[$script_name] WARNING: No email password available (neither in env nor Secrets Manager)"
    fi
    
    # Verify critical variables are loaded
    local required_vars=(
        "S3_BUCKET" "RUSTDESK_PORT" "MONITORING_PORT" 
        "EMAIL_USER" "ALERT_EMAIL" "MONITORING_ENABLED"
    )
    
    # Optional SSL variables (don't fail if missing)
    local ssl_vars=("SSL_ENABLED" "SSL_DOMAIN" "SSL_EMAIL")
    for var in "${ssl_vars[@]}"; do
        if [ -n "${!var}" ]; then
            echo "[$script_name] ✓ SSL Config - $var: ${!var}"
        fi
    done
    
    local missing_vars=()
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            missing_vars+=("$var")
        fi
    done
    
    if [ ${#missing_vars[@]} -gt 0 ]; then
        echo "[$script_name] ERROR: Missing environment variables: ${missing_vars[*]}"
        return 1
    fi
    
    echo "[$script_name] ✓ Environment loaded successfully"
    echo "[$script_name] ✓ Monitoring: $MONITORING_ENABLED"
    echo "[$script_name] ✓ RustDesk Port: $RUSTDESK_PORT"
    echo "[$script_name] ✓ Alert Email: $ALERT_EMAIL"
    
    return 0
}

# Auto-load environment if script is sourced
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    load_rustdesk_environment
fi
ENV_LOADER_EOF

    chmod 500 /opt/rustdesk/env-loader.sh
    echo "✓ Environment loader created at /opt/rustdesk/env-loader.sh"
else
    echo "✓ Using restored environment loader"
fi


# 2. Load environment using the loader script
echo "Loading environment using loader script..."
source /opt/rustdesk/env-loader.sh
load_rustdesk_environment

echo "✓ Environment exported: S3_BUCKET=$S3_BUCKET  PORT=$RUSTDESK_PORT"

# Function to log messages with timestamp (after LOG_DIR is set)
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a /opt/rustdesk/logs/rustdesk-bootstrap.log
}

log "Starting RustDesk Enhanced Bootstrap Script"
log "Environment configuration loaded successfully"

# ---------- CONFIG ------------------------------------------------------------
# All configuration is now loaded from S3 environment file via load-env.sh



# Create all directories
mkdir -p "$BACKUP_DIR" "$DATA_DIR" "$MONITORING_DIR" "$WEB_DIR" "$SCRIPTS_DIR" "$LOG_DIR"

# Check all directories exist
if [ ! -d "$BACKUP_DIR" ]; then
    mkdir -p "$BACKUP_DIR"
fi
if [ ! -d "$DATA_DIR" ]; then
    mkdir -p "$DATA_DIR"
fi
if [ ! -d "$MONITORING_DIR" ]; then
    mkdir -p "$MONITORING_DIR"
fi
if [ ! -d "$WEB_DIR" ]; then
    mkdir -p "$WEB_DIR"
fi
if [ ! -d "$SCRIPTS_DIR" ]; then
    mkdir -p "$SCRIPTS_DIR"
fi
if [ ! -d "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR"
fi
log "✓ All directories exist"


# Create dedicated Python SMTP email sender script
log "Creating Python SMTP email sender..."
cat > /opt/rustdesk/scripts/send_email.py << 'PYTHON_EMAIL_EOF'
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
PYTHON_EMAIL_EOF

chmod +x /opt/rustdesk/scripts/send_email.py
log "✓ Python SMTP email sender created"



# ---------- SYSTEM PREP -------------------------------------------------------
log "Updating apt cache & installing prerequisites …"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y || warn "apt-get upgrade returned non-zero; continuing"

# Install additional packages for monitoring
apt-get install -yq curl wget python3 python3-pip jq bc mailutils netcat-openbsd net-tools sysstat

# Install and configure CloudWatch agent for memory monitoring
wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i -E amazon-cloudwatch-agent.deb

# Create CloudWatch agent configuration
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<'CWAGENT'
{
    "agent": {
        "metrics_collection_interval": 60,
        "run_as_user": "root"
    },
    "metrics": {
        "namespace": "RustDesk/System",
        "metrics_collected": {
            "cpu": {
                "measurement": [
                    "cpu_usage_idle",
                    "cpu_usage_iowait",
                    "cpu_usage_user",
                    "cpu_usage_system"
                ],
                "metrics_collection_interval": 60
            },
            "disk": {
                "measurement": [
                    "used_percent"
                ],
                "metrics_collection_interval": 60,
                "resources": [
                    "*"
                ]
            },
            "diskio": {
                "measurement": [
                    "io_time"
                ],
                "metrics_collection_interval": 60,
                "resources": [
                    "*"
                ]
            },
            "mem": {
                "measurement": [
                    "mem_used_percent",
                    "mem_available_percent",
                    "mem_used",
                    "mem_cached",
                    "mem_total"
                ],
                "metrics_collection_interval": 60
            },
            "netstat": {
                "measurement": [
                    "tcp_established",
                    "tcp_time_wait"
                ],
                "metrics_collection_interval": 60
            },
            "processes": {
                "measurement": [
                    "running",
                    "sleeping",
                    "dead"
                ]
            }
        }
    }
}
CWAGENT

# Start CloudWatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

# Check if Docker GPG key exists before adding
if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
  sudo mkdir -p /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
fi

# Set up the Docker repository
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable
EOF

# Update package index
apt-get update -qq

# Install Docker and Docker Compose plugin
apt-get install -yq docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Install sysstat for CPU monitoring
sudo apt -y install sysstat

# Enable and start Docker
systemctl enable --now docker

# ---------- KEY MANAGEMENT ----------------------------------------------------
# Check S3 bucket connectivity
log "Checking connectivity to S3 bucket $S3_BUCKET …"
if ! aws s3 ls "s3://$S3_BUCKET" --region "$AWS_REGION" >/dev/null 2>&1; then
  error "Unable to reach S3 bucket $S3_BUCKET. Exiting."
  exit 1
fi

# Skip key‑restore if TEST_SERVER=true (any case: true / TRUE / True)
if [[ "${TEST_SERVER,,}" != "true" ]] && \
   aws s3 ls "s3://$S3_BUCKET/Keys/id_ed25519" --region "$AWS_REGION" >/dev/null 2>&1; then
  log "Restoring existing keys from S3 bucket $S3_BUCKET/Keys …"
  aws s3 cp "s3://$S3_BUCKET/Keys/id_ed25519"      "$DATA_DIR/id_ed25519"      --region "$AWS_REGION"
  aws s3 cp "s3://$S3_BUCKET/Keys/id_ed25519.pub"  "$DATA_DIR/id_ed25519.pub"  --region "$AWS_REGION"
  chmod 600 "$DATA_DIR/id_ed25519" "$DATA_DIR/id_ed25519.pub"
  RESTORED_KEYS=true
else
  RESTORED_KEYS=false
fi


# List files in S3 and save to output.txt
aws s3 ls "s3://$S3_BUCKET/Backups/" --region "$AWS_REGION" > "$BASE_DIR/output.txt"

# Process the output.txt to check for specific backup
if grep -q 'rustdesk_backup' "$BASE_DIR/output.txt"; then
  log "Backup found in S3."
else
  log "No backup found in S3."
fi

# Restore files from the latest backup if found
if grep -q 'rustdesk_backup' "$BASE_DIR/output.txt"; then
  log "Restoring from the latest backup …"
  LATEST_BACKUP=$(grep 'rustdesk_backup' "$BASE_DIR/output.txt" | sort | tail -n 1 | awk '{print $4}')
  aws s3 cp "s3://$S3_BUCKET/Backups/$LATEST_BACKUP" "$BACKUP_DIR/$LATEST_BACKUP" --region "$AWS_REGION"
  tar -xzf "$BACKUP_DIR/$LATEST_BACKUP" -C "$BASE_DIR"
  log "Data restoration complete."
  
  # Clean up any stale monitoring state files from the restored backup
  log "Cleaning up stale monitoring state files from restored backup..."
  rm -f "$BASE_DIR/monitoring/backup_status.txt"
  rm -f "$BASE_DIR/monitoring/alert_"*.tmp
  log "Stale monitoring state files cleaned up"
fi

# Update sync_keys function to use DATA_DIR only
sync_keys() {
  chmod 600 "$DATA_DIR/id_ed25519"
  chmod 644 "$DATA_DIR/id_ed25519.pub"
}

# Retry function
retry() { # retry <max> <cmd...>
  local -r max=$1; shift
  local attempt=1
  until "$@"; do
    if (( attempt++ >= max )); then return 1; fi
    sleep 2;
  done
}

# ---------- DOCKER-COMPOSE ----------------------------------------------------
log "Downloading and using RustDesk Pro YAML …"
# Download and use the official RustDesk Pro YAML
bash <(wget -qO- https://get.docker.com)
wget rustdesk.com/pro.yml -O "$BASE_DIR/compose.yml"

log "Starting RustDesk containers using Pro YAML …"
retry 3 docker compose -f "$BASE_DIR/compose.yml" up -d

# If keys were not restored, wait for hbbs to auto-generate them then upload.
if [ "$RESTORED_KEYS" = false ]; then
  log "Waiting for hbbs to create key pair in DATA_DIR …"
  for i in {1..30}; do
    if [ -f "$DATA_DIR/id_ed25519" ] && [ -f "$DATA_DIR/id_ed25519.pub" ]; then
      log "Keys detected after $i attempts. Uploading to S3 …"
      aws s3 cp "$DATA_DIR/id_ed25519"     "s3://$S3_BUCKET/Keys/id_ed25519" --region "$AWS_REGION"
      aws s3 cp "$DATA_DIR/id_ed25519.pub" "s3://$S3_BUCKET/Keys/id_ed25519.pub" --region "$AWS_REGION"
      break
    fi
    sleep 2
  done
fi

# ensure data directory copy
sync_keys

# ---------- MONITORING SETUP --------------------------------------------------
if [ "$MONITORING_ENABLED" = "true" ]; then
  log "Setting up monitoring and web UI ..."
  
  # Create enhanced monitoring script with backup awareness
  cat > "/opt/rustdesk/monitoring/monitor.sh" <<'MONITOR'
#!/bin/bash
set -eo pipefail

# Load environment using standardized loader
source /opt/rustdesk/env-loader.sh

# Check if backup is in progress
check_backup_status() {
    local backup_status_file="/opt/rustdesk/monitoring/backup_status.txt"
    if [ -f "$backup_status_file" ]; then
        local backup_status=$(cat "$backup_status_file" 2>/dev/null || echo "")
        if [ "$backup_status" = "BACKUP_IN_PROGRESS" ]; then
            echo "BACKUP_IN_PROGRESS"
            return 0
        fi
    fi
    echo "NO_BACKUP"
    return 0
}

# Get system metrics
get_cpu_usage() {
  # Instantaneous CPU busy % from a 1‑second mpstat sample
  LC_ALL=C mpstat 1 1 | awk 'END { printf("%.1f", 100 - $NF) }'
}

get_cpu_usage_30s() { 
  # 30 second average CPU usage
  LC_ALL=C mpstat 1 30 | awk '/Average:/ {idle=$NF} END {printf("%.1f", 100-idle)}'
}

get_memory_usage() {
  free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}'
}

get_disk_usage() {
  df / | tail -1 | awk '{print $5}' | sed 's/%//'
}

# Network connectivity tests
test_rustdesk_connectivity() {
  local port_tests=0
  local port_total=0
  
  # Test main RustDesk ports
  for port in $RUSTDESK_PORT $RUSTDESK_RELAY_PORT $RUSTDESK_WEB_PORT; do
    port_total=$((port_total + 1))
    if timeout 5 nc -z localhost $port 2>/dev/null; then
      port_tests=$((port_tests + 1))
    fi
  done
  
  # Calculate connectivity score
  if [ $port_total -gt 0 ]; then
    echo "scale=1; $port_tests * 100 / $port_total" | bc
  else
    echo "0"
  fi
}

get_network_metrics() {
  # Active connections
  local active_connections=$(netstat -an | grep ":$RUSTDESK_PORT" | grep ESTABLISHED | wc -l)
  
  # Listening ports check
  local listening_ports=$(netstat -tlnp | grep -E ":($RUSTDESK_PORT|$RUSTDESK_RELAY_PORT|$RUSTDESK_WEB_PORT)" | wc -l)
  
  # Response time test (simplified)
  local response_time=0
  if timeout 3 bash -c "</dev/tcp/localhost/$RUSTDESK_PORT" 2>/dev/null; then
    response_time=1  # Connection successful
  fi
  
  echo "$active_connections,$listening_ports,$response_time"
}

get_rustdesk_status() {
  # Check if backup is in progress first
  local backup_status=$(check_backup_status)
  if [ "$backup_status" = "BACKUP_IN_PROGRESS" ]; then
    echo "BACKUP_IN_PROGRESS"
    return 0
  fi
  
  # Check if containers are running
  local hbbs_status=$(docker ps --filter name=hbbs --format '{{.Status}}' 2>/dev/null | grep -c "Up" || echo "0")
  local hbbr_status=$(docker ps --filter name=hbbr --format '{{.Status}}' 2>/dev/null | grep -c "Up" || echo "0")
  
  if [ "$hbbs_status" -eq 1 ] && [ "$hbbr_status" -eq 1 ]; then
    # Enhanced health check - verify containers are actually healthy
# Note: We don't test HTTP connectivity on RustDesk ports as they use custom protocols, not HTTP
    local hbbs_healthy=$(docker ps --filter name=hbbs --format '{{.Status}}' 2>/dev/null | grep -c "Up" || echo "0")
    local hbbr_healthy=$(docker ps --filter name=hbbr --format '{{.Status}}' 2>/dev/null | grep -c "Up" || echo "0")
    

    
    if [ "$hbbs_healthy" -eq 1 ] && [ "$hbbr_healthy" -eq 1 ]; then
      echo "OK"
    else
      # Check if RustDesk service is actually working by checking logs
      local recent_activity=$(docker logs hbbs --tail 20 2>/dev/null | grep -E "(License OK|listening on|api listening)" | wc -l)
      if [ "$recent_activity" -gt 0 ]; then
        echo "OK"
      else
        echo "WARNING"  # Service not responding
      fi
    fi
  elif [ "$hbbs_status" -eq 0 ] && [ "$hbbr_status" -eq 0 ]; then
    echo "CRITICAL"
  else
    echo "WARNING"  # Only one container running
  fi
}

# Enhanced service health check with license detection
get_service_health() {
  local backup_status=$(check_backup_status)
  if [ "$backup_status" = "BACKUP_IN_PROGRESS" ]; then
    echo "BACKUP_IN_PROGRESS"
    return 0
  fi
  
  # Check Docker service
  if ! systemctl is-active --quiet docker; then
    echo "DOCKER_DOWN"
    return 0
  fi
  
  # Check for license issues in RustDesk logs
  local license_issue=$(docker logs hbbs --tail 50 2>/dev/null | grep -c "License already in use by another machine" || echo "0")
  if [ "$license_issue" -gt 0 ]; then
    echo "LICENSE_CONFLICT"
    return 0
  fi
  
  # Check RustDesk containers
  local rustdesk_status=$(get_rustdesk_status)
  if [ "$rustdesk_status" = "CRITICAL" ]; then
    echo "RUSTDESK_CRITICAL"
  elif [ "$rustdesk_status" = "WARNING" ]; then
    echo "RUSTDESK_WARNING"
  elif [ "$rustdesk_status" = "OK" ]; then
    echo "RUSTDESK_OK"
  else
    echo "RUSTDESK_UNKNOWN"
  fi
}

# Enhanced alert escalation system
send_alert_with_severity() {
  local severity="$1"
  local subject="$2"
  local message="$3"
  local alert_type="${4:-general}"
  
  # Don't send alerts during backup unless it's a backup-related issue
  local backup_status=$(check_backup_status)
  if [ "$backup_status" = "BACKUP_IN_PROGRESS" ] && [[ "$subject" != *"Backup"* ]]; then
    echo "Skipping alert during backup: $subject"
    return 0
  fi
  
  # Severity-based cooldown periods (in minutes)
  local cooldown_minutes
  case $severity in
    "CRITICAL") cooldown_minutes=5 ;;    # Critical: 5 min cooldown
    "WARNING")  cooldown_minutes=15 ;;   # Warning: 15 min cooldown  
    "INFO")     cooldown_minutes=60 ;;   # Info: 1 hour cooldown
    *) cooldown_minutes=$ALERT_COOLDOWN_MINUTES ;;
  esac
  
  # Check cooldown with severity-specific timing
  if ! should_send_alert_with_cooldown "$alert_type" "$cooldown_minutes"; then
    echo "[$severity] Alert suppressed due to cooldown: $subject"
    return 0
  fi
  
  # Enhanced subject without duplication
  local enhanced_subject="$subject"
  
  # Enhanced message with context
  local enhanced_message="$message

Severity: $severity
Timestamp: $(date)
Server: $(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo 'unknown')
Instance ID: $(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'unknown')
Alert Type: $alert_type

Dashboard: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo 'unknown'):$MONITORING_PORT
"

  # Log structured alert
  log_structured_alert "$severity" "$alert_type" "$subject" "$message"
  
  if [ -n "$EMAIL_PASSWORD" ]; then
    # Use dedicated Python SMTP sender for reliable email delivery
    if /opt/rustdesk/scripts/send_email.py "$severity" "$enhanced_subject" "$enhanced_message"; then
      echo "[ALERT SENT] $enhanced_subject"
    else
      # Fallback to system logger if email fails
      logger "RustDesk Alert: $enhanced_subject - $enhanced_message"
      echo "$(date): $enhanced_subject - $enhanced_message" >> /opt/rustdesk/logs/alerts.log
      echo "[ALERT FAILED] Email failed, logged to system"
    fi
  fi
}

# Enhanced cooldown function with configurable timing
should_send_alert_with_cooldown() {
  local alert_type="$1"
  local cooldown_minutes="$2"
  local cooldown_file="/tmp/alert_cooldown_${alert_type}"
  
  if [ -f "$cooldown_file" ]; then
    local last_alert=$(cat "$cooldown_file")
    local current_time=$(date +%s)
    local cooldown_seconds=$((cooldown_minutes * 60))
    
    if [ $((current_time - last_alert)) -lt $cooldown_seconds ]; then
      return 1
    fi
  fi
  
  echo "$(date +%s)" > "$cooldown_file"
  return 0
}

# Legacy function for backward compatibility
should_send_alert() {
  should_send_alert_with_cooldown "$1" "$ALERT_COOLDOWN_MINUTES"
}

# Structured logging function
log_structured_alert() {
  local severity="$1"
  local alert_type="$2"
  local subject="$3"
  local message="$4"
  local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  
  # Create structured log entry
  local log_entry="{
    \"timestamp\": \"$timestamp\",
    \"level\": \"$severity\",
    \"component\": \"rustdesk-monitor\",
    \"alert_type\": \"$alert_type\",
    \"subject\": \"$subject\",
    \"message\": \"$message\",
    \"instance_id\": \"$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'unknown')\",
    \"public_ip\": \"$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo 'unknown')\"
  }"
  
  # Write to structured log file
  echo "$log_entry" >> /opt/rustdesk/logs/alerts-structured.log
  
  # Also log to syslog
  logger -t rustdesk-monitor "[$severity] [$alert_type] $subject"
}

# Enhanced performance metrics collection
collect_performance_metrics() {
  local metrics_file="/opt/rustdesk/logs/metrics-$(date +%Y%m%d).csv"
  local timestamp=$(date +%s)
  
  # System metrics
  local cpu_usage=$(get_cpu_usage)
  local memory_usage=$(get_memory_usage)
  local disk_usage=$(get_disk_usage)
  
  # Network metrics
  local network_metrics=$(get_network_metrics)
  local active_connections=$(echo $network_metrics | cut -d',' -f1)
  local listening_ports=$(echo $network_metrics | cut -d',' -f2)
  local connectivity_score=$(test_rustdesk_connectivity)
  
  # Docker metrics
  local container_count=$(docker ps --filter name=hbb --format '{{.Names}}' | wc -l)
  local container_memory=$(docker stats --no-stream --format "table {{.MemUsage}}" | tail -n +2 | head -1 | awk '{print $1}' | sed 's/[^0-9.]//g' || echo "0")
  
  # RustDesk specific metrics
  # Get error count, ensuring we get a clean number
  local error_count=$(docker logs hbbs --since=5m 2>/dev/null | grep -i error | wc -l 2>/dev/null | xargs)
  # If error_count is empty or not a number, set to 0
  if [[ -z "$error_count" ]] || ! [[ "$error_count" =~ ^[0-9]+$ ]]; then
    error_count="0"
  fi
  local license_status="OK"
  if docker logs hbbs --tail 50 2>/dev/null | grep -q "License already in use"; then
    license_status="CONFLICT"
  fi
  
  # Write header if file doesn't exist
  if [ ! -f "$metrics_file" ]; then
    echo "timestamp,cpu_usage,memory_usage,disk_usage,active_connections,listening_ports,connectivity_score,container_count,container_memory,error_count,license_status" > "$metrics_file"
  fi
  
  # Append metrics
  echo "$timestamp,$cpu_usage,$memory_usage,$disk_usage,$active_connections,$listening_ports,$connectivity_score,$container_count,$container_memory,$error_count,$license_status" >> "$metrics_file"
  
  # Cleanup old metrics files (keep 7 days)
  find /opt/rustdesk/logs -name "metrics-*.csv" -mtime +7 -delete 2>/dev/null || true
  
  echo "$cpu_usage,$memory_usage,$disk_usage,$active_connections,$connectivity_score,$error_count"
}

# Trend analysis function
analyze_trends() {
  local metrics_file="/opt/rustdesk/logs/metrics-$(date +%Y%m%d).csv"
  
  if [ ! -f "$metrics_file" ] || [ $(wc -l < "$metrics_file") -lt 4 ]; then
    echo "INSUFFICIENT_DATA"
    return
  fi
  
  # Get last 3 readings for trend analysis
  local last_three=$(tail -n 3 "$metrics_file" | cut -d',' -f2 | tr '\n' ' ')
  local values=($last_three)
  
  if [ ${#values[@]} -lt 3 ]; then
    echo "INSUFFICIENT_DATA"
    return
  fi
  
  # Simple trend detection: 3 consecutive increases = upward trend
  if (( $(echo "${values[2]} > ${values[1]} && ${values[1]} > ${values[0]}" | bc -l) )); then
    echo "UPWARD"
  elif (( $(echo "${values[2]} < ${values[1]} && ${values[1]} < ${values[0]}" | bc -l) )); then
    echo "DOWNWARD"  
  else
    echo "STABLE"
  fi
}

# Data integrity checks
check_data_integrity() {
  local integrity_issues=0
  
  # Check key files exist and have correct permissions
  if [ ! -r "$DATA_DIR/id_ed25519" ]; then
    echo "CRITICAL: Private key file missing or unreadable"
    integrity_issues=$((integrity_issues + 1))
  elif [ ! -s "$DATA_DIR/id_ed25519" ]; then
    echo "CRITICAL: Private key file is empty"
    integrity_issues=$((integrity_issues + 1))
  elif [ "$(stat -c %a "$DATA_DIR/id_ed25519")" != "600" ]; then
    echo "WARNING: Private key has incorrect permissions"
    integrity_issues=$((integrity_issues + 1))
  fi
  
  if [ ! -r "$DATA_DIR/id_ed25519.pub" ]; then
    echo "CRITICAL: Public key file missing or unreadable"
    integrity_issues=$((integrity_issues + 1))
  fi
  
  # Check disk space for critical directories
  local data_disk_usage=$(df "$DATA_DIR" | tail -1 | awk '{print $5}' | sed 's/%//')
  if [ "$data_disk_usage" -gt 95 ]; then
    echo "CRITICAL: Data directory disk usage: ${data_disk_usage}%"
    integrity_issues=$((integrity_issues + 1))
  fi
  
  return $integrity_issues
}

# Send custom metrics to CloudWatch
send_cloudwatch_metrics() {
  local cpu_usage="$1"
  local memory_usage="$2" 
  local disk_usage="$3"
  local active_connections="$4"
  local connectivity_score="$5"
  local error_count="$6"
  local instance_id=$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "unknown")
  
  # Create metrics batch
  local metrics_data=""
  
  # RustDesk Application Metrics
  metrics_data+="MetricName=ActiveConnections,Value=${active_connections},Unit=Count,Dimensions=InstanceId=${instance_id} "
  metrics_data+="MetricName=ConnectivityScore,Value=${connectivity_score},Unit=Percent,Dimensions=InstanceId=${instance_id} "
  metrics_data+="MetricName=ErrorCount,Value=${error_count},Unit=Count,Dimensions=InstanceId=${instance_id} "
  
  # Enhanced System Metrics
  metrics_data+="MetricName=CustomCPUUtilization,Value=${cpu_usage},Unit=Percent,Dimensions=InstanceId=${instance_id} "
  metrics_data+="MetricName=CustomMemoryUtilization,Value=${memory_usage},Unit=Percent,Dimensions=InstanceId=${instance_id} "
  metrics_data+="MetricName=CustomDiskUtilization,Value=${disk_usage},Unit=Percent,Dimensions=InstanceId=${instance_id} "
  
  # Container Health Metrics
  local container_status=0
  if [ "$rustdesk_status" = "OK" ]; then
    container_status=1
  fi
  metrics_data+="MetricName=ServiceHealth,Value=${container_status},Unit=Count,Dimensions=InstanceId=${instance_id} "
  
  # License Status Metrics
  local license_status=1
  if [ "$service_health" = "LICENSE_CONFLICT" ]; then
    license_status=0
  fi
  metrics_data+="MetricName=LicenseStatus,Value=${license_status},Unit=Count,Dimensions=InstanceId=${instance_id} "
  
  # Send metrics to CloudWatch in batches (max 20 per call)
  aws cloudwatch put-metric-data \
    --namespace "RustDesk/Application" \
    --metric-data $metrics_data \
    --region "$AWS_REGION" 2>/dev/null || echo "Failed to send CloudWatch metrics"
  
  echo "Custom metrics sent to CloudWatch"
}

# Automated Remediation Engine
perform_auto_remediation() {
  local issue_type="$1"
  local severity="$2"
  local context="$3"
  
  echo "[AUTO-REMEDIATION] Attempting to resolve: $issue_type (severity: $severity)"
  
  case $issue_type in
    "docker")
      if [ "$severity" = "CRITICAL" ]; then
        echo "[AUTO-REMEDIATION] Docker service is down - attempting restart..."
        if systemctl restart docker; then
          sleep 10
          # Wait for Docker to fully start
          for i in {1..30}; do
            if systemctl is-active --quiet docker; then
              echo "[AUTO-REMEDIATION] ✅ Docker service restarted successfully"
              
              # Restart RustDesk containers
              cd $BASE_DIR
              if docker compose -f compose.yml up -d; then
                echo "[AUTO-REMEDIATION] ✅ RustDesk containers restarted"
                return 0
              fi
              break
            fi
            sleep 2
          done
        fi
        echo "[AUTO-REMEDIATION] ❌ Failed to restart Docker service"
        return 1
      fi
      ;;
      
    "service")
      if [ "$severity" = "CRITICAL" ] || [ "$severity" = "WARNING" ]; then
        echo "[AUTO-REMEDIATION] RustDesk service issues - attempting container restart..."
        cd $BASE_DIR
        
        # Graceful restart
        if docker compose -f compose.yml restart; then
          sleep 15
          
          # Verify containers are running
          local hbbs_running=$(docker ps --filter name=hbbs --filter status=running -q | wc -l)
          local hbbr_running=$(docker ps --filter name=hbbr --filter status=running -q | wc -l)
          
          if [ "$hbbs_running" -eq 1 ] && [ "$hbbr_running" -eq 1 ]; then
            echo "[AUTO-REMEDIATION] ✅ RustDesk containers restarted successfully"
            return 0
          else
            echo "[AUTO-REMEDIATION] ⚠️ Container restart completed but health check failed"
            # Try full recreation
            docker compose -f compose.yml down
            sleep 5
            docker compose -f compose.yml up -d
            echo "[AUTO-REMEDIATION] ✅ RustDesk containers recreated"
            return 0
          fi
        fi
        echo "[AUTO-REMEDIATION] ❌ Failed to restart RustDesk containers"
        return 1
      fi
      ;;
      
    "disk")
      if [ "$severity" = "CRITICAL" ] || [ "$severity" = "WARNING" ]; then
        echo "[AUTO-REMEDIATION] High disk usage - attempting cleanup..."
        local freed_space=0
        
        # Clean Docker system
        echo "[AUTO-REMEDIATION] Cleaning Docker system..."
        docker system prune -f >/dev/null 2>&1 && freed_space=$((freed_space + 1))
        
        # Clean old log files
        echo "[AUTO-REMEDIATION] Cleaning old logs..."
        find /opt/rustdesk/logs -name "*.log" -mtime +7 -delete 2>/dev/null && freed_space=$((freed_space + 1))
        find /opt/rustdesk/logs -name "metrics-*.csv" -mtime +7 -delete 2>/dev/null && freed_space=$((freed_space + 1))
        
        # Clean system logs if very critical
        if [ "$severity" = "CRITICAL" ]; then
          echo "[AUTO-REMEDIATION] Critical disk space - cleaning system logs..."
          journalctl --vacuum-time=7d >/dev/null 2>&1 && freed_space=$((freed_space + 1))
          
          # Clean apt cache
          apt-get clean >/dev/null 2>&1 && freed_space=$((freed_space + 1))
        fi
        
        # Clean old Docker images
        docker image prune -f >/dev/null 2>&1 && freed_space=$((freed_space + 1))
        
        if [ $freed_space -gt 0 ]; then
          new_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
          echo "[AUTO-REMEDIATION] ✅ Disk cleanup completed. New usage: ${new_usage}%"
          return 0
        else
          echo "[AUTO-REMEDIATION] ⚠️ Disk cleanup attempted but minimal space freed"
          return 1
        fi
      fi
      ;;
      
    "memory")
      if [ "$severity" = "CRITICAL" ] || [ "$severity" = "WARNING" ]; then
        echo "[AUTO-REMEDIATION] High memory usage - attempting memory cleanup..."
        
        # Send notification that remediation is starting
        local initial_memory=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
        send_alert_with_severity "INFO" "Memory Remediation Started" \
          "Auto-remediation initiated due to high memory usage
Current usage: ${initial_memory}%
Threshold: ${MEMORY_THRESHOLD}%
Severity: ${severity}
Action: Restarting containers to free memory" "memory"
        
        # Clear system caches
        sync
        echo 1 > /proc/sys/vm/drop_caches
        echo 2 > /proc/sys/vm/drop_caches  
        echo 3 > /proc/sys/vm/drop_caches
        
        # Restart containers to free memory leaks
        echo "[AUTO-REMEDIATION] Restarting containers to free memory..."
        cd $BASE_DIR
        if docker compose -f compose.yml restart; then
          sleep 10
          new_memory=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
          echo "[AUTO-REMEDIATION] ✅ Memory cleanup completed. New usage: ${new_memory}%"
          
          # Send success notification
          send_alert_with_severity "INFO" "Memory Remediation Successful" \
            "Auto-remediation completed successfully
Initial usage: ${initial_memory}%
New usage: ${new_memory}%
Threshold: ${MEMORY_THRESHOLD}%
Memory freed: $(echo "$initial_memory - $new_memory" | bc)%" "memory"
          
          return 0
        fi
        echo "[AUTO-REMEDIATION] ❌ Failed to restart containers for memory cleanup"
        
        # Send failure notification
        send_alert_with_severity "WARNING" "Memory Remediation Failed" \
          "Auto-remediation failed to restart containers
Current usage: ${initial_memory}%
Threshold: ${MEMORY_THRESHOLD}%
Manual intervention may be required" "memory"
        
        return 1
      fi
      ;;
      
    "connectivity")
      if [ "$severity" = "CRITICAL" ] || [ "$severity" = "WARNING" ]; then
        echo "[AUTO-REMEDIATION] Network connectivity issues - attempting fixes..."
        
        # Restart containers (most common fix for port issues)
        cd $BASE_DIR
        if docker compose -f compose.yml restart; then
          sleep 15
          
          # Test connectivity after restart
          new_score=$(test_rustdesk_connectivity)
          echo "[AUTO-REMEDIATION] Network connectivity after restart: ${new_score}%"
          
          if (( $(echo "$new_score >= 67" | bc -l) )); then
            echo "[AUTO-REMEDIATION] ✅ Connectivity restored"
            return 0
          fi
        fi
        
        # If still having issues, try restarting Docker networking
        echo "[AUTO-REMEDIATION] Restarting Docker networking..."
        systemctl restart docker
        sleep 10
        cd $BASE_DIR
        docker compose -f compose.yml up -d
        
        echo "[AUTO-REMEDIATION] ✅ Docker networking restarted"
        return 0
      fi
      ;;
      
    "errors")
      if [ "$severity" = "WARNING" ] || [ "$severity" = "CRITICAL" ]; then
        echo "[AUTO-REMEDIATION] High error rate detected - attempting restart..."
        cd $BASE_DIR
        
        # Restart containers to clear error conditions
        if docker compose -f compose.yml restart; then
          sleep 15
          echo "[AUTO-REMEDIATION] ✅ Containers restarted to clear errors"
          return 0
        fi
        echo "[AUTO-REMEDIATION] ❌ Failed to restart containers"
        return 1
      fi
      ;;
      
    *)
      echo "[AUTO-REMEDIATION] No automated remediation available for: $issue_type"
      return 1
      ;;
  esac
  
  return 1
}

# Log remediation attempts
log_remediation_attempt() {
  local issue_type="$1"
  local severity="$2"
  local success="$3"
  local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  
  local log_entry="{
    \"timestamp\": \"$timestamp\",
    \"level\": \"REMEDIATION\",
    \"component\": \"auto-remediation\",
    \"issue_type\": \"$issue_type\",
    \"severity\": \"$severity\",
    \"success\": $success,
    \"instance_id\": \"$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'unknown')\"
  }"
  
  # Write to remediation log
  echo "$log_entry" >> /opt/rustdesk/logs/remediation.log
  
  # Also log to structured alerts
  if [ "$success" = "true" ]; then
    log_structured_alert "INFO" "$issue_type" "Auto-Remediation Successful" "Automatically resolved $issue_type issue"
  else
    log_structured_alert "WARNING" "$issue_type" "Auto-Remediation Failed" "Failed to automatically resolve $issue_type issue"
  fi
}

# Main monitoring logic
echo "=== RustDesk Enhanced Monitoring ==="
echo "Timestamp: $(date)"

# Collect performance metrics
echo "Collecting performance metrics..."
performance_data=$(collect_performance_metrics)
cpu_usage=$(echo $performance_data | cut -d',' -f1)
memory_usage=$(echo $performance_data | cut -d',' -f2)
disk_usage=$(echo $performance_data | cut -d',' -f3)
active_connections=$(echo $performance_data | cut -d',' -f4)
connectivity_score=$(echo $performance_data | cut -d',' -f5)
error_count=$(echo $performance_data | cut -d',' -f6)

# Analyze trends
cpu_trend=$(analyze_trends)
echo "CPU Trend: $cpu_trend"

# Check data integrity
echo "Checking data integrity..."
if ! check_data_integrity; then
  echo "Data integrity issues detected"
fi

# Check backup status first
backup_status=$(check_backup_status)
if [ "$backup_status" = "BACKUP_IN_PROGRESS" ]; then
  echo "Backup in progress - monitoring in backup mode"
  # During backup, only check basic system health, not service status
  cpu_usage=$(get_cpu_usage)
  memory_usage=$(get_memory_usage)
  disk_usage=$(get_disk_usage)
  
  # Output JSON for web UI with backup status
  cat > /opt/rustdesk/web/status.json <<JSONEOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "cpu_usage": ${cpu_usage:-0},
  "memory_usage": ${memory_usage:-0},
  "disk_usage": ${disk_usage:-0},
  "rustdesk_status": "BACKUP_IN_PROGRESS",
  "cpu_threshold": ${CPU_THRESHOLD:-80},
  "memory_threshold": ${MEMORY_THRESHOLD:-85},
  "disk_threshold": ${DISK_THRESHOLD:-90},
  "overall_status": "BACKUP_IN_PROGRESS",
  "backup_status": "IN_PROGRESS"
}
JSONEOF
  
  echo "Monitoring completed in backup mode"
  exit 0
fi

# Normal monitoring mode
cpu_usage=$(get_cpu_usage)
memory_usage=$(get_memory_usage)
disk_usage=$(get_disk_usage)
rustdesk_status=$(get_rustdesk_status)
service_health=$(get_service_health)

echo "System Metrics:"
echo "  CPU Usage: ${cpu_usage}%"
echo "  Memory Usage: ${memory_usage}%"
echo "  Disk Usage: ${disk_usage}%"
echo "  RustDesk Status: ${rustdesk_status}"
echo "  Service Health: ${service_health}"

# Enhanced alerting with automated remediation

# Check CPU with trend analysis
if (( $(echo "$cpu_usage > $CPU_THRESHOLD" | bc -l) )); then
  cpu_30s=$(get_cpu_usage_30s)
  if (( $(echo "$cpu_30s > $CPU_THRESHOLD" | bc -l) )); then
    severity="WARNING"
    if (( $(echo "$cpu_30s > $(echo "$CPU_THRESHOLD * 1.2" | bc)" | bc -l) )) || [ "$cpu_trend" = "UPWARD" ]; then
      severity="CRITICAL"
    fi
    
    # Note: CPU issues usually indicate load problems, not remediation targets
    send_alert_with_severity "$severity" "High CPU Usage" \
      "CPU usage: ${cpu_usage}% (30s avg: ${cpu_30s}%)
Threshold: ${CPU_THRESHOLD}%
Trend: $cpu_trend
Active connections: $active_connections
Recent errors: $error_count" "cpu"
  fi
fi

# Check Memory with auto-remediation
if (( $(echo "$memory_usage > $MEMORY_THRESHOLD" | bc -l) )); then
  local severity="WARNING"
  if (( $(echo "$memory_usage > $(echo "$MEMORY_THRESHOLD * 1.2" | bc)" | bc -l) )); then
    severity="CRITICAL"
  fi
  
  # Attempt auto-remediation for high memory issues
  remediation_attempted=false
  if [ "$severity" = "CRITICAL" ] || [ "$severity" = "WARNING" ]; then
    echo "Attempting auto-remediation for high memory usage (${severity})..."
    if perform_auto_remediation "memory" "$severity" "Memory usage: ${memory_usage}%"; then
      log_remediation_attempt "memory" "$severity" "true"
      # Re-check memory after remediation
      sleep 5
      new_memory_usage=$(get_memory_usage)
      if (( $(echo "$new_memory_usage <= $MEMORY_THRESHOLD" | bc -l) )); then
        send_alert_with_severity "INFO" "Memory Issue Resolved" \
          "Auto-remediation successful
Original usage: ${memory_usage}%
New usage: ${new_memory_usage}%
Threshold: ${MEMORY_THRESHOLD}%" "memory"
        remediation_attempted=true
      fi
    else
      log_remediation_attempt "memory" "$severity" "false"
    fi
  fi
  
  # Send alert if remediation wasn't attempted or failed
  if [ "$remediation_attempted" = "false" ]; then
    send_alert_with_severity "$severity" "High Memory Usage" \
      "Memory usage: ${memory_usage}%
Threshold: ${MEMORY_THRESHOLD}%
Container memory: ${container_memory}MB" "memory"
  fi
fi

# Check Disk with auto-remediation
if [ "$disk_usage" -gt "$DISK_THRESHOLD" ]; then
  local severity="WARNING"
  if [ "$disk_usage" -gt 95 ]; then
    severity="CRITICAL"
  fi
  
  # Attempt auto-remediation for disk issues
  remediation_attempted=false
  echo "Attempting auto-remediation for high disk usage..."
  if perform_auto_remediation "disk" "$severity" "Disk usage: ${disk_usage}%"; then
    log_remediation_attempt "disk" "$severity" "true"
    # Re-check disk after remediation
    sleep 5
    new_disk_usage=$(get_disk_usage)
    if [ "$new_disk_usage" -le "$DISK_THRESHOLD" ]; then
      send_alert_with_severity "INFO" "Disk Issue Resolved" \
        "Auto-remediation successful
Original usage: ${disk_usage}%
New usage: ${new_disk_usage}%
Threshold: ${DISK_THRESHOLD}%" "disk"
      remediation_attempted=true
    fi
  else
    log_remediation_attempt "disk" "$severity" "false"
  fi
  
  # Send alert if remediation failed or didn't resolve the issue completely
  if [ "$remediation_attempted" = "false" ]; then
    send_alert_with_severity "$severity" "High Disk Usage" \
      "Disk usage: ${disk_usage}%
Threshold: ${DISK_THRESHOLD}%
Data directory: $(df "$DATA_DIR" | tail -1 | awk '{print $5}')
Auto-cleanup attempted but space still high" "disk"
  fi
fi

# Check connectivity with auto-remediation
if (( $(echo "$connectivity_score < 100" | bc -l) )); then
  local severity="WARNING"
  if (( $(echo "$connectivity_score < 67" | bc -l) )); then
    severity="CRITICAL"
  fi
  
  # Attempt auto-remediation for connectivity issues
  remediation_attempted=false
  if [ "$severity" = "CRITICAL" ] || [ "$severity" = "WARNING" ]; then
    echo "Attempting auto-remediation for connectivity issues..."
    if perform_auto_remediation "connectivity" "$severity" "Connectivity: ${connectivity_score}%"; then
      log_remediation_attempt "connectivity" "$severity" "true"
      # Re-check connectivity after remediation
      sleep 10
      new_connectivity_score=$(test_rustdesk_connectivity)
      if (( $(echo "$new_connectivity_score >= 100" | bc -l) )); then
        send_alert_with_severity "INFO" "Connectivity Restored" \
          "Auto-remediation successful
Original connectivity: ${connectivity_score}%
New connectivity: ${new_connectivity_score}%" "connectivity"
        remediation_attempted=true
      fi
    else
      log_remediation_attempt "connectivity" "$severity" "false"
    fi
  fi
  
  # Send alert if remediation wasn't attempted or failed to fully resolve
  if [ "$remediation_attempted" = "false" ]; then
    send_alert_with_severity "$severity" "Network Connectivity Issues" \
      "Port connectivity: ${connectivity_score}%
Active connections: $active_connections
Listening ports: $(echo $network_metrics | cut -d',' -f2)/3
Auto-remediation attempted" "connectivity"
  fi
fi

# Check error rate
if [ "$error_count" -gt 0 ]; then
  severity="INFO"
  if [ "$error_count" -gt 5 ]; then
    severity="WARNING"
  fi
  if [ "$error_count" -gt 20 ]; then
    severity="CRITICAL"
  fi
  send_alert_with_severity "$severity" "Application Errors Detected" \
    "Error count (last 5 minutes): $error_count
Check logs: docker logs hbbs" "errors"
fi

# Check RustDesk status with auto-remediation
if [ "$rustdesk_status" = "CRITICAL" ]; then
  remediation_attempted=false
  echo "Attempting auto-remediation for critical service status..."
  if perform_auto_remediation "service" "CRITICAL" "RustDesk service down"; then
    log_remediation_attempt "service" "CRITICAL" "true"
    # Re-check service after remediation
    sleep 15
    new_rustdesk_status=$(get_rustdesk_status)
    if [ "$new_rustdesk_status" = "OK" ]; then
      send_alert_with_severity "INFO" "Service Recovered" \
        "Auto-remediation successful - RustDesk service restored
Previous status: $rustdesk_status
New status: $new_rustdesk_status" "service"
      remediation_attempted=true
    fi
  else
    log_remediation_attempt "service" "CRITICAL" "false"
  fi
  
  if [ "$remediation_attempted" = "false" ]; then
    send_alert_with_severity "CRITICAL" "Service Down" \
      "RustDesk service is not running properly
Status: $rustdesk_status
Connectivity: ${connectivity_score}%
Container count: $(docker ps --filter name=hbb | wc -l)
Auto-remediation attempted but failed" "service"
  fi
elif [ "$rustdesk_status" = "WARNING" ]; then
  remediation_attempted=false
  echo "Attempting auto-remediation for service warnings..."
  if perform_auto_remediation "service" "WARNING" "RustDesk service degraded"; then
    log_remediation_attempt "service" "WARNING" "true"
    sleep 15
    new_rustdesk_status=$(get_rustdesk_status)
    if [ "$new_rustdesk_status" = "OK" ]; then
      send_alert_with_severity "INFO" "Service Recovered" \
        "Auto-remediation successful - RustDesk service restored
Previous status: $rustdesk_status  
New status: $new_rustdesk_status" "service"
      remediation_attempted=true
    fi
  else
    log_remediation_attempt "service" "WARNING" "false"
  fi
  
  if [ "$remediation_attempted" = "false" ]; then
    send_alert_with_severity "WARNING" "Service Degraded" \
      "RustDesk service has issues
Status: $rustdesk_status
Connectivity: ${connectivity_score}%
Auto-remediation attempted" "service"
  fi
fi

# Check Docker service with auto-remediation
if [ "$service_health" = "DOCKER_DOWN" ]; then
  remediation_attempted=false
  echo "Attempting auto-remediation for Docker service..."
  if perform_auto_remediation "docker" "CRITICAL" "Docker service down"; then
    log_remediation_attempt "docker" "CRITICAL" "true"
    # Re-check Docker after remediation
    sleep 15
    if systemctl is-active --quiet docker; then
      send_alert_with_severity "INFO" "Docker Service Recovered" \
        "Auto-remediation successful - Docker service restored
RustDesk containers should be starting up" "docker"
      remediation_attempted=true
    fi
  else
    log_remediation_attempt "docker" "CRITICAL" "false"
  fi
  
  if [ "$remediation_attempted" = "false" ]; then
    send_alert_with_severity "CRITICAL" "Docker Service Down" \
      "Docker service is not running
All RustDesk containers will be offline
Auto-remediation attempted but failed" "docker"
  fi
fi

# Check for license conflicts
if [ "$service_health" = "LICENSE_CONFLICT" ]; then
  send_alert_with_severity "CRITICAL" "License Conflict" \
    "RustDesk Pro license is already in use by another machine
Service may be degraded or non-functional
Action required: Migrate license or resolve conflict" "license"
fi

# Send recovery notifications
if [ "$rustdesk_status" = "OK" ] && [ -f "/tmp/alert_cooldown_service" ]; then
  send_alert_with_severity "INFO" "Service Recovered" \
    "RustDesk service has returned to normal operation
Status: $rustdesk_status
Connectivity: ${connectivity_score}%" "recovery"
  rm -f /tmp/alert_cooldown_service
fi

# Send custom metrics to CloudWatch
echo "Sending metrics to CloudWatch..."
send_cloudwatch_metrics "$cpu_usage" "$memory_usage" "$disk_usage" "$active_connections" "$connectivity_score" "$error_count"

# Calculate overall status first to avoid complex bash in JSON
if [ "$service_health" = "LICENSE_CONFLICT" ]; then
    overall_status="LICENSE_CONFLICT"
elif [ "${rustdesk_status:-UNKNOWN}" = "OK" ] && (( $(echo "${cpu_usage:-0} <= ${CPU_THRESHOLD:-80}" | bc -l) )) && (( $(echo "${memory_usage:-0} <= ${MEMORY_THRESHOLD:-85}" | bc -l) )) && [ "${disk_usage:-0}" -le "${DISK_THRESHOLD:-90}" ]; then
    overall_status="OK"
elif [ "${rustdesk_status:-UNKNOWN}" = "WARNING" ]; then
    overall_status="WARNING"
else
    overall_status="CRITICAL"
fi

# Calculate license status
if [ "$service_health" = "LICENSE_CONFLICT" ]; then
    license_status="CONFLICT"
else
    license_status="OK"
fi

# Output clean JSON for web UI with trend data
cat > /opt/rustdesk/web/status.json <<JSONEOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "cpu_usage": ${cpu_usage:-0},
  "memory_usage": ${memory_usage:-0},
  "disk_usage": ${disk_usage:-0},
  "cpu_trend": "${cpu_trend:-STABLE}",
  "active_connections": ${active_connections:-0},
  "connectivity_score": ${connectivity_score:-0},
  "error_count": $(echo ${error_count:-0} | xargs),
  "rustdesk_status": "${rustdesk_status:-UNKNOWN}",
  "cpu_threshold": ${CPU_THRESHOLD:-80},
  "memory_threshold": ${MEMORY_THRESHOLD:-85},
  "disk_threshold": ${DISK_THRESHOLD:-90},
  "overall_status": "${overall_status}",
  "backup_status": "IDLE",
  "service_health": "${service_health:-UNKNOWN}",
  "license_status": "${license_status}"
}
JSONEOF

echo "Monitoring completed successfully"
echo "Status written to /opt/rustdesk/web/status.json"
MONITOR

  chmod +x "/opt/rustdesk/monitoring/monitor.sh"
  
  # Create enhanced web UI with backup status display
  cat > "/opt/rustdesk/web/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RustDesk Server Status - Enhanced</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .status-indicator {
            display: inline-block;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 10px;
            animation: pulse 2s infinite;
        }
        .status-ok { background-color: #27ae60; }
        .status-warning { background-color: #f39c12; }
        .status-critical { background-color: #e74c3c; }
        .status-backup { background-color: #3498db; animation: backup-pulse 1s infinite; }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        @keyframes backup-pulse {
            0% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.7; transform: scale(1.1); }
            100% { opacity: 1; transform: scale(1); }
        }
        .content {
            padding: 30px;
        }
        .metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 0;
            border-bottom: 1px solid #eee;
        }
        .metric:last-child {
            border-bottom: none;
        }
        .metric-name {
            font-weight: 600;
            color: #2c3e50;
        }
        .metric-value {
            font-weight: 500;
        }
        .progress-bar {
            width: 200px;
            height: 8px;
            background-color: #ecf0f1;
            border-radius: 4px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        .progress-ok { background-color: #27ae60; }
        .progress-warning { background-color: #f39c12; }
        .progress-critical { background-color: #e74c3c; }
        .progress-backup { background-color: #3498db; }
        .timestamp {
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        .refresh-btn {
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            margin-bottom: 20px;
            margin-right: 10px;
        }
        .refresh-btn:hover {
            background: linear-gradient(135deg, #2980b9 0%, #21618c 100%);
        }
        .backup-status {
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
            color: white;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
            font-weight: 500;
        }
        .backup-status.backup-active {
            background: linear-gradient(135deg, #e67e22 0%, #d35400 100%);
            animation: backup-notice 2s ease-in-out infinite;
        }
        @keyframes backup-notice {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-2px); }
        }
        .service-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .service-card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            border-left: 4px solid #ddd;
        }
        .service-card.ok { border-left-color: #27ae60; }
        .service-card.warning { border-left-color: #f39c12; }
        .service-card.critical { border-left-color: #e74c3c; }
        .service-card.backup { border-left-color: #3498db; }
        .service-card.license-conflict { border-left-color: #e74c3c; background: linear-gradient(135deg, #fff5f5 0%, #fed7d7 100%); }
        .service-name {
            font-weight: 600;
            margin-bottom: 10px;
            color: #2c3e50;
        }
        .service-status {
            font-size: 1.1em;
            font-weight: 500;
        }
        .alert-history {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }
        .alert-history h3 {
            margin-top: 0;
            color: #2c3e50;
        }
        .alert-item {
            padding: 10px;
            margin: 5px 0;
            border-radius: 4px;
            background: white;
            border-left: 3px solid #ddd;
        }
        .alert-item.critical { border-left-color: #e74c3c; }
        .alert-item.warning { border-left-color: #f39c12; }
        .alert-item.info { border-left-color: #3498db; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><span id="status-indicator" class="status-indicator"></span>RustDesk Server Status</h1>
        </div>
        <div class="content">
            <button class="refresh-btn" id="refresh-btn" onclick="loadStatus()">Refresh Status</button>
            <button class="refresh-btn" onclick="testServer()" style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);">Test Server</button>
            <button class="refresh-btn" onclick="viewLogs()" style="background: linear-gradient(135deg, #9b59b6 0%, #8e44ad 100%);">View Logs</button>
            
            <div id="backup-status" class="backup-status" style="display: none;">
                <strong>🔄 Backup in Progress</strong><br>
                <small>Monitoring is in backup mode - service alerts are temporarily suspended</small>
            </div>
            
            <div class="service-grid" id="service-grid"></div>
            
            <div id="charts-section" style="margin: 20px 0;">
                <h3 style="color: #2c3e50; margin-bottom: 15px;">📈 Historical Trends</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 8px;">
                        <div id="cpu-chart"></div>
                    </div>
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 8px;">
                        <div id="memory-chart"></div>
                    </div>
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 8px;">
                        <div id="connections-chart"></div>
                    </div>
                </div>
            </div>
            
            <div id="metrics"></div>
            
            <div class="alert-history">
                <h3>Recent Alerts</h3>
                <div id="alert-history"></div>
            </div>
            
            <div id="timestamp" class="timestamp"></div>
        </div>
    </div>

    <script>
        let alertHistory = [];
        
        function loadStatus() {
            console.log('Refreshing status...');
            const refreshBtn = document.getElementById('refresh-btn');
            const originalText = refreshBtn.textContent;
            
            // Show loading state
            refreshBtn.textContent = 'Refreshing...';
            refreshBtn.disabled = true;
            
            // First trigger monitoring script to update status.json, then fetch it
            fetch('/refresh')
                .then(() => {
                    // Wait a moment for the monitoring script to complete
                    return new Promise(resolve => setTimeout(resolve, 2000));
                })
                .then(() => {
                    return fetch('/status.json');
                })
                .then(response => {
                    console.log('Response status:', response.status);
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    return response.json();
                })
                .then(data => {
                    console.log('Status data received:', data);
                    updateUI(data);
                    // Load historical data for charts
                    loadHistoricalData();
                })
                .catch(error => {
                    console.error('Error loading status:', error);
                    document.getElementById('metrics').innerHTML = '<p style="color: #e74c3c;">Error loading status data: ' + error.message + '</p>';
                })
                .finally(() => {
                    // Reset button state
                    refreshBtn.textContent = originalText;
                    refreshBtn.disabled = false;
                });
        }

        function updateUI(data) {
            const statusIndicator = document.getElementById('status-indicator');
            const metricsDiv = document.getElementById('metrics');
            const timestampDiv = document.getElementById('timestamp');
            const backupStatusDiv = document.getElementById('backup-status');
            const serviceGridDiv = document.getElementById('service-grid');

            // Update status indicator
            statusIndicator.className = 'status-indicator';
            if (data.backup_status === 'IN_PROGRESS') {
                statusIndicator.classList.add('status-backup');
                backupStatusDiv.style.display = 'block';
                backupStatusDiv.classList.add('backup-active');
            } else {
                backupStatusDiv.style.display = 'none';
                backupStatusDiv.classList.remove('backup-active');
                
                if (data.overall_status === 'LICENSE_CONFLICT') {
                    statusIndicator.classList.add('status-critical');
                    statusIndicator.textContent = '🔑';
                } else if (data.overall_status === 'OK') {
                    statusIndicator.classList.add('status-ok');
                    statusIndicator.textContent = '●';
                } else if (data.overall_status === 'WARNING') {
                    statusIndicator.classList.add('status-warning');
                    statusIndicator.textContent = '●';
                } else {
                    statusIndicator.classList.add('status-critical');
                    statusIndicator.textContent = '●';
                }
            }

            // Update service grid
            serviceGridDiv.innerHTML = `
                <div class="service-card ${getServiceCardClass(data.rustdesk_status)}">
                    <div class="service-name">RustDesk Service</div>
                    <div class="service-status">${data.rustdesk_status}</div>
                </div>
                <div class="service-card ${getServiceCardClass(data.service_health)}">
                    <div class="service-name">Service Health</div>
                    <div class="service-status">${data.service_health || 'UNKNOWN'}</div>
                </div>
                <div class="service-card ${getServiceCardClass(data.license_status)}">
                    <div class="service-name">License Status</div>
                    <div class="service-status">${data.license_status || 'UNKNOWN'}</div>
                </div>
                <div class="service-card ${getServiceCardClass(data.backup_status)}">
                    <div class="service-name">Backup Status</div>
                    <div class="service-status">${data.backup_status || 'IDLE'}</div>
                </div>
            `;

            // Update metrics
            metricsDiv.innerHTML = `
                <div class="metric">
                    <span class="metric-name">Overall Status</span>
                    <span class="metric-value">${data.overall_status}</span>
                </div>
                <div class="metric">
                    <span class="metric-name">CPU Usage</span>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="metric-value">${data.cpu_usage.toFixed(1)}%</span>
                        <div class="progress-bar">
                            <div class="progress-fill ${getProgressClass(data.cpu_usage, data.cpu_threshold)}" 
                                 style="width: ${Math.min(data.cpu_usage, 100)}%"></div>
                        </div>
                    </div>
                </div>
                <div class="metric">
                    <span class="metric-name">Memory Usage</span>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="metric-value">${data.memory_usage.toFixed(1)}%</span>
                        <div class="progress-bar">
                            <div class="progress-fill ${getProgressClass(data.memory_usage, data.memory_threshold)}" 
                                 style="width: ${Math.min(data.memory_usage, 100)}%"></div>
                        </div>
                    </div>
                </div>
                <div class="metric">
                    <span class="metric-name">Disk Usage</span>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="metric-value">${data.disk_usage}%</span>
                        <div class="progress-bar">
                            <div class="progress-fill ${getProgressClass(data.disk_usage, data.disk_threshold)}" 
                                 style="width: ${Math.min(data.disk_usage, 100)}%"></div>
                        </div>
                    </div>
                </div>
            `;

            // Update timestamp
            timestampDiv.textContent = `Last updated: ${new Date(data.timestamp).toLocaleString()}`;
            
            // Add to alert history if there's a status change
            addToAlertHistory(data);
        }

        function getServiceCardClass(status) {
            if (status === 'BACKUP_IN_PROGRESS' || status === 'IN_PROGRESS') return 'backup';
            if (status === 'LICENSE_CONFLICT' || status === 'CONFLICT') return 'license-conflict';
            if (status === 'OK') return 'ok';
            if (status === 'WARNING') return 'warning';
            if (status === 'CRITICAL' || status === 'DOCKER_DOWN' || status === 'RUSTDESK_CRITICAL') return 'critical';
            return '';
        }

        function getProgressClass(value, threshold) {
            if (value >= threshold) return 'progress-critical';
            if (value >= threshold * 0.8) return 'progress-warning';
            return 'progress-ok';
        }

        function addToAlertHistory(data) {
            const currentStatus = data.overall_status;
            const currentTime = new Date().toLocaleString();
            
            // Only add if status changed
            if (alertHistory.length === 0 || alertHistory[alertHistory.length - 1].status !== currentStatus) {
                let alertClass = 'info';
                let message = `Status: ${currentStatus}`;
                
                if (currentStatus === 'LICENSE_CONFLICT') {
                    alertClass = 'critical';
                    message = `🔑 License Conflict: RustDesk Pro license is already in use by another machine. Please migrate your license or resolve the conflict.`;
                } else if (currentStatus === 'CRITICAL') {
                    alertClass = 'critical';
                    message = `🚨 Service Critical: ${data.rustdesk_status}`;
                } else if (currentStatus === 'WARNING') {
                    alertClass = 'warning';
                    message = `⚠️ Service Warning: ${data.rustdesk_status}`;
                } else if (data.backup_status === 'IN_PROGRESS') {
                    alertClass = 'info';
                    message = '🔄 Backup in Progress - Monitoring in backup mode';
                } else if (currentStatus === 'OK') {
                    alertClass = 'info';
                    message = '✅ All systems operational';
                }
                
                alertHistory.push({
                    time: currentTime,
                    status: currentStatus,
                    message: message,
                    class: alertClass
                });
                
                // Keep only last 10 alerts
                if (alertHistory.length > 10) {
                    alertHistory.shift();
                }
                
                updateAlertHistory();
            }
        }

        function updateAlertHistory() {
            const alertHistoryDiv = document.getElementById('alert-history');
            alertHistoryDiv.innerHTML = alertHistory.map(alert => `
                <div class="alert-item ${alert.class}">
                    <strong>${alert.time}</strong><br>
                    ${alert.message}
                </div>
            `).join('');
        }

        function testServer() {
            console.log('Testing server...');
            fetch('/test')
                .then(response => response.json())
                .then(data => {
                    console.log('Test response:', data);
                    alert('Server test successful: ' + data.message);
                })
                .catch(error => {
                    console.error('Server test failed:', error);
                    alert('Server test failed: ' + error.message);
                });
        }

        function viewLogs() {
            // This would typically open a log viewer or fetch recent logs
            alert('Log viewer functionality would be implemented here.\n\nYou can view logs manually using:\n\nsudo journalctl -u rustdesk-monitor.service -f\nsudo tail -f /opt/rustdesk/logs/backup.log');
        }

        // Historical data management
        let historicalData = [];
        let maxHistoricalPoints = 50;

        function loadHistoricalData() {
            fetch('/historical-metrics')
                .then(response => response.json())
                .then(data => {
                    if (data && data.length > 0) {
                        historicalData = data.slice(-maxHistoricalPoints);
                        updateCharts();
                    }
                })
                .catch(error => console.log('Historical data not available:', error));
        }

        function updateCharts() {
            if (historicalData.length < 2) return;
            
            // Simple ASCII-style mini charts
            updateMiniChart('cpu-chart', historicalData.map(d => d.cpu_usage), 'CPU %');
            updateMiniChart('memory-chart', historicalData.map(d => d.memory_usage), 'Memory %');
            updateMiniChart('connections-chart', historicalData.map(d => d.active_connections), 'Connections');
        }

        function updateMiniChart(chartId, data, label) {
            const chartElement = document.getElementById(chartId);
            if (!chartElement) return;
            
            const max = Math.max(...data);
            const min = Math.min(...data);
            const range = max - min || 1;
            
            // Create simple bar chart
            let chartHtml = `<div style="font-size: 0.8em; color: #666; margin-bottom: 5px;">${label} (${min.toFixed(1)} - ${max.toFixed(1)})</div>`;
            chartHtml += '<div style="display: flex; align-items: end; height: 30px; gap: 1px;">';
            
            data.slice(-20).forEach(value => {
                const height = Math.max(2, ((value - min) / range) * 25);
                const color = value > max * 0.8 ? '#e74c3c' : value > max * 0.6 ? '#f39c12' : '#27ae60';
                chartHtml += `<div style="background: ${color}; height: ${height}px; flex: 1; opacity: 0.7;"></div>`;
            });
            
            chartHtml += '</div>';
            chartElement.innerHTML = chartHtml;
        }

        function addCurrentDataPoint(data) {
            const currentPoint = {
                timestamp: Date.now(),
                cpu_usage: data.cpu_usage,
                memory_usage: data.memory_usage,
                disk_usage: data.disk_usage,
                active_connections: parseInt(data.connectivity_score) || 0
            };
            
            historicalData.push(currentPoint);
            if (historicalData.length > maxHistoricalPoints) {
                historicalData.shift();
            }
            
            updateCharts();
        }

        // Enhanced updateUI to include charts
        const originalUpdateUI = updateUI;
        updateUI = function(data) {
            originalUpdateUI(data);
            addCurrentDataPoint(data);
        };

        // Load status on page load and refresh every 30 seconds
        loadStatus();
        setInterval(loadStatus, 30000);
    </script>
</body>
</html>
HTML

  # Create simple web server script
  cat > "/opt/rustdesk/web/server.py" <<PYTHON
#!/usr/bin/env python3
import http.server
import socketserver
import os
import sys
import json
import subprocess

PORT = $MONITORING_PORT
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")

    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

    def do_GET(self):
        global os
        print(f"Request: {self.path}")
        
        # Test endpoint
        if self.path == '/test':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"message": "Web server is working"}).encode())
            return
            
        # Historical metrics endpoint
        if self.path == '/historical-metrics':
            try:
                import csv
                import os
                from datetime import datetime, timedelta
                
                # Read today's metrics file
                metrics_file = f"/opt/rustdesk/logs/metrics-{datetime.now().strftime('%Y%m%d')}.csv"
                historical_data = []
                
                if os.path.exists(metrics_file):
                    with open(metrics_file, 'r') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            try:
                                historical_data.append({
                                    'timestamp': int(row['timestamp']),
                                    'cpu_usage': float(row['cpu_usage']),
                                    'memory_usage': float(row['memory_usage']),
                                    'disk_usage': float(row['disk_usage']),
                                    'active_connections': int(row['active_connections']),
                                    'connectivity_score': float(row['connectivity_score']),
                                    'error_count': int(row['error_count'])
                                })
                            except (ValueError, KeyError):
                                continue
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(historical_data[-50:]).encode())  # Last 50 points
                return
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
                return
        
        # Refresh endpoint - triggers monitoring script
        if self.path == '/refresh':
            try:
                # Run the monitoring script to update status.json
                result = subprocess.run(['/opt/rustdesk/monitoring/monitor.sh'], 
                                      capture_output=True, text=True, timeout=30)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"message": "Status refreshed", "success": True}).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"message": str(e), "success": False}).encode())
            return
            
        if self.path == '/status.json':
            status_file = os.path.join(DIRECTORY, 'status.json')
            if os.path.exists(status_file):
                print(f"Status file exists: {status_file}")
                with open(status_file, 'r') as f:
                    content = f.read()
                    print(f"Status file content: {content[:200]}...")
            else:
                print(f"Status file not found: {status_file}")
                # Create a test status.json if it doesn't exist
                test_status = {
                    "timestamp": "2025-07-20T10:50:09Z",
                    "cpu_usage": 0.0,
                    "memory_usage": 0.0,
                    "disk_usage": 0,
                    "rustdesk_status": "UNKNOWN",
                    "cpu_threshold": $CPU_THRESHOLD,
                    "memory_threshold": $MEMORY_THRESHOLD,
                    "disk_threshold": $DISK_THRESHOLD,
                    "overall_status": "UNKNOWN",
                    "backup_status": "IDLE",
                    "service_health": "UNKNOWN"
                }
                with open(status_file, 'w') as f:
                    json.dump(test_status, f)
                print(f"Created test status file: {status_file}")
        super().do_GET()

if __name__ == "__main__":
    os.chdir(DIRECTORY)
    with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
        print(f"Server running at http://localhost:{PORT}")
        httpd.serve_forever()
PYTHON

  chmod +x "/opt/rustdesk/web/server.py"
  
  # Create systemd service for web server
  cat > /etc/systemd/system/rustdesk-monitor.service <<EOF
[Unit]
Description=RustDesk Monitoring Web Server
After=network.target

[Service]
EnvironmentFile=/opt/rustdesk/rustdesk.env
Type=simple
User=root
WorkingDirectory=/opt/rustdesk/web
ExecStart=/usr/bin/python3 /opt/rustdesk/web/server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

  # Create systemd service for monitoring
  cat > /etc/systemd/system/rustdesk-monitoring.service <<EOF
[Unit]
Description=RustDesk Monitoring Service
After=network.target

[Service]
EnvironmentFile=/opt/rustdesk/rustdesk.env
Type=oneshot
User=root
ExecStart=/opt/rustdesk/monitoring/monitor.sh

[Install]
WantedBy=multi-user.target
EOF

  # Create systemd timer for monitoring
  cat > /etc/systemd/system/rustdesk-monitoring.timer <<EOF
[Unit]
Description=Run RustDesk monitoring every 5 minutes
Requires=rustdesk-monitoring.service

[Timer]
Unit=rustdesk-monitoring.service
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
EOF

  # Clean up any stale monitoring state files before starting monitoring
  log "Cleaning up any stale monitoring state files..."
  rm -f "$BASE_DIR/monitoring/backup_status.txt"
  rm -f "$BASE_DIR/monitoring/alert_"*.tmp
  log "Monitoring state files cleaned up"

  # Enable and start services
  systemctl daemon-reload
  systemctl enable rustdesk-monitor.service
  systemctl enable rustdesk-monitoring.timer
  systemctl start rustdesk-monitor.service
  systemctl start rustdesk-monitoring.timer
  
  log "Monitoring setup complete. Web UI available at http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):$MONITORING_PORT"
fi

# ---------- ENHANCED BACKUP SCRIPT -----------------------------------------------------
log "Creating enhanced backup script with false alert prevention …"

# Ensure environment variables are available for script creation
source /opt/rustdesk/env-loader.sh

cat > "$BASE_DIR/backup.sh" <<BACKUP
#!/bin/bash
set -eo pipefail

# Load environment variables
source /opt/rustdesk/env-loader.sh

# Use environment variables for configuration
BACKUP_DIR="$BACKUP_DIR"
S3_BUCKET="$S3_BUCKET"
AWS_REGION="$AWS_REGION"
FILE="rustdesk_backup_\$(date +%Y%m%d_%H%M%S).tar.gz"
cd "$BASE_DIR"

# Create backup status file to signal monitoring system (prevents false alerts)
echo "BACKUP_IN_PROGRESS" > /opt/rustdesk/monitoring/backup_status.txt
echo "\$(date): Backup started" >> /opt/rustdesk/logs/backup.log

# Function to send backup notification
send_backup_notification() {
    local status="\$1"
    local message="\$2"
    
    # Get email password dynamically
    local email_password=""
    if [ -n "\$EMAIL_PASSWORD_SECRET_NAME" ] && [ "\$EMAIL_PASSWORD_SECRET_NAME" != "PLACEHOLDER" ]; then
        email_password=\$(aws secretsmanager get-secret-value \\
            --secret-id "\$EMAIL_PASSWORD_SECRET_NAME" \\
            --region "\$AWS_REGION" \\
            --query SecretString --output text 2>/dev/null | jq -r .password 2>/dev/null)
    elif [ -n "\$EMAIL_PASSWORD" ]; then
        email_password="\$EMAIL_PASSWORD"
    fi
    
    if [ -n "\$email_password" ]; then
        python3 -c "
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    msg = MIMEMultipart()
    msg['From'] = '\$EMAIL_USER'
    msg['To'] = '\$ALERT_EMAIL'
    msg['Subject'] = 'RustDesk Backup: \$status'
    msg.attach(MIMEText('\$message', 'plain'))
    
    server = smtplib.SMTP('\$SMTP_SERVER', \$SMTP_PORT)
    server.starttls()
    server.login('\$EMAIL_USER', '\$email_password')
    
    text = msg.as_string()
    server.sendmail('\$EMAIL_USER', '\$ALERT_EMAIL', text)
    server.quit()
    print('Backup notification sent successfully')
    
except Exception as e:
    print(f'Backup notification failed: {e}')
    logger 'RustDesk Backup: \$status - \$message'
" || {
            logger "RustDesk Backup: \$status - \$message"
            echo "\$(date): \$status - \$message" >> /opt/rustdesk/logs/backup.log
        }
    fi
}

# Send backup start notification
send_backup_notification "Started" "Daily backup process initiated at \$(date)"

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
if /bin/tar -czf "\$BACKUP_DIR/\$FILE" data monitoring web; then
    echo "Backup archive created: \$FILE"
    BACKUP_SIZE=\$(du -h "\$BACKUP_DIR/\$FILE" | cut -f1)
    echo "Backup size: \$BACKUP_SIZE"
else
    echo "Error: Failed to create backup archive"
    send_backup_notification "Failed" "Backup archive creation failed"
    exit 1
fi

echo "Uploading \$FILE to S3..."
if /usr/bin/aws s3 cp "\$BACKUP_DIR/\$FILE" "s3://\$S3_BUCKET/Backups/" --region "\$AWS_REGION"; then
    echo "Backup uploaded to S3 successfully"
else
    echo "Error: Failed to upload backup to S3"
    send_backup_notification "Failed" "S3 upload failed for backup \$FILE"
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
    echo "Waiting for containers... attempt \$i/30"
    sleep 2
done

if [ "\$HEALTHY" = true ]; then
    echo "All containers are healthy"
    
    # Verify RustDesk service is responding
    echo "Verifying RustDesk service health..."
    if timeout 10 curl -s "http://localhost:$RUSTDESK_PORT" > /dev/null 2>&1; then
        echo "RustDesk service is responding"
    else
        echo "Warning: RustDesk service not responding on port $RUSTDESK_PORT"
    fi
    
    # Send successful backup notification
    send_backup_notification "Completed" "Daily backup completed successfully\n- File: \$FILE\n- Size: \$BACKUP_SIZE\n- S3 Location: s3://\$S3_BUCKET/Backups/\$FILE\n- Service Status: Healthy"
    
    # Clean up old backups (keep last 7)
    echo "Cleaning up old backups..."
    cd "\$BACKUP_DIR" && ls -t | tail -n +8 | xargs -r rm -f
    echo "Old backups cleaned up"
    
else
    echo "Error: Containers failed to become healthy after restart"
    send_backup_notification "Failed" "Containers unhealthy after backup restart"
    exit 1
fi

# Remove backup status file
rm -f /opt/rustdesk/monitoring/backup_status.txt

# Log completion
echo "\$(date): Backup completed successfully" >> /opt/rustdesk/logs/backup.log

echo "Backup process completed successfully!"
BACKUP
chmod +x "$BASE_DIR/backup.sh"

# Safely add a daily cron job at 02:00 UTC
(crontab -l 2>/dev/null | grep -v -F "$BASE_DIR/backup.sh"; echo "0 2 * * * $BASE_DIR/backup.sh > /dev/null 2>&1") | crontab - || true

# Add weekly database maintenance cron job (Sundays at 03:00 UTC)
(crontab -l 2>/dev/null | grep -v -F "sqlite3.*VACUUM"; echo "0 3 * * 0 cd $DATA_DIR && sqlite3 db_v2.sqlite3 'VACUUM;' >> $LOG_DIR/maintenance.log 2>&1") | crontab - || true

# Add daily container restart cron job (daily at 01:00 UTC)
(crontab -l 2>/dev/null | grep -v -F "docker compose.*restart"; echo "0 1 * * * cd $BASE_DIR && docker compose restart >> $LOG_DIR/restart.log 2>&1") | crontab - || true

# ---------- ENHANCED STATUS SCRIPT -----------------------------------------------------
log "Creating enhanced status script …"
cat > "$BASE_DIR/status.sh" <<STATUS
#!/bin/bash
set -e
printf "=== Enhanced RustDesk Server Status ===\n"
printf "HBBS Container: %s\n" "\$(docker ps --filter name=hbbs --format '{{.Status}}')"
printf "HBBR Container: %s\n" "\$(docker ps --filter name=hbbr --format '{{.Status}}')"
printf "Public Key:\n%s\n" "\$(cat $DATA_DIR/id_ed25519.pub)"
printf "Server IP: %s\n" "\$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)"

if [ "$MONITORING_ENABLED" = "true" ]; then
    printf "\n=== Monitoring Status ===\n"
    printf "Web UI: http://\$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):$MONITORING_PORT\n"
    printf "Monitoring Service: %s\n" "\$(systemctl is-active rustdesk-monitoring.timer)"
    printf "Web Server: %s\n" "\$(systemctl is-active rustdesk-monitor.service)"
    
    if [ -f $WEB_DIR/status.json ]; then
        printf "\n=== Current Metrics ===\n"
        cat $WEB_DIR/status.json | jq -r '.overall_status + " - CPU: " + (.cpu_usage | tostring) + "%, Memory: " + (.memory_usage | tostring) + "%, Disk: " + (.disk_usage | tostring) + "%"'
    fi
fi
STATUS
chmod +x "$BASE_DIR/status.sh"

# Stop containers in docker compose
docker compose -f $BASE_DIR/compose.yml down

# Start containers
docker compose -f $BASE_DIR/compose.yml up -d

# Wait 20 Seconds and send status
sleep 10
"$BASE_DIR/status.sh"

# Clear alert cooldowns after bootstrap completion
log "Clearing alert cooldowns for fresh start..."
rm -f /tmp/alert_cooldown_* 2>/dev/null || true
log "Alert cooldowns cleared - monitoring system ready for immediate alerts"

log "Enhanced bootstrap complete! Use 'sudo $BASE_DIR/status.sh' to view server status." 