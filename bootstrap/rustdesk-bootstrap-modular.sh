#!/bin/bash
# -----------------------------------------------------------------------------
# Enhanced RustDesk Docker bootstrap with modular S3-based scripts
#   Installs Docker & Compose, restores (or generates) RustDesk encryption keys,
#   launches HBBS/HBBR containers, sets up monitoring, web UI, and daily backups.
# -----------------------------------------------------------------------------
# This script downloads all component scripts from S3 instead of creating them inline
# All scripts should be uploaded to s3://bucket/Components/ folder
# -----------------------------------------------------------------------------
set -eo pipefail

# Set TEST_SERVER to true to skip key‑restore
TEST_SERVER=false

# Function to download script from S3 with fallback
download_script_from_s3() {
    local script_name="$1"
    local destination="$2"
    local make_executable="${3:-true}"
    local retries=3
    local retry_count=0

    echo "Downloading $script_name from S3..."

    while [ $retry_count -lt $retries ]; do
        if aws s3 cp "s3://$S3_BUCKET/Components/$script_name" "$destination" --region "$AWS_REGION" 2>/dev/null; then
            echo "✓ Successfully downloaded $script_name"
            if [ "$make_executable" = "true" ]; then
                chmod +x "$destination"
            fi
            return 0
        else
            retry_count=$((retry_count + 1))
            echo "⚠ Download failed for $script_name (attempt $retry_count/$retries)"
            if [ $retry_count -lt $retries ]; then
                sleep 2
            fi
        fi
    done

    echo "❌ Failed to download $script_name after $retries attempts"
    return 1
}

# Function to create fallback script if S3 download fails
create_fallback_env_loader() {
    echo "Creating fallback environment loader script..."
    cat > /opt/rustdesk/env-loader.sh << 'ENV_LOADER_FALLBACK'
#!/bin/bash
# Fallback environment loader - basic functionality only
load_rustdesk_environment() {
    local env_file="/opt/rustdesk/rustdesk.env"
    local script_name="${0##*/}"

    echo "[$script_name] Loading RustDesk environment (fallback mode)..."

    if [ ! -f "$env_file" ]; then
        echo "[$script_name] ERROR: Environment file not found at $env_file"
        return 1
    fi

    set -a
    source "$env_file"
    set +a

    echo "[$script_name] ✓ Environment loaded successfully"
    return 0
}

if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    load_rustdesk_environment
fi
ENV_LOADER_FALLBACK
    chmod 500 /opt/rustdesk/env-loader.sh
    echo "✓ Fallback environment loader created"
}

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
    echo "ℹ No backup environment loader found, will download from S3"
    USING_RESTORED_LOADER=false
fi

# Load environment to get S3_BUCKET and AWS_REGION for script downloads
echo "Loading environment using loader script..."
source /opt/rustdesk/env-loader.sh
load_rustdesk_environment

echo "✓ Environment exported: S3_BUCKET=$S3_BUCKET  PORT=$RUSTDESK_PORT"

# Download or create environment loader script if we don't have a restored one
if [ "$USING_RESTORED_LOADER" = "false" ]; then
    if ! download_script_from_s3 "env-loader.sh" "/opt/rustdesk/env-loader.sh" true; then
        create_fallback_env_loader
    fi

    # Reload environment with the new loader
    source /opt/rustdesk/env-loader.sh
    load_rustdesk_environment
fi

# Function to log messages with timestamp (after LOG_DIR is set)
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a /opt/rustdesk/logs/rustdesk-bootstrap.log
}

log "Starting RustDesk Enhanced Bootstrap Script (Modular Version)"
log "Environment configuration loaded successfully"

# Create all directories
mkdir -p "$BACKUP_DIR" "$DATA_DIR" "$MONITORING_DIR" "$WEB_DIR" "$SCRIPTS_DIR" "$LOG_DIR"

# Check all directories exist
for dir in "$BACKUP_DIR" "$DATA_DIR" "$MONITORING_DIR" "$WEB_DIR" "$SCRIPTS_DIR" "$LOG_DIR"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
    fi
done
log "✓ All directories exist"

# Download Python SMTP email sender script
log "Downloading Python SMTP email sender..."
if download_script_from_s3 "send_email.py" "/opt/rustdesk/scripts/send_email.py" true; then
    log "✓ Python SMTP email sender downloaded from S3"
else
    log "❌ Failed to download send_email.py - email alerts may not work"
fi

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

# Download CloudWatch agent configuration from S3
log "Downloading CloudWatch agent configuration..."
if download_script_from_s3 "cloudwatch-agent-config.json" "/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json" false; then
    log "✓ CloudWatch agent configuration downloaded from S3"
else
    log "❌ Failed to download CloudWatch config - using minimal fallback"
    cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<'CWAGENT_FALLBACK'
{
    "agent": {
        "metrics_collection_interval": 60,
        "run_as_user": "root"
    },
    "metrics": {
        "namespace": "RustDesk/System",
        "metrics_collected": {
            "cpu": {"measurement": ["cpu_usage_idle"], "metrics_collection_interval": 60},
            "mem": {"measurement": ["mem_used_percent"], "metrics_collection_interval": 60},
            "disk": {"measurement": ["used_percent"], "metrics_collection_interval": 60, "resources": ["*"]}
        }
    }
}
CWAGENT_FALLBACK
fi

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

# Update package index and install Docker
apt-get update -qq
apt-get install -yq docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo apt -y install sysstat
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

  # Download monitoring script from S3
  log "Downloading monitoring script from S3..."
  if download_script_from_s3 "monitor.sh" "/opt/rustdesk/monitoring/monitor.sh" true; then
    log "✓ Monitoring script downloaded from S3"
  else
    log "❌ Failed to download monitor.sh - monitoring will be disabled"
    MONITORING_ENABLED="false"
  fi
fi

# Only continue monitoring setup if enabled and script downloaded successfully
if [ "$MONITORING_ENABLED" = "true" ]; then

  # Download web dashboard files
  log "Downloading web dashboard files..."
  if download_script_from_s3 "dashboard.html" "/opt/rustdesk/web/index.html" false; then
    log "✓ Dashboard HTML downloaded from S3"
  else
    log "❌ Failed to download dashboard.html"
  fi

  if download_script_from_s3 "dashboard-server.py" "/opt/rustdesk/web/server.py" true; then
    log "✓ Dashboard server downloaded from S3"
  else
    log "❌ Failed to download dashboard-server.py"
  fi

  # Download systemd service files
  log "Downloading systemd service files..."

  if download_script_from_s3 "rustdesk-monitor.service" "/etc/systemd/system/rustdesk-monitor.service" false; then
    log "✓ Monitor service file downloaded from S3"
  else
    log "❌ Failed to download rustdesk-monitor.service"
  fi

  if download_script_from_s3 "rustdesk-monitoring.service" "/etc/systemd/system/rustdesk-monitoring.service" false; then
    log "✓ Monitoring service file downloaded from S3"
  else
    log "❌ Failed to download rustdesk-monitoring.service"
  fi

  if download_script_from_s3 "rustdesk-monitoring.timer" "/etc/systemd/system/rustdesk-monitoring.timer" false; then
    log "✓ Monitoring timer file downloaded from S3"
  else
    log "❌ Failed to download rustdesk-monitoring.timer"
  fi

  # Enable and start systemd services
  systemctl daemon-reload
  systemctl enable rustdesk-monitor rustdesk-monitoring.timer
  systemctl start rustdesk-monitor rustdesk-monitoring.timer

  log "Monitoring setup complete. Web UI available at http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):$MONITORING_PORT"
fi

# ---------- BACKUP SETUP ------------------------------------------------------
log "Setting up backup system ..."

# Download backup script from S3
if download_script_from_s3 "backup.sh" "$BASE_DIR/backup.sh" true; then
    log "✓ Backup script downloaded from S3"
else
    log "❌ Failed to download backup.sh - creating minimal fallback"
    cat > "$BASE_DIR/backup.sh" <<'BACKUP_FALLBACK'
#!/bin/bash
echo "Minimal backup fallback - please check S3 for full backup.sh script"
source /opt/rustdesk/env-loader.sh
cd /opt/rustdesk
tar -czf "backups/rustdesk_backup_$(date +%Y%m%d_%H%M%S).tar.gz" data/ monitoring/ *.env 2>/dev/null || true
echo "Backup completed (minimal mode)"
BACKUP_FALLBACK
    chmod +x "$BASE_DIR/backup.sh"
fi

# Set up daily backup cron job
(crontab -l 2>/dev/null; echo "0 2 * * * $BASE_DIR/backup.sh") | crontab -

# ---------- STATUS SETUP ------------------------------------------------------
log "Setting up status script ..."

# Download status script from S3
if download_script_from_s3 "status.sh" "$BASE_DIR/status.sh" true; then
    log "✓ Status script downloaded from S3"
else
    log "❌ Failed to download status.sh - creating minimal fallback"
    cat > "$BASE_DIR/status.sh" <<'STATUS_FALLBACK'
#!/bin/bash
echo "=== RustDesk Server Status (Minimal) ==="
docker ps --filter name=hbb --format 'table {{.Names}}\t{{.Status}}'
if [ -f /opt/rustdesk/data/id_ed25519.pub ]; then
    echo "Public Key: $(cat /opt/rustdesk/data/id_ed25519.pub)"
fi
echo "Status script ready (minimal mode)"
STATUS_FALLBACK
    chmod +x "$BASE_DIR/status.sh"
fi

# ---------- FINAL CHECKS ------------------------------------------------------
log "Performing final health checks..."

# Check if containers are running
sleep 10
if [ "$(docker ps --filter name=hbbs --filter status=running -q | wc -l)" -eq 1 ] && \
   [ "$(docker ps --filter name=hbbr --filter status=running -q | wc -l)" -eq 1 ]; then
  log "✓ RustDesk containers are running"
else
  log "⚠ Warning: RustDesk containers may not be running properly"
fi

# Test monitoring if enabled
if [ "$MONITORING_ENABLED" = "true" ]; then
    if timeout 10 curl -s "http://localhost:$MONITORING_PORT" > /dev/null 2>&1; then
        log "✓ Monitoring web interface is accessible"
    else
        log "⚠ Warning: Monitoring web interface not accessible"
    fi
fi

log "=== RustDesk Enhanced Bootstrap Complete ==="
log "Server Status: Run '$BASE_DIR/status.sh' to check status"
log "Backup: Daily backups scheduled at 2 AM"
if [ "$MONITORING_ENABLED" = "true" ]; then
    log "Monitoring: Web UI at http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null):$MONITORING_PORT"
fi
log "All component scripts downloaded from S3: s3://$S3_BUCKET/Components/"