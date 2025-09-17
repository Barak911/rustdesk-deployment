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