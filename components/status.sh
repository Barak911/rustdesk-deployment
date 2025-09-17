#!/bin/bash
set -e
printf "=== Enhanced RustDesk Server Status ===\n"
printf "HBBS Container: %s\n" "$(docker ps --filter name=hbbs --format '{{.Status}}')"
printf "HBBR Container: %s\n" "$(docker ps --filter name=hbbr --format '{{.Status}}')"
printf "Public Key:\n%s\n" "$(cat "$DATA_DIR/id_ed25519.pub")"
printf "Server IP: %s\n" "$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)"

if [ "$MONITORING_ENABLED" = "true" ]; then
    printf "\n=== Monitoring Status ===\n"
    printf "Web UI: http://%s:%s\n" "$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)" "$MONITORING_PORT"
    printf "Monitoring Service: %s\n" "$(systemctl is-active rustdesk-monitoring.timer)"
    printf "Web Server: %s\n" "$(systemctl is-active rustdesk-monitor.service)"

    if [ -f "$WEB_DIR/status.json" ]; then
        printf "\n=== Current Metrics ===\n"
        cat "$WEB_DIR/status.json" | jq -r '.overall_status + " - CPU: " + (.cpu_usage | tostring) + "%, Memory: " + (.memory_usage | tostring) + "%, Disk: " + (.disk_usage | tostring) + "%"'
    fi
fi