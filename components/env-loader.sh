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
    # shellcheck disable=SC1090
    source "$env_file"
    set +a

    # Dynamically retrieve email password from Secrets Manager
    if [ -n "$EMAIL_PASSWORD_SECRET_NAME" ] && [ "$EMAIL_PASSWORD_SECRET_NAME" != "PLACEHOLDER" ]; then
        echo "[$script_name] Retrieving email password from Secrets Manager..."
        if EMAIL_PASSWORD=$(aws secretsmanager get-secret-value \
            --secret-id "$EMAIL_PASSWORD_SECRET_NAME" \
            --region "$AWS_REGION" \
            --query SecretString --output text 2>/dev/null | jq -r .password 2>/dev/null) && \
           [ -n "$EMAIL_PASSWORD" ] && [ "$EMAIL_PASSWORD" != "null" ]; then
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