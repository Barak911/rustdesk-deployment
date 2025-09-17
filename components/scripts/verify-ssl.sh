#!/bin/bash
# -----------------------------------------------------------------------------
# RustDesk SSL Verification Script
# This script verifies that SSL is properly configured for RustDesk server
# -----------------------------------------------------------------------------

set -euo pipefail

DOMAIN="danyel-remote.com"
RUSTDESK_IP="51.16.78.234"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== RustDesk SSL Verification for $DOMAIN ===${NC}"

# Function to check if a port is open
check_port() {
    local host=$1
    local port=$2
    local protocol=${3:-tcp}
    
    echo -n "Checking $protocol port $port on $host: "
    if timeout 5 bash -c "</dev/$protocol/$host/$port" 2>/dev/null; then
        echo -e "${GREEN}✓ Open${NC}"
        return 0
    else
        echo -e "${RED}✗ Closed/Filtered${NC}"
        return 1
    fi
}

# Function to check SSL certificate
check_ssl() {
    local domain=$1
    local port=${2:-443}
    
    echo -e "${YELLOW}Checking SSL certificate for $domain:$port${NC}"
    
    # Check if certificate exists
    if timeout 10 openssl s_client -connect "$domain:$port" -servername "$domain" </dev/null 2>/dev/null | openssl x509 -noout -dates 2>/dev/null; then
        echo -e "${GREEN}✓ SSL certificate found${NC}"
        
        # Get certificate details
        cert_info=$(timeout 10 openssl s_client -connect "$domain:$port" -servername "$domain" </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null)
        echo "$cert_info" | sed 's/^/  /'
        
        return 0
    else
        echo -e "${RED}✗ SSL certificate not found or invalid${NC}"
        return 1
    fi
}

# Function to check HTTP redirect
check_http_redirect() {
    local domain=$1
    
    echo -e "${YELLOW}Checking HTTP to HTTPS redirect${NC}"
    
    if curl -s -I "http://$domain" | grep -q "Location: https://"; then
        echo -e "${GREEN}✓ HTTP redirects to HTTPS${NC}"
        return 0
    else
        echo -e "${RED}✗ HTTP redirect not working${NC}"
        return 1
    fi
}

# Function to test RustDesk connectivity
test_rustdesk_connectivity() {
    echo -e "${YELLOW}Testing RustDesk connectivity${NC}"
    
    # Test main RustDesk ports
    check_port "$DOMAIN" 21116 "tcp"
    check_port "$DOMAIN" 21117 "udp" 
    check_port "$DOMAIN" 21118 "tcp"
    
    # Test if web interface is accessible via HTTPS
    echo -n "Testing HTTPS web interface: "
    if curl -s -k --max-time 10 "https://$DOMAIN" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Accessible${NC}"
    else
        echo -e "${RED}✗ Not accessible${NC}"
    fi
}

# Main verification process
echo -e "${BLUE}Starting SSL verification...${NC}"
echo ""

# 1. Check DNS resolution
echo -e "${YELLOW}Checking DNS resolution${NC}"
if dig +short "$DOMAIN" | grep -q "$RUSTDESK_IP"; then
    echo -e "${GREEN}✓ DNS resolves correctly to $RUSTDESK_IP${NC}"
else
    echo -e "${RED}✗ DNS resolution issue${NC}"
    echo "Expected: $RUSTDESK_IP"
    echo "Got: $(dig +short "$DOMAIN")"
fi
echo ""

# 2. Check basic connectivity
echo -e "${YELLOW}Checking basic connectivity${NC}"
check_port "$DOMAIN" 80
check_port "$DOMAIN" 443
echo ""

# 3. Check SSL certificate
check_ssl "$DOMAIN"
echo ""

# 4. Check HTTP redirect
check_http_redirect "$DOMAIN"
echo ""

# 5. Test RustDesk specific connectivity
test_rustdesk_connectivity
echo ""

# 6. Check if services are running (if running on the server)
if [[ -f "/opt/rustdesk/docker-compose.yml" ]]; then
    echo -e "${YELLOW}Checking RustDesk services${NC}"
    cd /opt/rustdesk
    
    if docker-compose ps | grep -q "Up"; then
        echo -e "${GREEN}✓ RustDesk containers are running${NC}"
        docker-compose ps | sed 's/^/  /'
    else
        echo -e "${RED}✗ RustDesk containers are not running${NC}"
    fi
    echo ""
fi

# 7. Check nginx status (if running on the server)
if systemctl is-active --quiet nginx 2>/dev/null; then
    echo -e "${GREEN}✓ Nginx is running${NC}"
else
    echo -e "${RED}✗ Nginx is not running${NC}"
fi

# 8. Check certificate expiration
echo -e "${YELLOW}Checking certificate expiration${NC}"
if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
    expiry_date=$(openssl x509 -enddate -noout -in "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" | cut -d= -f2)
    echo "Certificate expires: $expiry_date"
    
    # Check if certificate expires in next 30 days
    if openssl x509 -checkend 2592000 -noout -in "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" >/dev/null; then
        echo -e "${GREEN}✓ Certificate is valid for more than 30 days${NC}"
    else
        echo -e "${YELLOW}⚠ Certificate expires within 30 days${NC}"
    fi
else
    echo -e "${RED}✗ Certificate file not found locally${NC}"
fi

echo ""
echo -e "${BLUE}=== Verification Complete ===${NC}"
echo ""
echo -e "${BLUE}If all checks pass, your RustDesk server should be accessible at:${NC}"
echo -e "${BLUE}  Main: https://$DOMAIN${NC}"
echo -e "${BLUE}  Client config: $DOMAIN:21116 (relay: $DOMAIN:21117)${NC}"