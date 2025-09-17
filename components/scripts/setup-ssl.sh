#!/bin/bash
# -----------------------------------------------------------------------------
# RustDesk SSL Setup Script for Let's Encrypt
# This script sets up SSL certificates for RustDesk server using Let's Encrypt
# -----------------------------------------------------------------------------

set -euo pipefail

# Configuration
DOMAIN="danyel-remote.com"
EMAIL="barak@danyel.co.il"  # Update this with your actual email
RUSTDESK_DIR="/opt/rustdesk"
NGINX_DIR="/etc/nginx"
CERT_DIR="/etc/letsencrypt/live/$DOMAIN"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== RustDesk SSL Setup for $DOMAIN ===${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Update system packages
echo -e "${YELLOW}Updating system packages...${NC}"
apt update

# Install required packages
echo -e "${YELLOW}Installing required packages...${NC}"
apt install -y nginx certbot python3-certbot-nginx ufw

# Stop nginx temporarily for certificate generation
echo -e "${YELLOW}Stopping nginx temporarily...${NC}"
systemctl stop nginx 2>/dev/null || true

# Configure firewall
echo -e "${YELLOW}Configuring firewall...${NC}"
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 21114:21119/tcp
ufw allow 21116:21117/udp
echo "y" | ufw enable

# Obtain SSL certificate using standalone mode
echo -e "${YELLOW}Obtaining SSL certificate for $DOMAIN...${NC}"
certbot certonly --standalone \
    --non-interactive \
    --agree-tos \
    --email "$EMAIL" \
    -d "$DOMAIN"

# Create nginx configuration for RustDesk
echo -e "${YELLOW}Creating nginx configuration...${NC}"
cat > "$NGINX_DIR/sites-available/rustdesk" << 'EOF'
server {
    listen 80;
    server_name danyel-remote.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name danyel-remote.com;
    
    ssl_certificate /etc/letsencrypt/live/danyel-remote.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/danyel-remote.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    
    # Main status page
    location = / {
        root /var/www/html;
        try_files /index.html =404;
    }
    
    # Proxy ALL requests to /static/ and sub-paths to RustDesk console
    location /static/ {
        proxy_pass http://localhost:21114/static/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        proxy_cache off;
    }
    
    # Proxy API calls that the console needs
    location /api/ {
        proxy_pass http://localhost:21114/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        proxy_cache off;
    }
    
    # Proxy WebSocket connections
    location /ws {
        proxy_pass http://localhost:21114/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Handle trailing slashes on API endpoints (redirect to no-slash version)
    location ~ ^/(status\.json|refresh|historical-metrics)/$ {
        return 301 $scheme://$server_name$1;
    }
    
    # Dashboard API endpoints - direct root access
    location /historical-metrics {
        proxy_pass http://localhost:8080/historical-metrics;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /status.json {
        proxy_pass http://localhost:8080/status.json;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /refresh {
        proxy_pass http://localhost:8080/refresh;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # RustDesk console - complete proxy
    location /console/ {
        proxy_pass http://localhost:21114/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        proxy_cache off;
    }
    
    location /console {
        return 301 https://$server_name/console/;
    }
    
    # Server status dashboard  
    location /status/ {
        proxy_pass http://localhost:8080/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /status {
        return 301 https://$server_name/status/;
    }
    
    # Monitoring with auth
    location /monitoring {
        auth_basic "RustDesk Monitoring";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://localhost:8080/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

# Enable the site
ln -sf "$NGINX_DIR/sites-available/rustdesk" "$NGINX_DIR/sites-enabled/"
rm -f "$NGINX_DIR/sites-enabled/default"

# Test nginx configuration
echo -e "${YELLOW}Testing nginx configuration...${NC}"
nginx -t

# Start nginx
echo -e "${YELLOW}Starting nginx...${NC}"
systemctl start nginx
systemctl enable nginx

# Create SSL certificate renewal script
echo -e "${YELLOW}Setting up SSL certificate auto-renewal...${NC}"
cat > /opt/rustdesk/renew-ssl.sh << 'EOF'
#!/bin/bash
# Auto-renewal script for RustDesk SSL certificates

# Renew certificates
certbot renew --quiet --nginx

# Restart services if certificates were renewed
if [ $? -eq 0 ]; then
    systemctl reload nginx
    echo "$(date): SSL certificates renewed successfully" >> /opt/rustdesk/logs/ssl-renewal.log
else
    echo "$(date): SSL certificate renewal failed" >> /opt/rustdesk/logs/ssl-renewal.log
fi
EOF

chmod +x /opt/rustdesk/renew-ssl.sh

# Add to crontab for automatic renewal
(crontab -l 2>/dev/null; echo "0 3 * * 0 /opt/rustdesk/renew-ssl.sh") | crontab -

# Create monitoring password file (optional)
echo -e "${YELLOW}Setting up monitoring authentication...${NC}"
htpasswd -bc "$NGINX_DIR/.htpasswd" admin rustdesk123

# Create status page
echo -e "${YELLOW}Creating status page...${NC}"
mkdir -p /var/www/html
cat > /var/www/html/index.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <title>RustDesk Server - danyel-remote.com</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .status { color: #28a745; font-weight: bold; }
        .config { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; }
        .code { font-family: monospace; background: #e9ecef; padding: 2px 5px; border-radius: 3px; }
        .btn { display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; margin: 5px; }
        .btn:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🖥️ RustDesk Server</h1>
        <h2>Domain: danyel-remote.com</h2>
        <p class="status">✅ SSL Certificate Active</p>
        <p class="status">✅ Server Running</p>
        
        <div class="config">
            <h3>Client Configuration:</h3>
            <p><strong>Server:</strong> <span class="code">danyel-remote.com:21116</span></p>
            <p><strong>Relay:</strong> <span class="code">danyel-remote.com:21117</span></p>
            <p><strong>Web Access:</strong> <span class="code">https://danyel-remote.com</span></p>
        </div>
        
        <div class="config">
            <h3>Management Links:</h3>
            <a href="/static/index.html" class="btn">🎛️ RustDesk Console</a>
            <a href="/console/" class="btn">🎛️ Console (Alt)</a>
            <a href="/status/" class="btn">📊 Server Status</a>
            <a href="/monitoring" class="btn">📈 Monitoring Dashboard</a>
        </div>
        
        <div class="config">
            <h3>Direct Access:</h3>
            <p>RustDesk Console: <a href="/static/index.html">https://danyel-remote.com/static/index.html</a></p>
            <p>Server Status: <a href="/status/">https://danyel-remote.com/status/</a></p>
        </div>
        
        <p><small>Powered by RustDesk Server Pro with Let's Encrypt SSL</small></p>
    </div>
</body>
</html>
HTMLEOF

# Update RustDesk environment to use SSL
if [ -f "$RUSTDESK_DIR/rustdesk.env" ]; then
    echo -e "${YELLOW}Updating RustDesk configuration for SSL...${NC}"
    
    # Add SSL configuration to environment file
    if ! grep -q "SSL_ENABLED" "$RUSTDESK_DIR/rustdesk.env"; then
        cat >> "$RUSTDESK_DIR/rustdesk.env" << EOF

# SSL Configuration
SSL_ENABLED=true
SSL_DOMAIN=$DOMAIN
SSL_CERT_PATH=$CERT_DIR/fullchain.pem
SSL_KEY_PATH=$CERT_DIR/privkey.pem
NGINX_ENABLED=true
EOF
    fi
fi

# Restart RustDesk containers to apply SSL configuration
echo -e "${YELLOW}Restarting RustDesk services...${NC}"
cd "$RUSTDESK_DIR"
if [ -f "docker-compose.yml" ]; then
    docker-compose down
    docker-compose up -d
fi

# Display status
echo -e "${GREEN}=== SSL Setup Complete ===${NC}"
echo -e "${GREEN}✓ SSL certificate obtained for $DOMAIN${NC}"
echo -e "${GREEN}✓ Nginx configured with SSL${NC}"
echo -e "${GREEN}✓ Auto-renewal configured${NC}"
echo -e "${GREEN}✓ Firewall configured${NC}"
echo ""
echo -e "${BLUE}Access your RustDesk server at:${NC}"
echo -e "${BLUE}  HTTPS: https://$DOMAIN${NC}"
echo -e "${BLUE}  Monitoring: https://$DOMAIN/monitoring${NC}"
echo -e "${BLUE}  Monitoring credentials: admin / rustdesk123${NC}"
echo ""
echo -e "${YELLOW}RustDesk Client Configuration:${NC}"
echo -e "${YELLOW}  Server: $DOMAIN:21116${NC}"
echo -e "${YELLOW}  Relay: $DOMAIN:21117${NC}"
echo -e "${YELLOW}  Web: https://$DOMAIN${NC}"
echo ""
echo -e "${BLUE}Certificate will auto-renew every Sunday at 3 AM${NC}"

# Check certificate status
echo -e "${YELLOW}Certificate information:${NC}"
certbot certificates

echo -e "${GREEN}Setup completed successfully!${NC}"