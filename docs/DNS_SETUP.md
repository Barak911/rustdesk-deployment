# DNS Setup for RustDesk Deployment

## Shared Domain Strategy

Both staging and production environments use the **same domain**: `danyel-remote.com`

### **Benefits of Shared Domain:**
- ✅ **No additional DNS setup** required
- ✅ **Same SSL certificate** for both environments
- ✅ **Simplified configuration** and maintenance
- ✅ **Cost effective** - single Elastic IP and domain

### **Domain Configuration**
- **Domain**: `danyel-remote.com`
- **Status**: ✅ Already configured
- **SSL**: Let's Encrypt automatic certificate
- **Usage**: Shared between staging and production (only one active at a time)

## Deployment Strategy

### **Environment Switching**
Since both environments share the same domain, only **one environment can be active at a time**:

1. **Staging Deployment**: Point `danyel-remote.com` to staging infrastructure
2. **Testing Phase**: Validate staging environment thoroughly
3. **Production Deployment**: Point `danyel-remote.com` to production infrastructure

### **Shared Elastic IP**
Both environments use the **same Elastic IP allocation**:

```json
{
  "ParameterKey": "EipAllocationId",
  "ParameterValue": "eipalloc-08ca6e6de8b21e7a8"
}
```

### **No Additional DNS Setup Required**

Since both environments use `danyel-remote.com`:
- ✅ **DNS already configured** correctly
- ✅ **SSL certificate** automatically managed
- ✅ **No subdomain creation** needed
- ✅ **Same Elastic IP** used for both environments

## SSL Certificate Requirements

### **Let's Encrypt Domain Validation**

Both domains need to be:
1. **Publicly resolvable** - DNS must return the correct IP
2. **Accessible on port 80** - For HTTP-01 challenge
3. **Valid domain ownership** - Must control DNS for the domain

### **Certificate Renewal**

- **Automatic renewal** every 90 days
- **Renewal process** uses HTTP-01 validation
- **Monitoring** included in deployment scripts

## Testing DNS Setup

### **Verify DNS Resolution**
```bash
# Test domain resolution (same for both environments)
nslookup danyel-remote.com
dig danyel-remote.com

# Should resolve to the Elastic IP: 51.16.78.234
```

### **Test HTTP Access**
```bash
# After deployment, test HTTP access (should redirect to HTTPS)
curl -I http://danyel-remote.com

# Should return 301/302 redirect to HTTPS
```

### **Verify SSL Certificate**
```bash
# Check SSL certificate (same for both environments)
openssl s_client -connect danyel-remote.com:443 -servername danyel-remote.com

# Should show valid Let's Encrypt certificate
```

## Troubleshooting DNS Issues

### **Common Problems**

#### **DNS Not Resolving**
```bash
# Check DNS propagation
dig @8.8.8.8 danyel-remote-staging.com
dig @1.1.1.1 danyel-remote-staging.com

# Wait for DNS propagation (up to 48 hours, usually much faster)
```

#### **Let's Encrypt Validation Failing**
```bash
# Check if domain points to correct IP
curl -I http://danyel-remote-staging.com/.well-known/acme-challenge/test

# Should return 404 (server responding) not connection refused
```

#### **Certificate Not Installing**
```bash
# Check CloudFormation logs
aws cloudformation describe-stack-events --stack-name rustdesk-staging

# Check EC2 instance logs
ssh -i your-key.pem ubuntu@staging-ip
sudo tail -f /opt/rustdesk/logs/ssl-setup.log
```

## Domain Alternatives

### **If You Can't Use danyel.co.il Subdomain**

You can use any domain you control:

```json
// Alternative staging domains:
"staging.yourdomain.com"
"rustdesk-staging.yourdomain.com"
"test-rustdesk.yourdomain.com"
```

Just update `parameters-staging.json`:
```json
{
  "ParameterKey": "SSLDomain",
  "ParameterValue": "your-staging-domain.com"
}
```

## Security Considerations

### **DNS Security**
- ✅ **DNSSEC** enabled if supported by provider
- ✅ **CAA records** to restrict certificate authorities
- ✅ **Short TTL** for faster updates during deployment

### **Certificate Security**
- ✅ **TLS 1.2+** only (configured in Nginx)
- ✅ **HSTS headers** for security
- ✅ **Automatic renewal** prevents expiration

## Next Steps

1. **Create staging Elastic IP**
2. **Add DNS A record** for danyel-remote-staging.com
3. **Update parameters-staging.json** with new EIP allocation ID
4. **Test DNS resolution** before deployment
5. **Deploy staging environment** and verify SSL

---

**Once DNS is configured correctly, both staging and production deployments will automatically obtain and maintain SSL certificates.**