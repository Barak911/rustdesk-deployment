# RustDesk Deployment Automation

Professional DevOps pipeline for deploying and managing RustDesk servers with automated CI/CD, monitoring, and multi-environment support.

## 🚀 **Quick Start**

### Prerequisites
- AWS Account with appropriate permissions
- GitHub repository access
- S3 buckets for staging and production

### 1. Fork and Configure
```bash
# Fork this repository to your GitHub account
# Configure repository secrets and variables (see setup guide below)
```

### 2. Deploy to Staging
```bash
# Push to staging branch to deploy to staging environment
git checkout -b staging
git push origin staging
```

### 3. Deploy to Production
```bash
# Merge staging to main for production deployment
git checkout main
git merge staging
git push origin main
```

## 📁 **Repository Structure**

```
rustdesk-deployment/
├── .github/workflows/          # GitHub Actions CI/CD pipelines
│   ├── deploy-components.yml   # Automated deployment
│   ├── test-scripts.yml       # Validation and testing
│   └── release.yml            # Release management
├── components/                 # RustDesk deployment components
│   ├── scripts/               # Core scripts (env-loader, monitor, email)
│   ├── web/                   # Dashboard and web interface
│   ├── systemd/               # Service definitions
│   ├── configs/               # Configuration files
│   └── utils/                 # Backup and status utilities
├── bootstrap/                  # Deployment bootstrap script
├── cloudformation/            # Infrastructure as Code
│   ├── template-docker-enhanced.yaml
│   ├── parameters-staging.json
│   └── parameters-prod.json
└── docs/                      # Documentation
```

## 🔧 **Features**

### ✅ **CI/CD Pipeline**
- **Automated Testing**: Script validation, syntax checking, security scanning
- **Multi-Environment**: Separate staging and production deployments
- **Rollback Support**: Easy reversion to previous versions
- **Release Management**: Automated versioning and changelog generation

### ✅ **Infrastructure**
- **AWS CloudFormation**: Complete infrastructure as code
- **Auto-scaling Components**: Modular, reusable deployment components
- **Environment Isolation**: Separate staging and production resources
- **Security Best Practices**: Secrets management, encrypted communication

### ✅ **Monitoring & Alerting**
- **Real-time Dashboard**: Web interface for server monitoring
- **Auto-remediation**: Self-healing for common issues
- **Email Alerts**: Severity-based notification system
- **CloudWatch Integration**: AWS native monitoring

### ✅ **Backup & Recovery**
- **Automated Backups**: Daily encrypted backups to S3
- **Point-in-time Recovery**: Restore from any backup
- **Cross-environment Restore**: Copy data between staging/prod

## 🌍 **Environment Strategy**

### **Staging Environment**
- **Purpose**: Testing and validation
- **Branch**: `staging`
- **S3 Bucket**: `rustdesk-staging`
- **Domain**: `DOMAIN-staging.com`
- **Instance**: `t3a.micro`
- **SSL**: Enabled with Let's Encrypt

### **Production Environment**
- **Purpose**: Live RustDesk service
- **Branch**: `main`
- **S3 Bucket**: `rustdesk-s3-bak`
- **Domain**: `DOMAIN.com`
- **Instance**: `t3a.micro`
- **SSL**: Enabled with Let's Encrypt

## ⚙️ **Setup Instructions**

### 1. **GitHub Repository Setup**

#### Required Secrets
Configure in GitHub Settings → Secrets and variables → Actions:

```
Secrets:
├── AWS_ACCESS_KEY_ID          # AWS access key for deployments
├── AWS_SECRET_ACCESS_KEY      # AWS secret key
└── GITHUB_TOKEN              # Auto-generated, used for releases
```

#### Required Variables
```
Variables:
├── AWS_REGION                 # il-central-1
├── STAGING_S3_BUCKET         # rustdesk-staging
├── PROD_S3_BUCKET            # rustdesk-s3-bak
└── CLOUDFRONT_ID             # (optional) for cache invalidation
```

### 2. **AWS Setup**

#### S3 Buckets
```bash
# Create staging bucket
aws s3 mb s3://rustdesk-staging --region il-central-1

# Create production bucket (if not exists)
aws s3 ls s3://rustdesk-s3-bak --region il-central-1
```

#### Secrets Manager
```bash
# Create staging email password secret
aws secretsmanager create-secret \
  --name "rustdesk/staging/email-password" \
  --description "RustDesk Staging SMTP Password" \
  --secret-string '{"password":"YOUR_EMAIL_PASSWORD"}' \
  --region il-central-1

# Production secret should already exist
aws secretsmanager describe-secret \
  --secret-id "rustdesk/email-password" \
  --region il-central-1
```

#### IAM Permissions
Ensure the AWS credentials have:
- `s3:*` on rustdesk buckets
- `secretsmanager:GetSecretValue` on email secrets
- `ec2:*` for instance management
- `cloudformation:*` for stack operations

## 🔄 **Deployment Workflow**

### **Development Process**
1. **Feature Development**: Create feature branch from `staging`
2. **Testing**: Push to feature branch → triggers validation
3. **Staging Deployment**: Merge to `staging` → deploys to staging
4. **Production Release**: Merge `staging` to `main` → deploys to production

### **Automated Actions**
- **On Push to Staging**: Deploy to staging environment
- **On Push to Main**: Deploy to production environment
- **On Pull Request**: Run validation tests
- **On Tag Creation**: Create GitHub release with assets

### **Manual Actions**
- **Emergency Deploy**: Use workflow_dispatch for immediate deployment
- **Rollback**: Revert commit or redeploy previous tag
- **Release Creation**: Tag main branch for versioned releases

## 🧪 **Testing & Validation**

### **Automated Tests**
- **Shellcheck**: Shell script validation
- **Python Syntax**: Python script compilation
- **JSON Validation**: Configuration file validation
- **Security Scanning**: Secret detection and security checks
- **Component Count**: Ensure all components are present

### **Manual Testing**
```bash
# Test staging deployment
curl https://DOMAIN-staging.com:8080

# Test production deployment
curl https://DOMAIN.com:8080

# Check RustDesk connectivity
telnet DOMAIN.com 21116
```

## 📊 **Monitoring & Observability**

### **Web Dashboard**
- **Staging**: `https://DOMAIN-staging.com/monitoring`
- **Production**: `https://DOMAIN.com/monitoring`

### **CloudWatch Metrics**
- Custom RustDesk metrics in `RustDesk/Application` namespace
- System metrics in `RustDesk/System` namespace
- Automated alerting for threshold breaches

### **Logs**
- **Deployment**: GitHub Actions logs
- **Application**: `/opt/rustdesk/logs/` on EC2 instances
- **System**: CloudWatch Logs and VPC Flow Logs

## 🛡️ **Security**

### **Best Practices Implemented**
- ✅ **No Secrets in Code**: All credentials in GitHub Secrets or AWS Secrets Manager
- ✅ **Encrypted Storage**: S3 server-side encryption for backups
- ✅ **Access Control**: IAM least-privilege permissions
- ✅ **Network Security**: VPC, security groups, and SSL/TLS
- ✅ **Audit Trail**: All deployments and changes tracked in Git

### **Security Scanning**
- **Code Scanning**: Automated security vulnerability detection
- **Secret Detection**: Prevents accidental credential commits
- **Dependency Scanning**: Monitors for vulnerable dependencies

## 🆘 **Troubleshooting**

### **Common Issues**

#### Deployment Failures
```bash
# Check GitHub Actions logs
# View CloudFormation events in AWS console
# Check S3 bucket permissions
```

#### Application Issues
```bash
# SSH to instance
ssh -i your-key.pem ubuntu@server-ip

# Check logs
sudo tail -f /opt/rustdesk/logs/rustdesk-bootstrap.log

# Check services
sudo systemctl status rustdesk-monitor rustdesk-monitoring.timer
```

#### Component Download Failures
```bash
# Test S3 access from EC2
aws s3 ls s3://rustdesk-staging/Components/

# Check IAM permissions
aws sts get-caller-identity
```

### **Support Contacts**
- **Technical Issues**: Check GitHub Issues
- **Infrastructure**: AWS Support
- **Security**: Follow security reporting guidelines

## 📈 **Roadmap**

### **Planned Enhancements**
- [ ] **Multi-region Deployment**: Support for multiple AWS regions
- [ ] **Blue-Green Deployments**: Zero-downtime deployment strategy
- [ ] **Enhanced Monitoring**: Prometheus/Grafana integration
- [ ] **Load Balancing**: Support for multiple RustDesk instances
- [ ] **Container Orchestration**: Kubernetes deployment option

### **Current Version**: v1.3
### **Last Updated**: 2024-12-17
### **Maintained by**: Barak Mooki

---

**Ready to deploy?** Follow the setup instructions above and start with a staging deployment to validate your configuration!
