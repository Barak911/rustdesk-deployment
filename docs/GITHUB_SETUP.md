# GitHub Repository Setup Guide

Step-by-step instructions for setting up the RustDesk deployment repository with GitHub Actions CI/CD pipeline.

## 📋 **Prerequisites**

- GitHub account with repository creation permissions
- AWS account with appropriate IAM permissions
- Local Git installation
- AWS CLI configured with deployment credentials

## 🏗️ **Repository Creation**

### **Option 1: Fork Existing Repository (Recommended)**
```bash
# If the repository already exists, fork it
# Go to the repository URL and click "Fork"
# Clone your fork locally
git clone https://github.com/YOUR_USERNAME/rustdesk-deployment.git
cd rustdesk-deployment
```

### **Option 2: Create New Repository**
```bash
# Create new repository on GitHub
# Clone the empty repository
git clone https://github.com/YOUR_USERNAME/rustdesk-deployment.git
cd rustdesk-deployment

# Copy the rustdesk-deployment folder contents
# (This guide assumes you have the local structure ready)
```

## 🔧 **Initial Repository Setup**

### **1. Initialize Git Repository**
```bash
# If starting fresh
cd rustdesk-deployment
git init
git branch -M main

# Add all files
git add .
git commit -m "Initial commit: RustDesk deployment automation"

# Add remote and push
git remote add origin https://github.com/YOUR_USERNAME/rustdesk-deployment.git
git push -u origin main
```

### **2. Create Staging Branch**
```bash
# Create and push staging branch
git checkout -b staging
git push -u origin staging

# Switch back to main
git checkout main
```

### **3. Set Up Branch Protection**
Go to GitHub → Settings → Branches → Add rule:

**For `main` branch:**
- ✅ **Require pull request reviews before merging**
- ✅ **Require status checks to pass before merging**
- ✅ **Require branches to be up to date before merging**
- ✅ **Include administrators**

**For `staging` branch:**
- ✅ **Require status checks to pass before merging**
- ✅ **Require branches to be up to date before merging**

## 🔐 **Configure Secrets and Variables**

### **GitHub Repository Secrets**
Go to Settings → Secrets and variables → Actions → New repository secret

#### **Required Secrets:**
```
Name: AWS_ACCESS_KEY_ID
Value: AKIA...your-access-key

Name: AWS_SECRET_ACCESS_KEY
Value: your-secret-access-key

Name: GITHUB_TOKEN
Value: (auto-generated, usually not needed to set manually)
```

#### **How to Create AWS Keys:**
```bash
# Create IAM user for GitHub Actions
aws iam create-user --user-name github-actions-rustdesk

# Create access key
aws iam create-access-key --user-name github-actions-rustdesk

# Save the AccessKeyId and SecretAccessKey for GitHub secrets
```

### **GitHub Repository Variables**
Go to Settings → Secrets and variables → Actions → Variables tab

#### **Required Variables:**
```
Name: AWS_REGION
Value: il-central-1

Name: STAGING_S3_BUCKET
Value: rustdesk-staging

Name: PROD_S3_BUCKET
Value: rustdesk-s3-bak

Name: CLOUDFRONT_ID (Optional)
Value: your-cloudfront-distribution-id
```

## 🪣 **S3 Bucket Setup**

### **Create Staging Bucket**
```bash
# Create staging bucket
aws s3 mb s3://rustdesk-staging --region il-central-1

# Configure bucket for deployment
aws s3api put-bucket-versioning \
  --bucket rustdesk-staging \
  --versioning-configuration Status=Enabled

# Set up bucket policy for GitHub Actions access
aws s3api put-bucket-policy \
  --bucket rustdesk-staging \
  --policy file://staging-bucket-policy.json
```

**staging-bucket-policy.json:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GitHubActionsAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::YOUR_ACCOUNT_ID:user/github-actions-rustdesk"
      },
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::rustdesk-staging",
        "arn:aws:s3:::rustdesk-staging/*"
      ]
    }
  ]
}
```

### **Verify Production Bucket**
```bash
# Check if production bucket exists
aws s3 ls s3://rustdesk-s3-bak --region il-central-1

# If it doesn't exist, create it
aws s3 mb s3://rustdesk-s3-bak --region il-central-1
```

## 🔑 **IAM Permissions Setup**

### **Create IAM Policy for GitHub Actions**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3BucketAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::rustdesk-staging",
        "arn:aws:s3:::rustdesk-staging/*",
        "arn:aws:s3:::rustdesk-s3-bak",
        "arn:aws:s3:::rustdesk-s3-bak/*"
      ]
    },
    {
      "Sid": "CloudFormationAccess",
      "Effect": "Allow",
      "Action": [
        "cloudformation:CreateStack",
        "cloudformation:UpdateStack",
        "cloudformation:DeleteStack",
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SecretsManagerAccess",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": [
        "arn:aws:secretsmanager:il-central-1:*:secret:rustdesk/*"
      ]
    }
  ]
}
```

### **Attach Policy to User**
```bash
# Save policy as github-actions-policy.json
aws iam put-user-policy \
  --user-name github-actions-rustdesk \
  --policy-name RustDeskDeploymentPolicy \
  --policy-document file://github-actions-policy.json
```

## 🔒 **Secrets Manager Setup**

### **Create Email Password Secrets**
```bash
# Production secret (if not exists)
aws secretsmanager create-secret \
  --name "rustdesk/email-password" \
  --description "RustDesk Production SMTP Password" \
  --secret-string '{"password":"YOUR_EMAIL_PASSWORD"}' \
  --region il-central-1

# Staging secret
aws secretsmanager create-secret \
  --name "rustdesk/staging/email-password" \
  --description "RustDesk Staging SMTP Password" \
  --secret-string '{"password":"YOUR_EMAIL_PASSWORD"}' \
  --region il-central-1
```

## 🌍 **Environment Setup**

### **GitHub Environments**
Go to Settings → Environments

#### **Create 'staging' Environment:**
- **Environment name**: `staging`
- **Deployment branches**: `staging` branch only
- **Environment secrets**: (inherit from repository)

#### **Create 'prod' Environment:**
- **Environment name**: `prod`
- **Deployment branches**: `main` branch only
- **Environment protection rules**:
  - ✅ **Required reviewers**: Add yourself
  - ✅ **Wait timer**: 5 minutes (optional)
- **Environment secrets**: (inherit from repository)

## 🧪 **Test Initial Setup**

### **1. Test Staging Deployment**
```bash
# Make a small change
echo "# Test change" >> README.md
git add README.md
git commit -m "Test: trigger staging deployment"

# Push to staging branch
git checkout staging
git merge main
git push origin staging

# Check GitHub Actions tab for deployment status
```

### **2. Verify Staging Environment**
```bash
# Check if components were uploaded
aws s3 ls s3://rustdesk-staging/Components/ --recursive

# Should see all component files
```

### **3. Test Production Deployment**
```bash
# After staging is successful, deploy to production
git checkout main
git merge staging
git push origin main

# Check GitHub Actions for production deployment
```

## 📊 **Verify Setup**

### **GitHub Actions Checks**
- [ ] **Workflows appear** in Actions tab
- [ ] **Secrets configured** correctly
- [ ] **Variables set** with correct values
- [ ] **Branch protection** rules active
- [ ] **Environments configured** with appropriate restrictions

### **AWS Checks**
- [ ] **S3 buckets created** and accessible
- [ ] **IAM permissions** working correctly
- [ ] **Secrets Manager** secrets created
- [ ] **Components uploaded** to S3

### **Functionality Checks**
- [ ] **Staging deployment** works automatically
- [ ] **Production deployment** requires approval (if configured)
- [ ] **Component validation** passes in CI
- [ ] **Rollback procedure** tested

## 🔧 **Customization Options**

### **Notification Webhooks**
Add Slack or Discord webhooks for deployment notifications:

```yaml
# Add to workflow files
- name: Notify Slack
  if: always()
  uses: 8398a7/action-slack@v3
  with:
    status: ${{ job.status }}
    webhook_url: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### **Additional Environments**
Create development or QA environments:

```bash
# Create additional branch
git checkout -b development
git push -u origin development

# Add corresponding S3 bucket and GitHub environment
```

### **Custom Validation Rules**
Modify `.github/workflows/test-scripts.yml` to add:
- Custom security scanning
- Performance testing
- Integration tests
- Code coverage reports

## 🆘 **Troubleshooting**

### **Common Setup Issues**

#### **Workflow Permissions**
```bash
# If workflows don't trigger, check:
# Settings → Actions → General → Workflow permissions
# Ensure "Read and write permissions" is selected
```

#### **AWS Credential Issues**
```bash
# Test AWS access with configured credentials
aws sts get-caller-identity

# Should return the github-actions-rustdesk user
```

#### **S3 Access Problems**
```bash
# Test bucket access
aws s3 ls s3://rustdesk-staging/

# Check bucket policy and IAM permissions
```

### **Debug Steps**
1. **Check GitHub Actions logs** for detailed error messages
2. **Verify all secrets** are correctly named and valued
3. **Test AWS CLI access** with the same credentials
4. **Check CloudFormation** events for infrastructure issues
5. **Validate JSON files** locally before committing

## 📞 **Support**

### **Getting Help**
- **GitHub Issues**: Create issues for bugs or feature requests
- **Documentation**: Check the docs folder for additional guides
- **AWS Documentation**: Refer to AWS service documentation
- **Community**: GitHub Discussions for questions and sharing

### **Useful Commands**
```bash
# Check workflow status
gh workflow list
gh run list

# View workflow logs
gh run view <run-id> --log

# Re-run failed workflow
gh run rerun <run-id>
```

---

**Once setup is complete, you'll have a fully automated CI/CD pipeline for RustDesk deployment with staging and production environments!**