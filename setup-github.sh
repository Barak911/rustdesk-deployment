#!/bin/bash
# GitHub Repository Setup Script
# Run this script to initialize the GitHub repository and push to remote

set -e

echo "🚀 RustDesk Deployment - GitHub Setup"
echo "======================================"

# Check if we're in the right directory
if [ ! -f ".github/workflows/deploy-components.yml" ]; then
    echo "❌ Error: Please run this script from the rustdesk-deployment directory"
    exit 1
fi

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "❌ Error: Git is not installed. Please install Git first."
    exit 1
fi

# Get repository URL from user
read -p "Enter your GitHub repository URL (e.g., https://github.com/username/rustdesk-deployment.git): " REPO_URL

if [ -z "$REPO_URL" ]; then
    echo "❌ Error: Repository URL is required"
    exit 1
fi

echo ""
echo "📋 Setting up Git repository..."

# Initialize git if not already done
if [ ! -d ".git" ]; then
    git init
    echo "✅ Git repository initialized"
else
    echo "✅ Git repository already exists"
fi

# Set main as default branch
git branch -M main

# Add all files
echo "📦 Adding all files to Git..."
git add .

# Create initial commit
if git diff --cached --quiet; then
    echo "ℹ️  No changes to commit"
else
    git commit -m "Initial commit: RustDesk deployment automation

- Complete CI/CD pipeline with GitHub Actions
- Multi-environment support (staging/production)
- Automated component validation and deployment
- Comprehensive monitoring and backup system
- Infrastructure as Code with CloudFormation
- Security best practices and secrets management"
    echo "✅ Initial commit created"
fi

# Add remote origin
if git remote get-url origin &> /dev/null; then
    echo "ℹ️  Remote origin already exists"
    git remote set-url origin "$REPO_URL"
    echo "✅ Updated remote origin URL"
else
    git remote add origin "$REPO_URL"
    echo "✅ Added remote origin"
fi

# Push main branch
echo "🚀 Pushing to main branch..."
git push -u origin main

# Create and push staging branch
echo "🌿 Creating staging branch..."
git checkout -b staging
git push -u origin staging

# Switch back to main
git checkout main

echo ""
echo "🎉 GitHub repository setup complete!"
echo ""
echo "📋 Next Steps:"
echo "1. Go to your GitHub repository: ${REPO_URL%.git}"
echo "2. Configure repository secrets and variables (see docs/GITHUB_SETUP.md)"
echo "3. Set up branch protection rules"
echo "4. Configure AWS S3 buckets and IAM permissions"
echo "5. Test the CI/CD pipeline by pushing to staging branch"
echo ""
echo "📚 Documentation:"
echo "- README.md - Project overview and quick start"
echo "- docs/GITHUB_SETUP.md - Detailed setup instructions"
echo "- docs/DEVOPS_GUIDE.md - DevOps practices and maintenance"
echo ""
echo "✅ Repository URL: ${REPO_URL%.git}"