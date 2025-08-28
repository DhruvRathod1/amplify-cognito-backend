# Amplify Auth Backend

Authentication backend built with AWS SAM, featuring Cognito User Pool authentication with Google OAuth integration.

## Features

- User signup/signin with email & password
- Google OAuth authentication
- Token refresh
- JWT token verification
- Password reset flow

## Deployment Options

### Option 1: AWS Amplify Console (Recommended)

1. Push this repository to GitHub
2. Go to [AWS Amplify Console](https://console.aws.amazon.com/amplify/home)
3. Choose "Host web app" and connect your GitHub repository
4. Add required environment variables:
   - `DEPLOYMENT_BUCKET_NAME` - S3 bucket for deployment artifacts
   - `GOOGLE_CLIENT_ID` - Your Google OAuth client ID
   - `GOOGLE_CLIENT_SECRET` - Your Google OAuth client secret
   - `ALLOWED_ORIGINS` - Comma-separated list of allowed origins
   - `FRONTEND_URL` - Your frontend URL
   - `AWS_ACCESS_KEY_ID` - AWS access key with appropriate permissions
   - `AWS_SECRET_ACCESS_KEY` - AWS secret key
   - `AWS_REGION` - AWS region (e.g., ap-south-1)

### Option 2: GitHub Actions

This repository includes a GitHub Actions workflow that automatically deploys when you push to main.

1. Add the required secrets in your GitHub repository:
   - AWS_ACCESS_KEY_ID
   - AWS_SECRET_ACCESS_KEY
   - AWS_REGION
   - DEPLOYMENT_BUCKET_NAME
   - GOOGLE_CLIENT_ID
   - GOOGLE_CLIENT_SECRET
   - ALLOWED_ORIGINS
   - FRONTEND_URL

### Option 3: Manual Deployment

```bash
# Install dependencies
cd auth
npm install
cd ..

# Deploy with SAM CLI
sam build
sam deploy --guided