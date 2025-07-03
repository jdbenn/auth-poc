#!/bin/bash
set -e  # Exit on error

# Build Java app
mvn clean package -DskipTests

# AWS ECR login
AWS_ACCOUNT_ID=042585258794
AWS_REGION=us-east-1
ECR_REPO=spring-idp-repo
PROFILE=sandbox

echo "Logging out of previous ECR session..."
docker logout ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com || true

echo "Logging in to ECR..."
aws ecr get-login-password --region ${AWS_REGION} --profile ${PROFILE} | \
docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Build Docker image for amd64 (for App Runner compatibility)
echo "Building Docker image for amd64..."
docker buildx build --platform linux/amd64 -t auth-app .

# Tag image for ECR
echo "Tagging image..."
docker tag auth-app:latest ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}:latest

# Push image
echo "Pushing image to ECR..."
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}:latest

echo "✅ Done"
