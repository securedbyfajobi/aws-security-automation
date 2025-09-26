#!/bin/bash

# AWS Security Automation Deployment Script
# Usage: ./scripts/deploy.sh [environment] [region]

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENVIRONMENT="${1:-prod}"
AWS_REGION="${2:-eu-west-2}"
PROJECT_NAME="aws-security-automation"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup function
cleanup() {
    log_info "Performing cleanup..."
    # Add any cleanup tasks here
}
trap cleanup EXIT

# Validation functions
validate_prerequisites() {
    log_info "Validating prerequisites..."

    # Check required tools
    local required_tools=("aws" "terraform" "docker" "jq")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "$tool is required but not installed"
            exit 1
        fi
    done

    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured or invalid"
        exit 1
    fi

    # Check Docker daemon
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi

    log_success "Prerequisites validated"
}

validate_environment() {
    log_info "Validating environment: $ENVIRONMENT"

    case "$ENVIRONMENT" in
        dev|staging|prod)
            log_success "Environment '$ENVIRONMENT' is valid"
            ;;
        *)
            log_error "Invalid environment '$ENVIRONMENT'. Use: dev, staging, or prod"
            exit 1
            ;;
    esac
}

# Build and push Docker image
build_and_push_image() {
    log_info "Building and pushing Docker image..."

    local image_tag="${PROJECT_NAME}:${ENVIRONMENT}-$(git rev-parse --short HEAD)"
    local latest_tag="${PROJECT_NAME}:${ENVIRONMENT}-latest"

    # Build image
    docker build -t "$image_tag" -t "$latest_tag" "$PROJECT_ROOT"

    # Get ECR repository URI (assuming ECR is used)
    local account_id=$(aws sts get-caller-identity --query Account --output text)
    local ecr_uri="${account_id}.dkr.ecr.${AWS_REGION}.amazonaws.com"

    # Login to ECR
    aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$ecr_uri"

    # Tag and push to ECR
    docker tag "$image_tag" "${ecr_uri}/${image_tag}"
    docker tag "$latest_tag" "${ecr_uri}/${latest_tag}"

    docker push "${ecr_uri}/${image_tag}"
    docker push "${ecr_uri}/${latest_tag}"

    log_success "Image built and pushed: ${ecr_uri}/${image_tag}"
    echo "${ecr_uri}/${image_tag}" > "${PROJECT_ROOT}/.latest_image"
}

# Deploy infrastructure with Terraform
deploy_infrastructure() {
    log_info "Deploying infrastructure with Terraform..."

    cd "${PROJECT_ROOT}/terraform"

    # Initialize Terraform
    terraform init -upgrade

    # Create workspace if it doesn't exist
    terraform workspace select "$ENVIRONMENT" 2>/dev/null || terraform workspace new "$ENVIRONMENT"

    # Plan deployment
    terraform plan \
        -var="environment=$ENVIRONMENT" \
        -var="aws_region=$AWS_REGION" \
        -out="tfplan-$ENVIRONMENT"

    # Apply deployment
    terraform apply -auto-approve "tfplan-$ENVIRONMENT"

    # Output important values
    terraform output -json > "${PROJECT_ROOT}/terraform-outputs.json"

    log_success "Infrastructure deployed successfully"
}

# Deploy application
deploy_application() {
    log_info "Deploying application..."

    local cluster_name="${PROJECT_NAME}-${ENVIRONMENT}"
    local service_name="${PROJECT_NAME}"
    local image_uri=$(cat "${PROJECT_ROOT}/.latest_image")

    # Update ECS service with new image
    aws ecs update-service \
        --cluster "$cluster_name" \
        --service "$service_name" \
        --force-new-deployment \
        --region "$AWS_REGION"

    # Wait for deployment to complete
    log_info "Waiting for deployment to stabilize..."
    aws ecs wait services-stable \
        --cluster "$cluster_name" \
        --services "$service_name" \
        --region "$AWS_REGION"

    log_success "Application deployed successfully"
}

# Deploy monitoring stack
deploy_monitoring() {
    log_info "Deploying monitoring stack..."

    # Deploy Prometheus and Grafana using docker-compose
    cd "$PROJECT_ROOT"

    # Set environment variables
    export ENVIRONMENT
    export AWS_REGION

    # Deploy monitoring stack
    docker-compose -f docker-compose.monitoring.yml up -d

    log_success "Monitoring stack deployed"
}

# Run health checks
run_health_checks() {
    log_info "Running health checks..."

    local cluster_name="${PROJECT_NAME}-${ENVIRONMENT}"
    local service_name="${PROJECT_NAME}"

    # Check ECS service health
    local running_count=$(aws ecs describe-services \
        --cluster "$cluster_name" \
        --services "$service_name" \
        --query 'services[0].runningCount' \
        --output text \
        --region "$AWS_REGION")

    local desired_count=$(aws ecs describe-services \
        --cluster "$cluster_name" \
        --services "$service_name" \
        --query 'services[0].desiredCount' \
        --output text \
        --region "$AWS_REGION")

    if [ "$running_count" -eq "$desired_count" ]; then
        log_success "ECS service health check passed ($running_count/$desired_count tasks running)"
    else
        log_error "ECS service health check failed ($running_count/$desired_count tasks running)"
        return 1
    fi

    # Additional health checks can be added here
    # - API endpoint checks
    # - Database connectivity
    # - External service dependencies

    log_success "All health checks passed"
}

# Generate deployment report
generate_deployment_report() {
    log_info "Generating deployment report..."

    local report_file="${PROJECT_ROOT}/deployment-report-${ENVIRONMENT}-$(date +%Y%m%d-%H%M%S).json"

    cat > "$report_file" << EOF
{
  "deployment": {
    "environment": "$ENVIRONMENT",
    "region": "$AWS_REGION",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "git_commit": "$(git rev-parse HEAD)",
    "git_branch": "$(git rev-parse --abbrev-ref HEAD)",
    "deployed_by": "$(whoami)",
    "image_uri": "$(cat "${PROJECT_ROOT}/.latest_image" 2>/dev/null || echo "not-available")"
  },
  "terraform_outputs": $(cat "${PROJECT_ROOT}/terraform-outputs.json" 2>/dev/null || echo "{}"),
  "deployment_status": "success"
}
EOF

    log_success "Deployment report generated: $report_file"
}

# Rollback function
rollback_deployment() {
    log_warning "Rolling back deployment..."

    local cluster_name="${PROJECT_NAME}-${ENVIRONMENT}"
    local service_name="${PROJECT_NAME}"

    # Get previous task definition
    local previous_task_def=$(aws ecs describe-services \
        --cluster "$cluster_name" \
        --services "$service_name" \
        --query 'services[0].taskDefinition' \
        --output text \
        --region "$AWS_REGION")

    # Rollback to previous version (this is a simplified example)
    log_warning "Manual rollback required. Previous task definition: $previous_task_def"

    # In a real scenario, you would:
    # 1. Get the previous stable image tag
    # 2. Update the task definition
    # 3. Update the service
}

# Main deployment function
main() {
    log_info "Starting deployment of $PROJECT_NAME to $ENVIRONMENT environment in $AWS_REGION"

    # Validation
    validate_prerequisites
    validate_environment

    # Deployment steps
    if ! build_and_push_image; then
        log_error "Image build failed"
        exit 1
    fi

    if ! deploy_infrastructure; then
        log_error "Infrastructure deployment failed"
        rollback_deployment
        exit 1
    fi

    if ! deploy_application; then
        log_error "Application deployment failed"
        rollback_deployment
        exit 1
    fi

    if ! run_health_checks; then
        log_error "Health checks failed"
        rollback_deployment
        exit 1
    fi

    # Optional: Deploy monitoring (only for prod)
    if [ "$ENVIRONMENT" = "prod" ]; then
        deploy_monitoring
    fi

    generate_deployment_report

    log_success "Deployment completed successfully!"
    log_info "Environment: $ENVIRONMENT"
    log_info "Region: $AWS_REGION"
    log_info "Git commit: $(git rev-parse --short HEAD)"
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi