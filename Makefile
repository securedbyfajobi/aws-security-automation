# AWS Security Automation Makefile
# Simplifies common development and deployment tasks

.PHONY: help setup test lint build deploy clean docker-build docker-push terraform-plan terraform-apply

# Variables
PROJECT_NAME := aws-security-automation
ENVIRONMENT ?= dev
AWS_REGION ?= eu-west-2
PYTHON_VERSION := 3.11
TERRAFORM_DIR := terraform
DOCKER_IMAGE := $(PROJECT_NAME)

# Colors
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

# Default target
help: ## Show this help message
	@echo "$(BLUE)AWS Security Automation - Available Commands$(NC)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Setup & Development
setup: ## Install dependencies and setup development environment
	@echo "$(BLUE)Setting up development environment...$(NC)"
	pip install --upgrade pip
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	pre-commit install
	@echo "$(GREEN)✓ Development environment ready$(NC)"

venv: ## Create and activate virtual environment
	@echo "$(BLUE)Creating virtual environment...$(NC)"
	python$(PYTHON_VERSION) -m venv venv
	@echo "$(GREEN)✓ Virtual environment created$(NC)"
	@echo "$(YELLOW)Run: source venv/bin/activate$(NC)"

install: ## Install project dependencies
	@echo "$(BLUE)Installing dependencies...$(NC)"
	pip install -r requirements.txt
	@echo "$(GREEN)✓ Dependencies installed$(NC)"

install-dev: ## Install development dependencies
	@echo "$(BLUE)Installing development dependencies...$(NC)"
	pip install -r requirements-dev.txt
	@echo "$(GREEN)✓ Development dependencies installed$(NC)"

##@ Code Quality
format: ## Format code with black and isort
	@echo "$(BLUE)Formatting code...$(NC)"
	black .
	isort .
	@echo "$(GREEN)✓ Code formatted$(NC)"

lint: ## Run linting checks
	@echo "$(BLUE)Running linting checks...$(NC)"
	flake8 --max-line-length=88 --extend-ignore=E203,W503 .
	pylint **/*.py || true
	mypy . || true
	@echo "$(GREEN)✓ Linting complete$(NC)"

security-scan: ## Run security scans
	@echo "$(BLUE)Running security scans...$(NC)"
	bandit -r . -x tests/
	safety check
	semgrep --config=auto . || true
	@echo "$(GREEN)✓ Security scan complete$(NC)"

pre-commit: ## Run pre-commit hooks
	@echo "$(BLUE)Running pre-commit hooks...$(NC)"
	pre-commit run --all-files
	@echo "$(GREEN)✓ Pre-commit hooks passed$(NC)"

##@ Testing
test: ## Run unit tests
	@echo "$(BLUE)Running unit tests...$(NC)"
	pytest tests/ -v --tb=short
	@echo "$(GREEN)✓ Tests completed$(NC)"

test-coverage: ## Run tests with coverage report
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	pytest tests/ --cov=. --cov-report=term-missing --cov-report=html
	@echo "$(GREEN)✓ Coverage report generated$(NC)"

test-integration: ## Run integration tests
	@echo "$(BLUE)Running integration tests...$(NC)"
	pytest tests/integration/ -v --tb=short
	@echo "$(GREEN)✓ Integration tests completed$(NC)"

##@ Docker
docker-build: ## Build Docker image
	@echo "$(BLUE)Building Docker image...$(NC)"
	docker build -t $(DOCKER_IMAGE):latest .
	docker build -t $(DOCKER_IMAGE):$(ENVIRONMENT) .
	@echo "$(GREEN)✓ Docker image built$(NC)"

docker-run: ## Run Docker container locally
	@echo "$(BLUE)Running Docker container...$(NC)"
	docker run -d --name $(PROJECT_NAME) \
		-e AWS_REGION=$(AWS_REGION) \
		-e ENVIRONMENT=$(ENVIRONMENT) \
		-v ~/.aws:/home/security/.aws:ro \
		$(DOCKER_IMAGE):latest
	@echo "$(GREEN)✓ Container started$(NC)"

docker-stop: ## Stop Docker container
	@echo "$(BLUE)Stopping Docker container...$(NC)"
	docker stop $(PROJECT_NAME) || true
	docker rm $(PROJECT_NAME) || true
	@echo "$(GREEN)✓ Container stopped$(NC)"

docker-logs: ## View Docker container logs
	docker logs -f $(PROJECT_NAME)

docker-compose-up: ## Start all services with docker-compose
	@echo "$(BLUE)Starting services with docker-compose...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)✓ Services started$(NC)"

docker-compose-down: ## Stop all services with docker-compose
	@echo "$(BLUE)Stopping services with docker-compose...$(NC)"
	docker-compose down
	@echo "$(GREEN)✓ Services stopped$(NC)"

##@ Terraform
terraform-init: ## Initialize Terraform
	@echo "$(BLUE)Initializing Terraform...$(NC)"
	cd $(TERRAFORM_DIR) && terraform init -upgrade
	@echo "$(GREEN)✓ Terraform initialized$(NC)"

terraform-fmt: ## Format Terraform files
	@echo "$(BLUE)Formatting Terraform files...$(NC)"
	cd $(TERRAFORM_DIR) && terraform fmt -recursive
	@echo "$(GREEN)✓ Terraform files formatted$(NC)"

terraform-validate: ## Validate Terraform configuration
	@echo "$(BLUE)Validating Terraform configuration...$(NC)"
	cd $(TERRAFORM_DIR) && terraform validate
	@echo "$(GREEN)✓ Terraform configuration valid$(NC)"

terraform-plan: terraform-init ## Create Terraform execution plan
	@echo "$(BLUE)Creating Terraform plan for $(ENVIRONMENT)...$(NC)"
	cd $(TERRAFORM_DIR) && terraform workspace select $(ENVIRONMENT) || terraform workspace new $(ENVIRONMENT)
	cd $(TERRAFORM_DIR) && terraform plan \
		-var="environment=$(ENVIRONMENT)" \
		-var="aws_region=$(AWS_REGION)" \
		-out=tfplan-$(ENVIRONMENT)
	@echo "$(GREEN)✓ Terraform plan created$(NC)"

terraform-apply: ## Apply Terraform changes
	@echo "$(BLUE)Applying Terraform changes...$(NC)"
	cd $(TERRAFORM_DIR) && terraform apply -auto-approve tfplan-$(ENVIRONMENT)
	@echo "$(GREEN)✓ Terraform changes applied$(NC)"

terraform-destroy: ## Destroy Terraform resources (BE CAREFUL!)
	@echo "$(RED)⚠️  This will destroy all resources in $(ENVIRONMENT)!$(NC)"
	@read -p "Are you sure? Type 'yes' to continue: " confirm && [ "$$confirm" = "yes" ]
	cd $(TERRAFORM_DIR) && terraform workspace select $(ENVIRONMENT)
	cd $(TERRAFORM_DIR) && terraform destroy \
		-var="environment=$(ENVIRONMENT)" \
		-var="aws_region=$(AWS_REGION)"
	@echo "$(GREEN)✓ Resources destroyed$(NC)"

terraform-output: ## Show Terraform outputs
	@echo "$(BLUE)Terraform outputs for $(ENVIRONMENT):$(NC)"
	cd $(TERRAFORM_DIR) && terraform workspace select $(ENVIRONMENT)
	cd $(TERRAFORM_DIR) && terraform output

##@ Deployment
deploy: ## Deploy to specified environment
	@echo "$(BLUE)Deploying to $(ENVIRONMENT) in $(AWS_REGION)...$(NC)"
	./scripts/deploy.sh $(ENVIRONMENT) $(AWS_REGION)
	@echo "$(GREEN)✓ Deployment completed$(NC)"

deploy-dev: ## Deploy to development environment
	$(MAKE) deploy ENVIRONMENT=dev

deploy-staging: ## Deploy to staging environment
	$(MAKE) deploy ENVIRONMENT=staging

deploy-prod: ## Deploy to production environment
	$(MAKE) deploy ENVIRONMENT=prod

##@ Monitoring & Maintenance
logs: ## View application logs
	@echo "$(BLUE)Viewing application logs...$(NC)"
	aws logs tail /aws/lambda/$(PROJECT_NAME) --follow --region $(AWS_REGION)

health-check: ## Run health checks
	@echo "$(BLUE)Running health checks...$(NC)"
	python scripts/health_check.py --environment $(ENVIRONMENT)

backup: ## Backup important data
	@echo "$(BLUE)Running backup...$(NC)"
	python scripts/backup.py --environment $(ENVIRONMENT)

##@ Utilities
clean: ## Clean temporary files and caches
	@echo "$(BLUE)Cleaning temporary files...$(NC)"
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type f -name "*.log" -delete
	rm -rf .coverage htmlcov/ .pytest_cache/ .mypy_cache/
	rm -rf build/ dist/ *.egg-info/
	docker system prune -f
	@echo "$(GREEN)✓ Cleanup completed$(NC)"

env-check: ## Check environment configuration
	@echo "$(BLUE)Environment Configuration:$(NC)"
	@echo "Project: $(PROJECT_NAME)"
	@echo "Environment: $(ENVIRONMENT)"
	@echo "AWS Region: $(AWS_REGION)"
	@echo "Python Version: $(PYTHON_VERSION)"
	@echo ""
	@echo "$(BLUE)AWS Configuration:$(NC)"
	aws sts get-caller-identity --region $(AWS_REGION) || echo "$(RED)AWS credentials not configured$(NC)"

version: ## Show project version
	@echo "$(BLUE)Project Information:$(NC)"
	@echo "Name: $(PROJECT_NAME)"
	@echo "Git Branch: $$(git rev-parse --abbrev-ref HEAD)"
	@echo "Git Commit: $$(git rev-parse --short HEAD)"
	@echo "Git Status: $$(git status --porcelain | wc -l) uncommitted changes"

generate-docs: ## Generate project documentation
	@echo "$(BLUE)Generating documentation...$(NC)"
	sphinx-build -b html docs/ docs/_build/html/
	@echo "$(GREEN)✓ Documentation generated$(NC)"

##@ CI/CD
ci-test: ## Run CI test suite
	@echo "$(BLUE)Running CI test suite...$(NC)"
	$(MAKE) lint
	$(MAKE) security-scan
	$(MAKE) test-coverage
	$(MAKE) terraform-validate
	@echo "$(GREEN)✓ CI tests completed$(NC)"

release: ## Create a new release
	@echo "$(BLUE)Creating release...$(NC)"
	@read -p "Enter release version (e.g., v1.2.3): " version && \
	git tag -a $$version -m "Release $$version" && \
	git push origin $$version
	@echo "$(GREEN)✓ Release created$(NC)"

##@ Development Shortcuts
dev: ## Start development environment
	$(MAKE) docker-compose-up
	@echo "$(GREEN)Development environment ready at:$(NC)"
	@echo "  - Grafana: http://localhost:3000"
	@echo "  - Prometheus: http://localhost:9090"

stop: ## Stop development environment
	$(MAKE) docker-compose-down

restart: stop dev ## Restart development environment

all: ## Run complete workflow (lint, test, build)
	$(MAKE) format
	$(MAKE) lint
	$(MAKE) test-coverage
	$(MAKE) docker-build