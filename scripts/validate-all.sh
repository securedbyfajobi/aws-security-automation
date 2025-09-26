#!/bin/bash
# Comprehensive validation script for AWS Security Automation Platform
# Validates all configuration files, scripts, and infrastructure components

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VALIDATION_LOG="/var/log/security-automation/validation-$(date +%Y%m%d-%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging setup
mkdir -p "$(dirname "$VALIDATION_LOG")"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$VALIDATION_LOG"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$VALIDATION_LOG"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$VALIDATION_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$VALIDATION_LOG"
}

# Validation counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# Function to increment counters
check_result() {
    local result=$1
    ((TOTAL_CHECKS++))

    case $result in
        "pass")
            ((PASSED_CHECKS++))
            ;;
        "fail")
            ((FAILED_CHECKS++))
            ;;
        "warning")
            ((WARNING_CHECKS++))
            ;;
    esac
}

# Function to validate Python syntax
validate_python_files() {
    log_info "Validating Python files..."

    local python_files=(
        "$PROJECT_ROOT/guardduty-automation/guardduty_responder.py"
        "$PROJECT_ROOT/security-hub-findings/security_hub_processor.py"
        "$PROJECT_ROOT/compliance-scanner/cis_benchmark_scanner.py"
        "$PROJECT_ROOT/cost-optimization/security_cost_optimizer.py"
        "$PROJECT_ROOT/incident-response/incident_automation.py"
        "$PROJECT_ROOT/iam-analyzer/iam_policy_analyzer.py"
        "$PROJECT_ROOT/cloudtrail-monitoring/cloudtrail_analyzer.py"
        "$PROJECT_ROOT/monitoring/advanced-alerting.py"
        "$PROJECT_ROOT/security-scanning/vulnerability-scanner.py"
        "$PROJECT_ROOT/disaster-recovery/backup-system.py"
    )

    for file in "${python_files[@]}"; do
        if [ -f "$file" ]; then
            if python3 -m py_compile "$file" 2>/dev/null; then
                log_success "Python syntax valid: $(basename "$file")"
                check_result "pass"
            else
                log_error "Python syntax error: $(basename "$file")"
                check_result "fail"
            fi
        else
            log_warning "Python file not found: $(basename "$file")"
            check_result "warning"
        fi
    done
}

# Function to validate Terraform configuration
validate_terraform() {
    log_info "Validating Terraform configuration..."

    cd "$PROJECT_ROOT/terraform"

    # Initialize Terraform
    if terraform init -backend=false &>/dev/null; then
        log_success "Terraform initialization successful"
        check_result "pass"
    else
        log_error "Terraform initialization failed"
        check_result "fail"
        return 1
    fi

    # Format check
    if terraform fmt -check &>/dev/null; then
        log_success "Terraform formatting correct"
        check_result "pass"
    else
        log_warning "Terraform formatting issues detected"
        check_result "warning"
    fi

    # Validation
    if terraform validate &>/dev/null; then
        log_success "Terraform configuration valid"
        check_result "pass"
    else
        log_error "Terraform configuration invalid"
        check_result "fail"
    fi

    cd "$PROJECT_ROOT"
}

# Function to validate YAML files
validate_yaml_files() {
    log_info "Validating YAML configuration files..."

    local yaml_files=(
        "$PROJECT_ROOT/config/config.yaml"
        "$PROJECT_ROOT/ansible/ansible.cfg"
        "$PROJECT_ROOT/ansible/inventory/hosts.yml"
        "$PROJECT_ROOT/ansible/group_vars/all.yml"
        "$PROJECT_ROOT/ansible/group_vars/production.yml"
        "$PROJECT_ROOT/ansible/requirements.yml"
        "$PROJECT_ROOT/security-scanning/security-tools.yml"
        "$PROJECT_ROOT/disaster-recovery/disaster-recovery-plan.yml"
        "$PROJECT_ROOT/.github/workflows/ci.yml"
        "$PROJECT_ROOT/.gitlab-ci.yml"
        "$PROJECT_ROOT/prometheus/prometheus.yml"
        "$PROJECT_ROOT/prometheus/rules/security-alerts.yml"
    )

    for file in "${yaml_files[@]}"; do
        if [ -f "$file" ]; then
            # Simple YAML syntax check using Python
            if python3 -c "import yaml; yaml.safe_load(open('$file', 'r'))" 2>/dev/null; then
                log_success "YAML syntax valid: $(basename "$file")"
                check_result "pass"
            else
                log_error "YAML syntax error: $(basename "$file")"
                check_result "fail"
            fi
        else
            log_warning "YAML file not found: $(basename "$file")"
            check_result "warning"
        fi
    done
}

# Function to validate JSON files
validate_json_files() {
    log_info "Validating JSON configuration files..."

    local json_files=(
        "$PROJECT_ROOT/grafana/dashboards/security-overview.json"
        "$PROJECT_ROOT/grafana/dashboards/ml-security-insights.json"
    )

    for file in "${json_files[@]}"; do
        if [ -f "$file" ]; then
            if python3 -c "import json; json.load(open('$file', 'r'))" 2>/dev/null; then
                log_success "JSON syntax valid: $(basename "$file")"
                check_result "pass"
            else
                log_error "JSON syntax error: $(basename "$file")"
                check_result "fail"
            fi
        else
            log_warning "JSON file not found: $(basename "$file")"
            check_result "warning"
        fi
    done
}

# Function to validate shell scripts
validate_shell_scripts() {
    log_info "Validating shell scripts..."

    local script_files=(
        "$PROJECT_ROOT/scripts/deploy.sh"
        "$PROJECT_ROOT/security-scanning/docker-security-scan.sh"
    )

    for file in "${script_files[@]}"; do
        if [ -f "$file" ]; then
            if bash -n "$file" 2>/dev/null; then
                log_success "Shell script syntax valid: $(basename "$file")"
                check_result "pass"
            else
                log_error "Shell script syntax error: $(basename "$file")"
                check_result "fail"
            fi

            # Check for executable permission
            if [ -x "$file" ]; then
                log_success "Script has execute permission: $(basename "$file")"
                check_result "pass"
            else
                log_warning "Script missing execute permission: $(basename "$file")"
                check_result "warning"
            fi
        else
            log_warning "Script file not found: $(basename "$file")"
            check_result "warning"
        fi
    done
}

# Function to validate Docker configuration
validate_docker_config() {
    log_info "Validating Docker configuration..."

    # Check Dockerfile
    if [ -f "$PROJECT_ROOT/Dockerfile" ]; then
        # Basic Dockerfile syntax check
        if grep -q "FROM" "$PROJECT_ROOT/Dockerfile" && \
           grep -q "WORKDIR" "$PROJECT_ROOT/Dockerfile"; then
            log_success "Dockerfile structure valid"
            check_result "pass"
        else
            log_error "Dockerfile structure invalid"
            check_result "fail"
        fi
    else
        log_warning "Dockerfile not found"
        check_result "warning"
    fi

    # Check docker-compose files
    local compose_files=(
        "$PROJECT_ROOT/docker-compose.yml"
        "$PROJECT_ROOT/docker-compose.monitoring.yml"
    )

    for file in "${compose_files[@]}"; do
        if [ -f "$file" ]; then
            # Basic docker-compose syntax check
            if python3 -c "import yaml; yaml.safe_load(open('$file', 'r'))" 2>/dev/null; then
                log_success "Docker Compose syntax valid: $(basename "$file")"
                check_result "pass"
            else
                log_error "Docker Compose syntax error: $(basename "$file")"
                check_result "fail"
            fi
        else
            log_warning "Docker Compose file not found: $(basename "$file")"
            check_result "warning"
        fi
    done
}

# Function to validate Ansible configuration
validate_ansible_config() {
    log_info "Validating Ansible configuration..."

    cd "$PROJECT_ROOT/ansible"

    # Check ansible.cfg
    if [ -f "ansible.cfg" ]; then
        log_success "Ansible configuration file found"
        check_result "pass"
    else
        log_error "Ansible configuration file missing"
        check_result "fail"
    fi

    # Validate playbooks
    local playbooks=(
        "playbooks/site.yml"
        "playbooks/security-hardening.yml"
        "deploy.yml"
    )

    for playbook in "${playbooks[@]}"; do
        if [ -f "$playbook" ]; then
            if ansible-playbook --syntax-check "$playbook" &>/dev/null; then
                log_success "Ansible playbook syntax valid: $(basename "$playbook")"
                check_result "pass"
            else
                log_error "Ansible playbook syntax error: $(basename "$playbook")"
                check_result "fail"
            fi
        else
            log_warning "Ansible playbook not found: $(basename "$playbook")"
            check_result "warning"
        fi
    done

    cd "$PROJECT_ROOT"
}

# Function to validate Makefile
validate_makefile() {
    log_info "Validating Makefile..."

    if [ -f "$PROJECT_ROOT/Makefile" ]; then
        # Check basic Makefile syntax
        if make -f "$PROJECT_ROOT/Makefile" -n help &>/dev/null; then
            log_success "Makefile syntax valid"
            check_result "pass"
        else
            log_error "Makefile syntax error"
            check_result "fail"
        fi
    else
        log_error "Makefile not found"
        check_result "fail"
    fi
}

# Function to validate dependencies
validate_dependencies() {
    log_info "Validating dependencies and requirements..."

    # Check requirements.txt
    if [ -f "$PROJECT_ROOT/requirements.txt" ]; then
        log_success "Python requirements.txt found"
        check_result "pass"

        # Validate requirements format
        if python3 -m pip install -r "$PROJECT_ROOT/requirements.txt" --dry-run &>/dev/null; then
            log_success "Python requirements valid"
            check_result "pass"
        else
            log_warning "Python requirements may have issues"
            check_result "warning"
        fi
    else
        log_error "Python requirements.txt not found"
        check_result "fail"
    fi

    # Check requirements-dev.txt
    if [ -f "$PROJECT_ROOT/requirements-dev.txt" ]; then
        log_success "Development requirements found"
        check_result "pass"
    else
        log_warning "Development requirements not found"
        check_result "warning"
    fi
}

# Function to validate directory structure
validate_directory_structure() {
    log_info "Validating directory structure..."

    local required_dirs=(
        "guardduty-automation"
        "security-hub-findings"
        "compliance-scanner"
        "cost-optimization"
        "incident-response"
        "iam-analyzer"
        "cloudtrail-monitoring"
        "terraform"
        "ansible"
        "monitoring"
        "security-scanning"
        "disaster-recovery"
        "grafana"
        "prometheus"
        "tests"
        "scripts"
    )

    for dir in "${required_dirs[@]}"; do
        if [ -d "$PROJECT_ROOT/$dir" ]; then
            log_success "Directory exists: $dir"
            check_result "pass"
        else
            log_error "Required directory missing: $dir"
            check_result "fail"
        fi
    done
}

# Function to validate security configurations
validate_security_configs() {
    log_info "Validating security configurations..."

    # Check for sensitive information in files
    local sensitive_patterns=("password" "secret" "key" "token")
    local config_files=(
        "$PROJECT_ROOT/config/config.yaml"
        "$PROJECT_ROOT/terraform/variables.tf"
    )

    for file in "${config_files[@]}"; do
        if [ -f "$file" ]; then
            for pattern in "${sensitive_patterns[@]}"; do
                if grep -i "$pattern" "$file" | grep -v "placeholder\|example\|template\|${}" >/dev/null 2>&1; then
                    log_warning "Potential sensitive data in $file (pattern: $pattern)"
                    check_result "warning"
                else
                    log_success "No exposed sensitive data found for pattern: $pattern in $(basename "$file")"
                    check_result "pass"
                fi
            done
        fi
    done
}

# Function to validate file permissions
validate_file_permissions() {
    log_info "Validating file permissions..."

    # Check script permissions
    local executable_files=(
        "$PROJECT_ROOT/scripts/deploy.sh"
        "$PROJECT_ROOT/security-scanning/docker-security-scan.sh"
    )

    for file in "${executable_files[@]}"; do
        if [ -f "$file" ] && [ -x "$file" ]; then
            log_success "Correct permissions: $(basename "$file")"
            check_result "pass"
        elif [ -f "$file" ]; then
            log_error "Missing execute permission: $(basename "$file")"
            check_result "fail"
        else
            log_warning "File not found: $(basename "$file")"
            check_result "warning"
        fi
    done

    # Check for overly permissive files
    find "$PROJECT_ROOT" -type f -perm 0777 | while read -r file; do
        log_warning "Overly permissive file (777): $file"
        check_result "warning"
    done
}

# Function to validate test coverage
validate_test_coverage() {
    log_info "Validating test coverage..."

    if [ -d "$PROJECT_ROOT/tests" ]; then
        local test_files=$(find "$PROJECT_ROOT/tests" -name "test_*.py" | wc -l)
        local module_files=$(find "$PROJECT_ROOT" -name "*.py" -not -path "*/tests/*" -not -path "*/.terraform/*" | wc -l)

        if [ "$test_files" -gt 0 ]; then
            log_success "Test files found: $test_files"
            check_result "pass"

            local coverage_ratio=$((test_files * 100 / module_files))
            if [ "$coverage_ratio" -ge 50 ]; then
                log_success "Reasonable test coverage: ${coverage_ratio}%"
                check_result "pass"
            else
                log_warning "Low test coverage: ${coverage_ratio}%"
                check_result "warning"
            fi
        else
            log_warning "No test files found"
            check_result "warning"
        fi
    else
        log_error "Tests directory not found"
        check_result "fail"
    fi
}

# Function to generate validation report
generate_validation_report() {
    log_info "Generating validation report..."

    local report_file="/var/log/security-automation/validation-report-$(date +%Y%m%d-%H%M%S).json"

    cat > "$report_file" << EOF
{
    "validation_summary": {
        "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "total_checks": $TOTAL_CHECKS,
        "passed_checks": $PASSED_CHECKS,
        "failed_checks": $FAILED_CHECKS,
        "warning_checks": $WARNING_CHECKS,
        "success_rate": $(echo "scale=2; $PASSED_CHECKS * 100 / $TOTAL_CHECKS" | bc)
    },
    "validation_categories": {
        "python_syntax": "completed",
        "terraform_config": "completed",
        "yaml_config": "completed",
        "json_config": "completed",
        "shell_scripts": "completed",
        "docker_config": "completed",
        "ansible_config": "completed",
        "makefile": "completed",
        "dependencies": "completed",
        "directory_structure": "completed",
        "security_configs": "completed",
        "file_permissions": "completed",
        "test_coverage": "completed"
    },
    "recommendations": [
        "Review failed checks and resolve issues",
        "Address security configuration warnings",
        "Improve test coverage if below 80%",
        "Ensure all scripts have proper execute permissions"
    ]
}
EOF

    log_success "Validation report generated: $report_file"
}

# Main validation function
main() {
    log_info "Starting comprehensive validation of AWS Security Automation Platform"
    log_info "Project root: $PROJECT_ROOT"
    log_info "Validation log: $VALIDATION_LOG"

    # Run all validation checks
    validate_directory_structure
    validate_python_files
    validate_terraform
    validate_yaml_files
    validate_json_files
    validate_shell_scripts
    validate_docker_config
    validate_ansible_config
    validate_makefile
    validate_dependencies
    validate_security_configs
    validate_file_permissions
    validate_test_coverage

    # Generate report
    generate_validation_report

    # Summary
    echo
    log_info "=== VALIDATION SUMMARY ==="
    log_info "Total checks performed: $TOTAL_CHECKS"
    log_success "Passed: $PASSED_CHECKS"
    log_error "Failed: $FAILED_CHECKS"
    log_warning "Warnings: $WARNING_CHECKS"

    local success_rate=$(echo "scale=1; $PASSED_CHECKS * 100 / $TOTAL_CHECKS" | bc)
    log_info "Success rate: ${success_rate}%"

    if [ "$FAILED_CHECKS" -eq 0 ]; then
        log_success "All critical validations passed! Platform is ready for deployment."
        exit 0
    else
        log_error "Some validations failed. Please review and fix issues before deployment."
        exit 1
    fi
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi