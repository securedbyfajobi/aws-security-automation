#!/bin/bash
# Docker Security Scanning Script with Multiple Tools
# Integrates Trivy, Grype, and other container security tools

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="/var/log/security-automation/container-scans"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOG_FILE="$REPORT_DIR/docker-scan-$TIMESTAMP.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Ensure report directory exists
mkdir -p "$REPORT_DIR"

# Function to install security tools
install_security_tools() {
    log_info "Installing container security tools..."

    # Install Trivy
    if ! command -v trivy &> /dev/null; then
        log_info "Installing Trivy..."
        sudo apt-get update
        sudo apt-get install wget apt-transport-https gnupg lsb-release -y
        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
        echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
        sudo apt-get update
        sudo apt-get install trivy -y
    fi

    # Install Grype
    if ! command -v grype &> /dev/null; then
        log_info "Installing Grype..."
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
    fi

    # Install Docker Bench Security
    if [ ! -d "/opt/docker-bench-security" ]; then
        log_info "Installing Docker Bench Security..."
        sudo git clone https://github.com/docker/docker-bench-security.git /opt/docker-bench-security
        sudo chmod +x /opt/docker-bench-security/docker-bench-security.sh
    fi

    # Install Hadolint
    if ! command -v hadolint &> /dev/null; then
        log_info "Installing Hadolint..."
        sudo wget -O /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64
        sudo chmod +x /usr/local/bin/hadolint
    fi

    log_success "Security tools installed successfully"
}

# Function to scan images with Trivy
scan_with_trivy() {
    local image=$1
    local output_file="$REPORT_DIR/trivy-$TIMESTAMP-$(echo "$image" | sed 's/[^a-zA-Z0-9]/_/g').json"

    log_info "Scanning $image with Trivy..."

    trivy image \
        --format json \
        --output "$output_file" \
        --severity HIGH,CRITICAL \
        --ignore-unfixed \
        --no-progress \
        "$image" || {
        log_error "Trivy scan failed for $image"
        return 1
    }

    # Parse results and display summary
    if [ -f "$output_file" ]; then
        local vulnerabilities=$(jq '.Results[0].Vulnerabilities | length' "$output_file" 2>/dev/null || echo "0")
        local critical=$(jq '.Results[0].Vulnerabilities | map(select(.Severity == "CRITICAL")) | length' "$output_file" 2>/dev/null || echo "0")
        local high=$(jq '.Results[0].Vulnerabilities | map(select(.Severity == "HIGH")) | length' "$output_file" 2>/dev/null || echo "0")

        log_info "Trivy scan results for $image:"
        echo "  Total vulnerabilities: $vulnerabilities"
        echo "  Critical: $critical"
        echo "  High: $high"
        echo "  Report: $output_file"
    fi
}

# Function to scan images with Grype
scan_with_grype() {
    local image=$1
    local output_file="$REPORT_DIR/grype-$TIMESTAMP-$(echo "$image" | sed 's/[^a-zA-Z0-9]/_/g').json"

    log_info "Scanning $image with Grype..."

    grype "$image" \
        -o json \
        --file "$output_file" \
        --only-fixed false || {
        log_error "Grype scan failed for $image"
        return 1
    }

    # Parse results and display summary
    if [ -f "$output_file" ]; then
        local total=$(jq '.matches | length' "$output_file" 2>/dev/null || echo "0")
        local critical=$(jq '.matches | map(select(.vulnerability.severity == "Critical")) | length' "$output_file" 2>/dev/null || echo "0")
        local high=$(jq '.matches | map(select(.vulnerability.severity == "High")) | length' "$output_file" 2>/dev/null || echo "0")

        log_info "Grype scan results for $image:"
        echo "  Total matches: $total"
        echo "  Critical: $critical"
        echo "  High: $high"
        echo "  Report: $output_file"
    fi
}

# Function to scan Dockerfile with Hadolint
scan_dockerfile() {
    local dockerfile=$1
    local output_file="$REPORT_DIR/hadolint-$TIMESTAMP.json"

    log_info "Scanning Dockerfile with Hadolint..."

    hadolint "$dockerfile" \
        --format json \
        > "$output_file" 2>&1 || {
        log_warning "Hadolint found issues in Dockerfile"
    }

    # Parse results
    if [ -f "$output_file" ] && [ -s "$output_file" ]; then
        local issues=$(jq 'length' "$output_file" 2>/dev/null || echo "0")
        log_info "Hadolint found $issues issues in Dockerfile"
        echo "  Report: $output_file"

        # Show top issues
        if [ "$issues" -gt 0 ]; then
            log_warning "Top Dockerfile issues:"
            jq -r '.[] | "  - \(.level): \(.message) (line \(.line))"' "$output_file" | head -5
        fi
    fi
}

# Function to run Docker Bench Security
run_docker_bench() {
    local output_file="$REPORT_DIR/docker-bench-$TIMESTAMP.log"

    log_info "Running Docker Bench Security..."

    cd /opt/docker-bench-security
    sudo ./docker-bench-security.sh -l "$output_file" || {
        log_warning "Docker Bench Security completed with warnings"
    }

    log_info "Docker Bench Security report: $output_file"

    # Parse and show summary
    if [ -f "$output_file" ]; then
        local warnings=$(grep -c "WARN" "$output_file" || echo "0")
        local info=$(grep -c "INFO" "$output_file" || echo "0")
        local pass=$(grep -c "PASS" "$output_file" || echo "0")

        log_info "Docker Bench Security summary:"
        echo "  Warnings: $warnings"
        echo "  Info: $info"
        echo "  Pass: $pass"
    fi
}

# Function to scan ECR repositories
scan_ecr_repositories() {
    log_info "Scanning ECR repositories..."

    # List ECR repositories
    aws ecr describe-repositories --region eu-west-2 --query 'repositories[].repositoryName' --output text | tr '\t' '\n' | while read -r repo; do
        if [ -n "$repo" ]; then
            log_info "Scanning ECR repository: $repo"

            # Get latest image
            local latest_image=$(aws ecr describe-images \
                --repository-name "$repo" \
                --region eu-west-2 \
                --query 'sort_by(imageDetails,&imagePushedAt)[-1].imageTags[0]' \
                --output text 2>/dev/null || echo "latest")

            if [ "$latest_image" != "None" ] && [ -n "$latest_image" ]; then
                local full_image="${AWS_ACCOUNT_ID}.dkr.ecr.eu-west-2.amazonaws.com/${repo}:${latest_image}"

                # Scan with both tools
                scan_with_trivy "$full_image"
                scan_with_grype "$full_image"
            fi
        fi
    done
}

# Function to generate comprehensive report
generate_report() {
    local report_file="$REPORT_DIR/comprehensive-report-$TIMESTAMP.html"

    log_info "Generating comprehensive security report..."

    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Container Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .summary { background: #e8f5e8; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #f57c00; font-weight: bold; }
        .medium { color: #fbc02d; font-weight: bold; }
        .low { color: #388e3c; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Container Security Scan Report</h1>
        <p><strong>Generated:</strong> $(date)</p>
        <p><strong>Scan ID:</strong> $TIMESTAMP</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This report contains the results of comprehensive container security scanning performed on $(date).</p>
    </div>

    <h2>Scan Results</h2>
EOF

    # Add scan results to report
    find "$REPORT_DIR" -name "*$TIMESTAMP*.json" -type f | while read -r result_file; do
        local tool=$(basename "$result_file" | cut -d'-' -f1)
        echo "<h3>$tool Results</h3>" >> "$report_file"
        echo "<pre>$(cat "$result_file" | jq '.' 2>/dev/null || cat "$result_file")</pre>" >> "$report_file"
    done

    cat >> "$report_file" << EOF
    <h2>Recommendations</h2>
    <ul>
        <li>Review and remediate all CRITICAL and HIGH severity vulnerabilities</li>
        <li>Update base images to latest versions</li>
        <li>Implement automated vulnerability scanning in CI/CD pipelines</li>
        <li>Follow Docker security best practices</li>
        <li>Regularly update and patch container images</li>
    </ul>
</body>
</html>
EOF

    log_success "Comprehensive report generated: $report_file"
}

# Function to send notifications
send_notifications() {
    local critical_count=$1
    local high_count=$2

    if [ "$critical_count" -gt 0 ] || [ "$high_count" -gt 5 ]; then
        log_warning "High priority vulnerabilities detected, sending notifications..."

        # Send Slack notification if webhook is configured
        if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
            curl -X POST -H 'Content-type: application/json' \
                --data "{\"text\":\"🚨 Container Security Alert: $critical_count critical and $high_count high severity vulnerabilities found. Scan ID: $TIMESTAMP\"}" \
                "$SLACK_WEBHOOK_URL" || log_error "Failed to send Slack notification"
        fi

        # Send SNS notification if topic is configured
        if [ -n "${SNS_TOPIC_ARN:-}" ]; then
            aws sns publish \
                --topic-arn "$SNS_TOPIC_ARN" \
                --message "Container Security Alert: $critical_count critical and $high_count high severity vulnerabilities found. Scan ID: $TIMESTAMP" \
                --subject "Container Security Scan Alert" \
                --region eu-west-2 || log_error "Failed to send SNS notification"
        fi
    fi
}

# Main execution
main() {
    log_info "Starting comprehensive container security scan..."

    # Install tools if needed
    install_security_tools

    # Scan local images
    log_info "Scanning local Docker images..."
    docker images --format "table {{.Repository}}:{{.Tag}}" | tail -n +2 | while read -r image; do
        if [ "$image" != "<none>:<none>" ]; then
            scan_with_trivy "$image"
            scan_with_grype "$image"
        fi
    done

    # Scan Dockerfile if it exists
    if [ -f "Dockerfile" ]; then
        scan_dockerfile "Dockerfile"
    elif [ -f "../Dockerfile" ]; then
        scan_dockerfile "../Dockerfile"
    fi

    # Run Docker Bench Security
    run_docker_bench

    # Scan ECR repositories if AWS credentials are available
    if aws sts get-caller-identity &>/dev/null; then
        AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
        scan_ecr_repositories
    fi

    # Generate comprehensive report
    generate_report

    # Count critical and high vulnerabilities for notification
    local critical_count=0
    local high_count=0

    find "$REPORT_DIR" -name "*$TIMESTAMP*.json" -type f | while read -r file; do
        if [[ "$file" == *trivy* ]]; then
            local crit=$(jq '.Results[0].Vulnerabilities | map(select(.Severity == "CRITICAL")) | length' "$file" 2>/dev/null || echo "0")
            local high=$(jq '.Results[0].Vulnerabilities | map(select(.Severity == "HIGH")) | length' "$file" 2>/dev/null || echo "0")
            critical_count=$((critical_count + crit))
            high_count=$((high_count + high))
        fi
    done

    # Send notifications if needed
    send_notifications "$critical_count" "$high_count"

    log_success "Container security scan completed successfully!"
    log_info "Results saved in: $REPORT_DIR"
    log_info "Scan ID: $TIMESTAMP"
}

# Execute main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi