variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "eu-west-2"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "aws-security-automation"
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

variable "notification_email" {
  description = "Email for security notifications"
  type        = string
  default     = ""
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_guardduty" {
  description = "Enable GuardDuty automation"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub automation"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config rules"
  type        = bool
  default     = true
}

variable "compliance_standards" {
  description = "List of compliance standards to enable"
  type        = list(string)
  default     = ["CIS", "PCI-DSS", "AWS-Foundational"]
}

variable "critical_finding_severity" {
  description = "Severity threshold for critical alerts"
  type        = string
  default     = "HIGH"

  validation {
    condition     = contains(["LOW", "MEDIUM", "HIGH", "CRITICAL"], var.critical_finding_severity)
    error_message = "Severity must be LOW, MEDIUM, HIGH, or CRITICAL."
  }
}

variable "auto_remediation_enabled" {
  description = "Enable automatic remediation for certain findings"
  type        = bool
  default     = false
}

variable "cost_optimization_threshold" {
  description = "Cost threshold in USD for optimization alerts"
  type        = number
  default     = 100.00
}

variable "backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 90
}