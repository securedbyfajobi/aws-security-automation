output "security_logs_bucket_name" {
  description = "Name of the S3 bucket for security logs"
  value       = aws_s3_bucket.security_logs.bucket
}

output "security_logs_bucket_arn" {
  description = "ARN of the S3 bucket for security logs"
  value       = aws_s3_bucket.security_logs.arn
}

output "security_automation_role_arn" {
  description = "ARN of the security automation IAM role"
  value       = aws_iam_role.security_automation_role.arn
}

output "security_alerts_topic_arn" {
  description = "ARN of the SNS topic for security alerts"
  value       = aws_sns_topic.security_alerts.arn
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.security_automation.name
}

output "guardduty_event_rule_arn" {
  description = "ARN of the GuardDuty EventBridge rule"
  value       = aws_cloudwatch_event_rule.guardduty_findings.arn
}

output "security_hub_event_rule_arn" {
  description = "ARN of the Security Hub EventBridge rule"
  value       = aws_cloudwatch_event_rule.security_hub_findings.arn
}

output "account_id" {
  description = "AWS Account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  description = "AWS Region"
  value       = data.aws_region.current.name
}