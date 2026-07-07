output "bucket_name" {
  description = "S3 バケット名"
  value       = aws_s3_bucket.reports.id
}

output "bucket_arn" {
  description = "S3 バケット ARN"
  value       = aws_s3_bucket.reports.arn
}

output "sns_topic_arn" {
  description = "SNS トピック ARN"
  value       = aws_sns_topic.alert.arn
}

output "sns_topic_name" {
  description = "SNS トピック名"
  value       = aws_sns_topic.alert.name
}

output "dynamodb_table_name" {
  description = "DynamoDB テーブル名"
  value       = aws_dynamodb_table.history.name
}

output "dynamodb_table_arn" {
  description = "DynamoDB テーブル ARN"
  value       = aws_dynamodb_table.history.arn
}

output "state_machine_arn" {
  description = "Step Functions ステートマシン ARN"
  value       = aws_sfn_state_machine.this.arn
}

output "state_machine_name" {
  description = "Step Functions ステートマシン名"
  value       = aws_sfn_state_machine.this.name
}

output "schedule_name" {
  description = "EventBridge Scheduler スケジュール名"
  value       = aws_scheduler_schedule.daily.name
}

output "ecr_repository_url" {
  description = "AgentCore Runtime 用コンテナイメージの ECR リポジトリ URL"
  value       = aws_ecr_repository.agent.repository_url
}

output "agent_runtime_arn" {
  description = "Bedrock AgentCore Runtime の ARN（Lambda の AGENT_RUNTIME_ARN 環境変数に設定する）"
  value       = aws_bedrockagentcore_agent_runtime.security_hub_agent.agent_runtime_arn
}
