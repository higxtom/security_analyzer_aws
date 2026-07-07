variable "aws_region" {
  type        = string
  description = "デプロイ先のAWSリージョン"
  default     = "ap-northeast-1"
}

variable "bucket_name_suffix" {
  type        = string
  description = <<-EOT
    S3レポートバケット名のサフィックス（例: <AccountId>-<Region>）。
    最終バケット名: security-hub-agent-reports-<bucket_name_suffix>
    未指定の場合は "<AccountId>-<Region>" を自動生成する。
  EOT
  default     = null
}

variable "email_subscription" {
  type        = string
  description = "セキュリティアラートを受信するメールアドレス"
}

variable "lambda_function_arn" {
  type        = string
  description = <<-EOT
    Security Hub Agent Lambda関数のARN。
    このTerraform構成はLambda関数自体を作成しない（別途デプロイ済みのものを指定する）。
    このLambdaはAgentCore Runtimeを起動する薄いトリガーであり、実処理は行わない。
  EOT
}

variable "agent_image_tag" {
  type        = string
  description = "AgentCore Runtimeが参照するECRイメージのタグ"
  default     = "latest"
}

variable "bedrock_model_id" {
  type        = string
  description = "AgentCore Runtime上のAgentが使用するBedrockモデルID"
  default     = "global.anthropic.claude-sonnet-4-6"
}

variable "dry_run" {
  type        = bool
  description = "true の場合、実際のリソース修復は行わずレポート生成・通知のみ行う"
  default     = true
}

data "aws_caller_identity" "current" {}

locals {
  bucket_name_suffix = coalesce(var.bucket_name_suffix, "${data.aws_caller_identity.current.account_id}-${var.aws_region}")
}
