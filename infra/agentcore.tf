# Bedrock AgentCore Runtime
# security_agent.py / tools の実処理をコンテナとしてホストする。
# Lambda はこの Runtime を A2A プロトコルで起動する薄いトリガーに過ぎない。

resource "aws_ecr_repository" "agent" {
  name                 = "security-hub-agent"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_iam_role" "agentcore_runtime" {
  name = "security-hub-agent-runtime-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "bedrock-agentcore.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "agentcore_runtime" {
  name = "security-hub-agent-runtime-policy"
  role = aws_iam_role.agentcore_runtime.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "securityhub:GetFindings", Resource = "*" },
      { Effect = "Allow", Action = ["s3:PutObject", "s3:GetObject"], Resource = "${aws_s3_bucket.reports.arn}/*" },
      { Effect = "Allow", Action = "sns:Publish", Resource = aws_sns_topic.alert.arn },
      { Effect = "Allow", Action = ["dynamodb:PutItem", "dynamodb:Query"], Resource = aws_dynamodb_table.history.arn },
      { Effect = "Allow", Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], Resource = "*" },
      {
        Effect = "Allow"
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
        ]
        Resource = aws_ecr_repository.agent.arn
      },
      { Effect = "Allow", Action = "ecr:GetAuthorizationToken", Resource = "*" },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
    ]
  })
}

resource "aws_bedrockagentcore_agent_runtime" "security_hub_agent" {
  agent_runtime_name = "security_hub_agent"
  role_arn           = aws_iam_role.agentcore_runtime.arn

  agent_runtime_artifact {
    container_configuration {
      container_uri = "${aws_ecr_repository.agent.repository_url}:${var.agent_image_tag}"
    }
  }

  network_configuration {
    network_mode = "PUBLIC"
  }

  protocol_configuration {
    server_protocol = "A2A"
  }

  # Bedrock 推論を複数回はさむ 4 ステップの処理が完走できるよう、
  # デフォルトより余裕を持たせたセッション寿命を設定する。
  lifecycle_configuration {
    idle_runtime_session_timeout = 900
    max_lifetime                 = 3600
  }

  environment_variables = {
    AWS_REGION          = var.aws_region
    BEDROCK_MODEL_ID    = var.bedrock_model_id
    REPORT_BUCKET_NAME  = aws_s3_bucket.reports.id
    REPORT_PREFIX       = "reports"
    SNS_TOPIC_ARN       = aws_sns_topic.alert.arn
    DYNAMODB_TABLE_NAME = aws_dynamodb_table.history.name
    DRY_RUN             = tostring(var.dry_run)
  }

  depends_on = [aws_iam_role_policy.agentcore_runtime]
}
