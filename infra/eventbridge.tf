# EventBridge Scheduler for Security Hub Agent (daily at 08:00 JST)

resource "aws_iam_role" "scheduler" {
  name = "security-hub-agent-scheduler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "scheduler.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  name = "StartStateMachinePolicy"
  role = aws_iam_role.scheduler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "states:StartExecution"
        Resource = aws_sfn_state_machine.this.arn
      }
    ]
  })
}

resource "aws_scheduler_schedule" "daily" {
  name        = "security-hub-agent-daily"
  description = "Run Security Hub Agent daily at 08:00 JST"

  # cron(分 時 日 月 曜日 年) — Asia/Tokyo タイムゾーン指定のため 08:00 JST をそのまま記述
  schedule_expression          = "cron(0 8 * * ? *)"
  schedule_expression_timezone = "Asia/Tokyo"
  state                        = "ENABLED"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_sfn_state_machine.this.arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({ action = "run_analysis" })

    retry_policy {
      maximum_retry_attempts       = 1
      maximum_event_age_in_seconds = 3600
    }
  }
}
