# Step Functions state machine for Security Hub Agent with error notification

resource "aws_iam_role" "sfn" {
  name = "security-hub-agent-sfn-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "states.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "sfn" {
  name = "StateMachinePolicy"
  role = aws_iam_role.sfn.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = var.lambda_function_arn
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alert.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_sfn_state_machine" "this" {
  name     = "security-hub-agent"
  role_arn = aws_iam_role.sfn.arn

  # Security Hub Agent の分析処理（AgentCore Runtime 上で Bedrock 推論を複数回はさむ）は
  # 数分〜十数分かかることがある。Lambda から AgentCore Runtime を1回の同期呼び出しで
  # 待つと、経路上のコネクションが数分でアイドル切断されてしまうため、
  # 「起動（非ブロッキング）→ Wait でポーリング」という非同期パターンにしている。
  # StartAnalysis: A2A message/send を blocking=false で呼び出し、即座に task_id を受け取る
  # WaitBeforePoll → PollAnalysis: task_id の状態を tasks/get で確認するループ
  definition = jsonencode({
    Comment = "Security Hub Agent daily workflow (async start + poll)"
    StartAt = "StartAnalysis"
    States = {
      StartAnalysis = {
        Type           = "Task"
        Resource       = var.lambda_function_arn
        TimeoutSeconds = 60
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
            IntervalSeconds = 10
            MaxAttempts     = 2
            BackoffRate     = 2.0
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "NotifyFailure"
            ResultPath  = "$.error"
          }
        ]
        Next = "WaitBeforePoll"
      }
      WaitBeforePoll = {
        Type    = "Wait"
        Seconds = 30
        Next    = "PollAnalysis"
      }
      PollAnalysis = {
        Type           = "Task"
        Resource       = var.lambda_function_arn
        TimeoutSeconds = 60
        Parameters = {
          action         = "poll_analysis"
          "task_id.$"    = "$.body.task_id"
          "session_id.$" = "$.body.session_id"
          "run_date.$"   = "$.body.run_date"
          "poll_count.$" = "$.body.poll_count"
        }
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
            IntervalSeconds = 10
            MaxAttempts     = 2
            BackoffRate     = 2.0
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "NotifyFailure"
            ResultPath  = "$.error"
          }
        ]
        Next = "CheckPollResult"
      }
      CheckPollResult = {
        Type = "Choice"
        Choices = [
          {
            Variable      = "$.statusCode"
            NumericEquals = 500
            Next          = "PrepareFailureFromResult"
          },
          {
            # 完了時のレスポンスには body.phase キー自体が存在しないため、
            # StringEquals の前に IsPresent で存在チェックしないと
            # 「Invalid path」で States.Runtime エラーになる。
            And = [
              { Variable = "$.body.phase", IsPresent = true },
              { Variable = "$.body.phase", StringEquals = "pending" }
            ]
            Next = "WaitBeforePoll"
          }
        ]
        Default = "Success"
      }
      # Lambda が例外を投げず statusCode: 500 を返した場合、Catch を経由しないため
      # $.error が未設定のまま NotifyFailure に到達してしまう。ここで Catch と同じ
      # $.error の形に揃えてから NotifyFailure に渡す。
      PrepareFailureFromResult = {
        Type = "Pass"
        Parameters = {
          "error.$" = "$.body"
        }
        ResultPath = "$"
        Next       = "NotifyFailure"
      }
      NotifyFailure = {
        Type     = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Parameters = {
          TopicArn    = aws_sns_topic.alert.arn
          Subject     = "[Security Hub Agent] Execution FAILED"
          "Message.$" = "States.Format('Security Hub Agent が失敗しました。\n実行日: {}\nエラー: {}', $$.Execution.StartTime, States.JsonToString($.error))"
        }
        End = true
      }
      Success = {
        Type = "Succeed"
      }
    }
  })
}
