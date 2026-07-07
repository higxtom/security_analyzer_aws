# SNS topic for Security Hub Agent alerts with email subscription

resource "aws_sns_topic" "alert" {
  name              = "security-hub-agent"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alert.arn
  protocol  = "email"
  endpoint  = var.email_subscription
}
