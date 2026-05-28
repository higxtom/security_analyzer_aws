# AWS Security Hub Agent

Strands Framework + Amazon Bedrock を使用して、AWS Security Hub の検出結果を自動分析し、
対応策を提案・レポートを S3 に保存・SNS で通知する AI Agent です。

## アーキテクチャ

```
EventBridge Scheduler (毎朝 08:00 JST)
    └─ Step Functions
         └─ Lambda / AgentCore Container
              └─ Bedrock Agent Core + Strands
                   └─ AWS API MCP Server (call_aws)
                        ├─ Security Hub (Findings 取得)
                        ├─ S3 (レポート保存 + Presigned URL)
                        ├─ SNS (通知送信)
                        └─ DynamoDB (実行履歴)
```

> **Note**: AWS リソースへのアクセスは `awslabs.aws-api-mcp-server` の `call_aws` ツール経由で行います。
> Agent は MCP プロトコルで AWS API MCP Server と通信し、AWS CLI コマンドを実行します。

## 前提条件

- Python 3.12+
- AWS CLI 設定済み（Bedrock・Security Hub・S3・SNS・DynamoDB へのアクセス権限）
- Amazon Bedrock で Claude 3.x または Nova のモデルアクセスを有効化済み
- AWS Security Hub が有効化済み

## セットアップ

### 1. 依存パッケージのインストール

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. 環境変数の設定

```bash
cp .env.example .env
# .env を編集して各値を設定する
```

必須の設定項目:
| 変数名 | 説明 |
|---|---|
| `REPORT_BUCKET_NAME` | S3 バケット名 |
| `SNS_TOPIC_ARN` | SNS トピック ARN |
| `AWS_REGION` | リージョン（デフォルト: ap-northeast-1） |
| `BEDROCK_MODEL_ID` | 使用する Bedrock モデル ID |

### 3. インフラのデプロイ（CloudFormation）

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=ap-northeast-1

# S3 バケット
aws cloudformation deploy \
  --template-file infra/s3.yaml \
  --stack-name security-hub-agent-s3 \
  --parameter-overrides BucketNameSuffix="${ACCOUNT_ID}-${REGION}"

# SNS トピック（メールアドレスを指定）
aws cloudformation deploy \
  --template-file infra/sns.yaml \
  --stack-name security-hub-agent-sns \
  --parameter-overrides EmailSubscription="your@email.com"

# DynamoDB テーブル
aws cloudformation deploy \
  --template-file infra/dynamodb.yaml \
  --stack-name security-hub-agent-dynamodb

# Step Functions（Lambda デプロイ後に実行）
aws cloudformation deploy \
  --template-file infra/stepfunctions.yaml \
  --stack-name security-hub-agent-sfn \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    LambdaFunctionArn="arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:security-hub-agent" \
    AlertTopicArn="$(aws cloudformation describe-stacks \
      --stack-name security-hub-agent-sns \
      --query 'Stacks[0].Outputs[?OutputKey==`TopicArn`].OutputValue' \
      --output text)"

# EventBridge Scheduler
aws cloudformation deploy \
  --template-file infra/eventbridge.yaml \
  --stack-name security-hub-agent-scheduler \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    StateMachineArn="$(aws cloudformation describe-stacks \
      --stack-name security-hub-agent-sfn \
      --query 'Stacks[0].Outputs[?OutputKey==`StateMachineArn`].OutputValue' \
      --output text)"
```

## ローカル実行

```bash
# DRY_RUN=true（デフォルト）で実行
python -m src.agent.security_agent

# 特定の日付を指定
python -c "from src.agent.security_agent import run_security_analysis; run_security_analysis('2026-05-25')"
```

## テスト実行

```bash
pip install pytest pytest-mock
pytest tests/ -v
```

## SNS 通知の例

```
=== AWS Security Hub 検出レポート (2026-05-25) ===

【重大度別サマリー】
  CRITICAL: 3 件
  HIGH: 12 件
  合計: 15 件

【上位検出結果（重大度順）】
  1. [CRITICAL] S3 buckets should have block public access settings enabled
     リソース: AwsS3Bucket / arn:aws:s3:::my-bucket
     アカウント: 123456789012 (ap-northeast-1)
  ...

【詳細ドキュメント（7日間有効）】
  📄 検出レポート（詳細）
  https://s3.ap-northeast-1.amazonaws.com/...

  🔧 CloudFormation 修復テンプレート
  https://s3.ap-northeast-1.amazonaws.com/...

  💻 CLI 修復コマンド集
  https://s3.ap-northeast-1.amazonaws.com/...
```

## IAM 権限（Lambda 実行ロールに必要）

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "securityhub:GetFindings", "Resource": "*" },
    { "Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"], "Resource": "arn:aws:s3:::security-hub-agent-reports-*/*" },
    { "Effect": "Allow", "Action": "sns:Publish", "Resource": "arn:aws:sns:*:*:security-hub-agent" },
    { "Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:Query"], "Resource": "arn:aws:dynamodb:*:*:table/security-hub-agent-history" },
    { "Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": "*" }
  ]
}
```

## フェーズ計画

| Phase | 内容 | ステータス |
|---|---|---|
| Phase 1 | Fetch & Propose（本実装） | ✅ 実装済み |
| Phase 2 | CFn/CLI コマンド生成 + S3 保存 | ✅ 実装済み |
| Phase 3 | Human Approval → 自動修復 | 🔜 次フェーズ |