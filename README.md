# AWS Security Hub Agent

Strands Framework + Amazon Bedrock を使用して、AWS Security Hub の検出結果を自動分析し、
対応策を提案・レポートを S3 に保存・SNS で通知する AI Agent です。

## アーキテクチャ

```
EventBridge Scheduler (毎朝 08:00 JST)
    └─ Step Functions（起動 → Wait でポーリング）
         └─ Lambda（薄いトリガー。AgentCore Runtime を A2A プロトコルで起動・ポーリングするのみ）
              └─ Bedrock AgentCore Runtime（コンテナ, Strands + A2AServer）
                   └─ Security Hub Agent（security_agent.py）
                        ├─ Tool: Security Hub (Findings 取得)
                        ├─ Tool: S3 (レポート保存 + Presigned URL)
                        ├─ Tool: SNS (通知送信)
                        └─ Tool: DynamoDB (実行履歴)
```

実際の分析処理・ツール呼び出しはすべて Bedrock AgentCore Runtime 上で実行される。
分析処理は Bedrock 推論を複数回はさむため数分〜20分程度かかることがあり、Lambda が
1回の同期呼び出しで完了を待つと接続が早期に切断されてしまうため、Lambda は
「起動（非ブロッキング）→ Step Functions の Wait ループでポーリング」という
非同期パターンで AgentCore Runtime を呼び出す（詳細は [docs/deployment.md](docs/deployment.md) 参照）。

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

### 3. インフラのデプロイ（Terraform）

インフラ（S3・SNS・DynamoDB・Step Functions・EventBridge Scheduler・ECR・
Bedrock AgentCore Runtime）は Terraform で一括管理する。
Lambda 関数自体は Terraform 管理外のため、先にデプロイして ARN を控えておく。

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars
# terraform.tfvars を編集（email_subscription, lambda_function_arn など）

terraform init
terraform plan
terraform apply
```

手順の詳細（前提条件・確認手順・削除方法・トラブルシューティングを含む）は
[docs/deployment.md](docs/deployment.md) を参照。
過去に使用していた CloudFormation テンプレートは `infra/CFn/` に参考として残してある（現在は未使用）。

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

## IAM 権限

### Lambda 実行ロール（薄いトリガー役。Terraform 管理外）

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "bedrock-agentcore:InvokeAgentRuntime", "Resource": "arn:aws:bedrock-agentcore:*:*:runtime/*" },
    { "Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "arn:aws:logs:*:*:*" }
  ]
}
```

### AgentCore Runtime 実行ロール（実処理担当。`infra/agentcore.tf` で Terraform 管理）

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "securityhub:GetFindings", "Resource": "*" },
    { "Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"], "Resource": "arn:aws:s3:::security-hub-agent-reports-*/*" },
    { "Effect": "Allow", "Action": "sns:Publish", "Resource": "arn:aws:sns:*:*:security-hub-agent" },
    { "Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:Query"], "Resource": "arn:aws:dynamodb:*:*:table/security-hub-agent-history" },
    { "Effect": "Allow", "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], "Resource": "*" }
  ]
}
```

## フェーズ計画

| Phase | 内容 | ステータス |
|---|---|---|
| Phase 1 | Fetch & Propose（本実装） | ✅ 実装済み |
| Phase 2 | CFn/CLI コマンド生成 + S3 保存 | ✅ 実装済み |
| Phase 3 | Human Approval → 自動修復 | 🔜 次フェーズ |