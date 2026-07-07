# AWS デプロイ手順ガイド

AWS Security Hub Agent を実際の AWS 環境にデプロイするための、はじめから終わりまでの手順書です。
インフラ（S3 / SNS / DynamoDB / Step Functions / EventBridge Scheduler / ECR / Bedrock AgentCore Runtime）は **Terraform** で管理します。
Lambda 関数本体は Terraform の管理対象外のため、別途デプロイします。

## 全体像

Security Hub の分析処理・ツール呼び出しは、すべて **Bedrock AgentCore Runtime**（コンテナ）上で実行されます。
Lambda は Step Functions からの起動を受けて AgentCore Runtime を A2A プロトコルで呼び出し、結果を返すだけの「薄いトリガー」です。

```
1. 前提条件を満たす（AWS CLI, Terraform, Docker, Bedrock/Security Hub 有効化）
2. Terraform で ECR リポジトリのみ先行作成する
3. Agent コンテナイメージをビルドして ECR に push する
4. Lambda 関数（薄いトリガー）をビルド & デプロイする
5. Terraform で残りのインフラを一括構築する（AgentCore Runtime, S3, SNS, DynamoDB, Step Functions, EventBridge）
6. Lambda の環境変数を Terraform の出力値で更新する
7. 動作確認する（手動実行 → 翌朝の自動実行を待つ）
```

```
EventBridge Scheduler (毎朝 08:00 JST)
    └─ Step Functions（起動 → Wait でポーリング）
         └─ Lambda（薄いトリガー。Terraform 管理外）
              └─ Bedrock AgentCore Runtime（コンテナ, Terraform 管理）
                   └─ Security Hub Agent（Strands + A2AServer）
                        ├─ Tool: Security Hub（Findings 取得）
                        ├─ Tool: S3（レポート保存 + Presigned URL）
                        ├─ Tool: SNS（通知送信）
                        └─ Tool: DynamoDB（実行履歴）
```

Security Hub Agent の分析処理は Bedrock 推論を複数回はさむため、**実行に数分〜20分程度かかることがあります**。
Lambda が 1 回の同期呼び出しで完了を待つ設計だと、経路上のネットワーク接続が数分でアイドル切断されてしまうため、
Lambda と AgentCore Runtime の間は次の非同期パターンで通信します。

1. **起動**: Lambda が A2A の `message/send` を `configuration.blocking=false` で呼び出し、
   処理の完了を待たずに `task_id` を含む応答を即座に受け取る（`action: "run_analysis"`）。
2. **ポーリング**: Step Functions が `Wait`（30秒）→ Lambda 再呼び出し（`action: "poll_analysis"`）→
   `tasks/get` で状態確認、を完了するまで繰り返す（最大 60 回 ≈ 30 分）。

ポーリングが同じセッション（同じコンテナ）に届くよう、起動時に発行した `runtimeSessionId` を
ポーリング時も明示的に指定しています（詳細は [src/lambda_handler.py](../src/lambda_handler.py)・
[infra/stepfunctions.tf](../infra/stepfunctions.tf) を参照）。

---

## 0. 前提条件

| 項目 | 内容 |
|---|---|
| AWS CLI | `aws configure` でデプロイ先アカウントの認証情報を設定済みであること |
| Terraform | v1.5 以上、AWS プロバイダ v6 系が必要（`aws_bedrockagentcore_agent_runtime` を使用するため） |
| Docker | Agent コンテナイメージのビルドに使用 |
| Python | 3.12（Lambda パッケージングに使用） |
| Amazon Bedrock | Claude 系モデルへのモデルアクセスをコンソールで有効化済みであること |
| AWS Security Hub | デプロイ先リージョンで有効化済みであること |
| IAM 権限 | 作業者に IAM ロール／DynamoDB／S3／SNS／Step Functions／EventBridge Scheduler／Lambda／ECR／Bedrock AgentCore を作成できる権限があること（管理者権限が最も簡単） |

Terraform がインストールされていない、またはバージョンが古い場合:

```bash
brew install terraform   # macOS の場合
terraform -version       # Terraform v1.5+ であることを確認
```

---

## 1. Terraform で ECR リポジトリのみ先行作成する

AgentCore Runtime はコンテナイメージを ECR から参照するため、イメージを push する前に ECR リポジトリが存在している必要があります。
他のリソース（AgentCore Runtime 本体や Step Functions）は Lambda の ARN やコンテナイメージがまだ無いと作成できないため、まず ECR リポジトリだけを先行して作成します。

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars
# terraform.tfvars を編集（email_subscription, bedrock_model_id など。
# lambda_function_arn は手順 4 で判明するため、一旦ダミー値のままで構いません）

terraform init
terraform apply -target=aws_ecr_repository.agent
```

作成された ECR リポジトリの URL を控えておきます。

```bash
ECR_REPO_URL=$(terraform output -raw ecr_repository_url)
echo "$ECR_REPO_URL"
```

---

## 2. Agent コンテナイメージをビルドして ECR に push する

```bash
cd ..  # プロジェクトルートへ
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=ap-northeast-1
ECR_REPO_URL="<手順1で控えたURL>"

aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

docker build --platform linux/arm64 -t security-hub-agent:latest .
docker tag security-hub-agent:latest "${ECR_REPO_URL}:latest"
docker push "${ECR_REPO_URL}:latest"
```

> **Bedrock AgentCore Runtime は `arm64` アーキテクチャのイメージのみをサポートします。**
> `--platform linux/arm64` を必ず指定してください（Intel Mac / Linux 上でビルドする場合も同様です）。
> `amd64`（`linux/amd64`）でビルドしたイメージを指定すると、`terraform apply` 時に
> `ValidationException: Architecture incompatible for uri ... Supported platforms: [arm64]` で失敗します。

---

## 3. Lambda 関数（薄いトリガー）のビルド & デプロイ

Lambda は AgentCore Runtime を呼び出すだけの薄いトリガーで、依存パッケージは `boto3` のみです（[requirements-lambda.txt](../requirements-lambda.txt)）。
`boto3`/`botocore` は純 Python 実装のため、以前のように `--platform manylinux2014_x86_64` を指定した特別なビルドは不要です。

### 3-1. zip を作成する

```bash
rm -rf build && mkdir -p build/package

pip install -r requirements-lambda.txt --target build/package

# bedrock-agentcore クライアントが使えるバージョンか確認する
python3 -c "import sys; sys.path.insert(0, 'build/package'); import boto3; assert 'bedrock-agentcore' in boto3.Session().get_available_services(), 'boto3 が古く bedrock-agentcore に対応していません'"

cp -r src build/package/

cd build/package
zip -r ../../lambda.zip . -x '*.pyc' -x '__pycache__/*'
cd ../..
```

### 3-2. Lambda 実行ロールを作成する

Lambda 自身が必要とする権限は「AgentCore Runtime の呼び出し」と「ログ出力」のみです。
Security Hub / S3 / SNS / DynamoDB / Bedrock モデル呼び出しの権限は、Terraform が作成する
**AgentCore Runtime 実行ロール**（`infra/agentcore.tf` の `aws_iam_role.agentcore_runtime`）側に付与されます。

```bash
cat > /tmp/lambda-trust-policy.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "lambda.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

cat > /tmp/lambda-permissions-policy.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "bedrock-agentcore:InvokeAgentRuntime", "Resource": "arn:aws:bedrock-agentcore:*:*:runtime/*" },
    { "Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "arn:aws:logs:*:*:*" }
  ]
}
EOF

aws iam create-role \
  --role-name security-hub-agent-lambda-role \
  --assume-role-policy-document file:///tmp/lambda-trust-policy.json

aws iam put-role-policy \
  --role-name security-hub-agent-lambda-role \
  --policy-name security-hub-agent-lambda-policy \
  --policy-document file:///tmp/lambda-permissions-policy.json
```

> ロール作成直後は Lambda 側からまだ Assume できない場合があります。次の手順でエラーになった場合は 10 秒ほど待って再実行してください。

### 3-3. Lambda 関数を作成する

AgentCore Runtime の ARN はこの時点ではまだ存在しない（手順 5 で作成する）ため、
`AGENT_RUNTIME_ARN` はいったんダミー値で作成し、手順 6 で実際の値に更新します。

```bash
aws lambda create-function \
  --function-name security-hub-agent \
  --runtime python3.12 \
  --role "arn:aws:iam::${ACCOUNT_ID}:role/security-hub-agent-lambda-role" \
  --handler src.lambda_handler.handler \
  --zip-file fileb://lambda.zip \
  --timeout 60 \
  --memory-size 256 \
  --region "${REGION}" \
  --environment "Variables={AGENT_RUNTIME_ARN=PLACEHOLDER}"
```

> Lambda は起動リクエスト・ポーリングリクエストのいずれも AgentCore Runtime からの応答を
> 即座（数秒）に受け取るだけなので、`--timeout 60` で十分です（分析処理そのものの完了を
> 待つのは Step Functions の Wait ループの役割）。`infra/stepfunctions.tf` の各 Task ステートの
> `TimeoutSeconds` と合わせておいてください。

作成した関数の ARN を控えておきます（Terraform の変数 `lambda_function_arn` に使用）。

```bash
LAMBDA_ARN=$(aws lambda get-function --function-name security-hub-agent --query 'Configuration.FunctionArn' --output text)
echo "$LAMBDA_ARN"
```

### コード更新時の再デプロイ

`src/lambda_handler.py` を変更した場合は、3-1 の zip 作成をやり直し、以下で更新します。

```bash
aws lambda update-function-code \
  --function-name security-hub-agent \
  --zip-file fileb://lambda.zip
```

`src/agent/` や `src/tools/` を変更した場合は、手順 2 のコンテナイメージの再ビルド & push、
および手順 5 の Terraform 再適用（`agent_image_tag` を更新した場合）が必要です。

---

## 4. Terraform で残りのインフラを構築する

### 4-1. 変数ファイルを更新する

`infra/terraform.tfvars` を編集し、以下を実際の値に設定します。

| 変数名 | 内容 |
|---|---|
| `aws_region` | デプロイ先リージョン（デフォルト `ap-northeast-1`） |
| `bucket_name_suffix` | 省略可。省略時は `<AccountId>-<Region>` が自動生成される |
| `email_subscription` | アラートを受け取るメールアドレス |
| `lambda_function_arn` | 手順 3 で控えた Lambda 関数 ARN |
| `agent_image_tag` | 手順 2 で push したイメージのタグ（デフォルト `latest`） |
| `bedrock_model_id` | AgentCore Runtime 上の Agent が使う Bedrock モデル ID |
| `dry_run` | `true`（デフォルト）の間は実際の修復は行わずレポート生成・通知のみ |

### 4-2. 差分確認 → 適用

```bash
cd infra
terraform plan   # 作成される内容を必ず確認する
terraform apply  # 内容を確認し、"yes" と入力
```

`terraform apply` が成功すると、以下がまとめて作成されます。

- ECR リポジトリ（手順 1 で作成済み）
- Bedrock AgentCore Runtime（Agent 実行ロール込み。手順 2 で push したイメージを参照）
- S3 バケット（レポート保存用、90 日で自動削除・TLS 必須・パブリックアクセス禁止）
- SNS トピック（メール購読つき。**購読確認メールが届くので必ず「Confirm subscription」をクリックしてください**）
- DynamoDB テーブル（実行履歴、TTL 90 日、PITR 有効）
- Step Functions ステートマシン（Lambda 実行 → 失敗時に SNS 通知）
- EventBridge Scheduler（毎朝 08:00 JST に自動実行）

適用後、出力値を確認します。

```bash
terraform output
```

> 過去に CloudFormation で運用していた場合は `infra/CFn/` に旧テンプレートを参考として残していますが、現在は使用しません。CloudFormation スタックが既に存在する場合は、先にそれらを削除してから Terraform を適用してください（同名リソースが重複して作成エラーになります）。

---

## 5. Lambda の環境変数を更新する

Terraform で作成された AgentCore Runtime の ARN を、手順 3 でダミー値にしていた Lambda の環境変数に反映します。

```bash
cd ..  # プロジェクトルートへ
AGENT_RUNTIME_ARN=$(terraform -chdir=infra output -raw agent_runtime_arn)

aws lambda update-function-configuration \
  --function-name security-hub-agent \
  --environment "Variables={AGENT_RUNTIME_ARN=${AGENT_RUNTIME_ARN}}"
```

ローカル実行用に `.env` も更新しておくと、`python -m src.agent.security_agent` での動作確認がしやすくなります。

```bash
terraform -chdir=infra output -raw bucket_name
terraform -chdir=infra output -raw sns_topic_arn
```

```
REPORT_BUCKET_NAME=<terraform output の bucket_name>
SNS_TOPIC_ARN=<terraform output の sns_topic_arn>
```

---

## 6. 動作確認

### 6-1. Step Functions を手動実行する

自動実行（毎朝 08:00 JST）を待たずに、今すぐ動作確認できます。

```bash
STATE_MACHINE_ARN=$(terraform -chdir=infra output -raw state_machine_arn)

aws stepfunctions start-execution \
  --state-machine-arn "$STATE_MACHINE_ARN" \
  --input '{"action": "run_analysis"}'
```

実行結果は以下で確認できます。

```bash
aws stepfunctions list-executions --state-machine-arn "$STATE_MACHINE_ARN" --max-results 5
```

`status` が `SUCCEEDED` になっていれば成功です。`FAILED` の場合は、まず Lambda のログを確認してください。

```bash
aws logs tail /aws/lambda/security-hub-agent --follow
```

AgentCore Runtime 側（実際の分析処理）のログは、CloudWatch Logs の
`/aws/bedrock-agentcore/runtimes/` 配下（Runtime 名を含むロググループ）で確認できます。

```bash
aws logs describe-log-groups --log-group-name-prefix /aws/bedrock-agentcore/runtimes/
```

### 6-2. 確認ポイント

- SNS のメール購読確認（「Confirm subscription」）が完了しているか
- Security Hub に CRITICAL / HIGH の Findings が存在するか（存在しない場合、通知は「該当なしのため送信をスキップ」といった内容になります）
- `dry_run = true` の間は実際の修復アクションは行われず、レポート生成・通知のみが行われます
- S3 バケットにレポートが保存されているか

```bash
aws s3 ls "s3://$(terraform -chdir=infra output -raw bucket_name)/reports/" --recursive
```

### 6-3. 翌朝の自動実行を待つ

EventBridge Scheduler により、毎朝 08:00 JST に自動実行されます。実行履歴は DynamoDB に記録されます。

```bash
aws dynamodb scan --table-name security-hub-agent-history --max-items 5
```

---

## 7. 更新・再デプロイ

| 変更内容 | 手順 |
|---|---|
| Lambda コード（`src/lambda_handler.py`） | 「3. コード更新時の再デプロイ」を実施 |
| Agent コード（`src/agent/`, `src/tools/`） | 手順 2 でイメージ再ビルド & push → `terraform apply`（`agent_image_tag` を上げた場合はタグも更新） |
| インフラ定義（`infra/*.tf`） | `terraform plan` で差分確認 → `terraform apply` |
| 環境変数 | Lambda は `aws lambda update-function-configuration`、AgentCore Runtime は `terraform.tfvars` を編集して `terraform apply` |

---

## 8. 削除（クリーンアップ）

検証環境などを削除する場合は、依存関係の都合上、次の順で削除します。

```bash
# 1. Terraform 管理のインフラを削除（AgentCore Runtime, S3, SNS, DynamoDB, Step Functions, EventBridge, ECR）
cd infra
terraform destroy

# 2. Lambda 関数と実行ロールを削除
aws lambda delete-function --function-name security-hub-agent
aws iam delete-role-policy --role-name security-hub-agent-lambda-role --policy-name security-hub-agent-lambda-policy
aws iam delete-role --role-name security-hub-agent-lambda-role
```

> S3 バケットにレポートが残っている場合、`terraform destroy` はバケット削除に失敗することがあります。その場合は先にオブジェクトを空にしてから再実行してください。
>
> ```bash
> aws s3 rm "s3://$(terraform -chdir=infra output -raw bucket_name)" --recursive
> ```
>
> ECR リポジトリにイメージが残っている場合も同様に、`terraform destroy`前に `aws ecr batch-delete-image` でイメージを削除するか、
> `infra/agentcore.tf` の `aws_ecr_repository` に `force_delete = true` を設定してください。

---

## State 管理（複数人・CI/CD で運用する場合）

デフォルトでは Terraform の state は `infra/terraform.tfstate` としてローカルに保存されます（Git 管理対象外）。
チームで運用する、または CI/CD から `terraform apply` を実行する場合は、S3 + DynamoDB によるリモートバックエンドの利用を推奨します。

```bash
# state 保管用のバケットとロックテーブルは別途一度だけ手動で用意する
aws s3api create-bucket --bucket your-terraform-state-bucket --region ap-northeast-1 \
  --create-bucket-configuration LocationConstraint=ap-northeast-1
aws dynamodb create-table \
  --table-name terraform-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

`infra/versions.tf` のコメントアウトされている `backend "s3"` ブロックを有効化し、`terraform init` を再実行してください。

---

## トラブルシューティング

| 事象 | 原因・対処 |
|---|---|
| `terraform apply` で S3 バケット名が重複してエラー | バケット名はグローバルで一意。`bucket_name_suffix` を明示的に指定するか、既存バケットを削除する |
| `terraform apply` で AgentCore Runtime の作成に失敗する（イメージが見つからない） | 手順 2 でイメージを push する前に `terraform apply` していないか確認。`aws ecr list-images --repository-name security-hub-agent` でイメージの有無を確認 |
| `terraform apply` で `Architecture incompatible for uri ... Supported platforms: [arm64]` エラー | イメージが `amd64` でビルドされている。手順 2 のとおり `docker build --platform linux/arm64 ...` でビルドし直して push する |
| Step Functions が `States.Runtime` などで失敗 | Lambda 関数がまだ存在しない、または `lambda_function_arn` の指定が誤っている可能性。`aws lambda get-function` で存在確認 |
| Lambda が 500 を返す（AgentCore 呼び出し失敗） | `AGENT_RUNTIME_ARN` がダミー値のままになっていないか確認。`aws lambda get-function-configuration --function-name security-hub-agent` で環境変数を確認 |
| Lambda が `AgentCore response did not contain text output` / `... completed without text output` エラー | AgentCore Runtime 上のディスパッチャー Agent が JSON 以外のテキスト（説明文など）を返している可能性。CloudWatch Logs で Agent の生レスポンスを確認し、`security_agent.py` の `DISPATCH_SYSTEM_PROMPT` を調整する |
| Step Functions が `Invalid path '$.body.xxx'` で `States.Runtime` 失敗 | Choice ステートが存在しない可能性のある JSONPath を直接参照している。`IsPresent` チェックを先に行うか、`And` で組み合わせる（`infra/stepfunctions.tf` の `CheckPollResult` を参照） |
| ポーリングが `AccessDeniedException` や `ResourceNotFoundException` で失敗する | 起動時とポーリング時で `runtimeSessionId` が一致しているか確認。異なるセッションID を使うと別のセッション（コンテナ）に対して `tasks/get` することになり、タスクが見つからない |
| `AccessDeniedException ... bedrock:InvokeModelWithResponseStream` | AgentCore Runtime 実行ロールに `bedrock:InvokeModelWithResponseStream` が付与されているか確認（`infra/agentcore.tf`）。Strands の Converse API はストリーミングのためこの権限が必須 |
| Step Functions の実行が `PrepareFailureFromResult` を経由して失敗し、原因が `Read timed out`（`bedrock-runtime` への接続） | Lambda→AgentCore Runtime の接続ではなく、**AgentCore Runtime コンテナ内から Bedrock を呼び出す際**のタイムアウト（`BEDROCK_READ_TIMEOUT`、デフォルト 600 秒）。1 回のツール呼び出しに埋め込むデータ量（レポート本文など）が大きすぎる、またはツール呼び出しの数が多すぎる可能性がある。`src/agent/security_agent.py` のステップ分割や `BEDROCK_READ_TIMEOUT` を見直す |
| SNS 通知が届かない | 購読確認メールの「Confirm subscription」を押し忘れていないか確認（`aws sns list-subscriptions-by-topic --topic-arn <ARN>` で `PendingConfirmation` になっていないか） |
| Bedrock 呼び出しがタイムアウトする | `bedrock_model_id` のモデルアクセスが有効化されているか、Bedrock のリージョンがデプロイ先と一致しているか確認 |
| `docker push` で `no matching manifest for linux/amd64` エラー | Apple Silicon で `--platform linux/amd64` を付けずにビルドした可能性。手順 2 の注記を参照 |
