security-hub-agent/
├── src/
│   ├── agent/
│   │   └── security_agent.py   # Strands Agent 本体・システムプロンプト
│   ├── tools/
│   │   ├── security_hub.py     # Findings 取得 (@tool)
│   │   ├── s3_reporter.py      # S3 保存 + Presigned URL (@tool)
│   │   ├── sns_notifier.py     # SNS 通知 (@tool)
│   │   └── history.py          # DynamoDB 履歴管理 (@tool)
│   ├── utils/
│   │   ├── config.py           # Pydantic 設定管理
│   │   └── logger.py           # 構造化ロギング
│   └── lambda_handler.py       # Lambda エントリーポイント
├── infra/
│   ├── s3/template.yaml        # S3 バケット (ライフサイクル・暗号化済)
│   ├── sns/template.yaml       # SNS トピック + メールサブスクリプション
│   ├── dynamodb/template.yaml  # 実行履歴テーブル (TTL 90日)
│   ├── stepfunctions/template.yaml # ワークフロー + エラー通知
│   └── eventbridge/template.yaml   # 毎朝 08:00 JST スケジューラ
└── tests/test_tools.py         # boto3 モックによるユニットテスト