"""
Security Hub Agent 本体
Strands Framework を使用して、Security Hub の検出結果を分析し
対応策を生成・レポートを作成・SNS 通知を行う
"""
from datetime import datetime, timezone

from strands import Agent

# boto3 グローバルタイムアウト設定を適用
from src.utils.boto3_config import DEFAULT_BOTO3_CONFIG  # noqa: F401
from src.tools.security_hub import get_security_findings, get_finding_detail
from src.tools.s3_reporter import save_report_to_s3, save_multiple_files_to_s3
from src.tools.sns_notifier import publish_security_report
from src.tools.history import save_execution_history, get_recent_execution_history
from src.utils.config import get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()

SYSTEM_PROMPT = """
あなたは AWS セキュリティ専門の AI エージェントです。
AWS Security Hub の検出結果を分析し、具体的な対応策を日本語で提案します。

## あなたの役割

1. Security Hub から検出結果を取得・分析する
2. 各検出項目に対してリスク評価と具体的な対応策を作成する
3. 対応策を CloudFormation テンプレートまたは AWS CLI コマンドとして生成する
4. レポートを S3 に保存し、SNS で通知する
5. 実行履歴を DynamoDB に記録する

## 対応策生成のガイドライン

### リスク評価基準
- CRITICAL: 即時対応が必要。悪用されれば深刻な被害が発生する
- HIGH: 優先的に対応が必要。近い将来リスクが顕在化する可能性が高い
- MEDIUM: 計画的に対応する。リスクは存在するが緊急性は低い
- LOW: 対応を検討する。ベストプラクティスとして対応することが望ましい

### 出力フォーマット
レポートは Markdown 形式で以下の構造で作成すること:

```
# AWS Security Hub 検出レポート - YYYY-MM-DD

## エグゼクティブサマリー
（検出状況の概要と最重要アクションを3行以内で記述）

## 重大度別サマリー
（件数の表）

## 検出結果と対応策

### 1. [CRITICAL] 検出タイトル
- **リソース**: リソースタイプ / リソースID
- **アカウント**: アカウントID (リージョン)
- **リスク評価**: リスクの説明（2〜3行）
- **推奨対応策**:
  1. 手順1
  2. 手順2
- **CloudFormation / CLI コマンド**: (コードブロック)
- **参考**: 公式ドキュメント URL
```

### コマンド・テンプレート生成ルール
- CloudFormation テンプレートは YAML 形式で生成する
- CLI コマンドは実行可能な形式で、プレースホルダー（<ACCOUNT_ID> 等）を明示する
- DRY_RUN モードの場合は実際のリソース変更を行わないコマンドを生成する
- 破壊的な変更（削除・無効化）は必ず確認ステップを含める

## 重要な制約
- dry_run={dry_run} の場合、CFn スタックの実際の作成は行わない
- 推測でコマンドを生成せず、Security Hub の remediation_url と remediation_text を参照する
- アカウント ID やリソース ID は検出結果から取得した実際の値を使用する
""".format(
    dry_run=settings.dry_run
)


def create_agent() -> Agent:
    """Security Hub Agent のインスタンスを生成する。

    注: Bedrock のタイムアウト設定は以下で行う：
      - 環境変数: AWS_PROFILE / AWS_REGION
      - tools/ の各 boto3 クライアントで個別に BotocoreConfig を設定
      - Step Functions の Lambda タイムアウト設定
    """
    return Agent(
        model=settings.bedrock_model_id,
        system_prompt=SYSTEM_PROMPT,
        name="security-hub-advisor",
        description=(
            "AWS Security Hub の検出結果を分析し、リスク評価・対応策レポートを生成して "
            "S3 に保存し SNS で通知する AWS セキュリティ専門エージェント。"
        ),
        tools=[
            get_security_findings,
            get_finding_detail,
            save_report_to_s3,
            save_multiple_files_to_s3,
            publish_security_report,
            save_execution_history,
            get_recent_execution_history,
        ],
    )


def run_security_analysis(run_date: str | None = None) -> dict:
    """
    Security Hub Agent のメインワークフローを実行する。

    Args:
        run_date: 対象日 (YYYY-MM-DD)。None の場合は今日。

    Returns:
        実行結果のサマリー。
    """
    if run_date is None:
        run_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    logger.info("Starting Security Hub Agent. run_date=%s, dry_run=%s", run_date, settings.dry_run)

    agent = create_agent()

    prompt = f"""
以下の手順で Security Hub の検出結果を分析し、レポートを作成・送信してください。
対象日: {run_date}
DRY_RUN モード: {settings.dry_run}

## 実行手順

1. **履歴確認**: get_recent_execution_history で直近7日の実行履歴を確認する。
   前回との差分がある場合はレポートにその旨を記載する。

2. **検出結果取得**: get_security_findings で CRITICAL と HIGH の検出結果を取得する。
   検出件数が 0 件の場合は SNS に「検出なし」の通知を送り、処理を終了する。

3. **レポート生成**: 取得した検出結果を分析し、以下のファイルを生成する:
   - report.md: 全検出結果の詳細レポート（Markdown 形式）
   - remediation.yaml: 対応可能な検出に対する CloudFormation テンプレート
   - commands.sh: AWS CLI による修復コマンド集

4. **S3 保存**: save_multiple_files_to_s3 で上記 3 ファイルを S3 に保存し、
   Presigned URL を取得する。

5. **SNS 通知**: publish_security_report で以下を含む通知を送信する:
   - 重大度別サマリー
   - 上位 5 件の検出結果
   - S3 の各ファイルへの Presigned URL

6. **履歴保存**: save_execution_history で実行結果を DynamoDB に記録する。

各ステップでエラーが発生した場合は、エラー内容を記録して次のステップを継続してください。
"""

    result = agent(prompt)
    logger.info("Security Hub Agent completed.")
    return {"status": "completed", "run_date": run_date, "result": str(result)}


if __name__ == "__main__":
    run_security_analysis()