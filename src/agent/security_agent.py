"""
Security Hub Agent 本体
Strands Framework を使用して、Security Hub の検出結果を分析し
対応策を生成・レポートを作成・SNS 通知を行う

AWS リソースへのアクセスは awslabs.aws-api-mcp-server の call_aws ツール経由で行う。
タスクを小さなステップに分割し、各 Agent 呼び出しが Bedrock の
推論タイムアウトに収まるようにしている。
"""
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from botocore.config import Config as BotocoreConfig
from strands import Agent
from strands.models.bedrock import BedrockModel

# boto3 グローバルタイムアウト設定を適用（Bedrock 推論用）
from src.utils.boto3_config import DEFAULT_BOTO3_CONFIG  # noqa: F401
from src.utils.config import get_settings
from src.utils.logger import get_logger
from src.utils.mcp_client import aws_mcp_context

logger = get_logger(__name__)
settings = get_settings()

# Bedrock 推論用のタイムアウト設定（ストリーミングチャンク間の read_timeout を十分に確保）
_BEDROCK_CLIENT_CONFIG = BotocoreConfig(
    connect_timeout=settings.bedrock_connect_timeout,
    read_timeout=settings.bedrock_read_timeout,
    retries={"max_attempts": 3, "mode": "adaptive"},
)

SYSTEM_PROMPT = """
あなたは AWS セキュリティ専門の AI エージェントです。
AWS Security Hub の検出結果を分析し、具体的な対応策を日本語で提案します。

## あなたの役割

1. Security Hub から検出結果を取得・分析する
2. 各検出項目に対してリスク評価と具体的な対応策を作成する
3. 対応策を CloudFormation テンプレートまたは AWS CLI コマンドとして生成する
4. レポートを S3 に保存し、SNS で通知する
5. 実行履歴を DynamoDB に記録する

## AWS リソースアクセス方法

AWS リソースへのアクセスには call_aws ツールを使用します。
call_aws は AWS CLI コマンドを引数として受け取り、実行結果を返します。

### 使用例
- Security Hub の検出結果取得:
  call_aws(cli_command="aws securityhub get-findings --filters '{{...}}' --region {region}")
- S3 へのファイル保存:
  call_aws(cli_command="aws s3api put-object --bucket BUCKET --key KEY --body CONTENT --region {region}")
- SNS への通知送信:
  call_aws(cli_command="aws sns publish --topic-arn ARN --subject SUBJECT --message MSG --region {region}")
- DynamoDB への履歴保存:
  call_aws(cli_command="aws dynamodb put-item --table-name TABLE --item '{{...}}' --region {region}")

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

## AWS リソース設定
- リージョン: {region}
- S3 バケット: {bucket}
- S3 プレフィックス: {prefix}
- SNS トピック ARN: {sns_topic}
- DynamoDB テーブル: {dynamodb_table}
- Presigned URL 有効期間: {presigned_expiry} 秒
""".format(
    dry_run=settings.dry_run,
    region=settings.aws_region,
    bucket=settings.report_bucket_name,
    prefix=settings.report_prefix,
    sns_topic=settings.sns_topic_arn,
    dynamodb_table=settings.dynamodb_table_name,
    presigned_expiry=settings.presigned_url_expiry_seconds,
)


def _create_bedrock_model() -> BedrockModel:
    """タイムアウトを十分に確保した BedrockModel を生成する。"""
    return BedrockModel(
        model_id=settings.bedrock_model_id,
        region_name=settings.aws_region,
        boto_client_config=_BEDROCK_CLIENT_CONFIG,
    )


def create_agent(
    tools: list[Any] | None = None,
    system_prompt: str | None = None,
) -> Agent:
    """Security Hub Agent のインスタンスを生成する。

    tools に MCPClient を渡すと、MCP Server のツールが Agent に提供される。

    Args:
        tools: Agent が使用するツール一覧。
        system_prompt: システムプロンプト。None の場合はデフォルトを使用。
    """
    return Agent(
        model=_create_bedrock_model(),
        system_prompt=system_prompt or SYSTEM_PROMPT,
        name="security-hub-advisor",
        description=(
            "AWS Security Hub の検出結果を分析し、リスク評価・対応策レポートを生成して "
            "S3 に保存し SNS で通知する AWS セキュリティ専門エージェント。"
        ),
        tools=tools or [],
    )


# ---------------------------------------------------------------------------
# ステップ別 Agent 呼び出し
# 1 回の Bedrock 推論が大きくなりすぎないようにタスクを分割する
# AWS リソースアクセスは MCP Server (call_aws) 経由で行う
# ---------------------------------------------------------------------------


def _build_severity_filter(severity_labels: list[str]) -> str:
    """Security Hub の SeverityLabel フィルタ JSON を生成する。"""
    filters = {
        "SeverityLabel": [
            {"Value": label, "Comparison": "EQUALS"} for label in severity_labels
        ],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
    }
    return json.dumps(filters, ensure_ascii=False)


def _step_fetch_data(mcp_client: Any, run_date: str) -> dict[str, Any]:
    """Step 1: 履歴確認 + Security Hub Findings 取得。

    call_aws ツールを使い、Security Hub と DynamoDB にアクセスする。
    """
    agent = create_agent(
        tools=[mcp_client],
        system_prompt=(
            "あなたは AWS セキュリティデータ収集アシスタントです。\n"
            "call_aws ツールを使って AWS CLI コマンドを実行し、結果を返してください。\n"
            f"リージョン: {settings.aws_region}\n"
            f"DynamoDB テーブル: {settings.dynamodb_table_name}\n"
        ),
    )

    severity_filter = _build_severity_filter(settings.findings_severity_list)

    prompt = f"""
以下の 2 つのタスクを call_aws ツールで順に実行してください。

## タスク 1: 直近 7 日の実行履歴を取得
DynamoDB テーブル "{settings.dynamodb_table_name}" から直近 7 日分の実行履歴を取得します。
今日の日付は {run_date} です。

call_aws で以下のコマンドを実行してください:
aws dynamodb query --table-name {settings.dynamodb_table_name} --key-condition-expression "run_date = :d" --expression-attribute-values ':d={{"S":"{run_date}"}}' --scan-index-forward false --limit 5 --region {settings.aws_region}

## タスク 2: Security Hub の検出結果を取得
call_aws で以下のコマンドを実行してください:
aws securityhub get-findings --filters '{severity_filter}' --sort-criteria '{{"Field":"SeverityLabel","SortOrder":"desc"}}' --max-items 50 --region {settings.aws_region}

両方の結果をそのまま返してください。
"""
    result = agent(prompt)
    logger.info("Step 1 (fetch data) completed.")
    return {"step": "fetch_data", "result": str(result)}


def _step_generate_report(
    findings_json: str,
    run_date: str,
) -> dict[str, Any]:
    """Step 2: Findings を分析してレポート (report.md) を生成する。

    ツール不要で推論のみ行う。
    """
    agent = create_agent(
        tools=[],
        system_prompt=SYSTEM_PROMPT,
    )

    prompt = f"""
以下の Security Hub 検出結果を分析し、**report.md** の内容を Markdown で生成してください。
対象日: {run_date}
DRY_RUN モード: {settings.dry_run}

## 検出結果データ
{findings_json}

## 出力ルール
- 出力は report.md の本文のみ（```markdown などのコードフェンスで囲まない）
- エグゼクティブサマリー → 重大度別サマリー → 各検出結果と対応策 の順で記述
- 各検出結果にはリスク評価・推奨対応策を含める
"""
    result = agent(prompt)
    logger.info("Step 2 (generate report) completed.")
    return {"step": "generate_report", "content": str(result)}


def _step_generate_remediation(
    findings_json: str,
    run_date: str,
) -> dict[str, Any]:
    """Step 3: CloudFormation テンプレートと CLI コマンド集を生成する。

    ツール不要で推論のみ行う。
    """
    agent = create_agent(
        tools=[],
        system_prompt=SYSTEM_PROMPT,
    )

    prompt = f"""
以下の Security Hub 検出結果に対して、修復用ファイルを 2 つ生成してください。
対象日: {run_date}
DRY_RUN モード: {settings.dry_run}

## 検出結果データ
{findings_json}

## 生成ルール
以下の 2 ブロックを順に出力してください。各ブロックは区切り行で明示します。

---REMEDIATION_YAML_START---
（remediation.yaml の内容: YAML 形式の CloudFormation テンプレート）
---REMEDIATION_YAML_END---

---COMMANDS_SH_START---
（commands.sh の内容: AWS CLI 修復コマンド集。シェルスクリプト形式）
---COMMANDS_SH_END---

- CloudFormation テンプレートは YAML 形式で生成する
- CLI コマンドにはプレースホルダー（<ACCOUNT_ID> 等）を明示する
- remediation_url と remediation_text を参照してコマンドを生成する
"""
    result = agent(prompt)
    logger.info("Step 3 (generate remediation) completed.")
    return {"step": "generate_remediation", "content": str(result)}


def _parse_remediation_output(raw: str) -> tuple[str, str]:
    """Step 3 の出力からYAML とシェルスクリプトを抽出する。"""
    yaml_content = ""
    sh_content = ""

    if "---REMEDIATION_YAML_START---" in raw and "---REMEDIATION_YAML_END---" in raw:
        yaml_content = raw.split("---REMEDIATION_YAML_START---")[1].split(
            "---REMEDIATION_YAML_END---"
        )[0].strip()
    if "---COMMANDS_SH_START---" in raw and "---COMMANDS_SH_END---" in raw:
        sh_content = raw.split("---COMMANDS_SH_START---")[1].split(
            "---COMMANDS_SH_END---"
        )[0].strip()

    if not yaml_content:
        yaml_content = "# 修復テンプレートの生成に失敗しました\n"
    if not sh_content:
        sh_content = "#!/bin/bash\n# 修復コマンドの生成に失敗しました\n"

    return yaml_content, sh_content


def _write_temp_files(
    report_md: str,
    remediation_yaml: str,
    commands_sh: str,
    workdir: Path,
) -> dict[str, str]:
    """レポートファイルを一時ディレクトリに書き出し、パスを返す。"""
    files = {
        "report.md": report_md,
        "remediation.yaml": remediation_yaml,
        "commands.sh": commands_sh,
    }
    paths: dict[str, str] = {}
    for name, content in files.items():
        path = workdir / name
        path.write_text(content, encoding="utf-8")
        paths[name] = str(path)
    return paths


def _step_save_and_notify(
    mcp_client: Any,
    report_md: str,
    remediation_yaml: str,
    commands_sh: str,
    severity_summary: dict[str, int],
    total_findings: int,
    top_findings: list[dict[str, Any]],
    run_date: str,
) -> dict[str, Any]:
    """Step 4: S3 保存 → Presigned URL 生成 → SNS 通知 → 履歴保存。

    call_aws ツールで S3, SNS, DynamoDB にアクセスする。
    S3 アップロード用のファイルは一時ディレクトリに書き出して --body file:// で渡す。
    """
    with tempfile.TemporaryDirectory(prefix="security_report_") as tmpdir:
        workdir = Path(tmpdir)
        file_paths = _write_temp_files(report_md, remediation_yaml, commands_sh, workdir)

        agent = create_agent(
            tools=[mcp_client],
            system_prompt=(
                "あなたは AWS セキュリティレポート配信アシスタントです。\n"
                "call_aws ツールを使って AWS CLI コマンドを実行してください。\n"
                f"リージョン: {settings.aws_region}\n"
                f"S3 バケット: {settings.report_bucket_name}\n"
                f"SNS トピック ARN: {settings.sns_topic_arn}\n"
                f"DynamoDB テーブル: {settings.dynamodb_table_name}\n"
            ),
        )

        s3_prefix = f"{settings.report_prefix}/{run_date}"
        executed_at = datetime.now(timezone.utc).isoformat()

        # SNS 通知メッセージを事前構築
        sns_lines = [
            f"=== AWS Security Hub 検出レポート ({run_date}) ===",
            "",
            "【重大度別サマリー】",
        ]
        for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_summary.get(label, 0)
            if count > 0:
                sns_lines.append(f"  {label}: {count} 件")
        sns_lines.append(f"  合計: {total_findings} 件")
        sns_lines.append("")

        if top_findings:
            sns_lines.append("【上位検出結果（重大度順）】")
            for i, f in enumerate(top_findings[:5], start=1):
                severity = f.get("Severity", {}).get("Label", f.get("severity", "-"))
                title = f.get("Title", f.get("title", "-"))
                sns_lines.append(f"  {i}. [{severity}] {title}")
            sns_lines.append("")

        sns_lines += [
            "---",
            "このメッセージは Security Hub Agent によって自動生成されました。",
        ]
        sns_message = "\n".join(sns_lines)

        # SNS サブジェクト
        summary_parts = []
        for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_summary.get(label, 0)
            if count > 0:
                summary_parts.append(f"{label}: {count}件")
        summary_str = ", ".join(summary_parts) if summary_parts else "検出なし"
        sns_subject = f"[Security Hub] {run_date} 検出レポート ({summary_str})"[:100]

        # SNS メッセージを一時ファイルに書き出す（長文対策）
        sns_message_file = workdir / "sns_message.txt"
        sns_message_file.write_text(sns_message, encoding="utf-8")

        # DynamoDB item JSON を一時ファイルに書き出す
        dynamodb_item = {
            "run_date": {"S": run_date},
            "executed_at": {"S": executed_at},
            "status": {"S": "SUCCESS"},
            "total_findings": {"N": str(total_findings)},
            "s3_report_key": {"S": f"{s3_prefix}/report.md"},
        }
        dynamodb_item_file = workdir / "dynamodb_item.json"
        dynamodb_item_file.write_text(
            json.dumps(dynamodb_item, ensure_ascii=False), encoding="utf-8"
        )

        prompt = f"""
以下のタスクを call_aws で順に実行してください。

## タスク 1: S3 にレポートファイルを保存
3 つのファイルを S3 に保存してください。バッチモードで実行します:
call_aws(cli_command=[
  "aws s3api put-object --bucket {settings.report_bucket_name} --key {s3_prefix}/report.md --body file://{file_paths['report.md']} --content-type text/markdown --server-side-encryption AES256 --region {settings.aws_region}",
  "aws s3api put-object --bucket {settings.report_bucket_name} --key {s3_prefix}/remediation.yaml --body file://{file_paths['remediation.yaml']} --content-type application/x-yaml --server-side-encryption AES256 --region {settings.aws_region}",
  "aws s3api put-object --bucket {settings.report_bucket_name} --key {s3_prefix}/commands.sh --body file://{file_paths['commands.sh']} --content-type text/x-shellscript --server-side-encryption AES256 --region {settings.aws_region}"
])

## タスク 2: Presigned URL を生成
各ファイルの Presigned URL を生成してください:
call_aws(cli_command=[
  "aws s3 presign s3://{settings.report_bucket_name}/{s3_prefix}/report.md --expires-in {settings.presigned_url_expiry_seconds} --region {settings.aws_region}",
  "aws s3 presign s3://{settings.report_bucket_name}/{s3_prefix}/remediation.yaml --expires-in {settings.presigned_url_expiry_seconds} --region {settings.aws_region}",
  "aws s3 presign s3://{settings.report_bucket_name}/{s3_prefix}/commands.sh --expires-in {settings.presigned_url_expiry_seconds} --region {settings.aws_region}"
])

## タスク 3: SNS 通知を送信
call_aws(cli_command="aws sns publish --topic-arn {settings.sns_topic_arn} --subject '{sns_subject}' --message file://{sns_message_file} --region {settings.aws_region}")

## タスク 4: DynamoDB に実行履歴を保存
call_aws(cli_command="aws dynamodb put-item --table-name {settings.dynamodb_table_name} --item file://{dynamodb_item_file} --region {settings.aws_region}")

各タスクの結果を報告してください。
"""
        result = agent(prompt)
        logger.info("Step 4 (save & notify) completed.")
        return {"step": "save_and_notify", "result": str(result)}


def _step_no_findings_notify(mcp_client: Any, run_date: str) -> dict[str, Any]:
    """検出結果が 0 件の場合に SNS 通知 + 履歴保存を行う。"""
    agent = create_agent(
        tools=[mcp_client],
        system_prompt=(
            "あなたは AWS セキュリティレポート配信アシスタントです。\n"
            "call_aws ツールを使って AWS CLI コマンドを実行してください。\n"
            f"リージョン: {settings.aws_region}\n"
        ),
    )

    executed_at = datetime.now(timezone.utc).isoformat()

    with tempfile.TemporaryDirectory(prefix="security_nofinding_") as tmpdir:
        workdir = Path(tmpdir)

        # DynamoDB item JSON を一時ファイルに書き出す
        dynamodb_item = {
            "run_date": {"S": run_date},
            "executed_at": {"S": executed_at},
            "status": {"S": "NO_FINDINGS"},
            "total_findings": {"N": "0"},
            "s3_report_key": {"S": ""},
            "sns_message_id": {"S": ""},
        }
        dynamodb_item_file = workdir / "dynamodb_item.json"
        dynamodb_item_file.write_text(
            json.dumps(dynamodb_item, ensure_ascii=False), encoding="utf-8"
        )

        sns_message = (
            f"=== AWS Security Hub 検出レポート ({run_date}) ===\n\n"
            "検出結果: 0 件\n\n"
            "このメッセージは Security Hub Agent によって自動生成されました。"
        )
        sns_message_file = workdir / "sns_message.txt"
        sns_message_file.write_text(sns_message, encoding="utf-8")

        prompt = f"""
Security Hub の検出結果が 0 件でした。以下を call_aws で実行してください。

1. SNS 通知:
call_aws(cli_command="aws sns publish --topic-arn {settings.sns_topic_arn} --subject '[Security Hub] {run_date} 検出レポート (検出なし)' --message file://{sns_message_file} --region {settings.aws_region}")

2. DynamoDB に実行履歴を保存:
call_aws(cli_command="aws dynamodb put-item --table-name {settings.dynamodb_table_name} --item file://{dynamodb_item_file} --region {settings.aws_region}")
"""
        result = agent(prompt)
    logger.info("No findings notification completed.")
    return {"step": "no_findings", "result": str(result)}


# ---------------------------------------------------------------------------
# メインオーケストレーション
# ---------------------------------------------------------------------------


def run_security_analysis(run_date: str | None = None) -> dict:
    """
    Security Hub Agent のメインワークフローを実行する。

    AWS リソースへのアクセスは MCP Server (call_aws) 経由で行う。
    タスクをステップに分割し、各 Bedrock 推論呼び出しがタイムアウトしない
    サイズに抑えている。

    ステップ構成:
      1. データ取得（履歴 + Findings）  — call_aws でデータ取得
      2. レポート生成 (report.md)       — 推論のみ
      3. 修復ファイル生成               — 推論のみ
      4. S3 保存 + SNS 通知 + 履歴保存  — call_aws でリソース操作

    Args:
        run_date: 対象日 (YYYY-MM-DD)。None の場合は今日。

    Returns:
        実行結果のサマリー。
    """
    if run_date is None:
        run_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    logger.info(
        "Starting Security Hub Agent (MCP). run_date=%s, dry_run=%s",
        run_date,
        settings.dry_run,
    )

    steps_completed: list[str] = []

    with aws_mcp_context() as mcp_client:

        # --- Step 1: データ取得 ---
        try:
            step1 = _step_fetch_data(mcp_client, run_date)
            steps_completed.append("fetch_data")
        except Exception as e:
            logger.error("Step 1 (fetch data) failed: %s", e)
            return {
                "status": "failed",
                "run_date": run_date,
                "error": str(e),
                "failed_step": "fetch_data",
            }

        # Step 1 の Agent 出力から Findings データを抽出
        # MCP 経由では get-findings の結果が Agent の出力テキストに含まれる
        step1_text = step1.get("result", "")
        findings = _extract_findings_from_output(step1_text)

        # 検出 0 件の場合は早期終了
        if not findings:
            logger.info("No findings detected. Sending notification.")
            try:
                _step_no_findings_notify(mcp_client, run_date)
                steps_completed.append("no_findings_notify")
            except Exception as e:
                logger.error("No-findings notification failed: %s", e)
            return {
                "status": "completed",
                "run_date": run_date,
                "total_findings": 0,
                "steps_completed": steps_completed,
            }

        # 重大度サマリーを集計
        severity_summary: dict[str, int] = {}
        for f in findings:
            label = f.get("Severity", {}).get("Label", "UNKNOWN")
            severity_summary[label] = severity_summary.get(label, 0) + 1

        findings_json = json.dumps(findings, ensure_ascii=False, indent=2)
        total_findings = len(findings)
        logger.info("Findings fetched: %d items", total_findings)

        # --- Step 2: レポート生成 ---
        report_md = ""
        try:
            step2 = _step_generate_report(findings_json, run_date)
            report_md = step2["content"]
            steps_completed.append("generate_report")
        except Exception as e:
            logger.error("Step 2 (generate report) failed: %s", e)
            report_md = f"# レポート生成エラー\n\nエラー: {e}\n"

        # --- Step 3: 修復ファイル生成 ---
        remediation_yaml = ""
        commands_sh = ""
        try:
            step3 = _step_generate_remediation(findings_json, run_date)
            remediation_yaml, commands_sh = _parse_remediation_output(step3["content"])
            steps_completed.append("generate_remediation")
        except Exception as e:
            logger.error("Step 3 (generate remediation) failed: %s", e)
            remediation_yaml = "# 修復テンプレートの生成に失敗しました\n"
            commands_sh = "#!/bin/bash\n# 修復コマンドの生成に失敗しました\n"

        # --- Step 4: S3 保存 + SNS 通知 + 履歴保存 ---
        try:
            _step_save_and_notify(
                mcp_client=mcp_client,
                report_md=report_md,
                remediation_yaml=remediation_yaml,
                commands_sh=commands_sh,
                severity_summary=severity_summary,
                total_findings=total_findings,
                top_findings=findings[:5],
                run_date=run_date,
            )
            steps_completed.append("save_and_notify")
        except Exception as e:
            logger.error("Step 4 (save & notify) failed: %s", e)

    logger.info("Security Hub Agent completed. steps=%s", steps_completed)
    return {
        "status": "completed",
        "run_date": run_date,
        "total_findings": total_findings,
        "severity_summary": severity_summary,
        "steps_completed": steps_completed,
    }


def _extract_findings_from_output(text: str) -> list[dict[str, Any]]:
    """Agent の出力テキストから Findings リストを抽出する。

    call_aws の実行結果として get-findings のレスポンス JSON が含まれるため、
    その中の "Findings" キーを探す。
    """
    try:
        # JSON ブロックを探す（複数の JSON が含まれる可能性がある）
        import re

        # {"Findings": [...]} パターンを探す
        for match in re.finditer(r'\{[^{}]*"Findings"\s*:\s*\[', text):
            start = match.start()
            # 対応する閉じブレースを探す
            depth = 0
            for i in range(start, len(text)):
                if text[i] == '{':
                    depth += 1
                elif text[i] == '}':
                    depth -= 1
                    if depth == 0:
                        try:
                            data = json.loads(text[start:i + 1])
                            findings = data.get("Findings", [])
                            if isinstance(findings, list):
                                return findings
                        except json.JSONDecodeError:
                            continue
                        break
    except Exception as e:
        logger.warning("Failed to extract findings from output: %s", e)

    return []


if __name__ == "__main__":
    run_security_analysis()
