"""
Security Hub Agent 本体
Strands Framework を使用して、Security Hub の検出結果を分析し
対応策を生成・レポートを作成・SNS 通知を行う

タスクを小さなステップに分割し、各 Agent 呼び出しが Bedrock の
推論タイムアウトに収まるようにしている。
"""
import json
from datetime import datetime, timezone
from typing import Any

from botocore.config import Config as BotocoreConfig
from strands import Agent, tool
from strands.models.bedrock import BedrockModel

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

    Args:
        tools: Agent が使用するツール一覧。None の場合は全ツールを設定。
        system_prompt: システムプロンプト。None の場合はデフォルトを使用。
    """
    if tools is None:
        tools = [
            get_security_findings,
            get_finding_detail,
            save_report_to_s3,
            save_multiple_files_to_s3,
            publish_security_report,
            save_execution_history,
            get_recent_execution_history,
        ]

    return Agent(
        model=_create_bedrock_model(),
        system_prompt=system_prompt or SYSTEM_PROMPT,
        name="security-hub-advisor",
        description=(
            "AWS Security Hub の検出結果を分析し、リスク評価・対応策レポートを生成して "
            "S3 に保存し SNS で通知する AWS セキュリティ専門エージェント。"
        ),
        tools=tools,
    )


# ---------------------------------------------------------------------------
# AgentCore Runtime エントリーポイント用ディスパッチャー
# A2A 経由で {"run_date": ..., "action": "run_analysis"} を受け取り、
# run_security_analysis() をそのまま呼び出す単一ツール専用の Agent。
# ---------------------------------------------------------------------------

DISPATCH_SYSTEM_PROMPT = """
あなたは Security Hub Agent のディスパッチャーです。会話や説明は行いません。

受け取るメッセージは次の JSON 形式です:
{"run_date": "YYYY-MM-DD", "action": "run_analysis"}

## 実行手順
1. メッセージから run_date を取り出し、run_daily_security_analysis ツールを
   run_date を引数にして 1 回だけ呼び出す。
2. ツールが返した JSON をそのまま出力する。要約・説明・Markdown 装飾・
   コードフェンスなど、JSON 以外の文字は一切付け加えない。
"""


@tool
def run_daily_security_analysis(run_date: str) -> dict[str, Any]:
    """Security Hub Agent の日次ワークフローを実行する（AgentCore Runtime 用）。

    Args:
        run_date: 対象日 (YYYY-MM-DD)。

    Returns:
        run_security_analysis() の実行結果。
    """
    return run_security_analysis(run_date=run_date)


def create_dispatcher_agent() -> Agent:
    """AgentCore Runtime のエントリーポイント (agentcore_app.py) が使う、
    run_daily_security_analysis ツールのみを持つ専用 Agent を生成する。

    汎用ツール一式を持つ create_agent() とは異なり、この Agent は
    「run_date を受け取ってワークフローを起動する」以外の判断をしない。
    """
    return Agent(
        model=_create_bedrock_model(),
        system_prompt=DISPATCH_SYSTEM_PROMPT,
        name="security-hub-agent-dispatcher",
        description=(
            "Security Hub Agent の日次ワークフローを起動するディスパッチャー。"
            "run_date を受け取り run_daily_security_analysis ツールを呼び出す。"
        ),
        tools=[run_daily_security_analysis],
    )


# ---------------------------------------------------------------------------
# ステップ別 Agent 呼び出し
# 1 回の Bedrock 推論が大きくなりすぎないようにタスクを分割する
# ---------------------------------------------------------------------------


def _step_fetch_data(run_date: str) -> dict[str, Any]:
    """Step 1: 履歴確認 + Security Hub Findings 取得。

    ツール呼び出し中心のため推論負荷が小さい。
    """
    agent = create_agent(
        tools=[get_security_findings, get_recent_execution_history],
        system_prompt=(
            "あなたは AWS セキュリティデータ収集アシスタントです。"
            "指示に従ってツールを呼び出し、結果を JSON 形式で返してください。"
        ),
    )

    prompt = f"""
以下の 2 つのタスクを順に実行してください。

1. get_recent_execution_history を呼び出し、直近 7 日の実行履歴を取得する。
2. get_security_findings を severity_labels=["CRITICAL", "HIGH"] で呼び出し、
   検出結果を取得する。

最終的に以下の JSON 形式で結果を返してください（余計な説明は不要です）:
{{
  "history": <get_recent_execution_history の戻り値>,
  "findings_result": <get_security_findings の戻り値>
}}
"""
    result = agent(prompt)
    logger.info("Step 1 (fetch data) completed.")
    return {"step": "fetch_data", "result": str(result)}


def _step_generate_report(
    findings_json: str,
    run_date: str,
) -> dict[str, Any]:
    """Step 2: Findings を分析してレポート (report.md) を生成する。

    Findings データを直接プロンプトに埋め込み、ツール不要で推論のみ行う。
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

    Findings データを直接プロンプトに埋め込み、ツール不要で推論のみ行う。
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

    # マーカーが見つからない場合のフォールバック
    if not yaml_content:
        yaml_content = "# 修復テンプレートの生成に失敗しました\n"
    if not sh_content:
        sh_content = "#!/bin/bash\n# 修復コマンドの生成に失敗しました\n"

    return yaml_content, sh_content


def _step_save_and_notify(
    report_md: str,
    remediation_yaml: str,
    commands_sh: str,
    findings_result: dict[str, Any],
    run_date: str,
) -> dict[str, Any]:
    """Step 4: S3 保存 → SNS 通知 → 履歴保存。

    呼び出し順序・引数が完全に決定的なため、Bedrock 推論を挟まずツール関数を
    直接呼び出す。LLM 経由にすると大きなレポート本文を1回のプロンプトに
    埋め込むことになり、Bedrock の read_timeout（デフォルト 600 秒）を
    超えて失敗することがあったため。
    """
    severity_summary = findings_result.get("severity_summary", {})
    total = findings_result.get("total", 0)
    top_findings = findings_result.get("findings", [])[:5]

    s3_files = save_multiple_files_to_s3(
        files=[
            {"filename": "report.md", "content": report_md, "content_type": "text/markdown"},
            {"filename": "remediation.yaml", "content": remediation_yaml, "content_type": "application/x-yaml"},
            {"filename": "commands.sh", "content": commands_sh, "content_type": "text/x-shellscript"},
        ],
        run_date=run_date,
    )

    sns_result = publish_security_report(
        severity_summary=severity_summary,
        top_findings=top_findings,
        s3_files=s3_files,
        run_date=run_date,
    )

    report_s3_key = next(
        (f["s3_key"] for f in s3_files if f.get("filename") == "report.md"), ""
    )

    history_item = save_execution_history(
        run_date=run_date,
        severity_summary=severity_summary,
        total_findings=total,
        s3_report_key=report_s3_key,
        sns_message_id=sns_result.get("message_id", ""),
        status="SUCCESS",
    )

    logger.info("Step 4 (save & notify) completed.")
    return {
        "step": "save_and_notify",
        "s3_files": s3_files,
        "sns_result": sns_result,
        "history_item": history_item,
    }


def _step_no_findings_notify(run_date: str) -> dict[str, Any]:
    """検出結果が 0 件の場合に SNS 通知 + 履歴保存を行う（決定的処理のため直接呼び出し）。"""
    sns_result = publish_security_report(
        severity_summary={},
        top_findings=[],
        s3_files=[],
        run_date=run_date,
    )

    history_item = save_execution_history(
        run_date=run_date,
        severity_summary={},
        total_findings=0,
        s3_report_key="",
        sns_message_id=sns_result.get("message_id", ""),
        status="NO_FINDINGS",
    )

    logger.info("No findings notification completed.")
    return {"step": "no_findings", "sns_result": sns_result, "history_item": history_item}


# ---------------------------------------------------------------------------
# メインオーケストレーション
# ---------------------------------------------------------------------------


def run_security_analysis(run_date: str | None = None) -> dict:
    """
    Security Hub Agent のメインワークフローを実行する。

    タスクをステップに分割し、各 Bedrock 推論呼び出しがタイムアウトしない
    サイズに抑えている。

    ステップ構成:
      1. データ取得（履歴 + Findings）  — ツール呼び出し中心
      2. レポート生成 (report.md)       — 推論のみ
      3. 修復ファイル生成               — 推論のみ
      4. S3 保存 + SNS 通知 + 履歴保存  — ツール呼び出し中心

    Args:
        run_date: 対象日 (YYYY-MM-DD)。None の場合は今日。

    Returns:
        実行結果のサマリー。
    """
    if run_date is None:
        run_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    logger.info(
        "Starting Security Hub Agent (multi-step). run_date=%s, dry_run=%s",
        run_date,
        settings.dry_run,
    )

    steps_completed: list[str] = []

    # --- Step 1: データ取得 ---
    try:
        step1 = _step_fetch_data(run_date)
        steps_completed.append("fetch_data")
    except Exception as e:
        logger.error("Step 1 (fetch data) failed: %s", e)
        return {"status": "failed", "run_date": run_date, "error": str(e), "failed_step": "fetch_data"}

    # Findings データを Python 側で直接取得して後続ステップに渡す
    # （Agent の出力テキストのパースに頼らず、ツールを直接呼び出す）
    try:
        findings_result = get_security_findings(
            severity_labels=settings.findings_severity_list,
        )
    except Exception as e:
        logger.error("Direct findings fetch failed: %s", e)
        return {"status": "failed", "run_date": run_date, "error": str(e), "failed_step": "fetch_data_direct"}

    # 検出 0 件の場合は早期終了
    if findings_result["total"] == 0:
        logger.info("No findings detected. Sending notification.")
        try:
            _step_no_findings_notify(run_date)
            steps_completed.append("no_findings_notify")
        except Exception as e:
            logger.error("No-findings notification failed: %s", e)
        return {
            "status": "completed",
            "run_date": run_date,
            "total_findings": 0,
            "steps_completed": steps_completed,
        }

    findings_json = json.dumps(findings_result["findings"], ensure_ascii=False, indent=2)
    logger.info("Findings fetched: %d items", findings_result["total"])

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
        step4 = _step_save_and_notify(
            report_md=report_md,
            remediation_yaml=remediation_yaml,
            commands_sh=commands_sh,
            findings_result=findings_result,
            run_date=run_date,
        )
        steps_completed.append("save_and_notify")
    except Exception as e:
        logger.error("Step 4 (save & notify) failed: %s", e)

    logger.info("Security Hub Agent completed. steps=%s", steps_completed)
    return {
        "status": "completed",
        "run_date": run_date,
        "total_findings": findings_result["total"],
        "severity_summary": findings_result.get("severity_summary", {}),
        "steps_completed": steps_completed,
    }


if __name__ == "__main__":
    run_security_analysis()
