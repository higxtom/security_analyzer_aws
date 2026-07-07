"""
SNS 通知送信ツール
サマリーと S3 Presigned URL を含むメッセージを SNS トピックへパブリッシュする
"""
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.config import Config as BotocoreConfig
from strands import tool

from src.utils.config import get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()

_BOTO3_CONFIG = BotocoreConfig(
    connect_timeout=60,
    read_timeout=300,
    retries={"max_attempts": 3, "mode": "adaptive"},
)


def _get_sns_client():
    session = boto3.Session(
        region_name=settings.aws_region,
        profile_name=settings.aws_profile,
    )
    return session.client("sns", config=_BOTO3_CONFIG)


@tool
def publish_security_report(
    severity_summary: dict[str, int],
    top_findings: list[dict],
    s3_files: list[dict[str, str]],
    run_date: str | None = None,
) -> dict[str, Any]:
    """
    Security Hub のレポートを SNS トピックへ送信する。
    本文にサマリーと上位検出結果を含め、詳細は S3 Presigned URL で連携する。

    Args:
        severity_summary: 重大度別件数。例: {"CRITICAL": 3, "HIGH": 10}
        top_findings:     上位 5 件の検出結果（slim 形式）。
        s3_files:         S3 に保存したファイルのリスト（save_report_to_s3 の戻り値）。
        run_date:         レポート対象日 (YYYY-MM-DD)。None の場合は今日。

    Returns:
        SNS の publish レスポンス（MessageId を含む）。
    """
    if run_date is None:
        run_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    subject = _build_subject(severity_summary, run_date)
    message = _build_message(severity_summary, top_findings, s3_files, run_date)

    client = _get_sns_client()

    logger.info("Publishing to SNS topic: %s", settings.sns_topic_arn)

    response = client.publish(
        TopicArn=settings.sns_topic_arn,
        Subject=subject,
        Message=message,
    )

    logger.info("SNS publish succeeded. MessageId: %s", response.get("MessageId"))
    return {
        "message_id": response.get("MessageId"),
        "subject": subject,
    }


def _build_subject(severity_summary: dict[str, int], run_date: str) -> str:
    """SNS メッセージの件名を生成する（最大 100 文字）"""
    parts = []
    for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_summary.get(label, 0)
        if count > 0:
            parts.append(f"{label}: {count}件")

    summary_str = ", ".join(parts) if parts else "検出なし"
    subject = f"[Security Hub] {run_date} 検出レポート ({summary_str})"

    # SNS の件名は最大 100 文字
    return subject[:100]


def _build_message(
    severity_summary: dict[str, int],
    top_findings: list[dict],
    s3_files: list[dict[str, str]],
    run_date: str,
) -> str:
    """SNS メッセージ本文を生成する"""
    lines = [
        f"=== AWS Security Hub 検出レポート ({run_date}) ===",
        "",
        "【重大度別サマリー】",
    ]

    for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
        count = severity_summary.get(label, 0)
        if count > 0:
            lines.append(f"  {label}: {count} 件")

    total = sum(severity_summary.values())
    lines += [f"  合計: {total} 件", ""]

    # 上位検出結果（最大 5 件）
    if top_findings:
        lines.append("【上位検出結果（重大度順）】")
        for i, finding in enumerate(top_findings[:5], start=1):
            lines += [
                f"  {i}. [{finding.get('severity', '-')}] {finding.get('title', '-')}",
                f"     リソース: {finding.get('resource_type', '-')} / {finding.get('resource_id', '-')}",
                f"     アカウント: {finding.get('aws_account_id', '-')} ({finding.get('region', '-')})",
            ]
        lines.append("")

    # S3 ファイルリンク
    if s3_files:
        lines.append("【詳細ドキュメント（7日間有効）】")
        label_map = {
            "report.md": "📄 検出レポート（詳細）",
            "remediation.yaml": "🔧 CloudFormation 修復テンプレート",
            "commands.sh": "💻 CLI 修復コマンド集",
            "summary.json": "📊 サマリー JSON",
        }
        for f in s3_files:
            filename = f.get("filename", f.get("s3_key", "").split("/")[-1])
            display = label_map.get(filename, f"📎 {filename}")
            url = f.get("presigned_url", "")
            lines.append(f"  {display}")
            lines.append(f"  {url}")
            lines.append("")

    lines += [
        "---",
        "このメッセージは Security Hub Agent によって自動生成されました。",
        "修復を実行する場合は、内容を確認してから承認してください。",
    ]

    return "\n".join(lines)