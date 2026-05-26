"""
DynamoDB 実行履歴管理ツール
重複実行の防止と過去対応履歴の参照に使用する
"""
import json
from datetime import datetime, timezone
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
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


def _get_table():
    session = boto3.Session(
        region_name=settings.aws_region,
        profile_name=settings.aws_profile,
    )
    dynamodb = session.resource("dynamodb", config=_BOTO3_CONFIG)
    return dynamodb.Table(settings.dynamodb_table_name)


@tool
def save_execution_history(
    run_date: str,
    severity_summary: dict[str, int],
    total_findings: int,
    s3_report_key: str,
    sns_message_id: str,
    status: str = "SUCCESS",
) -> dict[str, Any]:
    """
    Agent の実行結果を DynamoDB に保存する。

    Args:
        run_date:         実行日 (YYYY-MM-DD)。パーティションキーとして使用。
        severity_summary: 重大度別件数。
        total_findings:   検出件数合計。
        s3_report_key:    S3 レポートのキー。
        sns_message_id:   SNS のメッセージ ID。
        status:           実行ステータス ("SUCCESS" / "FAILED" / "NO_FINDINGS")。

    Returns:
        保存した Item の内容。
    """
    table = _get_table()
    now = datetime.now(timezone.utc).isoformat()

    item = {
        "run_date": run_date,                # PK
        "executed_at": now,                  # SK
        "status": status,
        "severity_summary": severity_summary,
        "total_findings": total_findings,
        "s3_report_key": s3_report_key,
        "sns_message_id": sns_message_id,
        "ttl": _ttl_90days(),
    }

    table.put_item(Item=item)
    logger.info("Saved execution history: run_date=%s, status=%s", run_date, status)
    return item


@tool
def get_recent_execution_history(days: int = 7) -> list[dict[str, Any]]:
    """
    直近 N 日分の実行履歴を取得する。
    Agent が「前回との差分」を判断する際に使用する。

    Args:
        days: 遡る日数（デフォルト: 7）。

    Returns:
        実行履歴のリスト（新しい順）。
    """
    from datetime import timedelta

    table = _get_table()
    results = []

    for i in range(days):
        target_date = (datetime.now(timezone.utc) - timedelta(days=i)).strftime(
            "%Y-%m-%d"
        )
        response = table.query(
            KeyConditionExpression=Key("run_date").eq(target_date),
            ScanIndexForward=False,  # 新しい順
            Limit=5,
        )
        results.extend(response.get("Items", []))

    return sorted(results, key=lambda x: x.get("executed_at", ""), reverse=True)


@tool
def check_finding_previously_reported(finding_id: str) -> dict[str, Any]:
    """
    指定した Finding が過去に報告済みかを確認する。
    重複報告を避けるために使用する。

    Args:
        finding_id: Finding の ID。

    Returns:
        {"previously_reported": bool, "last_reported_at": str | None}
    """
    table = _get_table()

    response = table.query(
        IndexName="FindingIdIndex",
        KeyConditionExpression=Key("finding_id").eq(finding_id),
        Limit=1,
        ScanIndexForward=False,
    )

    items = response.get("Items", [])
    if items:
        return {
            "previously_reported": True,
            "last_reported_at": items[0].get("executed_at"),
        }
    return {"previously_reported": False, "last_reported_at": None}


def _ttl_90days() -> int:
    """90 日後の Unix タイムスタンプを返す（DynamoDB TTL 用）"""
    from datetime import timedelta
    import time

    return int(
        (datetime.now(timezone.utc) + timedelta(days=90)).timestamp()
    )