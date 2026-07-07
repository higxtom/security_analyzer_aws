"""
Security Hub Findings 取得ツール
Strands の @tool デコレータで定義し、Agent から直接呼び出せる形にする
"""
import json
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


def _get_securityhub_client():
    session = boto3.Session(
        region_name=settings.aws_region,
        profile_name=settings.aws_profile,
    )
    return session.client("securityhub", config=_BOTO3_CONFIG)


@tool
def get_security_findings(
    severity_labels: list[str] | None = None,
    max_results: int = 50,
    record_state: str = "ACTIVE",
    workflow_status: str = "NEW",
) -> dict[str, Any]:
    """
    AWS Security Hub から検出結果 (Findings) を取得する。

    Args:
        severity_labels: 取得する重大度ラベルのリスト。
                         例: ["CRITICAL", "HIGH", "MEDIUM"]
                         None の場合は設定値 (CRITICAL, HIGH) を使用。
        max_results:     最大取得件数（デフォルト: 50）。
        record_state:    レコード状態。"ACTIVE" または "ARCHIVED"。
        workflow_status: ワークフロー状態。"NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"。

    Returns:
        {
            "total": int,               # 取得件数
            "findings": [...],          # 検出結果リスト
            "severity_summary": {...},  # 重大度別集計
            "retrieved_at": str,        # 取得日時 (ISO 8601)
        }
    """
    if severity_labels is None:
        severity_labels = settings.findings_severity_list

    logger.info(
        "Fetching Security Hub findings: severity=%s, max=%d, workflow=%s",
        severity_labels,
        max_results,
        workflow_status,
    )

    client = _get_securityhub_client()

    filters = {
        "SeverityLabel": [
            {"Value": label, "Comparison": "EQUALS"} for label in severity_labels
        ],
        "RecordState": [{"Value": record_state, "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": workflow_status, "Comparison": "EQUALS"}],
    }

    findings: list[dict] = []
    paginator = client.get_paginator("get_findings")

    try:
        for page in paginator.paginate(
            Filters=filters,
            SortCriteria=[{"Field": "SeverityLabel", "SortOrder": "desc"}],
            PaginationConfig={"MaxItems": max_results, "PageSize": min(max_results, 100)},
        ):
            findings.extend(page.get("Findings", []))
            if len(findings) >= max_results:
                findings = findings[:max_results]
                break
    except client.exceptions.InvalidAccessException as e:
        logger.error("Security Hub is not enabled or insufficient permissions: %s", e)
        raise
    except Exception as e:
        logger.error("Unexpected error fetching findings: %s", e)
        raise

    # 重大度別に集計
    severity_summary: dict[str, int] = {}
    for f in findings:
        label = f.get("Severity", {}).get("Label", "UNKNOWN")
        severity_summary[label] = severity_summary.get(label, 0) + 1

    # Agent に渡すデータを整形（不要フィールドを除去してトークン節約）
    slim_findings = [_slim_finding(f) for f in findings]

    result = {
        "total": len(slim_findings),
        "findings": slim_findings,
        "severity_summary": severity_summary,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }

    logger.info(
        "Retrieved %d findings. Summary: %s",
        result["total"],
        json.dumps(severity_summary),
    )
    return result


def _slim_finding(finding: dict) -> dict:
    """
    Findings から Agent の推論に必要な項目だけを抽出する。
    元の Finding は属性が多く、そのまま渡すとトークンを大量消費する。
    """
    return {
        "id": finding.get("Id", ""),
        "title": finding.get("Title", ""),
        "description": finding.get("Description", ""),
        "severity": finding.get("Severity", {}).get("Label", "UNKNOWN"),
        "severity_score": finding.get("Severity", {}).get("Normalized", 0),
        "aws_account_id": finding.get("AwsAccountId", ""),
        "region": finding.get("Region", ""),
        "resource_type": _extract_resource_type(finding),
        "resource_id": _extract_resource_id(finding),
        "compliance_status": finding.get("Compliance", {}).get("Status", ""),
        "compliance_controls": finding.get("Compliance", {}).get(
            "AssociatedStandards", []
        ),
        "remediation_url": finding.get("Remediation", {})
        .get("Recommendation", {})
        .get("Url", ""),
        "remediation_text": finding.get("Remediation", {})
        .get("Recommendation", {})
        .get("Text", ""),
        "generator_id": finding.get("GeneratorId", ""),
        "created_at": finding.get("CreatedAt", ""),
        "updated_at": finding.get("UpdatedAt", ""),
        "workflow_status": finding.get("Workflow", {}).get("Status", ""),
    }


def _extract_resource_type(finding: dict) -> str:
    resources = finding.get("Resources", [])
    if resources:
        return resources[0].get("Type", "Unknown")
    return "Unknown"


def _extract_resource_id(finding: dict) -> str:
    resources = finding.get("Resources", [])
    if resources:
        return resources[0].get("Id", "Unknown")
    return "Unknown"


@tool
def get_finding_detail(finding_id: str) -> dict[str, Any]:
    """
    特定の Finding ID の詳細を取得する。

    Args:
        finding_id: Finding の ARN または ID。

    Returns:
        Finding の完全な詳細情報。
    """
    client = _get_securityhub_client()

    try:
        response = client.get_findings(
            Filters={"Id": [{"Value": finding_id, "Comparison": "EQUALS"}]}
        )
        findings = response.get("Findings", [])
        if not findings:
            return {"error": f"Finding not found: {finding_id}"}
        return findings[0]
    except Exception as e:
        logger.error("Error fetching finding detail for %s: %s", finding_id, e)
        raise