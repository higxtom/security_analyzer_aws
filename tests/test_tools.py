"""
Security Hub ツールのユニットテスト
boto3 をモックして AWS への実際の通信なしにテストする
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from src.tools.security_hub import get_security_findings, _slim_finding


# テスト用のサンプル Finding
SAMPLE_FINDING = {
    "Id": "arn:aws:securityhub:ap-northeast-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/abc123",
    "Title": "S3 general purpose buckets should have block public access settings enabled",
    "Description": "This control checks whether Amazon S3 general purpose buckets have block public access settings enabled at the bucket level.",
    "Severity": {"Label": "HIGH", "Normalized": 70},
    "AwsAccountId": "123456789012",
    "Region": "ap-northeast-1",
    "Resources": [
        {
            "Type": "AwsS3Bucket",
            "Id": "arn:aws:s3:::my-public-bucket",
        }
    ],
    "Compliance": {"Status": "FAILED", "AssociatedStandards": []},
    "Remediation": {
        "Recommendation": {
            "Text": "Enable S3 Block Public Access settings at the bucket level.",
            "Url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        }
    },
    "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/S3.1",
    "CreatedAt": "2026-05-01T00:00:00Z",
    "UpdatedAt": "2026-05-25T00:00:00Z",
    "Workflow": {"Status": "NEW"},
    "RecordState": "ACTIVE",
}


class TestSlimFinding:
    def test_extracts_required_fields(self):
        slim = _slim_finding(SAMPLE_FINDING)
        assert slim["title"] == SAMPLE_FINDING["Title"]
        assert slim["severity"] == "HIGH"
        assert slim["severity_score"] == 70
        assert slim["aws_account_id"] == "123456789012"
        assert slim["region"] == "ap-northeast-1"
        assert slim["resource_type"] == "AwsS3Bucket"
        assert slim["resource_id"] == "arn:aws:s3:::my-public-bucket"
        assert slim["compliance_status"] == "FAILED"
        assert "docs.aws.amazon.com" in slim["remediation_url"]

    def test_handles_missing_fields(self):
        """必須フィールドが欠けている場合にデフォルト値を返す"""
        slim = _slim_finding({})
        assert slim["title"] == ""
        assert slim["severity"] == "UNKNOWN"
        assert slim["severity_score"] == 0
        assert slim["resource_type"] == "Unknown"
        assert slim["resource_id"] == "Unknown"

    def test_handles_multiple_resources(self):
        """複数リソースがある場合は最初のものを使用する"""
        finding = {
            **SAMPLE_FINDING,
            "Resources": [
                {"Type": "AwsS3Bucket", "Id": "first-bucket"},
                {"Type": "AwsS3Bucket", "Id": "second-bucket"},
            ],
        }
        slim = _slim_finding(finding)
        assert slim["resource_id"] == "first-bucket"


class TestGetSecurityFindings:
    @patch("src.tools.security_hub.boto3.Session")
    def test_returns_findings_with_summary(self, mock_session):
        """正常系: 検出結果と重大度サマリーが返される"""
        mock_client = MagicMock()
        mock_session.return_value.client.return_value = mock_client

        # ページネーターのモック
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {"Findings": [SAMPLE_FINDING, {**SAMPLE_FINDING, "Severity": {"Label": "CRITICAL", "Normalized": 90}}]}
        ]

        result = get_security_findings(
            severity_labels=["CRITICAL", "HIGH"],
            max_results=50,
        )

        assert result["total"] == 2
        assert len(result["findings"]) == 2
        assert "HIGH" in result["severity_summary"]
        assert "CRITICAL" in result["severity_summary"]
        assert result["severity_summary"]["HIGH"] == 1
        assert result["severity_summary"]["CRITICAL"] == 1
        assert "retrieved_at" in result

    @patch("src.tools.security_hub.boto3.Session")
    def test_respects_max_results(self, mock_session):
        """max_results で件数が制限される"""
        mock_client = MagicMock()
        mock_session.return_value.client.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        # 10 件返すが max_results=3 で制限
        mock_paginator.paginate.return_value = [
            {"Findings": [SAMPLE_FINDING] * 10}
        ]

        result = get_security_findings(max_results=3)
        assert result["total"] == 3

    @patch("src.tools.security_hub.boto3.Session")
    def test_returns_empty_on_no_findings(self, mock_session):
        """検出なしの場合は空リストを返す"""
        mock_client = MagicMock()
        mock_session.return_value.client.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"Findings": []}]

        result = get_security_findings()
        assert result["total"] == 0
        assert result["findings"] == []
        assert result["severity_summary"] == {}


class TestSNSNotifier:
    """SNS 通知ツールのテスト"""

    def test_subject_truncation(self):
        """件名が 100 文字を超える場合に切り詰められる"""
        from src.tools.sns_notifier import _build_subject

        summary = {"CRITICAL": 99, "HIGH": 99, "MEDIUM": 99}
        subject = _build_subject(summary, "2026-05-25")
        assert len(subject) <= 100

    def test_subject_no_findings(self):
        from src.tools.sns_notifier import _build_subject

        subject = _build_subject({}, "2026-05-25")
        assert "検出なし" in subject

    def test_message_contains_presigned_urls(self):
        from src.tools.sns_notifier import _build_message

        s3_files = [
            {
                "filename": "report.md",
                "presigned_url": "https://s3.example.com/report.md?X-Amz-Signature=abc",
            }
        ]
        message = _build_message({"CRITICAL": 1}, [], s3_files, "2026-05-25")
        assert "https://s3.example.com" in message
        assert "report.md" in message