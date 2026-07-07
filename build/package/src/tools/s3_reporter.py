"""
S3 レポート保存・Presigned URL 生成ツール
生成したレポートや CFn テンプレートを S3 に保存し、
署名付き URL を返す
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


def _get_s3_client():
    session = boto3.Session(
        region_name=settings.aws_region,
        profile_name=settings.aws_profile,
    )
    return session.client("s3", config=_BOTO3_CONFIG)


def _make_s3_key(run_date: str, filename: str) -> str:
    """S3 キーを生成する。例: reports/2026-05-25/report.md"""
    return f"{settings.report_prefix}/{run_date}/{filename}"


@tool
def save_report_to_s3(
    content: str,
    filename: str,
    content_type: str = "text/markdown",
    run_date: str | None = None,
) -> dict[str, str]:
    """
    レポートコンテンツを S3 に保存し Presigned URL を返す。

    Args:
        content:      保存するコンテンツ（Markdown, JSON, YAML など）。
        filename:     ファイル名。例: "report.md", "remediation.yaml"
        content_type: MIME タイプ。デフォルト: "text/markdown"
        run_date:     保存先フォルダ用の日付文字列 (YYYY-MM-DD)。
                      None の場合は今日の日付を使用。

    Returns:
        {
            "s3_key": str,        # S3 オブジェクトキー
            "s3_uri": str,        # s3://bucket/key 形式
            "presigned_url": str, # 署名付きダウンロード URL
            "expires_in_days": int,
        }
    """
    if run_date is None:
        run_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    s3_key = _make_s3_key(run_date, filename)
    client = _get_s3_client()

    logger.info("Saving report to s3://%s/%s", settings.report_bucket_name, s3_key)

    client.put_object(
        Bucket=settings.report_bucket_name,
        Key=s3_key,
        Body=content.encode("utf-8"),
        ContentType=content_type,
        ServerSideEncryption="AES256",
        Metadata={
            "generated-by": "security-hub-agent",
            "run-date": run_date,
        },
    )

    presigned_url = client.generate_presigned_url(
        "get_object",
        Params={"Bucket": settings.report_bucket_name, "Key": s3_key},
        ExpiresIn=settings.presigned_url_expiry_seconds,
    )

    expires_in_days = settings.presigned_url_expiry_seconds // 86400

    logger.info("Saved and generated presigned URL (expires in %d days)", expires_in_days)

    return {
        "s3_key": s3_key,
        "s3_uri": f"s3://{settings.report_bucket_name}/{s3_key}",
        "presigned_url": presigned_url,
        "expires_in_days": expires_in_days,
    }


@tool
def save_multiple_files_to_s3(
    files: list[dict[str, str]],
    run_date: str | None = None,
) -> list[dict[str, str]]:
    """
    複数ファイルをまとめて S3 に保存する。

    Args:
        files: 保存するファイルのリスト。各要素は以下の構造:
               {
                 "filename": "remediation.yaml",
                 "content": "...",
                 "content_type": "application/x-yaml"  # optional
               }
        run_date: 保存先フォルダ用の日付文字列 (YYYY-MM-DD)。

    Returns:
        各ファイルの保存結果リスト（save_report_to_s3 の戻り値に filename を追加）。
    """
    if run_date is None:
        run_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    results = []
    for file_info in files:
        filename = file_info["filename"]
        content = file_info["content"]
        content_type = file_info.get("content_type", "text/plain")

        result = save_report_to_s3(
            content=content,
            filename=filename,
            content_type=content_type,
            run_date=run_date,
        )
        result["filename"] = filename
        results.append(result)

    return results