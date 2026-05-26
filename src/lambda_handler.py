"""
Lambda ハンドラー
Step Functions の各ステートから呼び出される。
環境変数で実行モードを切り替える。
"""
import json
import os
import traceback
from datetime import datetime, timezone

# boto3 グローバルタイムアウト設定を適用
from src.utils.boto3_config import DEFAULT_BOTO3_CONFIG  # noqa: F401
from src.agent.security_agent import run_security_analysis
from src.utils.logger import get_logger

logger = get_logger(__name__)


def handler(event: dict, context) -> dict:
    """
    Lambda エントリーポイント。

    event の構造:
    {
        "run_date": "2026-05-25",  # optional
        "action": "run_analysis"   # optional, デフォルト: run_analysis
    }
    """
    logger.info("Lambda invoked. event=%s", json.dumps(event))

    run_date = event.get("run_date") or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    action = event.get("action", "run_analysis")

    try:
        if action == "run_analysis":
            result = run_security_analysis(run_date=run_date)
            return {
                "statusCode": 200,
                "body": result,
            }
        else:
            return {
                "statusCode": 400,
                "body": {"error": f"Unknown action: {action}"},
            }

    except Exception as e:
        logger.error("Lambda handler failed: %s\n%s", str(e), traceback.format_exc())
        return {
            "statusCode": 500,
            "body": {
                "error": str(e),
                "run_date": run_date,
            },
        }