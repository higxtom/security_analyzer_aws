"""
Lambda ハンドラー
Step Functions から呼び出される薄いトリガー。

実際の Security Hub 分析処理・ツール呼び出しはすべて Bedrock AgentCore Runtime
（agentcore_app.py としてコンテナ化されたもの）側で行われる。この Lambda は
AgentCore Runtime を A2A プロトコルで起動・ポーリングし、結果を Step Functions
に返すだけの責務を持つ。

分析処理は Bedrock 推論を複数回はさむため数分〜十数分かかることがあり、
1 回の同期呼び出しで完了を待つと AWS 側のコネクションが早期に切断されてしまう。
そのため A2A の `message/send` を `configuration.blocking=false` で呼び出して
即座にタスクを起動し（action="run_analysis"）、以降は Step Functions の
Wait ループから `tasks/get` でポーリングする（action="poll_analysis"）。

そのため依存パッケージは boto3 のみで良い（requirements-lambda.txt 参照）。
"""
import json
import os
import traceback
import uuid
from datetime import datetime, timezone

import boto3

from src.utils.logger import get_logger

logger = get_logger(__name__)

_AGENT_RUNTIME_ARN = os.environ["AGENT_RUNTIME_ARN"]
# 明示的なエンドポイント修飾子。未設定の場合は AgentCore Runtime のデフォルトエンドポイントを使う。
_AGENT_RUNTIME_QUALIFIER = os.environ.get("AGENT_RUNTIME_QUALIFIER")

# WaitBeforePoll (30秒) x _MAX_POLLS = 最大待機時間。Step Functions 側の
# Wait 秒数と合わせて調整すること（infra/stepfunctions.tf 参照）。
_MAX_POLLS = 60

_client = boto3.client("bedrock-agentcore")


def _invoke(session_id: str, payload: dict) -> dict:
    """AgentCore Runtime を A2A JSON-RPC ペイロードで呼び出す。"""
    invoke_kwargs = {
        "agentRuntimeArn": _AGENT_RUNTIME_ARN,
        "runtimeSessionId": session_id,
        "contentType": "application/json",
        "accept": "application/json",
        "payload": json.dumps(payload).encode("utf-8"),
    }
    if _AGENT_RUNTIME_QUALIFIER:
        invoke_kwargs["qualifier"] = _AGENT_RUNTIME_QUALIFIER

    response = _client.invoke_agent_runtime(**invoke_kwargs)
    raw_body = response["response"].read()
    return json.loads(raw_body)


def _build_message_send_request(run_date: str, action: str) -> dict:
    """A2A の `message/send`（非ブロッキング）リクエストを組み立てる。"""
    task_text = json.dumps({"run_date": run_date, "action": action})
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "message/send",
        "params": {
            "message": {
                "kind": "message",
                "messageId": str(uuid.uuid4()),
                "role": "user",
                "parts": [{"kind": "text", "text": task_text}],
            },
            # blocking=false により、タスク完了を待たず即座に応答を受け取る。
            # 分析処理は数分〜十数分かかることがあり、同期待機だとコネクションが
            # 早期に切断されてしまうため。
            "configuration": {"blocking": False},
        },
    }


def _build_get_task_request(task_id: str) -> dict:
    """A2A の `tasks/get`（ポーリング）リクエストを組み立てる。"""
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "tasks/get",
        "params": {"id": task_id},
    }


def _extract_text_from_task(task: dict) -> str | None:
    """Task の artifacts からテキストを連結して取り出す（チャンク分割に対応）。"""
    parts_text = []
    for artifact in task.get("artifacts") or []:
        for part in artifact.get("parts", []):
            if part.get("kind") == "text" and part.get("text"):
                parts_text.append(part["text"])
    return "".join(parts_text) if parts_text else None


def _extract_failure_text(task: dict) -> str:
    """失敗した Task の status.message からテキストを取り出す。"""
    status_message = (task.get("status") or {}).get("message") or {}
    parts_text = [
        p.get("text", "")
        for p in status_message.get("parts", [])
        if p.get("kind") == "text"
    ]
    joined = "".join(parts_text)
    state = (task.get("status") or {}).get("state")
    return joined or f"AgentCore task ended with state={state}"


def _start_analysis(run_date: str) -> dict:
    """分析タスクを起動し、即座に task_id を含む「保留中」レスポンスを返す。"""
    session_id = f"security-hub-agent-{run_date}-{uuid.uuid4().hex}"
    response_body = _invoke(session_id, _build_message_send_request(run_date, "run_analysis"))

    if "error" in response_body:
        raise RuntimeError(f"AgentCore returned an error: {response_body['error']}")

    task = response_body.get("result", {})
    task_id = task.get("id")
    if not task_id:
        raise ValueError(f"AgentCore response did not contain a task id: {response_body}")

    return {
        "statusCode": 200,
        "body": {
            "phase": "pending",
            "task_id": task_id,
            "session_id": session_id,
            "run_date": run_date,
            "poll_count": 0,
        },
    }


def _poll_analysis(task_id: str, session_id: str, run_date: str, poll_count: int) -> dict:
    """タスクの状態を確認する。完了していれば最終結果を、失敗していればエラーを返す。"""
    if poll_count >= _MAX_POLLS:
        return {
            "statusCode": 500,
            "body": {
                "error": f"AgentCore task polling exceeded {_MAX_POLLS} attempts (task_id={task_id})",
                "run_date": run_date,
            },
        }

    response_body = _invoke(session_id, _build_get_task_request(task_id))

    if "error" in response_body:
        raise RuntimeError(f"AgentCore returned an error: {response_body['error']}")

    task = response_body.get("result", {})
    state = (task.get("status") or {}).get("state")

    if state in ("submitted", "working"):
        return {
            "statusCode": 200,
            "body": {
                "phase": "pending",
                "task_id": task_id,
                "session_id": session_id,
                "run_date": run_date,
                "poll_count": poll_count + 1,
            },
        }

    if state == "completed":
        result_text = _extract_text_from_task(task)
        if not result_text:
            raise ValueError(f"AgentCore task completed without text output: {response_body}")
        return {"statusCode": 200, "body": json.loads(result_text)}

    # failed / canceled / rejected
    return {
        "statusCode": 500,
        "body": {"error": _extract_failure_text(task), "run_date": run_date},
    }


def handler(event: dict, context) -> dict:
    """
    Lambda エントリーポイント。

    event の構造（起動時。Step Functions の初回呼び出しまたは手動実行）:
    {
        "run_date": "2026-05-25",  # optional
        "action": "run_analysis"   # optional, デフォルト: run_analysis
    }

    event の構造（ポーリング時。Step Functions の Wait ループから呼び出される）:
    {
        "action": "poll_analysis",
        "task_id": "...",
        "session_id": "...",
        "run_date": "2026-05-25",
        "poll_count": 0
    }
    """
    logger.info("Lambda invoked. event=%s", json.dumps(event))

    action = event.get("action", "run_analysis")
    run_date = event.get("run_date") or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    try:
        if action == "poll_analysis":
            return _poll_analysis(
                task_id=event["task_id"],
                session_id=event["session_id"],
                run_date=event.get("run_date", run_date),
                poll_count=event.get("poll_count", 0),
            )

        return _start_analysis(run_date=run_date)

    except Exception as e:
        logger.error("AgentCore Runtime invocation failed: %s\n%s", str(e), traceback.format_exc())
        return {
            "statusCode": 500,
            "body": {"error": str(e), "run_date": run_date},
        }
