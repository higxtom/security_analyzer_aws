"""
Amazon Bedrock AgentCore エントリーポイント

Strands A2AServer を使って HTTP サーバーとして起動する。
AgentCore Runtime はこのコンテナを起動し、A2A プロトコル (JSON-RPC "message/send")
経由でエージェントを呼び出す。実際の Security Hub 分析処理・ツール呼び出しは
すべてこのコンテナ内（AgentCore Runtime 上）で行われる。
Lambda はこの Runtime を起動する薄いトリガーに過ぎない（lambda_handler.py 参照）。

起動方法:
    python -m src.agent.agentcore_app

A2A メッセージの例 (Lambda から invoke_agent_runtime 経由で送られる内容):
    {
      "jsonrpc": "2.0",
      "id": "<uuid>",
      "method": "message/send",
      "params": {
        "message": {
          "kind": "message",
          "messageId": "<uuid>",
          "role": "user",
          "parts": [
            {"kind": "text", "text": "{\\"run_date\\": \\"2026-05-25\\", \\"action\\": \\"run_analysis\\"}"}
          ]
        }
      }
    }

ディスパッチャー Agent (create_dispatcher_agent) は run_date を取り出して
run_daily_security_analysis ツール（= run_security_analysis()）を呼び出し、
その戻り値の JSON をそのまま応答として返す。
"""
import os

import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse

# boto3 グローバルタイムアウト設定を適用
from src.utils.boto3_config import DEFAULT_BOTO3_CONFIG  # noqa: F401
from strands.multiagent.a2a.server import A2AServer

from src.agent.security_agent import create_dispatcher_agent
from src.utils.logger import get_logger

logger = get_logger(__name__)

_HOST = os.getenv("HOST", "0.0.0.0")
# AgentCore Runtime の A2A プロトコル契約では、コンテナはポート 9000 で待ち受ける必要がある
# （HTTP/MCP プロトコルとは異なるポート）。
# https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-a2a-protocol-contract.html
_PORT = int(os.getenv("PORT", "9000"))
# AgentCore がコンテナに割り当てるパブリック URL（ALB 経由の場合は設定する）
_HTTP_URL = os.getenv("AGENTCORE_HTTP_URL", None)


def build_server() -> A2AServer:
    """A2AServer インスタンスを生成して返す（テストでの差し替えを可能にする）。"""
    agent = create_dispatcher_agent()
    return A2AServer(
        agent=agent,
        host=_HOST,
        port=_PORT,
        http_url=_HTTP_URL,
        enable_a2a_compliant_streaming=True,
    )


async def _ping(_request) -> JSONResponse:
    """AgentCore Runtime のヘルスチェック用エンドポイント。

    Strands の A2AServer は A2A プロトコル本体のパスのみを実装しており、
    AgentCore Runtime が要求する /ping は含まれないため、ここで追加する。
    """
    return JSONResponse({"status": "Healthy"})


def build_app() -> Starlette:
    """/ping を追加した Starlette アプリを生成する。"""
    app = build_server().to_starlette_app()
    app.add_route("/ping", _ping, methods=["GET"])
    return app


if __name__ == "__main__":
    logger.info("Starting AgentCore A2A server. host=%s port=%d", _HOST, _PORT)
    uvicorn.run(build_app(), host=_HOST, port=_PORT)
