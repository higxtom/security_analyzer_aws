"""
Amazon Bedrock AgentCore エントリーポイント

Strands A2AServer を使って HTTP サーバーとして起動する。
AgentCore はこのコンテナを起動し、A2A プロトコル経由でエージェントを呼び出す。

起動方法:
    python -m src.agent.agentcore_app

A2A メッセージの例 (AgentCore / Step Functions から呼び出す場合):
    {
      "parts": [{"text": "Security Hub の検出結果を分析してください。対象日: 2026-05-25"}]
    }
または run_security_analysis() を直接起動する場合は lambda_handler.py を参照。
"""
import os

# boto3 グローバルタイムアウト設定を適用
from src.utils.boto3_config import DEFAULT_BOTO3_CONFIG  # noqa: F401
from strands.multiagent.a2a.server import A2AServer

from src.agent.security_agent import create_agent
from src.utils.logger import get_logger

logger = get_logger(__name__)

_HOST = os.getenv("HOST", "0.0.0.0")
_PORT = int(os.getenv("PORT", "8080"))
# AgentCore がコンテナに割り当てるパブリック URL（ALB 経由の場合は設定する）
_HTTP_URL = os.getenv("AGENTCORE_HTTP_URL", None)


def build_server() -> A2AServer:
    """A2AServer インスタンスを生成して返す（テストでの差し替えを可能にする）。"""
    agent = create_agent()
    return A2AServer(
        agent=agent,
        host=_HOST,
        port=_PORT,
        http_url=_HTTP_URL,
        enable_a2a_compliant_streaming=True,
    )


if __name__ == "__main__":
    logger.info("Starting AgentCore A2A server. host=%s port=%d", _HOST, _PORT)
    build_server().serve()
