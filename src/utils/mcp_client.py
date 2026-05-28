"""
AWS MCP Server 接続管理

awslabs.aws-api-mcp-server を stdio トランスポートで起動し、
Strands MCPClient 経由で Agent に AWS ツールを提供する。
"""
import os
from contextlib import contextmanager

from mcp import StdioServerParameters, stdio_client
from strands.tools.mcp import MCPClient

from src.utils.config import get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()


def _build_server_params() -> StdioServerParameters:
    """AWS API MCP Server の起動パラメータを組み立てる。"""
    env = {
        **os.environ,
        "AWS_REGION": settings.aws_region,
        "FASTMCP_LOG_LEVEL": "WARNING",
    }
    if settings.aws_profile:
        env["AWS_PROFILE"] = settings.aws_profile

    return StdioServerParameters(
        command="awslabs.aws-api-mcp-server",
        env=env,
    )


def create_aws_mcp_client() -> MCPClient:
    """AWS API MCP Server に接続する MCPClient を生成する。

    使い方::

        mcp = create_aws_mcp_client()
        mcp.start()
        try:
            agent = Agent(..., tools=[mcp])
            agent("...")
        finally:
            mcp.stop()

    または context manager パターン::

        with aws_mcp_context() as mcp:
            agent = Agent(..., tools=[mcp])
            agent("...")
    """
    return MCPClient(
        lambda: stdio_client(server=_build_server_params()),
        startup_timeout=settings.mcp_startup_timeout,
    )


@contextmanager
def aws_mcp_context():
    """AWS MCP Server への接続をコンテキストマネージャで管理する。

    Yields:
        起動済みの MCPClient インスタンス。
    """
    mcp = create_aws_mcp_client()
    mcp.start()
    logger.info("AWS MCP Server started.")
    try:
        yield mcp
    finally:
        mcp.stop()
        logger.info("AWS MCP Server stopped.")
