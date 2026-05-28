"""
Pydantic Settings による設定管理
環境変数または .env ファイルから設定を読み込む
"""
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # AWS
    aws_region: str = Field(default="ap-northeast-1")
    aws_profile: str | None = Field(default=None)

    # Amazon Bedrock
    bedrock_model_id: str = Field(default="global.anthropic.claude-sonnet-4-6")

    # S3
    report_bucket_name: str = Field(default="")
    report_prefix: str = Field(default="reports")
    presigned_url_expiry_seconds: int = Field(default=604800)  # 7 days

    # SNS
    sns_topic_arn: str = Field(default="")

    # DynamoDB
    dynamodb_table_name: str = Field(default="security-hub-agent-history")

    # Bedrock タイムアウト (秒)
    bedrock_connect_timeout: int = Field(default=120)
    bedrock_read_timeout: int = Field(default=600)

    # MCP Server
    mcp_startup_timeout: int = Field(default=60)

    # Agent behavior
    dry_run: bool = Field(default=True)
    findings_severity_list: list[str] = Field(default=["CRITICAL", "HIGH"])


@lru_cache
def get_settings() -> Settings:
    return Settings()
