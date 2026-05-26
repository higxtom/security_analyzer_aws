"""
boto3 グローバルタイムアウト設定
モジュール読み込み時に boto3 の client 作成をモンキーパッチして
すべてのクライアントにタイムアウト設定を強制適用する
"""
from botocore.config import Config as BotocoreConfig

# グローバルタイムアウト設定（すべての boto3 クライアントに適用）
DEFAULT_BOTO3_CONFIG = BotocoreConfig(
    connect_timeout=60,
    read_timeout=1800,  # 30 minutes - streaming の各チャンク読み取りタイムアウト
    retries={"max_attempts": 3, "mode": "adaptive"},
)


def apply_default_config():
    """
    boto3 Session.create_client() メソッドをモンキーパッチして、
    すべてのクライアント作成時に DEFAULT_BOTO3_CONFIG を強制適用する。
    """
    from botocore.session import Session as BotocoreSession

    # 元の create_client メソッドを保存
    _original_create_client = BotocoreSession.create_client

    def create_client_with_timeout(self, *args, **kwargs):
        """
        引数の構成を崩さずにタイムアウト設定を適用して client を作成する
        """
        existing_config = kwargs.get("config")

        if existing_config is not None:
            try:
                # 【重要】デフォルト設定に対して、個別設定(existing)をマージして上書きする
                # これにより、個別に read_timeout 等が指定された場合はそちらが優先される
                merged_config = DEFAULT_BOTO3_CONFIG.merge(existing_config)
            except Exception:
                merged_config = DEFAULT_BOTO3_CONFIG
        else:
            merged_config = DEFAULT_BOTO3_CONFIG
            
        kwargs["config"] = merged_config
        
        # *args, **kwargs をそのまま元の関数にフォワードする
        return _original_create_client(self, *args, **kwargs)

    # モンキーパッチを適用
    BotocoreSession.create_client = create_client_with_timeout


apply_default_config()