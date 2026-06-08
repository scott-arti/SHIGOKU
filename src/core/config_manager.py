"""
Config Manager - 設定ファイル一元管理 (Pydantic Settings 移行版)
"""

import logging
from typing import Dict, Any, Optional
from pathlib import Path

from src.core.config.settings import Settings, get_settings

logger = logging.getLogger(__name__)

# 後方互換性のためのエイリアス
ShigokuConfig = Settings

class ConfigManager:
    """
    設定ファイル一元管理
    
    Pydantic Settings を使用して、YAML、環境変数、デフォルト値を
    自動的にマージおよびバリデーションします。
    """
    
    DEFAULT_CONFIG_PATHS = [
        "config/shigoku.yaml",
        "shigoku.yaml",
        ".shigoku.yaml",
    ]
    
    def __init__(self, config_path: str = None):
        """
        初期化
        
        Args:
            config_path: 明示的な設定ファイルパス。None の場合は自動探索。
        """
        self.config_path = config_path
        # Pydantic Settings による初期化
        # config_path がある場合は init 時に渡すことで YamlConfigSettingsSource よりも優先される
        self.config: Settings = get_settings()
        
        if config_path:
            self.load(config_path)
    
    def load(self, path: str) -> Settings:
        """設定ファイル読み込み（再初期化）"""
        path_obj = Path(path)
        if not path_obj.exists():
            logger.warning("Config file not found: %s", path)
            return self.config
        
        # Pydantic Settings を再ロード
        # 注意: 実行中に設定を大幅に変えるのは非推奨だが、互換性のために実装
        import yaml
        try:
            with open(path_obj, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            
            # get_settings にデータを渡して再初期化
            self.config = get_settings(**data)
            self.config_path = str(path)
            logger.info("Loaded config from %s", path)
        except Exception as e:
            logger.error("Failed to load config from %s: %s", path, e)
            
        return self.config
    
    def _auto_load(self):
        """
        デフォルトパスから自動読み込み。
        Pydantic Settings 側で既に行われているため、ここではパスの保持のみ。
        """
        for path in self.DEFAULT_CONFIG_PATHS:
            if Path(path).exists():
                self.config_path = str(path)
                return
    
    def _apply_config(self, data: Dict):
        """設定データを適用（Pydantic で自動化されたため非推奨）"""
        # 互換性のために残すが、現在はモデル全体を再生成するか、model_copy を検討すべき
        # ここでは最低限の動作を保証
        for key, value in data.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)

    def _expand_env(self, value: str) -> str:
        """環境変数展開（Pydantic Settings で自動化されたため非推奨）"""
        import os
        if not value or not isinstance(value, str):
            return value
        return os.path.expandvars(value)
    
    def save(self, path: str = None):
        """設定を保存"""
        import yaml
        path = path or self.config_path or "config/shigoku.yaml"
        
        # Pydantic モデルを辞書に変換
        data = self.config.model_dump(exclude_none=True)
        
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                yaml.dump(data, f, default_flow_style=False)
            logger.info("Saved config to %s", path)
        except Exception as e:
            logger.error("Failed to save config: %s", e)
    
    def get(self, key: str, default: Any = None) -> Any:
        """ドット記法で設定取得"""
        parts = key.split(".")
        obj = self.config
        
        for part in parts:
            if hasattr(obj, part):
                obj = getattr(obj, part)
            else:
                return default
        
        return obj


# シングルトン
_config_manager: Optional[ConfigManager] = None


def get_config_manager() -> ConfigManager:
    """ConfigManagerシングルトン取得"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def get_config() -> Settings:
    """設定取得ショートカット"""
    return get_config_manager().config
