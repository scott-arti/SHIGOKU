"""
FeatureConfig: 機能設定の読み込みと管理 (Pydantic Settings 移行版)

config/features.yaml から設定を読み込み、
Phase 3機能のオン/オフ制御を提供する。
"""
from __future__ import annotations

import logging
from typing import Optional

from src.core.config.settings import get_settings

logger = logging.getLogger(__name__)

# 後方互換性のためのエイリアス
from src.core.config.settings import (
    WafBypassSettings as WafBypassConfig,
    MicroAgentSettings as MicroAgentConfig,
    SandboxSettings as SandboxConfig,
    ExploitVerifierSettings as ExploitVerifierConfig,
    AttackModulesSettings as AttackModulesConfig,
    Phase3Settings as Phase3Config,
    FeatureNotificationsSettings as NotificationsConfig,
    RetryControlSettings as RetryControlConfig,
    ExportSettings as ExportConfig,
)

class FeatureConfig:
    """
    機能設定全体 (Pydantic Settings へのラッパー)
    """
    @property
    def phase3(self):
        return get_settings().phase3

    @property
    def notifications(self):
        return get_settings().feature_notifications

    @property
    def retry_control(self):
        return get_settings().retry_control

    @property
    def export(self):
        return get_settings().export

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "FeatureConfig":
        """
        設定ファイルから読み込み (現在は get_settings が自動で行う)
        """
        if config_path:
            # Pydantic Settings はデフォルトで config/shigoku.yaml を見るが、
            # 特殊なパス指定がある場合は再初期化を試みる
            get_settings(reinit=True)
        return cls()

    def is_phase3_feature_enabled(self, feature_name: str) -> bool:
        """
        Phase 3機能が有効かチェック
        """
        p3 = get_settings().phase3
        feature_map = {
            "waf_bypass": p3.waf_bypass.enabled,
            "micro_agent": p3.micro_agent.enabled,
            "sandbox": p3.sandbox.enabled,
            "exploit_verifier": p3.exploit_verifier.enabled,
            "attack_modules": (
                p3.attack_modules.host_header_injection or
                p3.attack_modules.enhanced_patterns
            ),
        }
        return feature_map.get(feature_name, False)


# シングルトンインスタンス (互換性のために保持)
_feature_config_instance: Optional[FeatureConfig] = None


def get_feature_config() -> FeatureConfig:
    """FeatureConfigのシングルトンインスタンスを取得"""
    global _feature_config_instance
    if _feature_config_instance is None:
        _feature_config_instance = FeatureConfig()
    return _feature_config_instance


def reload_feature_config(config_path: Optional[str] = None) -> FeatureConfig:
    """設定を再読み込み"""
    get_settings(reinit=True)
    return get_feature_config()
