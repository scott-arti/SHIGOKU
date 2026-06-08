"""
ToolProfiles: ツールのプロファイル管理

コンテキストに応じたツール引数プリセットを提供し、
効率的なツール実行を可能にする。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ProfileMode(str, Enum):
    """プロファイルモード"""
    SPEED = "speed"       # 高速スキャン
    STEALTH = "stealth"   # 検知回避
    THOROUGH = "thorough" # 徹底スキャン
    DEFAULT = "default"   # デフォルト


@dataclass
class ToolProfile:
    """ツールプロファイル"""
    name: str
    mode: ProfileMode
    args: dict = field(default_factory=dict)
    description: str = ""
    timeout_seconds: int = 60
    rate_limit_per_minute: int = 60


@dataclass
class ToolProfileSet:
    """ツール用のプロファイルセット"""
    tool_name: str
    profiles: dict[str, ToolProfile] = field(default_factory=dict)
    default_mode: ProfileMode = ProfileMode.DEFAULT

    def get_profile(self, mode: Optional[str] = None) -> ToolProfile:
        """指定モードのプロファイルを取得"""
        mode_key = mode or self.default_mode.value
        
        if mode_key in self.profiles:
            return self.profiles[mode_key]
        
        # デフォルトにフォールバック
        if ProfileMode.DEFAULT.value in self.profiles:
            return self.profiles[ProfileMode.DEFAULT.value]
        
        # 空のプロファイルを返す
        return ToolProfile(name=self.tool_name, mode=ProfileMode.DEFAULT)


# 事前定義のプロファイル
TOOL_PROFILES: dict[str, ToolProfileSet] = {
    "nuclei": ToolProfileSet(
        tool_name="nuclei",
        default_mode=ProfileMode.DEFAULT,
        profiles={
            "speed": ToolProfile(
                name="nuclei_speed",
                mode=ProfileMode.SPEED,
                args={
                    "rate_limit": 150,
                    "bulk_size": 25,
                    "concurrency": 25,
                    "retries": 1,
                },
                description="High-speed scanning with minimal retries",
                timeout_seconds=300,
            ),
            "stealth": ToolProfile(
                name="nuclei_stealth",
                mode=ProfileMode.STEALTH,
                args={
                    "rate_limit": 10,
                    "bulk_size": 5,
                    "concurrency": 5,
                    "retries": 2,
                    "delay": "2s",
                },
                description="Low-profile scanning to avoid WAF detection",
                timeout_seconds=900,
                rate_limit_per_minute=10,
            ),
            "thorough": ToolProfile(
                name="nuclei_thorough",
                mode=ProfileMode.THOROUGH,
                args={
                    "rate_limit": 50,
                    "bulk_size": 10,
                    "concurrency": 10,
                    "retries": 3,
                    "severity": "info,low,medium,high,critical",
                },
                description="Comprehensive scanning with all severity levels",
                timeout_seconds=1800,
            ),
            "default": ToolProfile(
                name="nuclei_default",
                mode=ProfileMode.DEFAULT,
                args={
                    "rate_limit": 100,
                    "bulk_size": 15,
                    "concurrency": 15,
                },
                description="Balanced default settings",
                timeout_seconds=600,
            ),
        },
    ),
    
    "httpx": ToolProfileSet(
        tool_name="httpx",
        default_mode=ProfileMode.DEFAULT,
        profiles={
            "speed": ToolProfile(
                name="httpx_speed",
                mode=ProfileMode.SPEED,
                args={
                    "threads": 50,
                    "rate_limit": 150,
                    "timeout": 5,
                },
                description="Fast HTTP probing",
                timeout_seconds=120,
            ),
            "stealth": ToolProfile(
                name="httpx_stealth",
                mode=ProfileMode.STEALTH,
                args={
                    "threads": 5,
                    "rate_limit": 10,
                    "timeout": 30,
                    "delay": "1s",
                },
                description="Slow and stealthy HTTP probing",
                timeout_seconds=600,
                rate_limit_per_minute=10,
            ),
            "thorough": ToolProfile(
                name="httpx_thorough",
                mode=ProfileMode.THOROUGH,
                args={
                    "threads": 25,
                    "rate_limit": 50,
                    "timeout": 15,
                    "follow_redirects": True,
                    "tech_detect": True,
                },
                description="Detailed HTTP analysis with tech detection",
                timeout_seconds=300,
            ),
            "default": ToolProfile(
                name="httpx_default",
                mode=ProfileMode.DEFAULT,
                args={
                    "threads": 25,
                    "rate_limit": 100,
                    "timeout": 10,
                },
                description="Balanced default settings",
                timeout_seconds=180,
            ),
        },
    ),
    
    "ffuf": ToolProfileSet(
        tool_name="ffuf",
        default_mode=ProfileMode.DEFAULT,
        profiles={
            "speed": ToolProfile(
                name="ffuf_speed",
                mode=ProfileMode.SPEED,
                args={
                    "threads": 100,
                    "rate": 0,  # No rate limit
                    "timeout": 5,
                },
                description="Fast fuzzing",
                timeout_seconds=300,
            ),
            "stealth": ToolProfile(
                name="ffuf_stealth",
                mode=ProfileMode.STEALTH,
                args={
                    "threads": 5,
                    "rate": 10,
                    "timeout": 30,
                    "delay": "1",
                },
                description="Slow fuzzing to avoid detection",
                timeout_seconds=1800,
                rate_limit_per_minute=10,
            ),
            "thorough": ToolProfile(
                name="ffuf_thorough",
                mode=ProfileMode.THOROUGH,
                args={
                    "threads": 40,
                    "rate": 50,
                    "timeout": 15,
                    "recursion": True,
                    "recursion_depth": 2,
                },
                description="Deep fuzzing with recursion",
                timeout_seconds=900,
            ),
            "default": ToolProfile(
                name="ffuf_default",
                mode=ProfileMode.DEFAULT,
                args={
                    "threads": 40,
                    "rate": 100,
                    "timeout": 10,
                },
                description="Balanced default settings",
                timeout_seconds=600,
            ),
        },
    ),
    
    "subfinder": ToolProfileSet(
        tool_name="subfinder",
        default_mode=ProfileMode.DEFAULT,
        profiles={
            "speed": ToolProfile(
                name="subfinder_speed",
                mode=ProfileMode.SPEED,
                args={
                    "threads": 30,
                    "timeout": 30,
                },
                description="Fast subdomain enumeration",
                timeout_seconds=120,
            ),
            "thorough": ToolProfile(
                name="subfinder_thorough",
                mode=ProfileMode.THOROUGH,
                args={
                    "threads": 20,
                    "timeout": 60,
                    "all": True,
                    "recursive": True,
                },
                description="Comprehensive subdomain enumeration",
                timeout_seconds=600,
            ),
            "default": ToolProfile(
                name="subfinder_default",
                mode=ProfileMode.DEFAULT,
                args={
                    "threads": 20,
                    "timeout": 30,
                },
                description="Balanced default settings",
                timeout_seconds=180,
            ),
        },
    ),
    
    "sqlmap": ToolProfileSet(
        tool_name="sqlmap",
        default_mode=ProfileMode.DEFAULT,
        profiles={
            "speed": ToolProfile(
                name="sqlmap_speed",
                mode=ProfileMode.SPEED,
                args={
                    "level": 1,
                    "risk": 1,
                    "threads": 5,
                },
                description="Quick SQL injection test",
                timeout_seconds=120,
            ),
            "stealth": ToolProfile(
                name="sqlmap_stealth",
                mode=ProfileMode.STEALTH,
                args={
                    "level": 2,
                    "risk": 1,
                    "threads": 1,
                    "delay": 2,
                    "random_agent": True,
                },
                description="Stealthy SQL injection test",
                timeout_seconds=600,
                rate_limit_per_minute=15,
            ),
            "thorough": ToolProfile(
                name="sqlmap_thorough",
                mode=ProfileMode.THOROUGH,
                args={
                    "level": 5,
                    "risk": 3,
                    "threads": 3,
                    "technique": "BEUSTQ",
                },
                description="Comprehensive SQL injection test",
                timeout_seconds=1800,
            ),
            "default": ToolProfile(
                name="sqlmap_default",
                mode=ProfileMode.DEFAULT,
                args={
                    "level": 2,
                    "risk": 2,
                    "threads": 3,
                },
                description="Balanced default settings",
                timeout_seconds=300,
            ),
        },
    ),
}


class ToolProfileManager:
    """
    ツールプロファイルの管理と選択
    
    使用例:
        manager = ToolProfileManager()
        
        # プロファイルを取得
        profile = manager.get_profile("nuclei", "stealth")
        
        # コンテキストに基づいて自動選択
        profile = manager.auto_select("nuclei", {
            "waf_detected": True,
            "target_is_production": True,
        })
    """

    def __init__(self):
        self._profiles = TOOL_PROFILES.copy()

    def get_profile(
        self, 
        tool_name: str, 
        mode: Optional[str] = None
    ) -> ToolProfile:
        """
        ツールのプロファイルを取得
        
        Args:
            tool_name: ツール名
            mode: プロファイルモード
            
        Returns:
            ToolProfile
        """
        if tool_name not in self._profiles:
            logger.warning("No profile found for tool: %s", tool_name)
            return ToolProfile(name=tool_name, mode=ProfileMode.DEFAULT)
        
        return self._profiles[tool_name].get_profile(mode)

    def auto_select(
        self, 
        tool_name: str, 
        context: dict
    ) -> ToolProfile:
        """
        コンテキストに基づいてプロファイルを自動選択
        
        Args:
            tool_name: ツール名
            context: コンテキスト情報
                - waf_detected: WAF検知済みか
                - target_is_production: 本番環境か
                - time_limited: 時間制限があるか
                - stealth_required: ステルスが必要か
                
        Returns:
            選択されたToolProfile
        """
        # ステルスが必要な条件
        if context.get("waf_detected") or context.get("stealth_required"):
            return self.get_profile(tool_name, "stealth")
        
        # 時間制限がある場合
        if context.get("time_limited"):
            return self.get_profile(tool_name, "speed")
        
        # 本番環境でない場合は徹底的に
        if context.get("target_is_production") is False:
            return self.get_profile(tool_name, "thorough")
        
        return self.get_profile(tool_name, "default")

    def register_profile(
        self, 
        tool_name: str, 
        profile: ToolProfile
    ) -> None:
        """カスタムプロファイルを登録"""
        if tool_name not in self._profiles:
            self._profiles[tool_name] = ToolProfileSet(tool_name=tool_name)
        
        self._profiles[tool_name].profiles[profile.mode.value] = profile
        logger.info("Registered profile: %s/%s", tool_name, profile.mode.value)

    def list_tools(self) -> list[str]:
        """プロファイルが定義されているツール一覧"""
        return list(self._profiles.keys())

    def list_modes(self, tool_name: str) -> list[str]:
        """ツールで利用可能なモード一覧"""
        if tool_name not in self._profiles:
            return []
        return list(self._profiles[tool_name].profiles.keys())


# シングルトンインスタンス
_manager_instance: Optional[ToolProfileManager] = None


def get_tool_profile_manager() -> ToolProfileManager:
    """ToolProfileManagerのシングルトンインスタンスを取得"""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = ToolProfileManager()
    return _manager_instance
