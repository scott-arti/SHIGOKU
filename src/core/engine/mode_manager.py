"""
Mode Configuration System

動作モード（BugBounty/VulnTest/CTF）の管理とツールプリセット適用
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional
import yaml
import logging

logger = logging.getLogger(__name__)


class HuntingMode(str, Enum):
    """ハンティングモード"""
    BUGBOUNTY = "bugbounty"
    VULNTEST = "vulntest"
    CTF = "ctf"


@dataclass
class ModeConfig:
    """モード設定"""
    name: str
    display_name: str
    description: str
    ethics_guard: bool
    ethics_guard_strict: bool
    rate_limit: int  # 0 = 無制限
    attack_aggressiveness: str  # low, medium, high, maximum
    logging_level: str
    auto_report: bool
    tools: Dict[str, bool] = field(default_factory=dict)
    rag_collections: List[str] = field(default_factory=list)
    allowed_targets: List[str] = field(default_factory=list)
    
    # 機能オン・オフ設定
    rag_feedback_enabled: bool = True  # RAG Feedback ループ
    deduplication_enabled: bool = True  # 重複チェック
    notifications_enabled: bool = True  # 通知機能
    parallel_scan_enabled: bool = False  # 並列スキャン
    parallel_workers: int = 3  # 並列ワーカー数
    
    # AIエージェント戦略
    ai_strategy: Dict[str, any] = field(default_factory=dict)


# 組み込みモードプリセット
BUILTIN_MODES = {
    HuntingMode.BUGBOUNTY: ModeConfig(
        name="bugbounty",
        display_name="🎯 Bug Bounty",
        description="本番バグバウンティプログラム向け（安全性最優先）",
        ethics_guard=True,
        ethics_guard_strict=True,
        rate_limit=60,
        attack_aggressiveness="low",
        logging_level="info",
        auto_report=True,
        tools={
            # Intel - 偵察ツール (17種)
            "cartographer": True,
            "fingerprinter": True,
            "commit_watcher": True,
            "visual_filter": True,
            "google_dorker": True,
            "js_analyzer": True,
            "takeover_detector": False, # deprecated
            "subzy": True, # takeover_detector replacement
            "wayback_integrator": True,
            "cloud_misconfig_detector": False, # deprecated
            "cloud_enum": True, # cloud_misconfig_detector replacement
            "scoutsuite": True,
            "cve_explorer": True,
            "email_harvester": True,
            "asn_discoverer": True,
            "cert_transparency": True,
            "shodan_integrator": True,
            "dns_history": True,
            "headless_crawler": True,
            "proxy_log_analyzer": True,  # 新規追加
            # Attack - 攻撃ツール (11種)
            "jwt_inspector": True,
            "oauth_dancer": True,
            "mfa_bypasser": True,
            "biz_logic_hunter": True,
            "ssrf_tester": True,
            "lfi_tester": True,
            "cors_tester": True,
            "open_redirect_tester": True,
            "xss_tester": True,
            "crlf_tester": True,
            "graphql_analyzer": True,
            "race_the_web": False,  # 慎重モード
            "param_fuzzer": True,
            "websocket_tester": True,
            "openapi_tester": True,
        },
        rag_collections=["bugbounty_reports", "cve_database", "hackerone_disclosed"],
        # 機能設定: 安全性と精度を最優先
        rag_feedback_enabled=True,
        deduplication_enabled=True,
        notifications_enabled=True,
        parallel_scan_enabled=False,
        
        ai_strategy={
            "priority": ["high_impact", "low_noise"],
            "skip_bruteforce": True,
            "max_attempts": 3,
            "document_all": True,
        },
    ),
    
    HuntingMode.VULNTEST: ModeConfig(
        name="vulntest",
        display_name="🧪 Vuln Test",
        description="テスト環境向け（学習効果最大化）",
        ethics_guard=True,
        ethics_guard_strict=False,
        rate_limit=0,
        attack_aggressiveness="high",
        logging_level="debug",
        auto_report=False,
        tools={
            # Intel - 偵察ツール (17種、全て有効)
            "cartographer": True,
            "fingerprinter": True,
            "commit_watcher": True,
            "visual_filter": True,
            "google_dorker": True,
            "js_analyzer": True,
            "takeover_detector": False, # deprecated
            "subzy": True,
            "wayback_integrator": True,
            "cloud_misconfig_detector": False, # deprecated
            "cloud_enum": True,
            "scoutsuite": True,
            "cve_explorer": True,
            "email_harvester": True,
            "asn_discoverer": True,
            "cert_transparency": True,
            "shodan_integrator": True,
            "dns_history": True,
            "headless_crawler": True,
            "proxy_log_analyzer": True,  # 新規追加
            # Attack - 攻撃ツール (11種、全て有効)
            "jwt_inspector": True,
            "oauth_dancer": True,
            "mfa_bypasser": True,
            "biz_logic_hunter": True,
            "ssrf_tester": True,
            "lfi_tester": True,
            "cors_tester": True,
            "open_redirect_tester": True,
            "xss_tester": True,
            "crlf_tester": True,
            "graphql_analyzer": True,
            "race_the_web": True,
            "param_fuzzer": True,
            "websocket_tester": True,
            "openapi_tester": True,
        },
        rag_collections=["obsidian_notes", "owasp_guides"],
        # 機能設定: 効率と網羅性を重視
        rag_feedback_enabled=True,
        deduplication_enabled=True,
        notifications_enabled=False,
        parallel_scan_enabled=True,
        parallel_workers=5,
        
        allowed_targets=["localhost", "127.0.0.1", "*.local"],
        ai_strategy={
            "priority": ["variety", "completeness"],
            "skip_bruteforce": False,
            "max_attempts": 5,
            "document_all": True,
        },
    ),
    
    HuntingMode.CTF: ModeConfig(
        name="ctf",
        display_name="🏁 CTF",
        description="競技向け（速度最優先）",
        ethics_guard=False,
        ethics_guard_strict=False,
        rate_limit=0,
        attack_aggressiveness="maximum",
        logging_level="warning",
        auto_report=False,
        tools={
            # Intel - 偵察ツール（最小限、CTF向け最適化）
            "cartographer": True,
            "fingerprinter": True,
            "commit_watcher": False,  # CTFでは不要
            "visual_filter": True,
            "google_dorker": False,  # CTFでは不要
            "js_analyzer": True,
            "takeover_detector": False,  # CTFでは不要
            "subzy": False, # CTFでは不要
            "wayback_integrator": False,  # CTFでは不要
            "cloud_misconfig_detector": False, # deprecated
            "cloud_enum": True,
            "scoutsuite": True,
            "cve_explorer": True,
            "email_harvester": False,  # CTFでは不要
            "asn_discoverer": False,  # CTFでは不要
            "cert_transparency": False,  # CTFでは不要
            "shodan_integrator": False,  # CTFでは不要
            "dns_history": False,  # CTFでは不要
            "headless_crawler": True,
            "proxy_log_analyzer": True,  # 新規追加、ログ分析は有用
            # Attack - 攻撃ツール（全開）
            "jwt_inspector": True,
            "oauth_dancer": True,
            "mfa_bypasser": True,
            "biz_logic_hunter": True,
            "ssrf_tester": True,
            "lfi_tester": True,
            "cors_tester": True,
            "open_redirect_tester": True,
            "xss_tester": True,
            "crlf_tester": True,
            "graphql_analyzer": True,
            "race_the_web": True,
            "param_fuzzer": True,
            "websocket_tester": True,
            "openapi_tester": True,
        },
        rag_collections=["ctf_writeups", "flag_patterns", "common_challenges"],
        # 機能設定: 速度最優先
        rag_feedback_enabled=False,
        deduplication_enabled=False,
        notifications_enabled=False,
        parallel_scan_enabled=True,
        parallel_workers=8,
        
        ai_strategy={
            "priority": ["speed", "flag_extraction"],
            "parallel_attacks": True,
            "skip_slow_methods": True,
        },
    ),
}


class ModeManager:
    """モード管理クラス（シングルトン）"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.current_mode: Optional[ModeConfig] = None
        self.custom_modes: Dict[str, ModeConfig] = {}
        self.custom_modes_dir = Path("config/custom_modes")
        self.custom_modes_dir.mkdir(parents=True, exist_ok=True)
        
        self._load_custom_modes()
        self._initialized = True
    
    def set_mode(self, mode: str) -> ModeConfig:
        """
        モードを設定
        
        Args:
            mode: モード名（"bugbounty", "vulntest", "ctf" または カスタムモード名）
        
        Returns:
            設定されたモード設定
        """
        # 組み込みモードを確認
        if mode in [m.value for m in HuntingMode]:
            mode_enum = HuntingMode(mode)
            self.current_mode = BUILTIN_MODES[mode_enum]
            logger.info(f"Mode set to: {self.current_mode.display_name}")
            return self.current_mode
        
        # カスタムモードを確認
        if mode in self.custom_modes:
            self.current_mode = self.custom_modes[mode]
            logger.info(f"Custom mode set to: {self.current_mode.display_name}")
            return self.current_mode
        
        raise ValueError(f"Unknown mode: {mode}")
    
    def get_current_mode(self) -> Optional[ModeConfig]:
        """現在のモード設定を取得"""
        return self.current_mode
    
    def save_custom_mode(self, config: ModeConfig) -> None:
        """
        カスタムモードを保存
        
        Args:
            config: モード設定
        """
        mode_file = self.custom_modes_dir / f"{config.name}.yaml"
        
        with open(mode_file, 'w') as f:
            yaml.dump({
                'name': config.name,
                'display_name': config.display_name,
                'description': config.description,
                'ethics_guard': config.ethics_guard,
                'ethics_guard_strict': config.ethics_guard_strict,
                'rate_limit': config.rate_limit,
                'attack_aggressiveness': config.attack_aggressiveness,
                'logging_level': config.logging_level,
                'auto_report': config.auto_report,
                'tools': config.tools,
                'rag_collections': config.rag_collections,
                'allowed_targets': config.allowed_targets,
                'ai_strategy': config.ai_strategy,
            }, f, default_flow_style=False)
        
        self.custom_modes[config.name] = config
        logger.info(f"Custom mode saved: {config.name}")
    
    def _load_custom_modes(self) -> None:
        """カスタムモードをロード"""
        for mode_file in self.custom_modes_dir.glob("*.yaml"):
            try:
                with open(mode_file) as f:
                    data = yaml.safe_load(f)
                
                config = ModeConfig(**data)
                self.custom_modes[config.name] = config
                logger.debug(f"Loaded custom mode: {config.name}")
            except Exception as e:
                logger.error(f"Failed to load custom mode {mode_file}: {e}")
    
    def list_modes(self) -> List[ModeConfig]:
        """利用可能なモード一覧を取得"""
        modes = list(BUILTIN_MODES.values())
        modes.extend(self.custom_modes.values())
        return modes
    
    def update_tool_setting(self, tool_name: str, enabled: bool) -> None:
        """
        現在のモードでツール設定を上書き
        
        Args:
            tool_name: ツール名
            enabled: 有効/無効
        """
        if not self.current_mode:
            raise RuntimeError("No mode is currently active")
        
        self.current_mode.tools[tool_name] = enabled
        logger.info(f"Tool '{tool_name}' set to: {enabled}")


def get_mode_manager() -> ModeManager:
    """ModeManagerのシングルトンインスタンスを取得"""
    return ModeManager()
