"""
Mode-Aware Base Agent

モードを認識して戦略を変更するエージェント基底クラス
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Optional, Any
from src.core.mode_manager import ModeConfig
import logging

logger = logging.getLogger(__name__)


@dataclass
class AttackStrategy:
    """攻撃戦略"""
    priority: list[str]  # 優先する方針（例: ["high_impact", "low_noise"]）
    skip_bruteforce: bool = False
    max_attempts: int = 5
    document_all: bool = True
    explain_failures: bool = False
    try_all_variants: bool = False
    log_learning_notes: bool = False
    parallel_attacks: bool = False
    skip_slow_methods: bool = False


class ModeAwareAgent(ABC):
    """
    モード認識型エージェント基底クラス
    
    各エージェントはこのクラスを継承し、モード別の戦略を実装する
    """
    
    def __init__(self, program_name: str = ""):
        self.program_name = program_name
        self.current_mode: Optional[ModeConfig] = None
        self.strategy: Optional[AttackStrategy] = None
    
    def set_mode(self, mode_config: ModeConfig):
        """
        モードを設定して戦略を変更
        
        Args:
            mode_config: モード設定
        """
        self.current_mode = mode_config
        self.strategy = self._select_strategy(mode_config)
        logger.info(
            f"{self.__class__.__name__} mode set to: {mode_config.name} "
            f"(aggressiveness: {mode_config.attack_aggressiveness})"
        )
    
    def _select_strategy(self, mode_config: ModeConfig) -> AttackStrategy:
        """
        モード設定から攻撃戦略を選択
        
        Args:
            mode_config: モード設定
        
        Returns:
            攻撃戦略
        """
        # モードのai_strategyから戦略を構築
        ai_strategy = mode_config.ai_strategy
        
        if mode_config.name == "bugbounty":
            return AttackStrategy(
                priority=ai_strategy.get("priority", ["high_impact", "low_noise"]),
                skip_bruteforce=ai_strategy.get("skip_bruteforce", True),
                max_attempts=ai_strategy.get("max_attempts", 3),
                document_all=ai_strategy.get("document_all", True),
            )
        
        elif mode_config.name == "vulntest":
            return AttackStrategy(
                priority=ai_strategy.get("priority", ["educational", "comprehensive"]),
                skip_bruteforce=False,
                max_attempts=10,
                explain_failures=ai_strategy.get("explain_failures", True),
                try_all_variants=ai_strategy.get("try_all_variants", True),
                log_learning_notes=ai_strategy.get("log_learning_notes", True),
            )
        
        elif mode_config.name == "ctf":
            return AttackStrategy(
                priority=ai_strategy.get("priority", ["speed", "flag_extraction"]),
                skip_bruteforce=False,
                max_attempts=3,
                parallel_attacks=ai_strategy.get("parallel_attacks", True),
                skip_slow_methods=ai_strategy.get("skip_slow_methods", True),
                explain_failures=False,
            )
        
        # デフォルト戦略
        return AttackStrategy(
            priority=["balanced"],
            max_attempts=5,
        )
    
    @abstractmethod
    def execute(self, target: str, params: dict) -> Any:
        """
        エージェント実行（サブクラスで実装）
        
        Args:
            target: ターゲットURL
            params: パラメータ
        
        Returns:
            実行結果
        """
        pass
    
    def should_skip_method(self, method_name: str) -> bool:
        """
        メソッドをスキップすべきか判定
        
        Args:
            method_name: メソッド名
        
        Returns:
            スキップする: True
        """
        if not self.strategy:
            return False
        
        # ブルートフォースのスキップ
        if self.strategy.skip_bruteforce and "brute" in method_name.lower():
            logger.debug(f"Skipping bruteforce method: {method_name}")
            return True
        
        # 遅いメソッドのスキップ（CTFモード）
        slow_methods = ["exhaustive", "comprehensive", "full_scan"]
        if self.strategy.skip_slow_methods:
            if any(slow in method_name.lower() for slow in slow_methods):
                logger.debug(f"Skipping slow method: {method_name}")
                return True
        
        return False
    
    def log_attempt(
        self,
        target: str,
        method: str,
        success: bool,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        試行をログに記録
        
        Args:
            target: ターゲット
            method: メソッド
            success: 成功/失敗
            details: 詳細情報
        """
        log_msg = f"[{self.__class__.__name__}] {method} on {target}: {'SUCCESS' if success else 'FAILED'}"
        
        if success:
            logger.info(log_msg)
        else:
            # VulnTestモードでは失敗も詳細にログ
            if self.strategy and self.strategy.explain_failures:
                logger.info(f"{log_msg} - Reason: {details.get('error', 'Unknown') if details else 'Unknown'}")
            else:
                logger.debug(log_msg)
