"""
Debug Logger - 作業ログとサブエージェントハンドオフ記録

デバッグモード用の詳細ログ出力。
サブエージェントへのハンドオフ理由、判断根拠を日本語で出力。
"""

import logging
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class HandoffLog:
    """ハンドオフログ"""
    timestamp: str
    from_agent: str
    to_agent: str
    reason: str  # 日本語
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DecisionLog:
    """判断ログ"""
    timestamp: str
    agent: str
    decision: str  # 日本語
    reasoning: str  # 日本語
    next_steps: List[str] = field(default_factory=list)


@dataclass
class ActionLog:
    """アクションログ"""
    timestamp: str
    agent: str
    action: str
    target: str
    result: str
    details: Dict[str, Any] = field(default_factory=dict)


class DebugLogger:
    """
    デバッグモード用ロガー
    
    機能:
    - 作業ログの自動記録
    - サブエージェントハンドオフの記録
    - 判断理由の日本語出力
    """
    
    def __init__(self, log_dir: str = None, enabled: bool = True):
        self.enabled = enabled
        self.log_dir = Path(log_dir) if log_dir else Path("./logs/debug")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.handoffs: List[HandoffLog] = []
        self.decisions: List[DecisionLog] = []
        self.actions: List[ActionLog] = []
        
        # ファイルログ設定
        self._setup_file_logger()
    
    def _setup_file_logger(self):
        """ファイルロガー設定"""
        if not self.enabled:
            return
        
        log_file = self.log_dir / f"debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s'
        ))
        
        logger.addHandler(file_handler)
        logger.info("デバッグログ開始: %s", log_file)
    
    def _timestamp(self) -> str:
        """タイムスタンプ取得"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def log_handoff(
        self,
        from_agent: str,
        to_agent: str,
        reason: str,
        context: Dict[str, Any] = None
    ) -> None:
        """
        サブエージェントへのハンドオフを記録
        
        Args:
            from_agent: 元エージェント名
            to_agent: 先エージェント名
            reason: ハンドオフ理由（日本語）
            context: コンテキスト情報
        """
        if not self.enabled:
            return
        
        log = HandoffLog(
            timestamp=self._timestamp(),
            from_agent=from_agent,
            to_agent=to_agent,
            reason=reason,
            context=context or {}
        )
        self.handoffs.append(log)
        
        # コンソール出力
        print(f"\n{'='*50}")
        print(f"🔄 ハンドオフ [{log.timestamp}]")
        print(f"  From: {from_agent}")
        print(f"  To: {to_agent}")
        print(f"  理由: {reason}")
        if context:
            print(f"  コンテキスト: {json.dumps(context, ensure_ascii=False, indent=4)}")
        print(f"{'='*50}\n")
        
        # ファイルログ
        logger.info(
            "HANDOFF: %s -> %s | 理由: %s | コンテキスト: %s",
            from_agent, to_agent, reason, json.dumps(context or {}, ensure_ascii=False)
        )
    
    def log_decision(
        self,
        agent: str,
        decision: str,
        reasoning: str,
        next_steps: List[str] = None
    ) -> None:
        """
        判断を記録
        
        Args:
            agent: エージェント名
            decision: 判断内容（日本語）
            reasoning: 判断理由（日本語）
            next_steps: 次のステップ一覧
        """
        if not self.enabled:
            return
        
        log = DecisionLog(
            timestamp=self._timestamp(),
            agent=agent,
            decision=decision,
            reasoning=reasoning,
            next_steps=next_steps or []
        )
        self.decisions.append(log)
        
        # コンソール出力
        print(f"\n{'='*50}")
        print(f"🧠 判断 [{log.timestamp}]")
        print(f"  エージェント: {agent}")
        print(f"  判断: {decision}")
        print(f"  理由: {reasoning}")
        if next_steps:
            print(f"  次のステップ: {next_steps}")
        print(f"{'='*50}\n")
        
        # ファイルログ
        logger.info(
            "DECISION: %s | 判断: %s | 理由: %s | 次: %s",
            agent, decision, reasoning, next_steps or []
        )
    
    def log_action(
        self,
        agent: str,
        action: str,
        target: str,
        result: str,
        details: Dict[str, Any] = None
    ) -> None:
        """
        アクションを記録
        
        Args:
            agent: エージェント名
            action: アクション名
            target: ターゲット
            result: 結果
            details: 詳細情報
        """
        if not self.enabled:
            return
        
        log = ActionLog(
            timestamp=self._timestamp(),
            agent=agent,
            action=action,
            target=target,
            result=result,
            details=details or {}
        )
        self.actions.append(log)
        
        # コンソール出力
        print(f"[{log.timestamp}] ⚡ {agent}: {action} -> {target} ({result})")
        
        # ファイルログ
        logger.info(
            "ACTION: %s | %s | ターゲット: %s | 結果: %s",
            agent, action, target, result
        )
    
    def get_summary(self) -> Dict[str, Any]:
        """サマリー取得"""
        return {
            "handoffs": len(self.handoffs),
            "decisions": len(self.decisions),
            "actions": len(self.actions),
        }
    
    def export_json(self, filepath: str = None) -> str:
        """JSONエクスポート"""
        filepath = filepath or str(self.log_dir / "debug_export.json")
        
        data = {
            "handoffs": [asdict(h) for h in self.handoffs],
            "decisions": [asdict(d) for d in self.decisions],
            "actions": [asdict(a) for a in self.actions],
            "summary": self.get_summary(),
        }
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        return filepath
    
    def enable(self) -> None:
        """デバッグモード有効化"""
        self.enabled = True
        logger.info("デバッグモード有効化")
    
    def disable(self) -> None:
        """デバッグモード無効化"""
        self.enabled = False
        logger.info("デバッグモード無効化")


# シングルトン
_debug_logger: Optional[DebugLogger] = None


def get_debug_logger() -> DebugLogger:
    """DebugLoggerシングルトン取得"""
    global _debug_logger
    if _debug_logger is None:
        _debug_logger = DebugLogger()
    return _debug_logger


def enable_debug_mode() -> None:
    """デバッグモード有効化"""
    get_debug_logger().enable()


def disable_debug_mode() -> None:
    """デバッグモード無効化"""
    get_debug_logger().disable()
