"""
InputSanitizer: LLM入力のサニタイズとプロンプトインジェクション検出

外部入力をサニタイズし、プロンプトインジェクション攻撃を検出する。
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class SanitizeResult:
    """サニタイズ結果"""
    original: str
    sanitized: str
    is_suspicious: bool
    detected_patterns: list[str]
    risk_score: float  # 0.0 - 1.0


class InputSanitizer:
    """
    LLM入力のサニタイズとインジェクション検出
    
    検出パターン:
    - プロンプトインジェクション試行
    - システムプロンプト上書き試行
    - ロール偽装
    - 機密情報抽出試行
    
    使用例:
        sanitizer = InputSanitizer()
        
        result = sanitizer.sanitize(user_input)
        if result.is_suspicious:
            logger.warning(f"Suspicious input detected: {result.detected_patterns}")
    """

    # プロンプトインジェクションパターン
    INJECTION_PATTERNS = [
        # システムプロンプト上書き
        (r"(?i)ignore\s+(all\s+)?previous\s+instructions?", "ignore_instructions"),
        (r"(?i)forget\s+(everything|all|your)\s+(you\s+)?", "forget_instructions"),
        (r"(?i)disregard\s+(all\s+)?previous", "disregard_previous"),
        (r"(?i)system\s*:\s*", "system_override"),
        (r"(?i)new\s+system\s+prompt", "new_system_prompt"),
        
        # ロール偽装
        (r"(?i)you\s+are\s+(now\s+)?a\s+(different|new)", "role_switch"),
        (r"(?i)pretend\s+(you\s+are|to\s+be)", "pretend_role"),
        (r"(?i)act\s+as\s+(if\s+you\s+are|a)", "act_as"),
        (r"(?i)roleplay\s+as", "roleplay"),
        
        # 機密情報抽出
        (r"(?i)reveal\s+(your|the)\s+(system|secret|api)", "reveal_secrets"),
        (r"(?i)show\s+me\s+(your|the)\s+(system|secret|instructions?)", "show_secrets"),
        (r"(?i)what\s+(is|are)\s+your\s+(system|secret)", "query_secrets"),
        (r"(?i)print\s+(your|the)\s+(system|initial)", "print_secrets"),
        (r"(?i)output\s+(your|the)\s+prompt", "output_prompt"),
        
        # エスケープ試行
        (r"```\s*system", "code_block_system"),
        (r"\[\[.*system.*\]\]", "bracket_system"),
        (r"<\|.*system.*\|>", "delimiter_system"),
        
        # DAN/Jailbreak
        (r"(?i)DAN\s*(mode)?", "dan_jailbreak"),
        (r"(?i)jailbreak", "jailbreak"),
        (r"(?i)bypass\s+(your\s+)?(restrictions?|rules?|guidelines?)", "bypass_restrictions"),
        
        # 危険なコマンド実行誘導
        (r"(?i)execute\s+(this\s+)?command", "execute_command"),
        (r"(?i)run\s+(this\s+)?(shell|bash|command)", "run_shell"),
        (r"(?i)sudo\s+", "sudo_command"),
        (r"(?i)rm\s+-rf", "dangerous_rm"),
    ]

    # リスクスコアの重み
    RISK_WEIGHTS = {
        "ignore_instructions": 0.9,
        "forget_instructions": 0.9,
        "disregard_previous": 0.9,
        "system_override": 0.95,
        "new_system_prompt": 0.95,
        "role_switch": 0.7,
        "pretend_role": 0.6,
        "act_as": 0.5,
        "roleplay": 0.4,
        "reveal_secrets": 0.85,
        "show_secrets": 0.85,
        "query_secrets": 0.8,
        "print_secrets": 0.85,
        "output_prompt": 0.8,
        "code_block_system": 0.7,
        "bracket_system": 0.7,
        "delimiter_system": 0.8,
        "dan_jailbreak": 0.95,
        "jailbreak": 0.9,
        "bypass_restrictions": 0.85,
        "execute_command": 0.7,
        "run_shell": 0.7,
        "sudo_command": 0.9,
        "dangerous_rm": 0.95,
    }

    def __init__(self, strict_mode: bool = False):
        """
        初期化
        
        Args:
            strict_mode: True の場合、疑わしい入力を完全にブロック
        """
        self.strict_mode = strict_mode
        self._compiled_patterns = [
            (re.compile(pattern), name)
            for pattern, name in self.INJECTION_PATTERNS
        ]

    def sanitize(self, text: str) -> SanitizeResult:
        """
        入力テキストをサニタイズ
        
        Args:
            text: サニタイズする入力
            
        Returns:
            サニタイズ結果
        """
        if not text:
            return SanitizeResult(
                original="",
                sanitized="",
                is_suspicious=False,
                detected_patterns=[],
                risk_score=0.0,
            )

        detected = []
        
        # パターン検出
        for pattern, name in self._compiled_patterns:
            if pattern.search(text):
                detected.append(name)

        # リスクスコア計算
        risk_score = 0.0
        if detected:
            weights = [self.RISK_WEIGHTS.get(p, 0.5) for p in detected]
            # 最大値と平均の組み合わせ
            risk_score = max(weights) * 0.7 + (sum(weights) / len(weights)) * 0.3
            risk_score = min(1.0, risk_score)

        is_suspicious = risk_score >= 0.5

        # サニタイズ処理
        sanitized = text
        if is_suspicious:
            sanitized = self._sanitize_text(text)
            
            if self.strict_mode:
                sanitized = "[BLOCKED: Suspicious input detected]"
            
            logger.warning(
                f"Suspicious input detected: patterns={detected}, "
                f"risk_score={risk_score:.2f}"
            )

        return SanitizeResult(
            original=text,
            sanitized=sanitized,
            is_suspicious=is_suspicious,
            detected_patterns=detected,
            risk_score=risk_score,
        )

    def _sanitize_text(self, text: str) -> str:
        """テキストをサニタイズ"""
        sanitized = text
        
        # 危険なパターンを無害化
        replacements = [
            (r"(?i)ignore\s+(all\s+)?previous\s+instructions?", "[FILTERED]"),
            (r"(?i)system\s*:\s*", "[system] "),
            (r"(?i)forget\s+(everything|all)", "[FILTERED]"),
            (r"```\s*system", "``` system"),
        ]
        
        for pattern, replacement in replacements:
            sanitized = re.sub(pattern, replacement, sanitized)
        
        return sanitized

    def is_safe(self, text: str, threshold: float = 0.5) -> bool:
        """
        入力が安全かチェック
        
        Args:
            text: チェックする入力
            threshold: リスクスコアの閾値
            
        Returns:
            安全ならTrue
        """
        result = self.sanitize(text)
        return result.risk_score < threshold

    def get_risk_level(self, text: str) -> str:
        """
        リスクレベルを文字列で取得
        
        Returns:
            "low", "medium", "high", "critical"
        """
        result = self.sanitize(text)
        
        if result.risk_score < 0.3:
            return "low"
        elif result.risk_score < 0.6:
            return "medium"
        elif result.risk_score < 0.85:
            return "high"
        else:
            return "critical"


# シングルトンインスタンス
_sanitizer_instance: Optional[InputSanitizer] = None


def get_input_sanitizer(strict_mode: bool = False) -> InputSanitizer:
    """InputSanitizerのシングルトンインスタンスを取得"""
    global _sanitizer_instance
    if _sanitizer_instance is None:
        _sanitizer_instance = InputSanitizer(strict_mode=strict_mode)
    return _sanitizer_instance


def sanitize_llm_input(text: str) -> str:
    """
    便利関数: LLM入力をサニタイズして返す
    
    Args:
        text: サニタイズする入力
        
    Returns:
        サニタイズされたテキスト
    """
    return get_input_sanitizer().sanitize(text).sanitized
