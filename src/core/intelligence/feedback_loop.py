"""
Feedback Loop - WAF応答解析とペイロード適応フレームワーク

WAFブロックや応答パターンを分析し、
ペイロードを自動調整するフィードバックループ基盤。

用途:
- WAFブロック検知と回避戦略選択
- エラーメッセージ解析によるバリデーション回避
- 適応型ペイロード調整
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Any
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class ResponseType(Enum):
    """レスポンスタイプ"""
    SUCCESS = "success"             # 攻撃成功
    WAF_BLOCKED = "waf_blocked"     # WAFブロック
    VALIDATION_ERROR = "validation_error"  # バリデーションエラー
    AUTH_ERROR = "auth_error"       # 認証エラー
    RATE_LIMITED = "rate_limited"   # レート制限
    SERVER_ERROR = "server_error"   # サーバーエラー
    TIMEOUT = "timeout"             # タイムアウト
    UNKNOWN = "unknown"             # 不明


class BypassStrategy(Enum):
    """バイパス戦略"""
    DOUBLE_ENCODE = "double_encode"
    UNICODE_ESCAPE = "unicode_escape"
    MIXED_CASE = "mixed_case"
    COMMENT_INSERT = "comment_insert"
    NULL_BYTE = "null_byte"
    CONCAT_SPLIT = "concat_split"
    BASE64 = "base64"
    HEX_ENCODE = "hex_encode"
    DELAY = "delay"
    HEADER_MANIPULATION = "header_manipulation"


@dataclass
class ResponseAnalysis:
    """レスポンス解析結果"""
    response_type: ResponseType
    status_code: int
    confidence: float  # 0.0 - 1.0
    blocked_pattern: str = ""  # 検出されたブロックパターン
    suggested_strategies: List[BypassStrategy] = field(default_factory=list)
    raw_evidence: str = ""
    analyzed_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "type": self.response_type.value,
            "status_code": self.status_code,
            "confidence": self.confidence,
            "blocked_pattern": self.blocked_pattern,
            "strategies": [s.value for s in self.suggested_strategies],
        }


@dataclass
class FeedbackRecord:
    """フィードバック記録"""
    payload: str
    encoded_payload: str
    strategy_used: Optional[BypassStrategy]
    response_analysis: ResponseAnalysis
    success: bool
    timestamp: datetime = field(default_factory=datetime.now)


class FeedbackLoop:
    """
    フィードバックループ基盤
    
    WAFや検証エラーの応答を分析し、
    次のペイロードにフィードバックを反映する。
    """
    
    # WAFブロックを示すパターン
    WAF_PATTERNS = [
        (r"access\s*denied", "access_denied"),
        (r"forbidden", "forbidden"),
        (r"blocked", "blocked"),
        (r"firewall", "firewall"),
        (r"waf", "waf"),
        (r"security\s*violation", "security_violation"),
        (r"invalid\s*request", "invalid_request"),
        (r"attack\s*detected", "attack_detected"),
        (r"suspicious\s*activity", "suspicious_activity"),
        (r"mod_security", "modsecurity"),
        (r"cloudflare", "cloudflare"),
        (r"akamai", "akamai"),
        (r"imperva", "imperva"),
        (r"sucuri", "sucuri"),
        (r"wordfence", "wordfence"),
        (r"aws\s*waf", "aws_waf"),
    ]
    
    # バリデーションエラーパターン
    VALIDATION_PATTERNS = [
        (r"invalid\s*(input|parameter|value)", "invalid_input"),
        (r"must\s*be\s*a?\s*(number|string|integer)", "type_error"),
        (r"(too\s*long|maximum\s*length)", "length_error"),
        (r"(required|missing)\s*field", "required_field"),
        (r"invalid\s*format", "format_error"),
        (r"not\s*allowed", "not_allowed"),
        (r"(special\s*)?characters?\s*(not\s*)?allowed", "char_error"),
    ]
    
    # パターン別推奨戦略
    PATTERN_STRATEGIES = {
        "access_denied": [BypassStrategy.DOUBLE_ENCODE, BypassStrategy.UNICODE_ESCAPE],
        "forbidden": [BypassStrategy.MIXED_CASE, BypassStrategy.COMMENT_INSERT],
        "blocked": [BypassStrategy.DOUBLE_ENCODE, BypassStrategy.NULL_BYTE],
        "firewall": [BypassStrategy.UNICODE_ESCAPE, BypassStrategy.HEX_ENCODE],
        "waf": [BypassStrategy.COMMENT_INSERT, BypassStrategy.CONCAT_SPLIT],
        "modsecurity": [BypassStrategy.UNICODE_ESCAPE, BypassStrategy.DOUBLE_ENCODE],
        "cloudflare": [BypassStrategy.MIXED_CASE, BypassStrategy.BASE64],
        "akamai": [BypassStrategy.HEX_ENCODE, BypassStrategy.DELAY],
        "imperva": [BypassStrategy.COMMENT_INSERT, BypassStrategy.UNICODE_ESCAPE],
        "type_error": [BypassStrategy.BASE64, BypassStrategy.HEX_ENCODE],
        "length_error": [BypassStrategy.CONCAT_SPLIT],
        "char_error": [BypassStrategy.UNICODE_ESCAPE, BypassStrategy.HEX_ENCODE],
    }
    
    def __init__(
        self,
        max_history: int = 100,
        max_retries: int = 5,
    ):
        """
        Args:
            max_history: 保持するフィードバック履歴の最大数
            max_retries: 同一ペイロードの最大リトライ回数
        """
        self.max_history = max_history
        self.max_retries = max_retries
        self.history: List[FeedbackRecord] = []
        self.strategy_success_rate: Dict[BypassStrategy, Dict[str, int]] = {}
        self._callbacks: List[Callable[[FeedbackRecord], None]] = []
    
    def analyze_response(
        self,
        status_code: int,
        response_body: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> ResponseAnalysis:
        """
        レスポンスを解析してタイプと推奨戦略を判定
        
        Args:
            status_code: HTTPステータスコード
            response_body: レスポンスボディ
            headers: レスポンスヘッダー
        
        Returns:
            ResponseAnalysis
        """
        headers = headers or {}
        body_lower = response_body.lower()
        
        # ステータスコードベース判定
        if status_code == 200:
            return ResponseAnalysis(
                response_type=ResponseType.SUCCESS,
                status_code=status_code,
                confidence=0.7,
            )
        elif status_code == 403:
            # WAFブロックの可能性
            analysis = self._detect_waf(body_lower, headers)
            if analysis:
                return analysis
            return ResponseAnalysis(
                response_type=ResponseType.WAF_BLOCKED,
                status_code=status_code,
                confidence=0.8,
                suggested_strategies=[
                    BypassStrategy.DOUBLE_ENCODE,
                    BypassStrategy.UNICODE_ESCAPE,
                ],
            )
        elif status_code == 400:
            # バリデーションエラーの可能性
            analysis = self._detect_validation_error(body_lower)
            if analysis:
                return analysis
            return ResponseAnalysis(
                response_type=ResponseType.VALIDATION_ERROR,
                status_code=status_code,
                confidence=0.6,
            )
        elif status_code == 401 or status_code == 407:
            return ResponseAnalysis(
                response_type=ResponseType.AUTH_ERROR,
                status_code=status_code,
                confidence=0.9,
            )
        elif status_code == 429:
            return ResponseAnalysis(
                response_type=ResponseType.RATE_LIMITED,
                status_code=status_code,
                confidence=0.95,
                suggested_strategies=[BypassStrategy.DELAY],
            )
        elif status_code >= 500:
            return ResponseAnalysis(
                response_type=ResponseType.SERVER_ERROR,
                status_code=status_code,
                confidence=0.9,
            )
        
        # WAFパターンチェック (ステータスコード関係なく)
        waf_analysis = self._detect_waf(body_lower, headers)
        if waf_analysis:
            return waf_analysis
        
        return ResponseAnalysis(
            response_type=ResponseType.UNKNOWN,
            status_code=status_code,
            confidence=0.3,
        )
    
    def _detect_waf(
        self,
        body_lower: str,
        headers: Dict[str, str],
    ) -> Optional[ResponseAnalysis]:
        """WAFブロックを検出"""
        # ヘッダーチェック
        for header_name, header_value in headers.items():
            header_lower = header_value.lower()
            if "cloudflare" in header_lower:
                return ResponseAnalysis(
                    response_type=ResponseType.WAF_BLOCKED,
                    status_code=403,
                    confidence=0.95,
                    blocked_pattern="cloudflare",
                    suggested_strategies=self.PATTERN_STRATEGIES["cloudflare"],
                )
        
        # ボディパターンチェック
        for pattern, label in self.WAF_PATTERNS:
            if re.search(pattern, body_lower):
                strategies = self.PATTERN_STRATEGIES.get(label, [
                    BypassStrategy.DOUBLE_ENCODE,
                    BypassStrategy.UNICODE_ESCAPE,
                ])
                return ResponseAnalysis(
                    response_type=ResponseType.WAF_BLOCKED,
                    status_code=403,
                    confidence=0.85,
                    blocked_pattern=label,
                    suggested_strategies=strategies,
                    raw_evidence=body_lower[:200],
                )
        
        return None
    
    def _detect_validation_error(
        self,
        body_lower: str,
    ) -> Optional[ResponseAnalysis]:
        """バリデーションエラーを検出"""
        for pattern, label in self.VALIDATION_PATTERNS:
            if re.search(pattern, body_lower):
                strategies = self.PATTERN_STRATEGIES.get(label, [])
                return ResponseAnalysis(
                    response_type=ResponseType.VALIDATION_ERROR,
                    status_code=400,
                    confidence=0.8,
                    blocked_pattern=label,
                    suggested_strategies=strategies,
                    raw_evidence=body_lower[:200],
                )
        return None
    
    def record_attempt(
        self,
        payload: str,
        encoded_payload: str,
        strategy: Optional[BypassStrategy],
        response_analysis: ResponseAnalysis,
        success: bool,
    ) -> FeedbackRecord:
        """
        試行を記録
        
        Args:
            payload: 元のペイロード
            encoded_payload: エンコード後のペイロード
            strategy: 使用した戦略
            response_analysis: レスポンス解析結果
            success: 成功したか
        
        Returns:
            FeedbackRecord
        """
        record = FeedbackRecord(
            payload=payload,
            encoded_payload=encoded_payload,
            strategy_used=strategy,
            response_analysis=response_analysis,
            success=success,
        )
        
        self.history.append(record)
        
        # 履歴制限
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history:]
        
        # 成功率更新
        if strategy:
            if strategy not in self.strategy_success_rate:
                self.strategy_success_rate[strategy] = {"success": 0, "total": 0}
            self.strategy_success_rate[strategy]["total"] += 1
            if success:
                self.strategy_success_rate[strategy]["success"] += 1
        
        # コールバック
        for callback in self._callbacks:
            try:
                callback(record)
            except Exception as e:
                logger.error("Callback error: %s", e)
        
        return record
    
    def get_best_strategy(
        self,
        response_analysis: ResponseAnalysis,
        tried_strategies: Optional[List[BypassStrategy]] = None,
    ) -> Optional[BypassStrategy]:
        """
        最適なバイパス戦略を取得
        
        Args:
            response_analysis: レスポンス解析結果
            tried_strategies: 既に試した戦略
        
        Returns:
            推奨戦略、またはNone
        """
        tried = set(tried_strategies or [])
        
        # レスポンス解析からの推奨を優先
        for strategy in response_analysis.suggested_strategies:
            if strategy not in tried:
                return strategy
        
        # 過去の成功率から選択
        best_strategy = None
        best_rate = 0.0
        
        for strategy, stats in self.strategy_success_rate.items():
            if strategy in tried:
                continue
            if stats["total"] == 0:
                continue
            rate = stats["success"] / stats["total"]
            if rate > best_rate:
                best_rate = rate
                best_strategy = strategy
        
        if best_strategy:
            return best_strategy
        
        # 未試行の戦略から選択
        all_strategies = list(BypassStrategy)
        for strategy in all_strategies:
            if strategy not in tried:
                return strategy
        
        return None
    
    def should_retry(self, payload: str) -> bool:
        """
        リトライすべきか判定
        
        Args:
            payload: ペイロード
        
        Returns:
            リトライすべきかどうか
        """
        retry_count = sum(
            1 for r in self.history
            if r.payload == payload and not r.success
        )
        return retry_count < self.max_retries
    
    def get_retry_count(self, payload: str) -> int:
        """ペイロードのリトライ回数を取得"""
        return sum(
            1 for r in self.history
            if r.payload == payload
        )
    
    def register_callback(
        self,
        callback: Callable[[FeedbackRecord], None],
    ) -> None:
        """フィードバック記録時のコールバック登録"""
        self._callbacks.append(callback)
    
    def get_success_stats(self) -> Dict[str, float]:
        """戦略別成功率を取得"""
        stats = {}
        for strategy, data in self.strategy_success_rate.items():
            if data["total"] > 0:
                stats[strategy.value] = data["success"] / data["total"]
        return stats
    
    def get_summary(self) -> Dict:
        """サマリーを取得"""
        total = len(self.history)
        successes = sum(1 for r in self.history if r.success)
        
        by_type = {}
        for r in self.history:
            t = r.response_analysis.response_type.value
            by_type[t] = by_type.get(t, 0) + 1
        
        return {
            "total_attempts": total,
            "successes": successes,
            "success_rate": successes / total if total > 0 else 0,
            "by_response_type": by_type,
            "strategy_success_rates": self.get_success_stats(),
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"Feedback Loop Stats:\n"
            f"Total attempts: {summary['total_attempts']}\n"
            f"Success rate: {summary['success_rate']:.1%}\n"
            f"By type: {summary['by_response_type']}\n"
            f"Strategy success: {summary['strategy_success_rates']}"
        )


def create_feedback_loop(
    max_history: int = 100,
    max_retries: int = 5,
) -> FeedbackLoop:
    """FeedbackLoop作成ヘルパー"""
    return FeedbackLoop(
        max_history=max_history,
        max_retries=max_retries,
    )
