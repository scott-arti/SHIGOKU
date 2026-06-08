"""
Adaptive Payload Adjuster - 適応型ペイロード調整

レスポンス解析に基づいてペイロードを動的に調整。
FeedbackLoopと連携して学習ベースの調整を実行。

用途:
- レスポンス解析からの自動調整
- コンテキスト適応（HTML/JS/SQL等）
- 成功パターンの蓄積と活用
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class PayloadContext(Enum):
    """ペイロードコンテキスト"""
    HTML_TAG = "html_tag"
    HTML_ATTRIBUTE = "html_attribute"
    HTML_COMMENT = "html_comment"
    JAVASCRIPT = "javascript"
    URL = "url"
    JSON = "json"
    SQL = "sql"
    XML = "xml"
    UNKNOWN = "unknown"


class AdjustmentAction(Enum):
    """調整アクション"""
    ENCODE = "encode"
    ESCAPE = "escape"
    TRUNCATE = "truncate"
    PAD = "pad"
    BREAK_STRING = "break_string"
    CHANGE_CASE = "change_case"
    ADD_COMMENT = "add_comment"
    USE_ALTERNATIVE = "use_alternative"


@dataclass
class AdjustedPayload:
    """調整されたペイロード"""
    original: str
    adjusted: str
    context: PayloadContext
    actions: List[AdjustmentAction]
    reason: str = ""
    confidence: float = 0.0


class AdaptivePayloadAdjuster:
    """
    Adaptive Payload Adjuster
    
    機能:
    - コンテキスト自動判定
    - レスポンスからのヒント抽出
    - ルールベース+学習ベースの調整
    - エスケープ/フィルター回避
    """
    
    # コンテキスト判定パターン
    CONTEXT_PATTERNS = {
        PayloadContext.HTML_TAG: [
            r'<[a-zA-Z][^>]*>',
            r'<div', r'<span', r'<p[^>]*>',
        ],
        PayloadContext.HTML_ATTRIBUTE: [
            r'["\'][^"\']*$',
            r'=\s*["\'][^"\']*$',
        ],
        PayloadContext.JAVASCRIPT: [
            r'<script[^>]*>',
            r'\.js["\']',
            r'function\s*\(',
            r'var\s+\w+',
        ],
        PayloadContext.SQL: [
            r'SELECT\s+',
            r'FROM\s+',
            r'WHERE\s+',
            r'INSERT\s+',
        ],
        PayloadContext.JSON: [
            r'^\s*[\[{]',
            r'application/json',
        ],
        PayloadContext.URL: [
            r'https?://',
            r'\?[^=]+=',
        ],
    }
    
    # コンテキスト別の調整戦略
    CONTEXT_STRATEGIES = {
        PayloadContext.HTML_TAG: [
            AdjustmentAction.ESCAPE,
            AdjustmentAction.BREAK_STRING,
            AdjustmentAction.USE_ALTERNATIVE,
        ],
        PayloadContext.HTML_ATTRIBUTE: [
            AdjustmentAction.ESCAPE,
            AdjustmentAction.ENCODE,
            AdjustmentAction.BREAK_STRING,
        ],
        PayloadContext.JAVASCRIPT: [
            AdjustmentAction.ENCODE,
            AdjustmentAction.BREAK_STRING,
            AdjustmentAction.USE_ALTERNATIVE,
        ],
        PayloadContext.SQL: [
            AdjustmentAction.ADD_COMMENT,
            AdjustmentAction.CHANGE_CASE,
            AdjustmentAction.ENCODE,
        ],
        PayloadContext.JSON: [
            AdjustmentAction.ESCAPE,
            AdjustmentAction.ENCODE,
        ],
    }
    
    # エスケープパターンと対策
    ESCAPE_BYPASS = {
        '"': ['\\"', '&quot;', '&#34;', '\\u0022'],
        "'": ["\\'", '&apos;', '&#39;', '\\u0027'],
        '<': ['&lt;', '&#60;', '\\u003c', '%3c'],
        '>': ['&gt;', '&#62;', '\\u003e', '%3e'],
        '&': ['&amp;', '&#38;', '\\u0026'],
        '/': ['\\/', '&#47;', '%2f'],
    }
    
    def __init__(self):
        self.history: List[AdjustedPayload] = []
        self.learned_patterns: Dict[str, List[str]] = {}
    
    def adjust(
        self,
        payload: str,
        response_hint: str = "",
        detected_context: Optional[PayloadContext] = None,
    ) -> List[AdjustedPayload]:
        """
        ペイロードを調整
        
        Args:
            payload: 元のペイロード
            response_hint: レスポンスの一部（コンテキスト判定用）
            detected_context: 既知のコンテキスト
        
        Returns:
            調整されたペイロードのリスト
        """
        # コンテキスト判定
        context = detected_context or self._detect_context(response_hint)
        
        # 調整戦略取得
        strategies = self.CONTEXT_STRATEGIES.get(
            context, 
            [AdjustmentAction.ENCODE]
        )
        
        results = []
        
        for action in strategies:
            adjusted = self._apply_action(payload, action, context)
            if adjusted != payload:
                result = AdjustedPayload(
                    original=payload,
                    adjusted=adjusted,
                    context=context,
                    actions=[action],
                    reason=f"Context: {context.value}, Action: {action.value}",
                )
                results.append(result)
        
        # 複合調整
        combined = self._apply_combined_actions(payload, strategies[:3], context)
        if combined != payload:
            results.append(AdjustedPayload(
                original=payload,
                adjusted=combined,
                context=context,
                actions=strategies[:3],
                reason="Combined adjustment",
            ))
        
        self.history.extend(results)
        return results
    
    def _detect_context(self, hint: str) -> PayloadContext:
        """コンテキストを推測"""
        hint_lower = hint.lower()
        
        for context, patterns in self.CONTEXT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, hint, re.IGNORECASE):
                    return context
        
        return PayloadContext.UNKNOWN
    
    def _apply_action(
        self,
        payload: str,
        action: AdjustmentAction,
        context: PayloadContext,
    ) -> str:
        """単一アクション適用"""
        if action == AdjustmentAction.ENCODE:
            return self._action_encode(payload, context)
        elif action == AdjustmentAction.ESCAPE:
            return self._action_escape(payload)
        elif action == AdjustmentAction.TRUNCATE:
            return self._action_truncate(payload)
        elif action == AdjustmentAction.PAD:
            return self._action_pad(payload)
        elif action == AdjustmentAction.BREAK_STRING:
            return self._action_break_string(payload, context)
        elif action == AdjustmentAction.CHANGE_CASE:
            return self._action_change_case(payload)
        elif action == AdjustmentAction.ADD_COMMENT:
            return self._action_add_comment(payload, context)
        elif action == AdjustmentAction.USE_ALTERNATIVE:
            return self._action_use_alternative(payload, context)
        return payload
    
    def _action_encode(self, payload: str, context: PayloadContext) -> str:
        """エンコード"""
        from urllib.parse import quote
        if context == PayloadContext.URL:
            return quote(payload, safe='')
        elif context == PayloadContext.JAVASCRIPT:
            # Unicodeエスケープ
            return ''.join(f'\\u{ord(c):04x}' if not c.isalnum() else c for c in payload)
        elif context == PayloadContext.HTML_TAG:
            # HTMLエンティティ
            return ''.join(f'&#{ord(c)};' for c in payload)
        return quote(payload, safe='')
    
    def _action_escape(self, payload: str) -> str:
        """エスケープバイパス"""
        import random
        result = payload
        for char, alternatives in self.ESCAPE_BYPASS.items():
            if char in result:
                alt = random.choice(alternatives)
                result = result.replace(char, alt, 1)
        return result
    
    def _action_truncate(self, payload: str) -> str:
        """長さ制限対策"""
        if len(payload) > 100:
            return payload[:97] + "..."
        return payload
    
    def _action_pad(self, payload: str) -> str:
        """パディング追加"""
        import random
        paddings = ["", " ", "/**/", "\t", "\n"]
        return random.choice(paddings) + payload + random.choice(paddings)
    
    def _action_break_string(self, payload: str, context: PayloadContext) -> str:
        """文字列分割"""
        if context == PayloadContext.JAVASCRIPT:
            # JS文字列結合
            parts = [payload[i:i+3] for i in range(0, len(payload), 3)]
            return "+".join(f"'{p}'" for p in parts)
        elif context == PayloadContext.SQL:
            # SQL CONCAT
            parts = [payload[i:i+3] for i in range(0, len(payload), 3)]
            return f"CONCAT({','.join(repr(p) for p in parts)})"
        return payload
    
    def _action_change_case(self, payload: str) -> str:
        """大小文字変更"""
        return ''.join(
            c.upper() if i % 2 else c.lower()
            for i, c in enumerate(payload)
        )
    
    def _action_add_comment(self, payload: str, context: PayloadContext) -> str:
        """コメント挿入"""
        if context == PayloadContext.SQL:
            return "/**/".join(payload)
        elif context in (PayloadContext.HTML_TAG, PayloadContext.HTML_COMMENT):
            return "<!---->".join(payload)
        return payload
    
    def _action_use_alternative(self, payload: str, context: PayloadContext) -> str:
        """代替構文使用"""
        alternatives = {
            "<script>": ["<ScRiPt>", "<SCRIPT>", "<script >"],
            "alert(": ["prompt(", "confirm(", "console.log("],
            "onerror=": ["onload=", "onfocus=", "onmouseover="],
        }
        
        result = payload
        for original, alts in alternatives.items():
            if original in result.lower():
                import random
                result = re.sub(
                    re.escape(original), 
                    random.choice(alts), 
                    result, 
                    flags=re.IGNORECASE,
                    count=1
                )
        return result
    
    def _apply_combined_actions(
        self,
        payload: str,
        actions: List[AdjustmentAction],
        context: PayloadContext,
    ) -> str:
        """複合アクション適用"""
        result = payload
        for action in actions:
            result = self._apply_action(result, action, context)
        return result
    
    def adjust_from_error(
        self,
        payload: str,
        error_message: str,
    ) -> List[AdjustedPayload]:
        """
        エラーメッセージから調整
        
        Args:
            payload: 元のペイロード
            error_message: サーバーからのエラーメッセージ
        
        Returns:
            調整されたペイロード
        """
        results = []
        
        # エラーパターン分析
        if "length" in error_message.lower() or "too long" in error_message.lower():
            truncated = self._action_truncate(payload)
            results.append(AdjustedPayload(
                original=payload,
                adjusted=truncated,
                context=PayloadContext.UNKNOWN,
                actions=[AdjustmentAction.TRUNCATE],
                reason="Length restriction detected",
            ))
        
        if "invalid character" in error_message.lower():
            encoded = self._action_encode(payload, PayloadContext.URL)
            results.append(AdjustedPayload(
                original=payload,
                adjusted=encoded,
                context=PayloadContext.URL,
                actions=[AdjustmentAction.ENCODE],
                reason="Invalid character detected",
            ))
        
        if "blocked" in error_message.lower() or "denied" in error_message.lower():
            # WAFブロック検出
            escaped = self._action_escape(payload)
            results.append(AdjustedPayload(
                original=payload,
                adjusted=escaped,
                context=PayloadContext.UNKNOWN,
                actions=[AdjustmentAction.ESCAPE],
                reason="WAF block detected",
            ))
        
        self.history.extend(results)
        return results
    
    def learn_success(
        self,
        original: str,
        successful: str,
        context: PayloadContext,
    ) -> None:
        """成功パターンを学習"""
        key = f"{context.value}:{original[:20]}"
        if key not in self.learned_patterns:
            self.learned_patterns[key] = []
        self.learned_patterns[key].append(successful)
    
    def get_summary(self) -> Dict:
        """サマリー"""
        by_context = {}
        by_action = {}
        
        for h in self.history:
            by_context[h.context.value] = by_context.get(h.context.value, 0) + 1
            for a in h.actions:
                by_action[a.value] = by_action.get(a.value, 0) + 1
        
        return {
            "total_adjustments": len(self.history),
            "by_context": by_context,
            "by_action": by_action,
            "learned_patterns": len(self.learned_patterns),
        }


def create_adaptive_adjuster() -> AdaptivePayloadAdjuster:
    """AdaptivePayloadAdjuster作成ヘルパー"""
    return AdaptivePayloadAdjuster()
