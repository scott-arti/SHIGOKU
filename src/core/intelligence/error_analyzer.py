"""
ErrorAnalyzer: 深いエラー分析

エラーパターンを分類し、根本原因を推定して
再発防止策を提案する。
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time
from src.core.learning.repository import get_learning_repository, LearningRepository
from src.core.security.pii_masker import get_pii_masker

logger = logging.getLogger(__name__)


class ErrorCategory(str, Enum):
    """エラーカテゴリ"""
    # ネットワーク系
    NETWORK_TIMEOUT = "network_timeout"
    CONNECTION_REFUSED = "connection_refused"
    DNS_FAILURE = "dns_failure"
    SSL_ERROR = "ssl_error"
    
    # 認証/認可系
    AUTH_FAILURE = "auth_failure"
    PERMISSION_DENIED = "permission_denied"
    SESSION_EXPIRED = "session_expired"
    
    # レート制限/WAF系
    RATE_LIMITED = "rate_limited"
    WAF_BLOCKED = "waf_blocked"
    IP_BLOCKED = "ip_blocked"
    
    # アプリケーション系
    VALIDATION_ERROR = "validation_error"
    NOT_FOUND = "not_found"
    SERVER_ERROR = "server_error"
    
    # クライアント系
    PAYLOAD_ERROR = "payload_error"
    PARSE_ERROR = "parse_error"
    
    # 不明
    UNKNOWN = "unknown"


@dataclass
class ErrorRecord:
    """エラー記録"""
    error_message: str
    category: ErrorCategory = ErrorCategory.UNKNOWN
    status_code: Optional[int] = None
    target_url: Optional[str] = None
    action_type: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    context: dict = field(default_factory=dict)


@dataclass
class RootCauseAnalysis:
    """根本原因分析結果"""
    category: ErrorCategory
    likely_cause: str
    confidence: float  # 0.0 - 1.0
    mitigation: str
    retry_recommended: bool
    wait_seconds: Optional[float] = None
    
    def to_dict(self) -> dict:
        """辞書形式に変換"""
        return {
            "category": self.category.value,
            "likely_cause": self.likely_cause,
            "confidence": self.confidence,
            "mitigation": self.mitigation,
            "retry_recommended": self.retry_recommended,
            "wait_seconds": self.wait_seconds,
        }


class ErrorAnalyzer:
    """
    エラー分析エンジン
    
    エラーメッセージとコンテキストから
    エラーカテゴリを分類し、根本原因を推定する。
    
    使用例:
        analyzer = ErrorAnalyzer()
        
        record = ErrorRecord(
            error_message="429 Too Many Requests",
            status_code=429,
            target_url="https://example.com/api",
        )
        
        analysis = analyzer.analyze(record)
        if not analysis.retry_recommended:
            # 別のアプローチを試す
    """
    
    # エラーパターン（正規表現 -> カテゴリ）
    ERROR_PATTERNS = [
        (re.compile(r"timeout|timed?\s*out"), ErrorCategory.NETWORK_TIMEOUT),
        (re.compile(r"connection\s*(refused|reset|closed)"), ErrorCategory.CONNECTION_REFUSED),
        (re.compile(r"dns|name\s*resolution|resolve"), ErrorCategory.DNS_FAILURE),
        (re.compile(r"ssl|certificate|tls|handshake"), ErrorCategory.SSL_ERROR),
        (re.compile(r"401|unauthorized|auth.*fail|login\s*fail"), ErrorCategory.AUTH_FAILURE),
        (re.compile(r"403|forbidden|permission|access\s*denied"), ErrorCategory.PERMISSION_DENIED),
        (re.compile(r"session.*expir|token.*expir|invalid.*session"), ErrorCategory.SESSION_EXPIRED),
        (re.compile(r"429|rate\s*limit|too\s*many|throttl"), ErrorCategory.RATE_LIMITED),
        (re.compile(r"waf|firewall|blocked.*request|security\s*block"), ErrorCategory.WAF_BLOCKED),
        (re.compile(r"ip.*block|banned|blacklist"), ErrorCategory.IP_BLOCKED),
        (re.compile(r"400|bad\s*request|invalid.*param|validation"), ErrorCategory.VALIDATION_ERROR),
        (re.compile(r"404|not\s*found|does\s*not\s*exist"), ErrorCategory.NOT_FOUND),
        (re.compile(r"5\d\d|server\s*error|internal\s*error"), ErrorCategory.SERVER_ERROR),
        (re.compile(r"payload.*invalid|encoding\s*error|malformed"), ErrorCategory.PAYLOAD_ERROR),
        (re.compile(r"parse.*error|json.*error|xml.*error"), ErrorCategory.PARSE_ERROR),
    ]
    
    # カテゴリごとの対処法
    MITIGATIONS = {
        ErrorCategory.NETWORK_TIMEOUT: ("Increase timeout or check connectivity", True, 5.0),
        ErrorCategory.CONNECTION_REFUSED: ("Target may be down, retry later", True, 30.0),
        ErrorCategory.DNS_FAILURE: ("Check DNS or use IP directly", False, None),
        ErrorCategory.SSL_ERROR: ("Check certificate validity or disable verification", False, None),
        ErrorCategory.AUTH_FAILURE: ("Verify credentials and retry", True, None),
        ErrorCategory.PERMISSION_DENIED: ("Requires higher privileges", False, None),
        ErrorCategory.SESSION_EXPIRED: ("Refresh session and retry", True, None),
        ErrorCategory.RATE_LIMITED: ("Wait and use stealth mode", True, 60.0),
        ErrorCategory.WAF_BLOCKED: ("Use evasion techniques or different payload", True, 30.0),
        ErrorCategory.IP_BLOCKED: ("Use proxy or wait for unblock", False, 300.0),
        ErrorCategory.VALIDATION_ERROR: ("Fix request parameters", True, None),
        ErrorCategory.NOT_FOUND: ("Target endpoint may not exist", False, None),
        ErrorCategory.SERVER_ERROR: ("Server issue, retry later", True, 10.0),
        ErrorCategory.PAYLOAD_ERROR: ("Fix payload encoding", True, None),
        ErrorCategory.PARSE_ERROR: ("Response format unexpected", False, None),
        ErrorCategory.UNKNOWN: ("Manual investigation required", False, None),
    }
    
    def __init__(self, repository: Optional[LearningRepository] = None):
        self._history: list[tuple[ErrorRecord, RootCauseAnalysis]] = []
        self.repository = repository or get_learning_repository()
    
    async def analyze_async(self, record: ErrorRecord) -> RootCauseAnalysis:
        """
        エラーを非同期で分析（CPUバウンド処理をオフロード）
        
        Args:
            record: エラー記録
            
        Returns:
            根本原因分析結果
        """
        import asyncio
        return await asyncio.to_thread(self.analyze, record)

    def analyze(self, record: ErrorRecord) -> RootCauseAnalysis:
        """
        エラーを分析
        
        Args:
            record: エラー記録
            
        Returns:
            根本原因分析結果
        """
        # カテゴリ分類
        category = self._categorize(record)
        record.category = category
        
        # 過去の知見の検索
        knowledge = self._lookup_error_knowledge(record, category)
        
        # 根本原因推定
        analysis = self._infer_root_cause(record, category, knowledge)
        
        # リポジトリに知識を蓄積
        self._store_error_knowledge(record, analysis)
        
        # 履歴に追加
        self._history.append((record, analysis))
        
        logger.debug(
            "Error analyzed: %s -> %s (confidence: %.2f)",
            category.value,
            analysis.likely_cause[:50],
            analysis.confidence,
        )
        
        return analysis
    
    def _categorize(self, record: ErrorRecord) -> ErrorCategory:
        """エラーをカテゴリ分類"""
        # ステータスコードから判定
        if record.status_code:
            if record.status_code == 429:
                return ErrorCategory.RATE_LIMITED
            elif record.status_code == 401:
                return ErrorCategory.AUTH_FAILURE
            elif record.status_code == 403:
                return ErrorCategory.PERMISSION_DENIED
            elif record.status_code == 404:
                return ErrorCategory.NOT_FOUND
            elif 500 <= record.status_code < 600:
                return ErrorCategory.SERVER_ERROR
        
        # エラーメッセージからパターンマッチ
        msg_lower = record.error_message.lower()
        for pattern, category in self.ERROR_PATTERNS:
            if re.search(pattern, msg_lower):
                return category
        
        return ErrorCategory.UNKNOWN
    
    def _infer_root_cause(
        self,
        record: ErrorRecord,
        category: ErrorCategory,
        knowledge: Optional[dict] = None,
    ) -> RootCauseAnalysis:
        """根本原因を推定"""
        mitigation_info = self.MITIGATIONS.get(
            category,
            ("Unknown error, investigate manually", False, None)
        )
        
        mitigation, retry, wait = mitigation_info
        likely_cause = self._generate_cause_description(record, category)
        confidence = 0.7
        
        # 過去の知見があれば上書き・強化
        if knowledge:
            likely_cause = f"{likely_cause} (Confirmed by history: {knowledge.get('likely_cause', '')})"
            mitigation = knowledge.get('mitigation', mitigation)
            confidence = min(confidence + 0.1, 0.98)
        if category == ErrorCategory.UNKNOWN:
            confidence = 0.3
        elif record.status_code:
            confidence = 0.85  # ステータスコードがある場合は信頼度UP
        
        # 履歴から同じカテゴリの頻度を確認
        same_category_count = sum(
            1 for r, a in self._history
            if r.category == category
        )
        if same_category_count >= 3:
            confidence = min(confidence + 0.1, 0.95)
        
        return RootCauseAnalysis(
            category=category,
            likely_cause=likely_cause,
            confidence=confidence,
            mitigation=mitigation,
            retry_recommended=retry,
            wait_seconds=wait,
        )
    
    def _lookup_error_knowledge(self, record: ErrorRecord, category: ErrorCategory) -> Optional[dict]:
        """過去のエラー知見を検索"""
        if record.target_url:
            key = f"{category.value}:{record.target_url}"
            return self.repository.retrieve("error_knowledge", key)
        return None

    def _store_error_knowledge(self, record: ErrorRecord, analysis: RootCauseAnalysis) -> None:
        """将来のためにエラー知見を保存"""
        if record.target_url and analysis.confidence > 0.8:
            masker = get_pii_masker()
            key = f"{analysis.category.value}:{record.target_url}"
            
            # データをマスク
            data = analysis.to_dict()
            data["likely_cause"] = masker.mask(data["likely_cause"]).masked
            data["mitigation"] = masker.mask(data["mitigation"]).masked
            
            self.repository.store("error_knowledge", key, data)
    
    def _generate_cause_description(
        self,
        record: ErrorRecord,
        category: ErrorCategory,
    ) -> str:
        """原因の説明を生成"""
        descriptions = {
            ErrorCategory.NETWORK_TIMEOUT: "Request timed out - target slow or unreachable",
            ErrorCategory.CONNECTION_REFUSED: "Target actively refused connection",
            ErrorCategory.DNS_FAILURE: "DNS resolution failed for target domain",
            ErrorCategory.SSL_ERROR: "SSL/TLS handshake failed",
            ErrorCategory.AUTH_FAILURE: "Authentication credentials invalid or expired",
            ErrorCategory.PERMISSION_DENIED: "Authenticated but lacks required permissions",
            ErrorCategory.SESSION_EXPIRED: "Session token expired, needs refresh",
            ErrorCategory.RATE_LIMITED: "Request rate exceeded target's limits",
            ErrorCategory.WAF_BLOCKED: "Request blocked by WAF/security filter",
            ErrorCategory.IP_BLOCKED: "Client IP address has been blocked",
            ErrorCategory.VALIDATION_ERROR: "Request parameters failed validation",
            ErrorCategory.NOT_FOUND: "Requested resource does not exist",
            ErrorCategory.SERVER_ERROR: "Server encountered an internal error",
            ErrorCategory.PAYLOAD_ERROR: "Payload encoding or format invalid",
            ErrorCategory.PARSE_ERROR: "Response could not be parsed",
            ErrorCategory.UNKNOWN: f"Unknown error: {record.error_message[:100]}",
        }
        return descriptions.get(category, f"Error: {record.error_message[:100]}")
    
    def get_recurring_errors(self, min_count: int = 3) -> list[tuple[ErrorCategory, int]]:
        """
        頻発するエラーカテゴリを取得
        
        Args:
            min_count: 最小出現回数
            
        Returns:
            (カテゴリ, 出現回数) のリスト
        """
        counts = {}
        for record, _ in self._history:
            counts[record.category] = counts.get(record.category, 0) + 1
        
        recurring = [
            (cat, count) for cat, count in counts.items()
            if count >= min_count
        ]
        return sorted(recurring, key=lambda x: x[1], reverse=True)
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        category_counts = {}
        for category in ErrorCategory:
            category_counts[category.value] = sum(
                1 for r, _ in self._history if r.category == category
            )
        
        return {
            "total_errors": len(self._history),
            "category_counts": category_counts,
            "recurring_errors": self.get_recurring_errors(),
        }


# シングルトンインスタンス
_default_analyzer: Optional[ErrorAnalyzer] = None


def get_error_analyzer() -> ErrorAnalyzer:
    """デフォルトのErrorAnalyzerインスタンスを取得"""
    global _default_analyzer
    if _default_analyzer is None:
        _default_analyzer = ErrorAnalyzer()
    return _default_analyzer
