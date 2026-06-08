"""
Enhanced Ethics Guard - 強化版ガードレール

全リクエスト強制検証、スコープ厳格化
"""

import logging
import re
from typing import List, Set, Optional, Dict, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class BlockReason(Enum):
    """ブロック理由"""
    OUT_OF_SCOPE = "out_of_scope"
    DESTRUCTIVE_PAYLOAD = "destructive_payload"
    RATE_LIMIT = "rate_limit"
    DANGEROUS_FILE = "dangerous_file"
    DNS_REBINDING = "dns_rebinding"
    CUMULATIVE_LIMIT = "cumulative_limit"
    THIRD_PARTY_BLOCK = "third_party_block"


@dataclass
class ScopeConfig:
    """スコープ設定"""
    in_scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=lambda: [80, 443, 8080, 8443])
    max_requests_per_minute: int = 60
    max_cumulative_requests: int = 10000
    block_third_party: bool = True


@dataclass
class ValidationResult:
    """検証結果"""
    allowed: bool
    reason: Optional[BlockReason] = None
    message: str = ""
    url: str = ""


class EnhancedEthicsGuard:
    """
    強化版ガードレール
    
    機能:
    - 全リクエスト強制検証
    - スコープ厳格チェック
    - DNS リバインディング防止
    - サードパーティAPI ブロック
    - 破壊的ペイロード検出
    - 危険ファイルアップロード防止
    - 累積リクエスト上限
    - レート制限
    
    ⚠️ バイパス不可
    """
    
    # 破壊的ペイロードパターン
    DESTRUCTIVE_PATTERNS = [
        # SQL
        r"DROP\s+TABLE", r"DELETE\s+FROM", r"TRUNCATE\s+TABLE",
        r"UPDATE\s+\w+\s+SET", r"INSERT\s+INTO",
        # OS
        r"rm\s+-rf", r"rmdir", r"del\s+/", r"format\s+",
        r"shutdown", r"reboot", r"init\s+0",
        # その他
        r">\s*/etc/", r"chmod\s+777",
    ]
    
    # 危険なファイル拡張子
    DANGEROUS_EXTENSIONS = [
        ".php", ".phtml", ".php3", ".php4", ".php5",
        ".asp", ".aspx", ".jsp", ".jspx",
        ".exe", ".dll", ".bat", ".cmd", ".sh",
        ".py", ".rb", ".pl",
    ]
    
    # 内部IP範囲（DNS リバインディング対策）
    INTERNAL_IP_PATTERNS = [
        r"^127\.", r"^10\.", r"^172\.(1[6-9]|2[0-9]|3[01])\.",
        r"^192\.168\.", r"^169\.254\.", r"^0\.",
        r"localhost", r"^::1$", r"^fc00:", r"^fe80:",
    ]
    
    def __init__(self, scope_config: ScopeConfig = None):
        self.scope = scope_config or ScopeConfig()
        self.request_count = 0
        self.request_timestamps: List[datetime] = []
        self.blocked_requests: List[ValidationResult] = []
        self._enabled = True  # 常にTrue、無効化不可
    
    @property
    def enabled(self) -> bool:
        """ガードレールは常に有効"""
        return True
    
    @enabled.setter
    def enabled(self, value: bool):
        """無効化を試みてもログ警告のみ、無効化しない"""
        if not value:
            logger.warning("Ethics Guard cannot be disabled!")
    
    def validate_request(
        self,
        url: str,
        method: str = "GET",
        payload: str = None,
        headers: Dict = None
    ) -> ValidationResult:
        """
        リクエストを検証（全リクエスト必須）
        
        Args:
            url: リクエスト先URL
            method: HTTPメソッド
            payload: リクエストボディ
            headers: リクエストヘッダー
        
        Returns:
            ValidationResult
        """
        # 1. スコープチェック
        scope_result = self._check_scope(url)
        if not scope_result.allowed:
            self._log_block(scope_result)
            return scope_result
        
        # 2. DNS リバインディングチェック
        dns_result = self._check_dns_rebinding(url)
        if not dns_result.allowed:
            self._log_block(dns_result)
            return dns_result
        
        # 3. サードパーティチェック
        if self.scope.block_third_party:
            third_party_result = self._check_third_party(url)
            if not third_party_result.allowed:
                self._log_block(third_party_result)
                return third_party_result
        
        # 4. 破壊的ペイロードチェック
        if payload:
            payload_result = self._check_destructive_payload(payload)
            if not payload_result.allowed:
                self._log_block(payload_result)
                return payload_result
        
        # 5. レート制限チェック
        rate_result = self._check_rate_limit()
        if not rate_result.allowed:
            self._log_block(rate_result)
            return rate_result
        
        # 6. 累積リクエスト上限チェック
        cumulative_result = self._check_cumulative_limit()
        if not cumulative_result.allowed:
            self._log_block(cumulative_result)
            return cumulative_result
        
        # カウント更新
        self.request_count += 1
        self.request_timestamps.append(datetime.now())
        
        return ValidationResult(allowed=True, url=url)
    
    def validate_file_upload(self, filename: str) -> ValidationResult:
        """ファイルアップロード検証"""
        ext = "." + filename.split(".")[-1].lower() if "." in filename else ""
        
        if ext in self.DANGEROUS_EXTENSIONS:
            result = ValidationResult(
                allowed=False,
                reason=BlockReason.DANGEROUS_FILE,
                message=f"Dangerous file extension: {ext}",
                url=filename
            )
            self._log_block(result)
            return result
        
        return ValidationResult(allowed=True, url=filename)
    
    def validate_redirect(self, original_url: str, redirect_url: str) -> ValidationResult:
        """リダイレクト先もスコープ検証"""
        return self._check_scope(redirect_url)
    
    def _check_scope(self, url: str) -> ValidationResult:
        """スコープチェック"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # out_of_scopeチェック（優先）
        for pattern in self.scope.out_of_scope:
            if self._match_pattern(domain, pattern):
                return ValidationResult(
                    allowed=False,
                    reason=BlockReason.OUT_OF_SCOPE,
                    message=f"Domain {domain} is explicitly out of scope",
                    url=url
                )
        
        # in_scopeチェック
        if self.scope.in_scope:
            in_scope = False
            for pattern in self.scope.in_scope:
                if self._match_pattern(domain, pattern):
                    in_scope = True
                    break
            
            if not in_scope:
                return ValidationResult(
                    allowed=False,
                    reason=BlockReason.OUT_OF_SCOPE,
                    message=f"Domain {domain} is not in scope",
                    url=url
                )
        
        # ポートチェック
        port = parsed.port
        if port and port not in self.scope.allowed_ports:
            return ValidationResult(
                allowed=False,
                reason=BlockReason.OUT_OF_SCOPE,
                message=f"Port {port} is not allowed",
                url=url
            )
        
        return ValidationResult(allowed=True, url=url)
    
    def _check_dns_rebinding(self, url: str) -> ValidationResult:
        """DNS リバインディング防止"""
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0].lower()
        
        for pattern in self.INTERNAL_IP_PATTERNS:
            if re.match(pattern, host, re.I):
                return ValidationResult(
                    allowed=False,
                    reason=BlockReason.DNS_REBINDING,
                    message=f"Internal IP/hostname blocked: {host}",
                    url=url
                )
        
        return ValidationResult(allowed=True, url=url)
    
    def _check_third_party(self, url: str) -> ValidationResult:
        """サードパーティAPIブロック"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # スコープ内ドメインか確認
        for pattern in self.scope.in_scope:
            base_domain = pattern.replace("*.", "").replace("*", "")
            if base_domain in domain:
                return ValidationResult(allowed=True, url=url)
        
        return ValidationResult(
            allowed=False,
            reason=BlockReason.THIRD_PARTY_BLOCK,
            message=f"Third-party domain blocked: {domain}",
            url=url
        )
    
    def _check_destructive_payload(self, payload: str) -> ValidationResult:
        """破壊的ペイロード検出"""
        for pattern in self.DESTRUCTIVE_PATTERNS:
            if re.search(pattern, payload, re.I):
                return ValidationResult(
                    allowed=False,
                    reason=BlockReason.DESTRUCTIVE_PAYLOAD,
                    message=f"Destructive payload detected: {pattern}",
                    url=""
                )
        
        return ValidationResult(allowed=True)
    
    def _check_rate_limit(self) -> ValidationResult:
        """レート制限"""
        now = datetime.now()
        one_minute_ago = now.timestamp() - 60
        
        # 直近1分のリクエスト数
        recent = [t for t in self.request_timestamps if t.timestamp() > one_minute_ago]
        
        if len(recent) >= self.scope.max_requests_per_minute:
            return ValidationResult(
                allowed=False,
                reason=BlockReason.RATE_LIMIT,
                message=f"Rate limit exceeded: {len(recent)}/{self.scope.max_requests_per_minute} per minute",
            )
        
        return ValidationResult(allowed=True)
    
    def _check_cumulative_limit(self) -> ValidationResult:
        """累積リクエスト上限"""
        if self.request_count >= self.scope.max_cumulative_requests:
            return ValidationResult(
                allowed=False,
                reason=BlockReason.CUMULATIVE_LIMIT,
                message=f"Cumulative limit exceeded: {self.request_count}/{self.scope.max_cumulative_requests}",
            )
        
        return ValidationResult(allowed=True)
    
    def _match_pattern(self, domain: str, pattern: str) -> bool:
        """ワイルドカードパターンマッチ"""
        if pattern.startswith("*."):
            # *.example.com → example.comとそのサブドメイン
            base = pattern[2:]
            return domain == base or domain.endswith("." + base)
        return domain == pattern
    
    def _log_block(self, result: ValidationResult):
        """ブロックをログ記録"""
        logger.warning(
            "Request BLOCKED: %s - %s",
            result.reason.value if result.reason else "unknown",
            result.message
        )
        self.blocked_requests.append(result)
    
    def get_stats(self) -> Dict:
        """統計"""
        by_reason = {}
        for r in self.blocked_requests:
            if r.reason:
                by_reason.setdefault(r.reason.value, 0)
                by_reason[r.reason.value] += 1
        
        return {
            "total_requests": self.request_count,
            "blocked_requests": len(self.blocked_requests),
            "by_reason": by_reason,
        }
    
    def load_scope_from_file(self, path: str):
        """スコープファイルからロード"""
        import yaml
        with open(path) as f:
            data = yaml.safe_load(f)
        
        self.scope.in_scope = data.get("in_scope", [])
        self.scope.out_of_scope = data.get("out_of_scope", [])
        logger.info("Loaded scope: %d in, %d out", 
                   len(self.scope.in_scope), len(self.scope.out_of_scope))


def create_ethics_guard(scope_config: ScopeConfig = None) -> EnhancedEthicsGuard:
    """EnhancedEthicsGuard作成ヘルパー"""
    return EnhancedEthicsGuard(scope_config)
