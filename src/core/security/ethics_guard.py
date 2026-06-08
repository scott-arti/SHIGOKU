"""
EthicsGuard: Realtime Security Guardrail for SHIGOKU

全エージェントのツール実行・通信をフックし、
ScopeParserの定義に基づきリアルタイムで許可/遮断を判定。

バグバウンティにおいて、予期せぬスコープ外通信はアカウントBANや
法的リスクに直結するため、この「門番」が必要。
"""

import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse
from enum import Enum


class ActionType(Enum):
    """監視対象のアクションタイプ"""
    HTTP_REQUEST = "http_request"
    SHELL_COMMAND = "shell_command"
    FILE_WRITE = "file_write"
    DNS_LOOKUP = "dns_lookup"


class ActionResult(Enum):
    """アクション判定結果"""
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    RATE_LIMITED = "rate_limited"
    REQUIRES_APPROVAL = "requires_approval"

@dataclass
class ScopeDefinition:
    """スコープ定義"""
    program_name: str
    in_scope_domains: list[str] = field(default_factory=list)
    in_scope_ips: list[str] = field(default_factory=list)
    out_of_scope_domains: list[str] = field(default_factory=list)
    out_of_scope_paths: list[str] = field(default_factory=list)
    max_requests_per_minute: int = 60
    strict_mode: bool = False
    allow_post_exploit: bool = False



@dataclass
class ActionLog:
    """アクションログエントリ"""
    timestamp: float
    action_type: ActionType
    target: str
    params: dict
    result: ActionResult
    reason: Optional[str] = None


class EthicsGuard:
    """
    Realtime Guardrail - 全エージェントの通信をフックし、
    リアルタイムで許可/遮断を判定する「門番」。
    
    責務:
    1. Scope Check: ターゲットがIn-Scope内か検証
    2. Rate Limit: DoS防止のためのリクエスト制限
    3. Dangerous Action Check: 破壊的操作の検知・警告
    """
    
    # 危険なパターン（シェルコマンド用）
    DANGEROUS_COMMANDS = [
        r"rm\s+-rf",
        r"mkfs\.",
        r"dd\s+if=",
        r">\s*/dev/",
        r"chmod\s+777",
        r"wget.*\|\s*sh",
        r"curl.*\|\s*bash",
    ]
    
    def __init__(self, scope: Optional[ScopeDefinition] = None):
        self.scope = scope
        self.action_log: list[ActionLog] = []
        self._request_timestamps: list[float] = []
        self._enabled = True
    
    def set_scope(self, scope: ScopeDefinition) -> None:
        """スコープ定義を設定"""
        self.scope = scope
    
    def enable(self) -> None:
        """ガードを有効化"""
        self._enabled = True
    
    def disable(self) -> None:
        """ガードを無効化（テスト用のみ）"""
        self._enabled = False
    
    def check_action(
        self,
        action_type: ActionType,
        target: str,
        params: Optional[dict] = None
    ) -> tuple[ActionResult, str]:
        """
        アクションを検証し、許可/遮断を判定。
        
        Args:
            action_type: アクションの種類
            target: ターゲット（URL, IP, コマンド等）
            params: 追加パラメータ
        
        Returns:
            (ActionResult, reason)
        """
        params = params or {}
        
        if not self._enabled:
            return ActionResult.ALLOWED, "Guard disabled"
        
        # 1. Rate Limit Check
        result, reason = self._check_rate_limit()
        if result != ActionResult.ALLOWED:
            self._log_action(action_type, target, params, result, reason)
            return result, reason
        
        # 2. Action-specific checks
        if action_type == ActionType.HTTP_REQUEST:
            result, reason = self._check_http_request(target, params)
        elif action_type == ActionType.SHELL_COMMAND:
            result, reason = self._check_shell_command(target)
        elif action_type == ActionType.DNS_LOOKUP:
            result, reason = self._check_dns_lookup(target)
        else:
            result, reason = ActionResult.ALLOWED, "Action type not restricted"
        
        # 3. Requires Approval Check
        if result == ActionResult.ALLOWED and params.get("requires_approval") is True:
            result = ActionResult.REQUIRES_APPROVAL
            reason = "High-risk action requires user approval"
        
        self._log_action(action_type, target, params, result, reason)
        return result, reason
    
    def check_scope(self, url: str) -> bool:
        """
        スコープチェックの簡易エントリーポイント。
        
        Args:
            url: 検証対象のURL
            
        Returns:
            bool: 許可される場合はTrue
        """
        from .ethics_guard import ActionType, ActionResult
        result, _ = self.check_action(ActionType.HTTP_REQUEST, url)
        return result == ActionResult.ALLOWED
    
    def _check_rate_limit(self) -> tuple[ActionResult, str]:
        """リクエストレート制限をチェック"""
        if not self.scope:
            return ActionResult.ALLOWED, "No scope defined"
        
        now = time.time()
        one_minute_ago = now - 60
        
        # 1分以内のリクエストをカウント
        self._request_timestamps = [
            ts for ts in self._request_timestamps if ts > one_minute_ago
        ]
        
        if len(self._request_timestamps) >= self.scope.max_requests_per_minute:
            return (
                ActionResult.RATE_LIMITED,
                f"Rate limit exceeded: {self.scope.max_requests_per_minute}/min"
            )
        
        self._request_timestamps.append(now)
        return ActionResult.ALLOWED, ""
    
    def _check_http_request(
        self, url: str, params: dict
    ) -> tuple[ActionResult, str]:
        """HTTPリクエストのスコープチェック"""
        if not self.scope:
            return ActionResult.ALLOWED, "No scope defined"
        
        try:
            parsed = urlparse(url)
            domain = (parsed.hostname or "").strip().lower()
            domain_with_port = (parsed.netloc or "").strip().lower()
            path = parsed.path
        except Exception:
            return ActionResult.BLOCKED, "Invalid URL format"
        if not domain and not domain_with_port:
            return ActionResult.BLOCKED, "Invalid URL format"
        domain_candidates = [candidate for candidate in (domain, domain_with_port) if candidate]
        
        # Out-of-Scope ドメインチェック（最優先）
        for out_domain in self.scope.out_of_scope_domains:
            if any(self._domain_matches(candidate, out_domain) for candidate in domain_candidates):
                return (
                    ActionResult.BLOCKED,
                    f"Domain '{domain_with_port or domain}' is explicitly OUT OF SCOPE"
                )
        
        # Out-of-Scope パスチェック
        for out_path in self.scope.out_of_scope_paths:
            if path.startswith(out_path):
                return (
                    ActionResult.BLOCKED,
                    f"Path '{path}' is OUT OF SCOPE"
                )
        
        # In-Scope ドメインチェック
        in_scope = False
        for in_domain in self.scope.in_scope_domains:
            if any(self._domain_matches(candidate, in_domain) for candidate in domain_candidates):
                in_scope = True
                break
        
        if not in_scope and self.scope.in_scope_domains:
            return (
                ActionResult.BLOCKED,
                f"Domain '{domain_with_port or domain}' is NOT in scope. In-scope: {self.scope.in_scope_domains}"
            )
        
        return ActionResult.ALLOWED, "Target is in scope"
    
    def _check_shell_command(self, command: str) -> tuple[ActionResult, str]:
        """シェルコマンドの危険性チェック"""
        for pattern in self.DANGEROUS_COMMANDS:
            if re.search(pattern, command, re.IGNORECASE):
                return (
                    ActionResult.BLOCKED,
                    f"Dangerous command pattern detected: {pattern}"
                )
        
        return ActionResult.ALLOWED, "Command appears safe"
    
    def _check_dns_lookup(self, domain: str) -> tuple[ActionResult, str]:
        """DNSルックアップのスコープチェック"""
        if not self.scope:
            return ActionResult.ALLOWED, "No scope defined"
        
        domain = domain.lower()
        
        # Out-of-Scope チェック
        for out_domain in self.scope.out_of_scope_domains:
            if self._domain_matches(domain, out_domain):
                return (
                    ActionResult.BLOCKED,
                    f"DNS lookup for '{domain}' blocked: OUT OF SCOPE"
                )
        
        return ActionResult.ALLOWED, "DNS lookup allowed"
    
    def _domain_matches(self, target: str, pattern: str) -> bool:
        """
        ドメインパターンマッチング
        
        Examples:
            *.example.com -> sub.example.com (True)
            example.com -> example.com (True)
            *.example.com -> example.com (False)
        """
        pattern = pattern.lower()
        target = target.lower()
        if not pattern or not target:
            return False
        
        if self.scope and self.scope.strict_mode:
            # strict_mode: 完全一致のみ許可（ワイルドカード表現はルートドメインとしてパース）
            base_pattern = pattern[2:] if pattern.startswith("*.") else pattern
            return target == base_pattern

        if pattern.startswith("*."):
            # ワイルドカードパターン
            base = pattern[2:]  # Remove "*."
            return target.endswith(base) and target != base
        else:
            return target == pattern
    
    def _log_action(
        self,
        action_type: ActionType,
        target: str,
        params: dict,
        result: ActionResult,
        reason: str
    ) -> None:
        """アクションをログに記録"""
        log_entry = ActionLog(
            timestamp=time.time(),
            action_type=action_type,
            target=target,
            params=params,
            result=result,
            reason=reason
        )
        self.action_log.append(log_entry)
        
        # 最大1000件を保持
        if len(self.action_log) > 1000:
            self.action_log = self.action_log[-500:]
    
    def get_blocked_actions(self) -> list[ActionLog]:
        """ブロックされたアクションのリストを取得"""
        return [
            log for log in self.action_log
            if log.result in (ActionResult.BLOCKED, ActionResult.RATE_LIMITED)
        ]
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        total = len(self.action_log)
        blocked = len([l for l in self.action_log if l.result == ActionResult.BLOCKED])
        rate_limited = len([l for l in self.action_log if l.result == ActionResult.RATE_LIMITED])
        allowed = total - blocked - rate_limited
        
        return {
            "total_actions": total,
            "allowed": allowed,
            "blocked": blocked,
            "rate_limited": rate_limited,
            "block_rate": blocked / total if total > 0 else 0,
        }


# グローバルインスタンス（シングルトン）
_guard_instance: Optional[EthicsGuard] = None


def get_ethics_guard() -> EthicsGuard:
    """EthicsGuardのシングルトンインスタンスを取得"""
    global _guard_instance
    if _guard_instance is None:
        _guard_instance = EthicsGuard()
    return _guard_instance


def check_before_action(
    action_type: ActionType,
    target: str,
    params: Optional[dict] = None
) -> tuple[bool, str]:
    """
    便利関数: アクション実行前にチェックし、許可されたかを返す
    
    Returns:
        (is_allowed: bool, reason: str)
    """
    guard = get_ethics_guard()
    result, reason = guard.check_action(action_type, target, params)
    return result == ActionResult.ALLOWED, reason
