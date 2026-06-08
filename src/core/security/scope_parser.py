"""
ScopeParser: プログラムスコープの解析とEthicsGuard連携

HackerOne/Bugcrowdなどのバグバウンティプログラムのスコープ定義を解析し、
EthicsGuardに設定することで安全な自動攻撃を可能にする。
"""

import re
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

import yaml

from src.core.security.ethics_guard import (
    ScopeDefinition,
    EthicsGuard,
    get_ethics_guard,
)


@dataclass
class ScopeAsset:
    """スコープ内のアセット"""
    asset_type: str  # "domain", "ip", "url", "wildcard"
    identifier: str  # "*.example.com", "192.168.1.0/24", etc.
    in_scope: bool = True
    notes: str = ""


class ScopeParser:
    """
    プログラムスコープを解析し、EthicsGuard用のScopeDefinitionを生成。
    
    対応フォーマット:
    - YAML: 構造化されたスコープ定義
    - テキスト: HackerOne/Bugcrowdの平文スコープ
    """
    
    # ドメインパターン
    DOMAIN_PATTERN = re.compile(
        r"(?:https?://)?(?:\*\.)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)"
    )
    
    # IPアドレスパターン
    IP_PATTERN = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"
    )
    
    # Out-of-Scopeを示すキーワード
    OUT_OF_SCOPE_KEYWORDS = [
        "out of scope",
        "out-of-scope",
        "not in scope",
        "excluded",
        "do not test",
        "off limits",
    ]
    
    def __init__(self, ethics_guard: Optional[EthicsGuard] = None):
        self._guard = ethics_guard or get_ethics_guard()
        self._current_scope: Optional[ScopeDefinition] = None
    
    @property
    def current_scope(self) -> Optional[ScopeDefinition]:
        return self._current_scope
    
    def parse_from_yaml(self, yaml_path: str) -> ScopeDefinition:
        """
        YAMLファイルからスコープを読み込み
        
        Expected format:
        ```yaml
        program_name: "Example Program"
        max_requests_per_minute: 60
        
        in_scope:
          domains:
            - "*.example.com"
            - "api.example.com"
          ips:
            - "192.168.1.0/24"
        
        out_of_scope:
          domains:
            - "admin.example.com"
            - "*.staging.example.com"
          paths:
            - "/logout"
            - "/admin"
        ```
        """
        path = Path(yaml_path)
        if not path.exists():
            raise FileNotFoundError(f"Scope file not found: {yaml_path}")
        
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        
        if not data:
            raise ValueError("Empty or invalid YAML file")
        
        scope = ScopeDefinition(
            program_name=data.get("program_name", "Unknown"),
            max_requests_per_minute=data.get("max_requests_per_minute", 60),
            allow_post_exploit=data.get("allow_post_exploit", False)
        )
        
        # In-Scope
        in_scope = data.get("in_scope", {})
        scope.in_scope_domains = in_scope.get("domains", [])
        scope.in_scope_ips = in_scope.get("ips", [])
        
        # Out-of-Scope
        out_of_scope = data.get("out_of_scope", {})
        scope.out_of_scope_domains = out_of_scope.get("domains", [])
        scope.out_of_scope_paths = out_of_scope.get("paths", [])
        
        self._current_scope = scope
        return scope
    
    def parse_from_text(self, scope_text: str, program_name: str = "Parsed Program") -> ScopeDefinition:
        """
        テキスト形式のスコープを解析
        
        HackerOne/Bugcrowdのスコープページからコピペしたテキストを解析。
        「Out of Scope」セクションを自動検出。
        """
        lines = scope_text.strip().split("\n")
        
        in_scope_domains: list[str] = []
        in_scope_ips: list[str] = []
        out_of_scope_domains: list[str] = []
        out_of_scope_paths: list[str] = []
        allow_post_exploit = False
        
        is_out_of_scope_section = False
        
        for line in lines:
            line_lower = line.lower().strip()
            
            # Check for post-exploitation approval
            if "allow_post_exploit" in line_lower or "post-exploitation allowed" in line_lower or "post-exploitation is allowed" in line_lower:
                allow_post_exploit = True
                
            # Out-of-Scopeセクションの開始を検出
            if any(kw in line_lower for kw in self.OUT_OF_SCOPE_KEYWORDS):
                is_out_of_scope_section = True
                continue
            
            # In-Scopeセクションの開始を検出
            if "in scope" in line_lower or "in-scope" in line_lower:
                is_out_of_scope_section = False
                continue
            
            # ドメインを抽出
            domain_matches = self.DOMAIN_PATTERN.findall(line)
            for domain in domain_matches:
                # ワイルドカードを復元
                if "*." in line and domain in line:
                    domain = f"*.{domain}"
                
                if is_out_of_scope_section:
                    out_of_scope_domains.append(domain)
                else:
                    in_scope_domains.append(domain)
            
            # IPアドレスを抽出
            ip_matches = self.IP_PATTERN.findall(line)
            for ip in ip_matches:
                if not is_out_of_scope_section:
                    in_scope_ips.append(ip)
            
            # パスを抽出（/で始まる）
            path_match = re.search(r"(/[a-zA-Z0-9/_-]+)", line)
            if path_match and is_out_of_scope_section:
                out_of_scope_paths.append(path_match.group(1))
        
        scope = ScopeDefinition(
            program_name=program_name,
            in_scope_domains=list(set(in_scope_domains)),
            in_scope_ips=list(set(in_scope_ips)),
            out_of_scope_domains=list(set(out_of_scope_domains)),
            out_of_scope_paths=list(set(out_of_scope_paths)),
            allow_post_exploit=allow_post_exploit
        )
        
        self._current_scope = scope
        return scope
    
    def apply_to_ethics_guard(self, scope: Optional[ScopeDefinition] = None) -> None:
        """
        スコープをEthicsGuardに適用
        
        Args:
            scope: 適用するスコープ（Noneの場合は現在のスコープを使用）
        """
        scope = scope or self._current_scope
        if not scope:
            raise ValueError("No scope defined. Call parse_from_yaml or parse_from_text first.")
        
        self._guard.set_scope(scope)
        print(f"✅ Scope applied to EthicsGuard: {scope.program_name}")
        print(f"   In-Scope Domains: {len(scope.in_scope_domains)}")
        print(f"   Out-of-Scope Domains: {len(scope.out_of_scope_domains)}")
        print(f"   Rate Limit: {scope.max_requests_per_minute}/min")
    
    def validate_target(self, url: str) -> tuple[bool, str]:
        """
        ターゲットURLがスコープ内かを検証
        
        Returns:
            (is_valid, reason)
        """
        from src.core.security.ethics_guard import ActionType, ActionResult
        
        result, reason = self._guard.check_action(ActionType.HTTP_REQUEST, url)
        return result == ActionResult.ALLOWED, reason
    
    def get_summary(self) -> str:
        """現在のスコープのサマリーを取得"""
        if not self._current_scope:
            return "No scope defined"
        
        s = self._current_scope
        lines = [
            f"Program: {s.program_name}",
            f"",
            f"In-Scope Domains ({len(s.in_scope_domains)}):",
        ]
        for d in s.in_scope_domains[:10]:
            lines.append(f"  ✓ {d}")
        if len(s.in_scope_domains) > 10:
            lines.append(f"  ... and {len(s.in_scope_domains) - 10} more")
        
        lines.append(f"")
        lines.append(f"Out-of-Scope Domains ({len(s.out_of_scope_domains)}):")
        for d in s.out_of_scope_domains[:5]:
            lines.append(f"  ✗ {d}")
        if len(s.out_of_scope_domains) > 5:
            lines.append(f"  ... and {len(s.out_of_scope_domains) - 5} more")
        
        if s.out_of_scope_paths:
            lines.append(f"")
            lines.append(f"Out-of-Scope Paths ({len(s.out_of_scope_paths)}):")
            for p in s.out_of_scope_paths[:5]:
                lines.append(f"  ✗ {p}")
        
        lines.append(f"")
        lines.append(f"Rate Limit: {s.max_requests_per_minute}/min")
        
        return "\n".join(lines)


# ===== Convenience Functions =====

_parser_instance: Optional[ScopeParser] = None


def get_scope_parser() -> ScopeParser:
    """ScopeParserのシングルトンインスタンスを取得"""
    global _parser_instance
    if _parser_instance is None:
        _parser_instance = ScopeParser()
    return _parser_instance


def load_scope_from_yaml(yaml_path: str) -> ScopeDefinition:
    """
    YAMLからスコープを読み込み、EthicsGuardに自動適用
    """
    parser = get_scope_parser()
    scope = parser.parse_from_yaml(yaml_path)
    parser.apply_to_ethics_guard(scope)
    return scope


def load_scope_from_text(scope_text: str, program_name: str = "Program") -> ScopeDefinition:
    """
    テキストからスコープを解析し、EthicsGuardに自動適用
    """
    parser = get_scope_parser()
    scope = parser.parse_from_text(scope_text, program_name)
    parser.apply_to_ethics_guard(scope)
    return scope
