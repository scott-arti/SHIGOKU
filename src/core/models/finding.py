"""
Finding: 発見した脆弱性を表現する共通モデル

攻撃エージェント（JWTInspector, OAuthDancer等）や
情報収集モジュール（CommitWatcher等）が発見した脆弱性を
統一フォーマットで表現し、Auto-Reporterへ渡す。
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, List, Any


class Severity(Enum):
    """脆弱性の深刻度（CVSS v3.1ベース）"""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"          # 7.0-8.9
    MEDIUM = "medium"      # 4.0-6.9
    LOW = "low"            # 0.1-3.9
    INFO = "info"          # 情報のみ


class VulnType(Enum):
    """脆弱性タイプ"""
    # Authentication
    JWT_ALG_NONE = "jwt_alg_none"
    JWT_RS256_HS256 = "jwt_rs256_hs256"
    JWT_WEAK_SECRET = "jwt_weak_secret"
    JWT_KID_INJECTION = "jwt_kid_injection"
    OAUTH_REDIRECT_BYPASS = "oauth_redirect_bypass"
    OAUTH_PKCE_BYPASS = "oauth_pkce_bypass"
    MFA_BYPASS = "mfa_bypass"
    WEAK_PASSWORD = "weak_password"
    WEAK_SESSION_ID = "weak_session_id"
    SESSION_FIXATION = "session_fixation"
    JWT_NONE_ALG = "jwt_alg_none" # Alias or specific for Ninja
    
    # Information Disclosure
    SECRET_LEAK = "secret_leak"
    API_KEY_EXPOSURE = "api_key_exposure"
    DEBUG_ENABLED = "debug_enabled"
    
    # Injection
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    SSTI = "ssti"
    LFI = "lfi"
    NOSQL_INJECTION = "nosql_injection"
    CRLF_INJECTION = "crlf_injection"
    OPEN_REDIRECT = "open_redirect"
    HOST_HEADER_INJECTION = "host_header_injection"
    DESERIALIZATION = "deserialization"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    SQL_INJECTION = "sqli"
    OS_COMMAND_INJECTION = "os_command_injection"
    
    # Business Logic
    MASS_ASSIGNMENT = "mass_assignment"
    RACE_CONDITION = "race_condition"
    
    # Access Control
    IDOR = "idor"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    
    # Configuration
    MISCONFIGURATION = "misconfiguration"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    GRAPHQL_INTROSPECTION = "graphql_introspection"

    
    # Other
    OTHER = "other"
    RCE = "rce"
    FILE_UPLOAD = "file_upload"


@dataclass
class Evidence:
    """攻撃の証拠"""
    request_method: str = ""
    request_url: str = ""
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    response_status: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""
    screenshot_path: Optional[str] = None
    
    def to_dict(self) -> dict:
        """辞書形式で出力"""
        return {
            "request_method": self.request_method,
            "request_url": self.request_url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "response_status": self.response_status,
            "response_headers": self.response_headers,
            "response_body": self.response_body,
            "screenshot_path": self.screenshot_path,
        }

    def to_markdown(self) -> str:
        """Markdown形式で出力"""
        lines = []
        
        if self.request_url:
            lines.append("### Request")
            lines.append("```http")
            lines.append(f"{self.request_method} {self.request_url}")
            for k, v in self.request_headers.items():
                lines.append(f"{k}: {v}")
            if self.request_body:
                lines.append("")
                lines.append(self.request_body)
            lines.append("```")
        
        if self.response_status:
            lines.append("")
            lines.append("### Response")
            lines.append("```http")
            lines.append(f"HTTP/1.1 {self.response_status}")
            for k, v in self.response_headers.items():
                lines.append(f"{k}: {v}")
            if self.response_body:
                lines.append("")
                # レスポンスボディは最大500文字まで
                body = self.response_body[:500]
                if len(self.response_body) > 500:
                    body += "\n... (truncated)"
                lines.append(body)
            lines.append("```")
        
        return "\n".join(lines)


@dataclass
class Finding:
    """
    発見した脆弱性を表現する統一フォーマット
    
    攻撃エージェントや情報収集モジュールが生成し、
    Auto-Reporterへ渡す。
    """
    # 基本情報
    vuln_type: VulnType
    severity: Severity
    title: str
    description: str
    
    # ターゲット
    target_url: str
    target_program: str = ""
    
    # 証拠
    evidence: Evidence = field(default_factory=Evidence)
    
    # 再現手順
    reproduction_steps: list[str] = field(default_factory=list)
    
    # 影響
    impact: str = ""
    
    # メタデータ
    discovered_at: datetime = field(default_factory=datetime.now)
    source_agent: str = ""  # "jwt_inspector", "commit_watcher", etc.
    confidence: float = 0.0  # 0.0-1.0
    
    # 追加情報
    additional_info: dict = field(default_factory=dict)
    
    # Swarm用フィールド (Implementation Plan準拠)
    is_aggressive: bool = False  # True = ターゲットに影響を与える操作を実行した
    recommended_followup: str = "none"  # "report", "escalate", "none"
    tags: list[str] = field(default_factory=list)  # Swarm ルーティング用タグ (継承用)
    
    # 関連情報
    related_findings: list[str] = field(default_factory=list)  # Finding IDs
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    
    def __post_init__(self):
        """IDを生成し、データの正規化を行う"""
        # evidence が辞書の場合は Evidence オブジェクトに変換
        if isinstance(self.evidence, dict):
            import dataclasses
            valid_fields = {f.name for f in dataclasses.fields(Evidence)}
            evidence_kwargs = {}
            extra_info = {}
            
            for k, v in self.evidence.items():
                if k in valid_fields:
                    evidence_kwargs[k] = v
                else:
                    extra_info[k] = v
            
            if extra_info:
                if not isinstance(self.additional_info, dict):
                    self.additional_info = {}
                self.additional_info.update(extra_info)
                
            self.evidence = Evidence(**evidence_kwargs)
            
        import hashlib
        content = f"{self.vuln_type.value}:{self.target_url}:{self.title}"
        self.id = hashlib.md5(content.encode()).hexdigest()[:12]
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        辞書形式のアクセスを可能にするための get() メソッド。
        レガシーコードとの互換性のため、一部のキーをマッピングする。
        """
        # マッピング（dictキー -> 属性名）
        key_map = {
            "type": "vuln_type",
            "target": "target_url",
            "url": "target_url",
        }
        actual_key = key_map.get(key, key)
        
        if hasattr(self, actual_key):
            val = getattr(self, actual_key)
            # Enum の場合は値を返す
            if isinstance(val, Enum):
                return val.value
            return val
        return default

    def to_dict(self) -> dict:
        """辞書形式で出力 (互換性のためキーを正規化)"""
        return {
            "id": hasattr(self, 'id') and self.id or "unknown",
            "vuln_type": self.vuln_type.value if hasattr(self.vuln_type, 'value') else str(self.vuln_type),
            "type": self.vuln_type.value if hasattr(self.vuln_type, 'value') else str(self.vuln_type), # Alias
            "severity": self.severity.value if hasattr(self.severity, 'value') else str(self.severity),
            "title": self.title,
            "description": self.description,
            "target_url": self.target_url,
            "target": self.target_url, # Alias
            "url": self.target_url,    # Alias
            "target_program": self.target_program,
            "reproduction_steps": self.reproduction_steps,
            "impact": self.impact,
            "discovered_at": self.discovered_at.isoformat() if hasattr(self.discovered_at, 'isoformat') else str(self.discovered_at),
            "source_agent": self.source_agent,
            "confidence": self.confidence,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "severity_icon": self.get_severity_icon(),
            "evidence": self.evidence.to_dict() if hasattr(self.evidence, 'to_dict') else {},
            "additional_info": self.additional_info,
        }
    
    def get_severity_icon(self) -> str:
        """深刻度に応じたアイコンを返す"""
        icons = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFO: "🔵",
        }
        return icons.get(self.severity, "⚪")
