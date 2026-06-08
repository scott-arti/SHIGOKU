"""
RichUrlContext Model

URL に関するリッチなコンテキスト情報を格納するデータモデル。
TaggingFilter の出力として使用され、SwarmDispatcher に渡される。

Implementation Plan Phase 6 準拠
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime


@dataclass
class TagMatch:
    """タグマッチ情報（どのルールで何にマッチしたか）"""
    tag: str               # "id_param", "auth", "admin" 等
    rule_name: str         # "id_param_in_query", "auth_path" 等
    matched_on: str        # "path", "query", "body", "response_body", "headers"
    matched_value: str     # マッチした実際の値 (e.g., "user_id=123")
    param_name: Optional[str] = None  # パラメータ名 (該当する場合: "user_id")
    
    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return {
            "tag": self.tag,
            "rule_name": self.rule_name,
            "matched_on": self.matched_on,
            "matched_value": self.matched_value,
            "param_name": self.param_name,
        }


@dataclass
class SubdomainContext:
    """
    パイプラインで収集済みのサブドメイン情報
    
    pipeline.py の step6_classify() で生成される entry から構築。
    """
    subdomain: str
    status_code: int = 0
    ports: List[int] = field(default_factory=list)
    waf: Optional[str] = None
    tech_stack: List[str] = field(default_factory=list)
    category_tags: List[str] = field(default_factory=list)  # "live_200", "dev_staging" 等
    
    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return {
            "subdomain": self.subdomain,
            "status_code": self.status_code,
            "ports": self.ports,
            "waf": self.waf,
            "tech_stack": self.tech_stack,
            "category_tags": self.category_tags,
        }
    
    @classmethod
    def from_pipeline_entry(cls, entry: Dict[str, Any]) -> "SubdomainContext":
        """pipeline.py の entry から構築"""
        return cls(
            subdomain=entry.get("subdomain", ""),
            status_code=entry.get("status_code", 0),
            ports=entry.get("ports", []),
            waf=entry.get("waf"),
            tech_stack=entry.get("tech", []),
            category_tags=[],  # 後で分類時に付与
        )


@dataclass
class RichUrlContext:
    """
    URL に関するリッチなコンテキスト情報
    
    TaggingFilter が出力し、SwarmDispatcher が利用する。
    サブドメインレベルの情報と URL レベルの情報を統合。
    """
    # 基本情報
    url: str
    method: str = "GET"
    
    # サブドメインコンテキスト（パイプラインから継承）
    subdomain_context: Optional[SubdomainContext] = None
    
    # タグ情報（マッチ詳細付き）
    tags: List[TagMatch] = field(default_factory=list)
    
    # リクエスト詳細
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    
    # レスポンス詳細
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body_preview: str = ""  # 最初の N 文字
    
    # 認証コンテキスト
    auth_context: Dict[str, str] = field(default_factory=dict)  # Cookie, Authorization 等
    
    # メタデータ
    timestamp: Optional[datetime] = None
    source: str = "caido"  # "caido", "katana", "gau"
    
    # 解析データ
    forms: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def tag_names(self) -> List[str]:
        """タグ名のリストを取得（SwarmDispatcher 互換）"""
        return list(set(t.tag for t in self.tags))
    
    @property
    def subdomain(self) -> str:
        """サブドメインを取得"""
        if self.subdomain_context:
            return self.subdomain_context.subdomain
        # URL からサブドメイン抽出
        from urllib.parse import urlparse
        parsed = urlparse(self.url)
        return parsed.hostname or ""
    
    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換（JSON シリアライズ用）"""
        return {
            "url": self.url,
            "method": self.method,
            "subdomain": self.subdomain,
            "subdomain_context": self.subdomain_context.to_dict() if self.subdomain_context else None,
            "tags": [t.to_dict() for t in self.tags],
            "tag_names": self.tag_names,
            "headers": self.headers,
            "body": self.body,
            "response_status": self.response_status,
            "response_headers": self.response_headers,
            "response_body_preview": self.response_body_preview,
            "auth_context": self.auth_context,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source": self.source,
            "forms": self.forms,
        }
    
    @classmethod
    def from_caido_entry(cls, entry: Dict[str, Any], subdomain_context: Optional[SubdomainContext] = None) -> "RichUrlContext":
        """
        CaidoImporter の出力エントリから構築
        
        Args:
            entry: CaidoImporter が出力する標準化エントリ
            subdomain_context: 事前に取得した SubdomainContext (Optional)
        """
        response = entry.get("response", {})
        
        return cls(
            url=entry.get("url", ""),
            method=entry.get("method", "GET"),
            subdomain_context=subdomain_context,
            headers=entry.get("headers", {}),
            body=entry.get("body"),
            response_status=response.get("status", 0),
            response_headers=response.get("headers", {}),
            response_body_preview=response.get("body", "")[:1000],  # 最初の 1000 文字
            auth_context={},  # TaggingFilter が後で設定
            source="caido",
            forms=entry.get("forms", []),
        )
