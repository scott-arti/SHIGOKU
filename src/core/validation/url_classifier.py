"""
URL Classifier - Juice Shop用URL分類モジュール

計画書4.1分類タクソノミー実装:
- auth, admin, product_search, basket_order, feedback_review
- file_exposure_upload, api_data, client_route_dom, realtime, meta_observability
"""
import re
from dataclasses import dataclass, field
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urlparse


# タクソノミー定義（計画書4.1準拠）
TAXONOMY_RULES = {
    "auth": {
        "path_patterns": [
            r"/rest/user/login",
            r"/rest/user/register",
            r"/rest/user/reset-password",
            r"/rest/user/verify-2fa",
            r"/rest/user/token",
            r"/#/login",
            r"/#/register",
            r"/#/forgot-password",
        ],
        "methods": ["POST", "GET"],
        "description": "login, register, forgot-password, token/2FA"
    },
    "admin": {
        "path_patterns": [
            r"/rest/admin/.*",
            r"/#/admin",
        ],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "description": "管理画面遷移、admin API"
    },
    "product_search": {
        "path_patterns": [
            r"/rest/products/search",
            r"/api/products/search",
            r"/#/search",
        ],
        "methods": ["GET"],
        "description": "検索クエリ"
    },
    "basket_order": {
        "path_patterns": [
            r"/rest/basket",
            r"/api/basket",
            r"/api/orders",
            r"/#/basket",
            r"/#/checkout",
            r"/#/order",
            r"/api/coupon",
        ],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "description": "basket, checkout, order, coupon"
    },
    "feedback_review": {
        "path_patterns": [
            r"/api/products/\d+/reviews",
            r"/api/feedback",
            r"/#/contact",
        ],
        "methods": ["GET", "POST"],
        "description": "feedback, review, complaint"
    },
    "file_exposure_upload": {
        "path_patterns": [
            r"/ftp/.*",
            r"/api/file-upload",
            r"/api/file-download",
            r"/assets.*backup",
            r"/assets.*\.bak",
        ],
        "methods": ["GET", "POST", "PUT"],
        "description": "upload, download, backup"
    },
    "api_data": {
        "path_patterns": [
            r"/api/.*",
            r"/rest/.*",
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
        "description": "データ取得/更新系API"
    },
    "client_route_dom": {
        "path_patterns": [
            r"/#/.*",
            r".*#/.*",  # URLフラグメントとしてのSPAルート
            r"/main\.js",
            r"/chunk-.*\.js",
            r"/runtime.*\.js",
        ],
        "methods": ["GET"],
        "description": "フロントルート、DOMイベント、JSアセット"
    },
    "realtime": {
        "path_patterns": [
            r"/socket\.io/.*",
            r"/ws/.*",
            r"/websocket.*",
        ],
        "methods": ["GET", "POST", "WS"],
        "description": "websocket/long-poll"
    },
    "meta_observability": {
        "path_patterns": [
            r"/api/Challenges",
            r"/metrics",
            r"/health",
            r"/logs",
        ],
        "methods": ["GET"],
        "description": "metrics, logs, health, configuration"
    }
}


@dataclass
class ClassificationResult:
    """分類結果"""
    url: str
    tags: Set[str] = field(default_factory=set)
    primary_tag: Optional[str] = None
    confidence: float = 0.0
    matched_rules: List[str] = field(default_factory=list)
    method: Optional[str] = None


class URLClassifier:
    """
    URL分類器
    
    計画書4.1分類タクソノミーに基づき、URLを10系統に分類する。
    1 URLは複数タグを持つことが可能（api_data + authなど）。
    """
    
    def __init__(self, taxonomy_rules: Optional[Dict] = None):
        self.taxonomy = taxonomy_rules or TAXONOMY_RULES
        self._compile_patterns()
    
    def _compile_patterns(self):
        """正規表現パターンをコンパイル"""
        self._compiled = {}
        for tag, config in self.taxonomy.items():
            self._compiled[tag] = [
                re.compile(pattern) for pattern in config["path_patterns"]
            ]
    
    def classify(self, url: str, method: Optional[str] = None) -> ClassificationResult:
        """
        URLを分類
        
        Args:
            url: 分類対象URL
            method: HTTPメソッド（オプション）
            
        Returns:
            ClassificationResult: 分類結果
        """
        result = ClassificationResult(url=url, method=method)
        parsed = urlparse(url)
        path = parsed.path
        fragment = parsed.fragment
        
        # マッチング対象: パス + フラグメント（/#/形式のSPAルート対応）
        match_targets = [path]
        if fragment:
            match_targets.append(f"#/{fragment}")
            match_targets.append(url)  # 完全URLもマッチング対象に
        
        # 各タグのパターンマッチング
        for tag, config in self.taxonomy.items():
            compiled_patterns = self._compiled[tag]
            matched = False
            
            for pattern in compiled_patterns:
                # 複数のマッチング対象をチェック
                for target in match_targets:
                    if pattern.match(target):
                        # メソッドチェック（指定がある場合）
                        if method and config["methods"]:
                            if method.upper() not in config["methods"] and "WS" not in config["methods"]:
                                continue
                        
                        result.tags.add(tag)
                        result.matched_rules.append(f"{tag}:{pattern.pattern}")
                        matched = True
                        break
                if matched:
                    break
        
        # プライマリタグ決定（最長一致優先）
        if result.tags:
            # 優先順位: admin > auth > specific > general
            priority_order = [
                "admin", "auth", "basket_order", "product_search",
                "feedback_review", "file_exposure_upload", "realtime",
                "meta_observability", "api_data", "client_route_dom"
            ]
            for priority_tag in priority_order:
                if priority_tag in result.tags:
                    result.primary_tag = priority_tag
                    break
            
            # 信頼度計算
            result.confidence = min(1.0, len(result.tags) * 0.3 + 0.4)
        
        return result
    
    def classify_batch(self, urls: List[str], methods: Optional[List[str]] = None) -> List[ClassificationResult]:
        """
        複数URLのバッチ分類
        
        Args:
            urls: URLリスト
            methods: メソッドリスト（オプション、urlsと同じ長さ）
            
        Returns:
            List[ClassificationResult]: 分類結果リスト
        """
        results = []
        for i, url in enumerate(urls):
            method = methods[i] if methods and i < len(methods) else None
            results.append(self.classify(url, method))
        return results
    
    def is_uncategorized(self, result: ClassificationResult) -> bool:
        """未分類チェック"""
        return len(result.tags) == 0 or result.primary_tag is None
    
    def get_uncategorized_rate(self, results: List[ClassificationResult]) -> float:
        """未分類率計算"""
        if not results:
            return 0.0
        uncategorized = sum(1 for r in results if self.is_uncategorized(r))
        return uncategorized / len(results)


# グローバルインスタンス
_default_classifier: Optional[URLClassifier] = None


def get_classifier() -> URLClassifier:
    """デフォルト分類器取得"""
    global _default_classifier
    if _default_classifier is None:
        _default_classifier = URLClassifier()
    return _default_classifier


def classify_url(url: str, method: Optional[str] = None) -> ClassificationResult:
    """グローバル関数: single URL分類"""
    return get_classifier().classify(url, method)


def classify_urls(urls: List[str], methods: Optional[List[str]] = None) -> List[ClassificationResult]:
    """グローバル関数: batch分類"""
    return get_classifier().classify_batch(urls, methods)
