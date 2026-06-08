"""
App Analyzer - ターゲットアプリ分析

クロール結果からアプリの機能・分類・構成・脆弱性スコアを分析。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
from collections import Counter

logger = logging.getLogger(__name__)


@dataclass
class AppAnalysisResult:
    """アプリ分析結果"""
    target: str
    functions: List[str] = field(default_factory=list)  # 機能リスト
    app_type: str = "不明"  # ECサイト, SPA, API等
    tech_stack: Dict[str, str] = field(default_factory=dict)  # 技術スタック
    architecture: Dict[str, List[str]] = field(default_factory=dict)  # 構成
    vuln_score: float = 50.0  # 脆弱性スコア 0-100
    vuln_reasons: List[str] = field(default_factory=list)  # 評価理由


class AppAnalyzer:
    """
    ターゲットアプリ分析器
    
    出力:
    - ターゲットアプリの機能リスト
    - アプリ分類 (ECサイト, SPA等)
    - システム構成図 (Mermaid形式)
    - 脆弱性スコアと評価理由
    """
    
    # 機能検出パターン
    FUNCTION_PATTERNS = {
        "認証・ログイン": [re.compile(p) for p in [r"/login", r"/signin", r"/auth", r"/oauth"]],
        "ユーザー登録": [re.compile(p) for p in [r"/register", r"/signup", r"/join"]],
        "パスワードリセット": [re.compile(p) for p in [r"/reset", r"/forgot", r"/password"]],
        "ユーザープロフィール": [re.compile(p) for p in [r"/profile", r"/account", r"/settings", r"/user/\d+"]],
        "検索機能": [re.compile(p) for p in [r"/search", r"\?q=", r"\?query=", r"\?keyword="]],
        "商品・カタログ": [re.compile(p) for p in [r"/product", r"/item", r"/catalog", r"/shop"]],
        "カート・決済": [re.compile(p) for p in [r"/cart", r"/checkout", r"/payment", r"/order"]],
        "コメント・レビュー": [re.compile(p) for p in [r"/comment", r"/review", r"/feedback"]],
        "メッセージ・通知": [re.compile(p) for p in [r"/message", r"/inbox", r"/notification"]],
        "ファイルアップロード": [re.compile(p) for p in [r"/upload", r"/file", r"/attachment"]],
        "管理画面": [re.compile(p) for p in [r"/admin", r"/dashboard", r"/manage", r"/cms"]],
        "API": [re.compile(p) for p in [r"/api/", r"/v1/", r"/v2/", r"/graphql"]],
        "WebSocket": [re.compile(p) for p in [r"/ws", r"/socket", r"/realtime"]],
    }
    
    # アプリ分類パターン
    APP_TYPE_PATTERNS = {
        "ECサイト": ["cart", "checkout", "product", "shop", "payment"],
        "SPA": ["bundle.js", "chunk", "react", "vue", "angular"],
        "API専用": ["/api/", "/v1/", "graphql", "swagger", "openapi"],
        "CMS": ["wp-", "wordpress", "drupal", "joomla", "admin"],
        "SNS・コミュニティ": ["profile", "message", "follow", "feed"],
        "SaaS": ["dashboard", "subscription", "billing", "workspace"],
        "ブログ": ["post", "article", "blog", "category", "tag"],
    }
    
    # 脆弱性評価要素
    VULN_FACTORS = {
        "positive": {  # 脆弱性が見つかりやすい
            "古いjQuery": 15,
            "WAFなし": 10,
            "入力フォーム多数": 10,
            "ファイルアップロード": 15,
            "API露出": 10,
            "GraphQL": 10,
            "管理画面露出": 15,
        },
        "negative": {  # 堅牢な兆候
            "CSP設定あり": -10,
            "最新フレームワーク": -10,
            "CloudFlare/WAF": -15,
            "認証必須API": -10,
        }
    }
    
    async def analyze_async(
        self,
        target: str,
        urls: List[str],
        tech_stack: Dict[str, str] = None
    ) -> AppAnalysisResult:
        """
        アプリを非同期で分析（CPUバウンド処理をオフロード）
        
        Args:
            target: ターゲットURL
            urls: クロールで取得したURL一覧
            tech_stack: 検出済み技術スタック
        
        Returns:
            AppAnalysisResult
        """
        import asyncio
        return await asyncio.to_thread(self.analyze, target, urls, tech_stack)

    def analyze(
        self,
        target: str,
        urls: List[str],
        tech_stack: Dict[str, str] = None
    ) -> AppAnalysisResult:
        """
        アプリを分析
        
        Args:
            target: ターゲットURL
            urls: クロールで取得したURL一覧
            tech_stack: 検出済み技術スタック
        
        Returns:
            AppAnalysisResult
        """
        result = AppAnalysisResult(target=target)
        
        # 1. 機能検出
        result.functions = self.detect_functions(urls)
        
        # 2. アプリ分類
        result.app_type = self.classify_app(urls, tech_stack or {})
        
        # 3. 技術スタック
        result.tech_stack = tech_stack or self._detect_tech_stack(urls)
        
        # 4. 構成推定
        result.architecture = self._estimate_architecture(urls, result.tech_stack)
        
        # 5. 脆弱性スコア
        result.vuln_score, result.vuln_reasons = self.assess_vulnerability(
            urls, result.functions, result.tech_stack
        )
        
        return result
    
    def detect_functions(self, urls: List[str]) -> List[str]:
        """機能を検出"""
        detected = set()
        
        for url in urls:
            url_lower = url.lower()
            for func_name, patterns in self.FUNCTION_PATTERNS.items():
                for pattern in patterns:
                    if pattern.search(url_lower):
                        detected.add(func_name)
                        break
        
        return sorted(list(detected))
    
    def classify_app(self, urls: List[str], tech_stack: Dict[str, str]) -> str:
        """アプリを分類"""
        url_text = " ".join(urls).lower()
        
        scores = {}
        for app_type, keywords in self.APP_TYPE_PATTERNS.items():
            score = sum(1 for kw in keywords if kw in url_text)
            if score > 0:
                scores[app_type] = score
        
        if scores:
            return max(scores, key=scores.get)
        
        return "Webアプリケーション"
    
    def assess_vulnerability(
        self,
        urls: List[str],
        functions: List[str],
        tech_stack: Dict[str, str]
    ) -> Tuple[float, List[str]]:
        """脆弱性スコアを評価"""
        score = 50.0  # 基準点
        reasons = []
        
        url_text = " ".join(urls).lower()
        
        # 機能ベースの評価
        if "ファイルアップロード" in functions:
            score += 15
            reasons.append("ファイルアップロード機能あり (+15)")
        
        if "管理画面" in functions:
            score += 10
            reasons.append("管理画面が露出 (+10)")
        
        if "API" in functions:
            score += 10
            reasons.append("APIエンドポイント露出 (+10)")
        
        # 入力フォーム数
        form_count = sum(1 for u in urls if "?" in u)
        if form_count > 20:
            score += 10
            reasons.append(f"パラメータ付きURL多数 ({form_count}件, +10)")
        
        # 技術スタックベース
        if "jquery" in url_text:
            score += 10
            reasons.append("jQuery使用 (+10)")
        
        if "graphql" in url_text:
            score += 10
            reasons.append("GraphQL使用 (+10)")
        
        # 堅牢な兆候
        if tech_stack.get("waf"):
            score -= 15
            reasons.append("WAF検出 (-15)")
        
        if tech_stack.get("framework") in ["nextjs", "nuxt", "django"]:
            score -= 5
            reasons.append("モダンフレームワーク使用 (-5)")
        
        return min(100, max(0, score)), reasons
    
    def _detect_tech_stack(self, urls: List[str]) -> Dict[str, str]:
        """簡易技術スタック検出"""
        stack = {}
        url_text = " ".join(urls).lower()
        
        if "react" in url_text or "bundle.js" in url_text:
            stack["frontend"] = "React/SPA"
        elif "vue" in url_text:
            stack["frontend"] = "Vue.js"
        
        if "/api/" in url_text:
            stack["api"] = "REST API"
        if "graphql" in url_text:
            stack["api"] = "GraphQL"
        
        return stack
    
    def _estimate_architecture(
        self,
        urls: List[str],
        tech_stack: Dict[str, str]
    ) -> Dict[str, List[str]]:
        """システム構成を推定"""
        arch = {
            "frontend": [],
            "backend": [],
            "external_api": [],
            "security": [],
            "unknown": [],
        }
        
        url_text = " ".join(urls).lower()
        
        # フロントエンド
        if tech_stack.get("frontend"):
            arch["frontend"].append(tech_stack["frontend"])
        elif "bundle.js" in url_text:
            arch["frontend"].append("SPA (不明)")
        else:
            arch["frontend"].append("SSR/MPA")
        
        # バックエンド
        if tech_stack.get("api"):
            arch["backend"].append(tech_stack["api"])
        if "/api/" in url_text:
            arch["backend"].append("REST API")
        
        # 外部API
        external_patterns = ["stripe", "paypal", "twilio", "sendgrid", "aws", "firebase"]
        for pattern in external_patterns:
            if pattern in url_text:
                arch["external_api"].append(pattern.capitalize())
        
        # セキュリティ
        if tech_stack.get("waf"):
            arch["security"].append(tech_stack["waf"])
        
        return arch
    
    def generate_architecture_diagram(self, result: AppAnalysisResult) -> str:
        """Mermaid形式のシステム構成図を生成"""
        lines = [
            "```mermaid",
            "graph LR",
        ]
        
        # ユーザー
        lines.append("    User([ユーザー])")
        
        # セキュリティ層
        if result.architecture.get("security"):
            waf = result.architecture["security"][0]
            lines.append(f"    User --> WAF[{waf}]")
            prev_node = "WAF"
        else:
            prev_node = "User"
        
        # フロントエンド
        if result.architecture.get("frontend"):
            fe = result.architecture["frontend"][0]
            lines.append(f"    {prev_node} --> FE[Frontend<br>{fe}]")
            prev_node = "FE"
        
        # バックエンド
        if result.architecture.get("backend"):
            be = result.architecture["backend"][0]
            lines.append(f"    {prev_node} --> API[Backend<br>{be}]")
            prev_node = "API"
        
        # データベース (推定)
        lines.append(f"    {prev_node} --> DB[(Database<br>不明)]")
        
        # 外部API
        if result.architecture.get("external_api"):
            ext = ", ".join(result.architecture["external_api"][:3])
            lines.append(f"    {prev_node} --> EXT[外部API<br>{ext}]")
        
        lines.append("```")
        
        return "\n".join(lines)
    
    def format_report(self, result: AppAnalysisResult) -> str:
        """レポートをフォーマット"""
        lines = [
            "=" * 60,
            f"📱 アプリ分析レポート: {result.target}",
            "=" * 60,
            "",
            f"## アプリ分類: {result.app_type}",
            "",
            "## 検出された機能:",
        ]
        
        for func in result.functions:
            lines.append(f"  - {func}")
        
        lines.extend([
            "",
            "## システム構成図:",
            self.generate_architecture_diagram(result),
            "",
            f"## 脆弱性スコア: {result.vuln_score:.0f}/100",
            "",
            "### 評価理由:",
        ])
        
        for reason in result.vuln_reasons:
            lines.append(f"  - {reason}")
        
        return "\n".join(lines)


def create_app_analyzer() -> AppAnalyzer:
    """ヘルパー関数"""
    return AppAnalyzer()
