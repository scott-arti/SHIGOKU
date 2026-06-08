"""
Tool Registry

ツールの登録と管理、モード連携
"""

from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ToolInfo:
    """ツール情報"""
    name: str
    display_name: str
    category: str  # "intel", "attack", "analysis"
    description: str
    enabled: bool = True
    required_for_modes: List[str] = None


class ToolRegistry:
    """ツールレジストリ（シングルトン）"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.tools: Dict[str, ToolInfo] = {}
        self._register_builtin_tools()
        self._initialized = True
    
    def _register_builtin_tools(self) -> None:
        """組み込みツールを登録"""
        builtin_tools = [
            # ===== Intel - 偵察ツール =====
            ToolInfo(
                name="cartographer",
                display_name="Cartographer",
                category="intel",
                description="サイトマップ作成とクローリング",
            ),
            ToolInfo(
                name="fingerprinter",
                display_name="Fingerprinter",
                category="intel",
                description="技術スタック検出",
            ),
            ToolInfo(
                name="commit_watcher",
                display_name="Commit Watcher",
                category="intel",
                description="GitHub監視とシークレット検出",
            ),
            ToolInfo(
                name="visual_filter",
                display_name="Visual Filter",
                category="intel",
                description="ページタイプ画像分類",
            ),
            ToolInfo(
                name="google_dorker",
                display_name="Google Dorker",
                category="intel",
                description="Google Dork検索",
            ),
            ToolInfo(
                name="js_analyzer",
                display_name="JS Analyzer",
                category="intel",
                description="JavaScript解析とエンドポイント抽出",
            ),
            ToolInfo(
                name="subzy",
                display_name="Subzy",
                category="intel",
                description="サブドメインテイクオーバー検出 (Go)",
            ),
            ToolInfo(
                name="wayback_integrator",
                display_name="Wayback Integrator",
                category="intel",
                description="Wayback Machine履歴取得",
            ),
            ToolInfo(
                name="cloud_enum",
                display_name="Cloud Enum",
                category="intel",
                description="マルチクラウド資産列挙 (Python)",
            ),
            ToolInfo(
                name="scoutsuite",
                display_name="Scout Suite",
                category="intel",
                description="マルチクラウドセキュリティ監査 (Python)",
            ),
            ToolInfo(
                name="cve_explorer",
                display_name="CVE Explorer",
                category="intel",
                description="CVE情報検索",
            ),
            ToolInfo(
                name="email_harvester",
                display_name="Email Harvester",
                category="intel",
                description="メールアドレス収集",
            ),
            ToolInfo(
                name="asn_discoverer",
                display_name="ASN Discoverer",
                category="intel",
                description="ASN情報とIP範囲発見",
            ),
            ToolInfo(
                name="cert_transparency",
                display_name="Cert Transparency",
                category="intel",
                description="証明書透明性ログ検索",
            ),
            ToolInfo(
                name="shodan_integrator",
                display_name="Shodan Integrator",
                category="intel",
                description="Shodan API連携",
            ),
            ToolInfo(
                name="dns_history",
                display_name="DNS History",
                category="intel",
                description="DNS履歴収集",
            ),
            ToolInfo(
                name="headless_crawler",
                display_name="Headless Crawler",
                category="intel",
                description="ヘッドレスブラウザクローリング",
            ),
            ToolInfo(
                name="proxy_log_analyzer",
                display_name="Proxy Log Analyzer",
                category="intel",
                description="プロキシログ解析とSmell検出",
            ),
            ToolInfo(
                name="secret_finder",
                display_name="Secret Finder",
                category="intel",
                description="カスタムSecretFinderによるシークレット探索",
            ),
            # ===== Attack - 攻撃ツール =====
            ToolInfo(
                name="jwt_inspector",
                display_name="JWT Inspector",
                category="attack",
                description="JWT認証バイパス",
            ),
            ToolInfo(
                name="oauth_dancer",
                display_name="OAuth Dancer",
                category="attack",
                description="OAuth/OIDC脆弱性検出",
            ),
            ToolInfo(
                name="mfa_bypasser",
                display_name="MFA Bypasser",
                category="attack",
                description="多要素認証バイパス",
            ),
            ToolInfo(
                name="biz_logic_hunter",
                display_name="BizLogic Hunter",
                category="attack",
                description="ビジネスロジック脆弱性検出",
            ),
            ToolInfo(
                name="ssrf_tester",
                display_name="SSRF Tester",
                category="attack",
                description="SSRF脆弱性テスト",
            ),
            ToolInfo(
                name="lfi_tester",
                display_name="LFI Tester",
                category="attack",
                description="LFI脆弱性テスト",
            ),
            ToolInfo(
                name="cors_tester",
                display_name="CORS Tester",
                category="attack",
                description="CORS設定ミス検出",
            ),
            ToolInfo(
                name="open_redirect_tester",
                display_name="Open Redirect Tester",
                category="attack",
                description="オープンリダイレクト検出",
            ),
            ToolInfo(
                name="xss_tester",
                display_name="XSS Tester",
                category="attack",
                description="XSS脆弱性テスト",
            ),
            ToolInfo(
                name="crlf_tester",
                display_name="CRLF Tester",
                category="attack",
                description="CRLFインジェクション検出",
            ),
            ToolInfo(
                name="graphql_analyzer",
                display_name="GraphQL Analyzer",
                category="attack",
                description="GraphQL脆弱性分析",
            ),
            ToolInfo(
                name="race_the_web",
                display_name="Race The Web",
                category="attack",
                description="レースコンディション検出（並列リクエスト）",
            ),
            ToolInfo(
                name="param_fuzzer",
                display_name="Parameter Fuzzer",
                category="attack",
                description="隠しパラメータ発見と反射検出",
            ),
            ToolInfo(
                name="websocket_tester",
                display_name="WebSocket Tester",
                category="attack",
                description="WebSocket脆弱性テスト",
            ),
            ToolInfo(
                name="openapi_tester",
                display_name="OpenAPI Tester",
                category="attack",
                description="OpenAPI/Swagger自動テスト",
            ),
            # ===== Analysis - 分析ツール =====
            ToolInfo(
                name="triage_simulator",
                display_name="Triage Simulator",
                category="analysis",
                description="レポート品質評価と却下リスク予測",
            ),
            ToolInfo(
                name="screenshot_poc",
                display_name="Screenshot PoC",
                category="analysis",
                description="Obsidian形式スクリーンショットPoC生成",
            ),
            ToolInfo(
                name="nuclei_template_gen",
                display_name="Nuclei Template Generator",
                category="analysis",
                description="Nucleiテンプレート動的生成",
            ),
            ToolInfo(
                name="disclosed_report_hunter",
                display_name="Disclosed Report Hunter",
                category="intel",
                description="公開レポート探索と傾向分析",
            ),
        ]
        
        for tool in builtin_tools:
            self.tools[tool.name] = tool
    
    def register_tool(self, tool: ToolInfo) -> None:
        """
        ツールを登録
        
        Args:
            tool: ツール情報
        """
        self.tools[tool.name] = tool
        logger.info(f"Tool registered: {tool.name}")
    
    def enable_tool(self, tool_name: str) -> None:
        """ツールを有効化"""
        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        self.tools[tool_name].enabled = True
        logger.info(f"Tool enabled: {tool_name}")
    
    def disable_tool(self, tool_name: str) -> None:
        """ツールを無効化"""
        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        self.tools[tool_name].enabled = False
        logger.info(f"Tool disabled: {tool_name}")
    
    def is_enabled(self, tool_name: str) -> bool:
        """ツールが有効かチェック"""
        if tool_name not in self.tools:
            return False
        return self.tools[tool_name].enabled
    
    def get_enabled_tools(self, category: Optional[str] = None) -> List[ToolInfo]:
        """
        有効なツール一覧を取得
        
        Args:
            category: カテゴリでフィルタ（オプション）
        
        Returns:
            有効なツール一覧
        """
        tools = [t for t in self.tools.values() if t.enabled]
        
        if category:
            tools = [t for t in tools if t.category == category]
        
        return tools
    
    def list_all_tools(self, category: Optional[str] = None) -> List[ToolInfo]:
        """
        全ツール一覧を取得
        
        Args:
            category: カテゴリでフィルタ（オプション）
        
        Returns:
            ツール一覧
        """
        tools = list(self.tools.values())
        
        if category:
            tools = [t for t in tools if t.category == category]
        
        return tools


def get_tool_registry() -> ToolRegistry:
    """ToolRegistryのシングルトンインスタンスを取得"""
    return ToolRegistry()
