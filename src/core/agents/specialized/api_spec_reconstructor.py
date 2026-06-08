"""
APISpecReconstructor: JavaScript解析によるAPI仕様復元エージェント

クライアントサイドJSを解析し、隠蔽されたAPIエンドポイントやパラメータ仕様を復元する。
Shadow APIの発見や、ドキュメント化されていないエンドポイントの特定に使用。
"""

import re
import logging
import urllib.parse
from typing import Dict, Any, List, Set, Optional
from dataclasses import dataclass
from src.core.infra.network_client import AsyncNetworkClient, NetworkClientError
from src.core.agents.base import BaseAgent, AgentConfig
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


logger = logging.getLogger(__name__)

@dataclass
class APIEndpoint:
    """復元されたAPIエンドポイント情報"""
    path: str
    method: str = "GET"  # 推定メソッド
    params: List[str] = None
    source_file: str = ""
    confidence: float = 0.5
    
    def __post_init__(self):
        if self.params is None:
            self.params = []

class APISpecReconstructor(BaseAgent):
    """
    API仕様復元エージェント
    
    機能:
    - HTMLからJSファイルを抽出
    - JSファイル内のAPIコールパターン解析 (fetch, axios, $.ajax 等)
    - 相対パス/絶対パスの正規化
    - 重複排除と信頼度スコアリング
    """
    
    # API予兆パターン
    PATTERNS = [
        # fetch('/api/v1/user')
        r"fetch\s*\(\s*['\"]([^'\"]+)['\"]",
        # axios.get('/api/...') or http.post('...')
        r"(?:axios|http|request)\.(?:get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]",
        # $.ajax({ url: '...' })
        r"url\s*:\s*['\"]([^'\"]+)['\"]",
        # Explicit path assignment: const API_URL = "..."
        r"(?:API_URL|BASE_URL|endpoint)\s*[:=]\s*['\"]([^'\"]+)['\"]",
        # General API-like paths
        r"['\"](/api/[^'\"]+)['\"]",
        r"['\"](/v\d+/[^'\"]+)['\"]",
    ]
    
    # 無視する静的ファイル拡張子
    IGNORE_EXTS = {
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', 
        '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.webm', '.map'
    }

    def __init__(self, config: AgentConfig, workspace_root: Optional[str] = None):
        super().__init__(config, workspace_root)
        self.timeout = 15
        self.found_endpoints: Dict[str, APIEndpoint] = {}
        self._client = None

    async def close(self):
        """リソース解放"""
        if self._client:
            await self._client.close()
            self._client = None

    def _get_client(self) -> AsyncNetworkClient:
        if not self._client:
            self._client = AsyncNetworkClient()
        return self._client

    async def process(self, input_message: str) -> str:
        """BaseAgent 互換の対話プロトコル（未実装）"""
        return "APISpecReconstructor is a specialized agent and does not support chat messages yet."

    async def reconstruct(self, target_url: str) -> List[Dict[str, Any]]:
        """
        指定されたURLからAPI仕様を復元する
        
        Args:
            target_url: 解析開始URL
            
        Returns:
            JSONシリアライズ可能なエンドポイントリスト
        """
        self.found_endpoints = {}
        logger.info(f"Starting API reconstruction for: {target_url}")
        
        try:
            # 1. HTML取得
            html = await self._fetch_content(target_url)
            if not html:
                return []
                
            # 2. JSファイルURL収集
            js_urls = self._extract_js_urls(html, target_url)
            logger.info(f"Found {len(js_urls)} JS files to analyze")
            
            # 3. 各JSファイルを解析
            for js_url in js_urls:
                js_content = await self._fetch_content(js_url)
                if js_content:
                    self._analyze_js_content(js_content, js_url)
                    
            # 4. HTML内のインラインスクリプトも解析
            self._analyze_inline_scripts(html, target_url)
            
        except (NetworkClientError, TimeoutError) as e:
            logger.error("Network error during reconstruction: %s", e)
        except Exception as e:
            logger.error("Reconstruction failed: %s", e)
            
        # 結果の整形
        results = []
        for ep in self.found_endpoints.values():
            results.append({
                "path": ep.path,
                "method": ep.method,
                "params": ep.params,
                "source": ep.source_file,
                "confidence": ep.confidence
            })
            
        logger.info(f"Reconstruction complete. Found {len(results)} potential endpoints.")
        return results

    async def _fetch_content(self, url: str) -> Optional[str]:
        """コンテンツ取得"""
        try:
            # User-Agent偽装はBaseAgentの責務だが、ここでは簡易的に実装
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            client = self._get_client()
            resp = await client.request("GET", url, headers=headers, timeout=self.timeout, follow_redirects=True, use_proxy_rotation=True)
            if resp.status_code == 200:
                return resp.text
        except Exception as e:
            logger.debug(f"Failed to fetch {url}: {e}")
        return None

    def _extract_js_urls(self, html: str, base_url: str) -> Set[str]:
        """HTMLからscript srcを抽出"""
        js_urls = set()
        soup = BeautifulSoup(html, 'html.parser')
        
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                full_url = urllib.parse.urljoin(base_url, src)
                js_urls.add(full_url)
                
        # Source Mapの自動推測 (main.js -> main.js.map) も可能だが今回はスキップ
        return js_urls

    def _analyze_js_content(self, content: str, source_url: str):
        """JSコンテンツからAPIパターンを抽出"""
        for pattern in self.PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                path = match.group(1)
                if self._is_valid_api_path(path):
                    self._register_endpoint(path, source_url, content, match.start())

    def _analyze_inline_scripts(self, html: str, source_url: str):
        """インラインスクリプト解析"""
        soup = BeautifulSoup(html, 'html.parser')
        for script in soup.find_all('script'):
            if not script.get('src') and script.string:
                self._analyze_js_content(script.string, f"{source_url} (inline)")

    def _is_valid_api_path(self, path: str) -> bool:
        """APIパスとして妥当かチェック"""
        if not path or len(path) < 2:
            return False
        
        # 明らかにURLでないもの
        if " " in path or "\n" in path:
            return False
            
        # 静的ファイル除外
        parsed = urllib.parse.urlparse(path)
        path_only = parsed.path
        if "." in path_only:
            ext = "." + path_only.split(".")[-1].lower()
            if ext in self.IGNORE_EXTS:
                return False
        
        # よくある誤検知の除外
        invalid_starts = ["<", ">", "{", "}", "(", ")", ";", "//"]
        if any(path.startswith(c) for c in invalid_starts):
            return False
            
        return True

    def _register_endpoint(self, path: str, source: str, context: str = "", position: int = 0):
        """エンドポイント登録・マージ処理"""
        # クエリパラメータ除去して正規化
        if "?" in path:
            base_path = path.split("?")[0]
            # パラメータ抽出ロジック（簡易）
            # params = ...
        else:
            base_path = path

        if base_path not in self.found_endpoints:
            # メソッド推測
            snippet = context[max(0, position-50):min(len(context), position+50)]
            method = "GET"
            if "post" in snippet.lower(): method = "POST"
            elif "put" in snippet.lower(): method = "PUT"
            elif "delete" in snippet.lower(): method = "DELETE"
            
            self.found_endpoints[base_path] = APIEndpoint(
                path=base_path,
                method=method,
                source_file=source,
                confidence=0.7 if "/api/" in base_path else 0.4
            )

    async def execute(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """MasterConductor互換の実行メソッド"""
        # targetはURLであることを期待
        if not target.startswith("http"):
             return {
                "success": False,
                "error": "Target must be a valid URL starting with http/https"
            }
            
        endpoints = await self.reconstruct(target)
        
        return {
            "success": True,
            "target": target,
            "endpoints": endpoints,
            "count": len(endpoints)
        }
