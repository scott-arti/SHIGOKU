"""
Cartographer: サイトマッピング & クローリングモジュール

ターゲットの構造を把握し、エンドポイントを発見する。
EthicsGuardによるスコープ制限を厳守し、RotatingSessionでブロックを回避する。
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Set, List, Dict, Optional
from urllib.parse import urlparse, urljoin, urldefrag

from bs4 import BeautifulSoup

from src.core.security.ethics_guard import get_ethics_guard, ActionType, ActionResult
from src.core.infra.network_client import AsyncNetworkClient

logger = logging.getLogger(__name__)


@dataclass
class SiteNode:
    """サイトマップのノード（1つのURLに対応）"""
    url: str
    method: str = "GET"
    status_code: int = 0
    title: str = ""
    content_type: str = ""
    links: List[str] = field(default_factory=list)
    forms: List[dict] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class SiteMap:
    """サイトマップデータ構造"""
    def __init__(self, root_url: str):
        self.root_url = root_url
        self.nodes: Dict[str, SiteNode] = {}
    
    def add_node(self, node: SiteNode):
        self.nodes[node.url] = node

    def get_endpoints(self) -> List[str]:
        return list(self.nodes.keys())


class Cartographer:
    """
    自律型クローラー & サイトマッパー (非同期版)
    """

    def __init__(self, start_url: str, network_client: Optional[AsyncNetworkClient] = None, max_depth: int = 2, max_pages: int = 50):
        self.start_url = start_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        
        self.sitemap = SiteMap(start_url)
        self.visited: Set[str] = set()
        self.queue: List[tuple[str, int]] = [(start_url, 0)] # (url, depth)
        
        # 外部から受領するか、なければ（テスト用等）新規作成
        self._network_client = network_client or AsyncNetworkClient()
        self._guard = get_ethics_guard()

    def close(self):
        """リソース解放"""
        # 注意: Conductorから共有されている場合は、ここでcloseしてはいけない。
        # 単発実行時のみ考慮が必要。
        pass

    async def map_site(self) -> SiteMap:
        """サイトマップを作成開始"""
        logger.info(f"🗺️ Starting mapping: {self.start_url} (Max Depth: {self.max_depth})")
        
        while self.queue and len(self.visited) < self.max_pages:
            current_url, depth = self.queue.pop(0)
            
            # 正規化・重複チェック
            current_url = self._normalize_url(current_url)
            if current_url in self.visited:
                continue
            
            # スコープチェック
            is_allowed, reason = self._guard.check_action(ActionType.HTTP_REQUEST, current_url)
            if is_allowed != ActionResult.ALLOWED:
                logger.debug(f"Scope blocked {current_url}: {reason}")
                continue

            await self._crawl_page(current_url, depth)
        
        logger.info(f"🗺️ Mapping complete. Found {len(self.sitemap.nodes)} nodes.")
        return self.sitemap

    async def _crawl_page(self, url: str, depth: int):
        """単一ページをクロールしてリンク抽出 (Async)"""
        self.visited.add(url)
        logger.info(f"Crawling: {url} (Depth: {depth})")
        
        try:
            # 共有NetworkClientを使用して非同期リクエスト
            response = await self._network_client.request("GET", url, timeout=10)
            
            if not response:
                return

            # ノード作成
            soup = BeautifulSoup(response.body, 'html.parser')
            title = soup.title.string if soup.title else ""
            
            node = SiteNode(
                url=url,
                method="GET",
                status_code=response.status,
                title=title or "",
                content_type=response.headers.get("Content-Type", ""),
            )
            
            # HTML以外はパースしない
            content_type = response.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type:
                self.sitemap.add_node(node)
                return

            # リンク抽出
            links = self._extract_links(soup, url)
            node.links = links
            
            # フォーム抽出 (簡易)
            node.forms = self._extract_forms(soup, url)
            
            self.sitemap.add_node(node)
            
            # 深さ制限内ならキューに追加
            if depth < self.max_depth:
                for link in links:
                    if link not in self.visited:
                        self.queue.append((link, depth + 1))
                        
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
            # エラーノードとして記録
            self.sitemap.add_node(SiteNode(url=url, status_code=0))

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """各種タグからリンクを抽出"""
        links = set()
        
        # <a> tags
        for a in soup.find_all('a', href=True):
            links.add(a['href'])
            
        # <script src>
        for script in soup.find_all('script', src=True):
            links.add(script['src'])
            
        # <link href>
        for link in soup.find_all('link', href=True):
            links.add(link['href'])
            
        # 絶対パス化
        absolute_links = []
        for link in links:
            full_url = urljoin(base_url, link)
            
            # Scheme check
            parsed = urlparse(full_url)
            if parsed.scheme not in ("http", "https"):
                continue

            normalized = self._normalize_url(full_url)
            
            # ドメイン内のみを対象とするフィルタリング（オプション）
            # ここでは厳密なフィルタはEthicsGuardに任せるが、
            # 明らかに外部サイトへの大量クロールを防ぐため、単純なドメイン一致を一応チェック推奨
            # (今回はEthicsGuardを信頼して全て追加し、アクセス直前にチェックする方式をとる)
            
            absolute_links.append(normalized)
            
        return list(set(absolute_links))

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[dict]:
        """フォーム情報を抽出"""
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method', 'GET').upper()
            full_action = urljoin(base_url, action) if action else base_url
            
            inputs = []
            for inp in form.find_all('input'):
                inputs.append({
                    "name": inp.get('name'),
                    "type": inp.get('type', 'text'),
                    "value": inp.get('value')
                })
                
            forms.append({
                "action": full_action,
                "method": method,
                "inputs": inputs
            })
        return forms

    def _normalize_url(self, url: str) -> str:
        """URLの正規化（フラグメント削除）"""
        url, _ = urldefrag(url)
        return url


# テスト用
if __name__ == "__main__":
    import sys
    
    # 簡易ログ設定
    logging.basicConfig(level=logging.DEBUG)
    
    start = "http://localhost:8888/"  # 末尾スラッシュ追加
    
    scope_yaml = """
    program_name: Test
    in_scope:
      domains:
        - localhost
        - 127.0.0.1
    """
