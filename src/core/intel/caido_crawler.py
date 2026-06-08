"""
Caido Crawler - gospider/katana をCaido IO経由で実行

Caido IOプロキシ経由でクロールし、全リクエストをCaidoに記録。

プロキシ設定方法:
1. 環境変数: SHIGOKU_CRAWLER_PROXY=http://127.0.0.1:8080
2. コンストラクタ引数: CaidoCrawler(proxy="http://...")
3. set_proxy()メソッド: crawler.set_proxy("http://...")
"""

import os
import subprocess
import logging
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path

from src.config import settings

logger = logging.getLogger(__name__)


@dataclass
class CrawlResult:
    """クロール結果"""
    target: str
    urls: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    forms: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    tool: str = ""


class CaidoCrawler:
    """
    Caido IO経由でgospider/katanaを実行するクローラー
    
    全リクエストがCaidoに記録され、後から分析可能。
    
    プロキシ設定優先順位:
    1. コンストラクタ引数
    2. 環境変数 SHIGOKU_CRAWLER_PROXY
    3. デフォルト値 (127.0.0.1:8080)
    """
    
    DEFAULT_PROXY = "http://127.0.0.1:8080"
    ENV_PROXY_KEY = "SHIGOKU_CRAWLER_PROXY"
    
    # クロール深度プリセット
    DEPTH_PRESETS = {
        "quick": 1,
        "standard": 3,
        "deep": 5,
    }
    
    def __init__(self, proxy: str = None):
        # 優先順位: 引数 > 環境変数 > デフォルト
        self.proxy = proxy or os.getenv(self.ENV_PROXY_KEY) or self.DEFAULT_PROXY
        self._gospider_path = settings.tool_gospider_path
        self._katana_path = settings.tool_katana_path
        logger.info("CaidoCrawler初期化: プロキシ=%s", self.proxy)
    
    def set_proxy(self, proxy_url: str) -> None:
        """プロキシを設定"""
        self.proxy = proxy_url
        logger.info("プロキシを設定: %s", proxy_url)
    
    def run_gospider(
        self,
        target: str,
        depth: int = 3,
        threads: int = 5,
        timeout: int = 300
    ) -> CrawlResult:
        """
        gospiderでクロール実行
        
        Args:
            target: ターゲットURL
            depth: クロール深度
            threads: 並列スレッド数
            timeout: タイムアウト秒
        
        Returns:
            CrawlResult
        """
        result = CrawlResult(target=target, tool="gospider")
        
        cmd = [
            self._gospider_path,
            "-s", target,
            "-d", str(depth),
            "-t", str(threads),
            "-p", self.proxy,
            "--no-redirect",
            "-q",  # quiet mode
        ]
        
        logger.info("gospider実行: %s (深度=%d, プロキシ=%s)", target, depth, self.proxy)
        
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            if proc.returncode == 0:
                result.urls = self._parse_gospider_output(proc.stdout)
                logger.info("gospider完了: %d URL検出", len(result.urls))
            else:
                result.errors.append(proc.stderr[:500])
                logger.warning("gospiderエラー: %s", proc.stderr[:200])
                
        except subprocess.TimeoutExpired:
            result.errors.append("タイムアウト")
            logger.error("gospiderタイムアウト")
        except FileNotFoundError:
            result.errors.append("gospiderが見つかりません")
            logger.error("gospiderが見つかりません")
        
        return result
    
    def run_katana(
        self,
        target: str,
        depth: int = 3,
        js_crawl: bool = True,
        timeout: int = 300
    ) -> CrawlResult:
        """
        katanaでクロール実行
        
        Args:
            target: ターゲットURL
            depth: クロール深度
            js_crawl: JSファイル解析有効
            timeout: タイムアウト秒
        
        Returns:
            CrawlResult
        """
        import json
        
        result = CrawlResult(target=target, tool="katana")
        
        cmd = [
            self._katana_path,
            "-u", target,
            "-d", str(depth),
            "-proxy", self.proxy,
            "-silent",
            "-json",  # JSON 出力有効
        ]
        
        if js_crawl:
            cmd.append("-jc")  # JS crawling
        
        logger.info("katana実行: %s (深度=%d, JS解析=%s)", target, depth, js_crawl)
        
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            if proc.returncode == 0:
                urls = []
                js_files = []
                endpoints = []
                
                for line in proc.stdout.split("\n"):
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        url = data.get("request", {}).get("endpoint", "")
                        if not url:
                            url = data.get("url", "")
                        if url:
                            urls.append(url)
                            # JS ファイル判定 (URL or Content-Type)
                            content_type = data.get("response", {}).get("content_type", "")
                            if url.endswith(".js") or "javascript" in content_type:
                                js_files.append(url)
                            # エンドポイント判定
                            if "?" in url or "/api/" in url:
                                endpoints.append(url)
                    except json.JSONDecodeError:
                        # JSON パース失敗時は URL として扱う
                        if line.strip().startswith("http"):
                            urls.append(line.strip())
                
                result.urls = urls
                result.js_files = list(set(js_files))  # 重複除去
                result.endpoints = list(set(endpoints))
                logger.info("katana完了: %d URL, %d JS, %d エンドポイント",
                           len(result.urls), len(result.js_files), len(result.endpoints))
            else:
                result.errors.append(proc.stderr[:500])
                logger.warning("katanaエラー: %s", proc.stderr[:200])
                
        except subprocess.TimeoutExpired:
            result.errors.append("タイムアウト")
            logger.error("katanaタイムアウト")
        except FileNotFoundError:
            result.errors.append("katanaが見つかりません")
            logger.error("katanaが見つかりません")
        
        return result
    
    def run_both(
        self,
        target: str,
        depth: str = "standard",
        timeout: int = 300
    ) -> CrawlResult:
        """
        gospiderとkatana両方を実行し結果をマージ
        
        Args:
            target: ターゲットURL
            depth: "quick", "standard", "deep"
        
        Returns:
            CrawlResult (マージ済み)
        """
        depth_num = self.DEPTH_PRESETS.get(depth, 3)
        
        logger.info("=== Caido経由クロール開始 ===")
        logger.info("ターゲット: %s", target)
        logger.info("深度: %s (%d)", depth, depth_num)
        logger.info("プロキシ: %s", self.proxy)
        
        # gospider実行
        gospider_result = self.run_gospider(target, depth_num, timeout=timeout)
        
        # katana実行
        katana_result = self.run_katana(target, depth_num, timeout=timeout)
        
        # 結果マージ
        merged = CrawlResult(
            target=target,
            tool="gospider+katana",
            urls=list(set(gospider_result.urls + katana_result.urls)),
            js_files=katana_result.js_files,
            endpoints=katana_result.endpoints,
            errors=gospider_result.errors + katana_result.errors,
        )
        
        logger.info("=== クロール完了 ===")
        logger.info("総URL数: %d", len(merged.urls))
        logger.info("JSファイル: %d", len(merged.js_files))
        logger.info("エンドポイント: %d", len(merged.endpoints))
        
        return merged
    
    def _parse_gospider_output(self, output: str) -> List[str]:
        """gospider出力をパース"""
        urls = []
        for line in output.split("\n"):
            # gospiderは [url] - URL 形式で出力
            if line.strip() and "http" in line:
                # URLを抽出
                parts = line.split()
                for part in parts:
                    if part.startswith("http"):
                        urls.append(part)
        return list(set(urls))
    
    def get_summary(self, result: CrawlResult) -> str:
        """結果サマリーを取得"""
        lines = [
            "=" * 50,
            f"🕷️ クロール結果: {result.target}",
            "=" * 50,
            f"ツール: {result.tool}",
            f"URL数: {len(result.urls)}",
            f"JSファイル: {len(result.js_files)}",
            f"エンドポイント: {len(result.endpoints)}",
        ]
        
        if result.errors:
            lines.append(f"エラー: {len(result.errors)}")
        
        return "\n".join(lines)


def create_caido_crawler(proxy: str = None) -> CaidoCrawler:
    """ヘルパー関数"""
    return CaidoCrawler(proxy)
