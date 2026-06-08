"""
ProxyManager - プロキシリスト管理とローテーション

Swarm Agent 用のプロキシ管理モジュール。
ProxyNode の状態管理（成功/失敗カウント、遅延時間）を行い、
健全なプロキシを提供する。
"""

import logging
import random
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Iterator, Any
from src.core.infra.cache_manager import get_cache

logger = logging.getLogger(__name__)


@dataclass
class ProxyNode:
    """
    プロキシノード情報
    
    Notes:
        msgpack 互換のため辞書変換メソッドを提供
    """
    url: str  # http://user:pass@host:port
    fail_count: int = 0
    success_count: int = 0
    total_calls: int = 0
    last_used: float = 0.0
    latency: float = 0.0  # ms
    is_active: bool = True
    score: float = 100.0  # 信頼性スコア (0-100)

    def mark_success(self, latency_ms: float = 0.0):
        """成功を記録"""
        self.success_count += 1
        self.total_calls += 1
        self.fail_count = 0  # 連続失敗リセット
        self.last_used = time.time()
        
        # レイテンシ移動平均更新 (alpha=0.2)
        if self.latency == 0.0:
            self.latency = latency_ms
        else:
            self.latency = (self.latency * 0.8) + (latency_ms * 0.2)
            
        # スコア回復
        self.score = min(100.0, self.score + 1.0)
        self.is_active = True

    def mark_failure(self):
        """失敗を記録"""
        self.fail_count += 1
        self.total_calls += 1
        self.last_used = time.time()
        
        # スコア減少 (失敗回数に応じてペナルティ増大)
        penalty = 10.0 * (1 + (self.fail_count * 0.5))
        self.score = max(0.0, self.score - penalty)
        
        # 連続失敗または低スコアで一時無効化
        if self.fail_count >= 5 or self.score < 20.0:
            self.is_active = False
            logger.warning(
                "Proxy %s deactivated (fails=%d, score=%.1f)",
                self.url, self.fail_count, self.score
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "fail_count": self.fail_count,
            "success_count": self.success_count,
            "total_calls": self.total_calls,
            "last_used": self.last_used,
            "latency": self.latency,
            "is_active": self.is_active,
            "score": self.score
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProxyNode":
        return cls(**data)


class ProxyChainManager:
    """
    プロキシ管理・ローテーション・チェイン構築
    
    主な機能:
    - プロキシリストのロード
    - アクティブなプロキシの提供 (ラウンドロビン/ランダム)
    - プロキシの状態管理 (スコアリング)
    """

    def __init__(self, proxy_urls: List[str] = None):
        self.proxies: List[ProxyNode] = []
        self._proxy_map: Dict[str, ProxyNode] = {}
        self._cache = get_cache()
        
        if proxy_urls:
            # Note: __init__ は async にできないため、ここではキャッシュからの復元は行わない。
            # add_proxies_async を別途呼ぶ必要がある。
            for url in proxy_urls:
                if url and url not in self._proxy_map:
                    node = ProxyNode(url=url)
                    self.proxies.append(node)
                    self._proxy_map[url] = node
            logger.info("Added %d proxies (total: %d)", len(proxy_urls), len(self.proxies))


    async def add_proxies(self, urls: List[str]):
        """
        プロキシリストを追加
        
        キャッシュ（L2）から最新のステータスを復元しようと試みる。
        """
        count = 0
        for url in urls:
            if url and url not in self._proxy_map:
                # キャッシュから復元を試みる
                cache_key = f"proxy:stats:{url}"
                cached_data = await self._cache.get(cache_key)
                if cached_data:
                    node = ProxyNode.from_dict(cached_data)
                else:
                    node = ProxyNode(url=url)
                
                self.proxies.append(node)
                self._proxy_map[url] = node
                count += 1
        logger.info("Added %d proxies (total: %d)", count, len(self.proxies))

    async def load_from_file(self, filepath: str):
        """ファイルからプロキシリストをロード (1行1URL)"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            await self.add_proxies(urls)
        except Exception as e:
            logger.error("Failed to load proxies from %s: %s", filepath, e)

    def get_proxy(self) -> Optional[str]:
        """
        使用可能なプロキシを1つ取得
        
        戦略:
        - アクティブなプロキシの中から、スコア加重ランダムまたはラウンドロビンで選択
        - ここではシンプルに「アクティブかつスコアが高いもの」からランダム選択
        """
        active_proxies = [p for p in self.proxies if p.is_active]
        
        if not active_proxies:
            # 救済措置: 全滅している場合、少しでもスコアがあるものを復活させるか、
            # 最も失敗回数が少ないものを試す
            if not self.proxies:
                return None
                
            # 全滅時はリセットトライ
            candidates = sorted(self.proxies, key=lambda p: p.fail_count)
            best_candidate = candidates[0]
            logger.info("All proxies inactive, retrying best candidate: %s", best_candidate.url)
            return best_candidate.url

        # スコアに基づいて重み付け選択 (上位50%から選択など)
        # 簡易的に random.choice
        node = random.choice(active_proxies)
        return node.url

    async def report_success(self, proxy_url: str, latency_ms: float = 0.0):
        """プロキシ成功を報告"""
        if not proxy_url:
            return
        node = self._proxy_map.get(proxy_url)
        if node:
            node.mark_success(latency_ms)
            # キャッシュに同期
            await self._cache.set(f"proxy:stats:{proxy_url}", node.to_dict())

    async def report_failure(self, proxy_url: str):
        """プロキシ失敗を報告"""
        if not proxy_url:
            return
        node = self._proxy_map.get(proxy_url)
        if node:
            node.mark_failure()
            # キャッシュに同期
            await self._cache.set(f"proxy:stats:{proxy_url}", node.to_dict())

    def get_stats(self) -> Dict[str, Any]:
        """統計情報を取得"""
        total = len(self.proxies)
        active = len([p for p in self.proxies if p.is_active])
        return {
            "total": total,
            "active": active,
            "inactive": total - active,
            "avg_latency": sum(p.latency for p in self.proxies if p.is_active) / active if active > 0 else 0.0
        }



# シングルトン管理
_global_proxy_manager: Optional[ProxyChainManager] = None

def get_proxy_manager() -> ProxyChainManager:
    """グローバルな ProxyChainManager を取得（なければ作成）"""
    global _global_proxy_manager
    if _global_proxy_manager is None:
        from src.core.config.settings import get_settings
        proxy_url = get_settings().get_proxy_url()
        if proxy_url:
            _global_proxy_manager = ProxyChainManager(proxy_urls=[proxy_url])
            logger.info("Initialized global ProxyChainManager with settings proxy: %s", proxy_url)
        else:
            _global_proxy_manager = ProxyChainManager()
    return _global_proxy_manager

def create_proxy_manager(proxy_file: Optional[str] = None) -> ProxyChainManager:
    """ProxyChainManager 作成ヘルパー (グローバルインスタンスも更新)"""
    global _global_proxy_manager
    manager = ProxyChainManager()
    # 注意: ここは同期メソッドのままなので、ファイルロードは別途呼んでもらうか、
    # async版作成ヘルパーを用意するのが望ましい。
    # 現状の実装依存を確認しながら慎重に変更。

    if _global_proxy_manager is None:
        _global_proxy_manager = manager
        
    return manager

async def create_proxy_manager_async(proxy_file: Optional[str] = None) -> ProxyChainManager:
    """ProxyChainManager 作成ヘルパー (Async版)"""
    global _global_proxy_manager
    manager = ProxyChainManager()
    if proxy_file:
        await manager.load_from_file(proxy_file)
    
    if _global_proxy_manager is None:
        _global_proxy_manager = manager
    return manager
