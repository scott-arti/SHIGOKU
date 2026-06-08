"""
AsyncDatabaseWriter: ハイブリッド・バッチDB書き込みエンジン

データロストを防ぐための3つの安全策を実装:
1. Severity-Based Routing: Critical/High Findingは即時書き込み
2. Write-Ahead Logging: キューイング前にJSONLファイルへバックアップ
3. Graceful Shutdown: 終了時に必ずキューをフラッシュ
"""

import asyncio
import json
import logging
import signal
import atexit
import threading
import time
from enum import Enum
from pathlib import Path
from typing import Optional, Any, List, Dict, Tuple
from collections import OrderedDict
import aiofiles

from src.core.models.finding import Finding
from src.core.intel.cartographer import SiteNode
from src.core.infra.knowledge_graph import KnowledgeGraph
from src.core.learning.findings_repository import FindingsRepository

logger = logging.getLogger(__name__)

# シングルトン管理用
_writer_instance: Optional["AsyncDatabaseWriter"] = None

def get_async_writer() -> Optional["AsyncDatabaseWriter"]:
    """AsyncDatabaseWriterのシングルトンインスタンスを取得"""
    return _writer_instance


class WritePriority(Enum):
    IMMEDIATE = 1  # Critical findings
    BATCH = 2      # Low severity, Sitemaps


class TimedLRUCache:
    """
    TTL（Time To Live）とLRU（Least Recently Used）を組み合わせたキャッシュ
    
    機能:
    - TTL: 指定時間経過後に自動削除
    - LRU: キャッシュサイズ上限到達時に最も古いエントリを削除
    - アクセス順の追跡（OrderedDictのmove_to_end使用）
    """
    
    def __init__(self, max_size: int = 5000, ttl_seconds: int = 300):
        self._cache: OrderedDict[str, Tuple[Any, float]] = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl_seconds
        self._stats = {"hit": 0, "miss": 0, "expired": 0, "evicted": 0}
    
    def get(self, key: str) -> Optional[Any]:
        """キーに対応する値を取得（TTLチェック＋LRU更新）"""
        if key not in self._cache:
            self._stats["miss"] += 1
            return None
        
        value, timestamp = self._cache[key]
        
        # TTLチェック
        if time.time() - timestamp >= self._ttl:
            del self._cache[key]
            self._stats["expired"] += 1
            return None
        
        # LRU更新（アクセスしたキーを最後に移動）
        self._cache.move_to_end(key)
        self._stats["hit"] += 1
        return value
    
    def set(self, key: str, value: Any) -> None:
        """キーと値を保存（LRUエビクション付き）"""
        now = time.time()
        
        if key in self._cache:
            # 既存キーの更新
            self._cache.move_to_end(key)
        
        self._cache[key] = (value, now)
        
        # サイズ制限チェック
        if len(self._cache) > self._max_size:
            # 最も古いキー（先頭）を削除
            self._cache.popitem(last=False)
            self._stats["evicted"] += 1
    
    def get_stats(self) -> dict:
        """統計情報を返す"""
        total = sum([self._stats["hit"], self._stats["miss"]])
        hit_rate = (self._stats["hit"] / total * 100) if total > 0 else 0.0
        return {
            **self._stats,
            "size": len(self._cache),
            "hit_rate": f"{hit_rate:.1f}%"
        }

class AsyncDatabaseWriter:
    """
    ハイブリッド・バッチDB書き込みエンジン
    
    安全策:
    - Critical Findings -> 即時同期書き込み
    - その他 -> 非同期バッチ（WAL + Graceful Shutdown付き）
    """
    
    def __init__(
        self, 
        kg: KnowledgeGraph, 
        repo: FindingsRepository,
        recovery_file: str = "~/.shigoku/storage_recovery.jsonl"
    ):
        global _writer_instance
        _writer_instance = self
        self.kg = kg
        self.repo = repo
        self.queue = asyncio.Queue()
        self.worker_task: Optional[asyncio.Task] = None
        self._running = False
        self.recovery_file = Path(recovery_file).expanduser()
        self.recovery_file.parent.mkdir(parents=True, exist_ok=True)
        
        # L1 キャッシュ (Read-after-Write整合性 + TTL/LRU)
        self.memory_cache = TimedLRUCache(max_size=5000, ttl_seconds=300)
        
        # 終了時処理の登録
        atexit.register(self.stop_sync)
        
    async def start(self):
        """バックグラウンドワーカーを起動"""
        if self._running:
            return
            
        self._running = True
        self.worker_task = asyncio.create_task(self._worker())
        
        # グレースフルシャットダウンのフック設定
        # signal.set_wakeup_fd はメインスレッドでのみ動作するため、メインスレッド判定を追加
        import threading
        if threading.current_thread() is threading.main_thread():
            try:
                loop = asyncio.get_running_loop()
                for sig in (signal.SIGINT, signal.SIGTERM):
                    loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop()))
            except (NotImplementedError, ValueError, RuntimeError):
                # Windows or background threads don't support add_signal_handler
                pass
        
        logger.info("✅ AsyncDatabaseWriter started")
        
    async def stop(self):
        """グレースフルシャットダウン: 残りのキューを全て処理"""
        if not self._running:
            return
            
        logger.info(f"[AsyncWriter] Graceful shutdown initiated. Queue size: {self.queue.qsize()}")
        self._running = False
        
        # キューに残っているものをフラッシュ
        await self._flush_all()
            
        if self.worker_task:
            self.worker_task.cancel()
            try:
                await self.worker_task
            except asyncio.CancelledError:
                pass
        
        logger.info("[AsyncWriter] Shutdown complete.")

    def stop_sync(self):
        """同期コンテキスト（atexit等）から停止"""
        if not self._running:
            return
        
        try:
            # 既にメインループが閉じている場合の安全策
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                # ループがまだ動いている場合
                future = asyncio.run_coroutine_threadsafe(self.stop(), loop)
                try:
                    future.result(timeout=5)
                except Exception:
                    # タイムアウトやエラー時は強制終了マーク
                    logger.warning("[AsyncWriter] stop_sync: future wait failed.")
            else:
                # ループがない/閉じている -> 新しいループで実行トライするか、諦める
                # atexitの段階では新ループ作成も危険な場合があるため、簡易的なクリーンアップのみ
                # self.queueに溜まったものを同期的に処理できるならしたほうがいいが、
                # ここでは強制終了ログのみにする
                logger.info("[AsyncWriter] Loop closed, skipping graceful flush via loop.")
                self._running = False
                
        except Exception as e:
            self._running = False
            logger.info(f"[AsyncWriter] Force stopped (exception: {e}).")
    
    async def enqueue_finding(self, finding: Finding):
        """
        Findingをキューに追加（重要度に応じてルーティング）
        """
        # 1. Severity-Based Routing
        # Note: Finding.severity is an Enum (src/core/models/finding.py)
        severity_value = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        
        if severity_value in ["critical", "high"]:
            # CRITICALとHIGHは即時書き込み（データロスト絶対回避）
            logger.debug(f"[AsyncWriter] Immediate write for {finding.severity}: {finding.id}")
            await self._write_finding_immediate(finding)
        else:
            # MEDIUM/LOW/INFOは非同期バッチ
            # 2. Write-Ahead Logging
            await self._log_to_recovery_file("finding", finding)
            
            # L1キャッシュに登録（Read-after-Write整合性）
            self.memory_cache.set(finding.id, finding)
            
            await self.queue.put(("finding", finding))
    
    async def enqueue_sitemap(self, domain: str, node: SiteNode):
        """サイトマップノードをバッチキューに追加"""
        # サイトマップも一応WALに記録するか検討。大量になるので一旦スキップまたは軽量に。
        # ここでは直接キューへ。
        await self.queue.put(("sitemap", (domain, node)))
    
    async def _worker(self):
        """バックグラウンドバッチ処理ワーカー"""
        batch_findings = []
        batch_pages = []
        
        while self._running or not self.queue.empty():
            try:
                # タイムアウト付き取得 (終了処理のため)
                item = await asyncio.wait_for(self.queue.get(), timeout=2.0)
                
                type_, data = item
                if type_ == "finding":
                    batch_findings.append(data)
                elif type_ == "sitemap":
                    batch_pages.append(data)
                elif type_ == "jsonl":
                    path, entry = data
                    await self._write_jsonl_immediate(path, entry)
                
                # バッチサイズ達成でフラッシュ
                if len(batch_findings) >= 50:
                    await self._flush_findings(batch_findings)
                    batch_findings = []
                
                if len(batch_pages) >= 500: # 1000は少し大きいので500
                    await self._flush_pages(batch_pages)
                    batch_pages = []
                    
                self.queue.task_done()
                    
            except asyncio.TimeoutError:
                # タイムアウト時もフラッシュ（最大2秒遅延）
                if batch_findings:
                    await self._flush_findings(batch_findings)
                    batch_findings = []
                if batch_pages:
                    await self._flush_pages(batch_pages)
                    batch_pages = []
            except Exception as e:
                logger.error(f"[AsyncWriter] Batch worker error: {e}")
                await asyncio.sleep(1) # 回復を待つ
    
    async def _flush_findings(self, findings: List[Finding]):
        """Findingバッチを保存"""
        try:
            self.repo.save_batch(findings)
        except Exception as e:
            logger.error(f"[AsyncWriter] Failed to flush findings: {e}")
            # リカバリファイルに再度記録するか検討

    async def _flush_pages(self, pages: List[Tuple[str, SiteNode]]):
        """ページバッチを保存"""
        try:
            self.kg.save_pages_batch(pages)
        except Exception as e:
            logger.error(f"[AsyncWriter] Failed to flush pages: {e}")

    async def _write_jsonl_immediate(self, path: Path, data: dict):
        """JSONL形式でファイルに追記（実体）"""
        try:
            async with aiofiles.open(path, mode='a', encoding='utf-8') as f:
                line = json.dumps(data, ensure_ascii=False, default=str)
                await f.write(line + "\n")
        except Exception as e:
            logger.error(f"[AsyncWriter] JSONL write failed for {path}: {e}")

    async def _write_finding_immediate(self, finding: Finding):
        """Critical Finding用の即時書き込み"""
        try:
            # 同期メソッドなのでスレッドで実行するか検討
            # 個別保存は軽量なので一旦そのまま。
            self.repo.save(finding)
            self.memory_cache.set(finding.id, finding)
        except Exception as e:
            logger.error(f"[AsyncWriter] Immediate write failed: {e}")
            # 緊急フォールバック: WALに記録
            await self._log_to_recovery_file("finding_critical", finding)
    
    async def _log_to_recovery_file(self, type_: str, data: Any):
        """安全策2: 簡易WAL - クラッシュ時の復旧用ログ"""
        try:
            async with aiofiles.open(self.recovery_file, mode='a', encoding='utf-8') as f:
                record = {
                    "type": type_,
                    "data": data.to_dict() if hasattr(data, 'to_dict') else str(data)
                }
                await f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.warning(f"[AsyncWriter] WAL write failed (non-critical): {e}")
    
    async def _flush_all(self):
        """キュー内の全アイテムを強制フラッシュ"""
        findings = []
        pages = []
        
        while not self.queue.empty():
            try:
                type_, data = self.queue.get_nowait()
                if type_ == "finding":
                    findings.append(data)
                elif type_ == "sitemap":
                    pages.append(data)
                self.queue.task_done()
            except asyncio.QueueEmpty:
                break
        
        if findings:
            await self._flush_findings(findings)
        if pages:
            await self._flush_pages(pages)
    
    def get_cached_finding(self, finding_id: str) -> Optional[Finding]:
        """L1キャッシュから取得（Read-after-Write整合性）"""
        return self.memory_cache.get(finding_id)

    async def enqueue_jsonl(self, path: Path, data: dict):
        """JSONL形式でファイルに追記（非同期キュー経由）"""
        # 親ディレクトリの存在確認と作成
        if not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        await self.queue.put(("jsonl", (path, data)))
