"""
Parallel Orchestrator - 機能別並列オーケストレーター

機能カテゴリに応じて最適な並列度とレート制限を自動適用。
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Callable, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import asyncio

from src.config import settings
from src.core.engine.adaptive_rate_limiter import AdaptiveRateLimiter, get_rate_limiter

logger = logging.getLogger(__name__)



@dataclass
class TaskConfig:
    """タスク設定 (動的)"""
    category: str
    workers: int = 3
    min_workers: int = 1
    max_workers: int = 20
    rate_limit: float = 10.0  # requests per second
    base_rate_limit: float = 10.0
    
    
@dataclass
class ParallelTask:
    """並列タスク"""
    id: str
    func: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    category: str = "default"


@dataclass
class TaskResult:
    """タスク結果"""
    task_id: str
    success: bool
    result: Any = None
    error: str = ""
    elapsed: float = 0.0
    category: str = "default"


# カテゴリ別設定
CATEGORY_CONFIGS = {
    # Intel - パッシブ (外部API、DNSなど)
    "intel_passive": TaskConfig(category="intel_passive", workers=10, rate_limit=50),
    
    # Intel - アクティブ (クローリングなど)
    "intel_active": TaskConfig(category="intel_active", workers=3, rate_limit=10),
    
    # Attack - 認証系
    "attack_auth": TaskConfig(category="attack_auth", workers=2, rate_limit=5),
    
    # Attack - インジェクション系
    "attack_inject": TaskConfig(category="attack_inject", workers=2, rate_limit=3),
    
    # ローカル処理 (GPU等)
    "local": TaskConfig(category="local", workers=4, rate_limit=0),
    
    # デフォルト
    "default": TaskConfig(category="default", workers=3, rate_limit=10),
}


class ParallelOrchestrator:
    """
    機能別並列オーケストレーター
    
    自動的に最適な並列度とレート制限を適用。
    """
    
    def __init__(self):
        self._rate_limiters: Dict[str, AdaptiveRateLimiter] = {}
        self._results: List[TaskResult] = []
        # 設定のコピーを保持 (動的変更用)
        self.configs = {k: v for k, v in CATEGORY_CONFIGS.items()}
        self._lock = threading.Lock()
        
        # 共有エグゼキュータ (最大 20 スレッド)
        self._executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix="ShigokuParallel")
        
        # カテゴリ別セマフォ (Lazy Initialized)
        self._semaphores: Dict[str, asyncio.Semaphore] = {}
    
    def update_config(self, category: str, workers: int = None, rate_limit: float = None):
        """設定を動的に更新"""
        with self._lock:
            if category not in self.configs:
                return
            
            config = self.configs[category]
            if workers is not None:
                new_workers = max(config.min_workers, min(config.max_workers, workers))
                if new_workers != config.workers:
                    config.workers = new_workers
                    # セマフォを再生成 (新規タスクから新しい制限が適用される)
                    if category in self._semaphores:
                        self._semaphores[category] = asyncio.Semaphore(new_workers)
            
            if rate_limit is not None:
                config.rate_limit = rate_limit

    def get_category_metrics(self, category: str) -> Optional[dict]:
        """
        カテゴリ別のメトリクスを取得 (ResourceManager用)
        """
        # 直近100件の結果から計算
        with self._lock:
            recent_results = [r for r in self._results if r.category == category][-100:]
        
        if not recent_results:
            return None
            
        avg_latency = float(sum(r.elapsed for r in recent_results) / len(recent_results))
        
        limiter = self._rate_limiters.get(category)
        throttle_rate = 0.0
        if limiter:
            stats = limiter.get_stats()
            throttle_rate = stats.get("throttle_rate", 0.0)
            
        # セマフォから現在の空き状況を推測 (簡易的)
        active_tasks = 0
        if category in self._semaphores:
            sem = self._semaphores[category]
            active_tasks = max(0, self.configs[category].workers - sem._value)

        return {
            "avg_latency": avg_latency,
            "throttle_rate": throttle_rate,
            "active_tasks": active_tasks
        }

    def adjust_scaling(self, category: str, factor: float) -> None:
        """
        Resource Manager からの指令に基づきワーカー数を動的にスケール
        """
        with self._lock:
            config = self._get_config(category)
            new_workers = int(config.workers * factor)
            logger.info(f"Dynamic Scaling: Category '{category}' workers {config.workers} -> {new_workers}")
            self.update_config(category, workers=new_workers)
    
    def _get_config(self, category: str) -> TaskConfig:
        """カテゴリ設定取得"""
        return self.configs.get(category, self.configs["default"])
    
    def _get_rate_limiter(self, category: str) -> AdaptiveRateLimiter:
        """レートリミッター取得"""
        if category not in self._rate_limiters:
            self._rate_limiters[category] = get_rate_limiter(category)
        return self._rate_limiters[category]
    
    def _get_semaphore(self, category: str) -> asyncio.Semaphore:
        """カテゴリ別セマフォの取得（遅延初期化）"""
        if category not in self._semaphores:
            config = self._get_config(category)
            self._semaphores[category] = asyncio.Semaphore(config.workers)
        return self._semaphores[category]

    async def execute_parallel(
        self,
        tasks: List[ParallelTask],
        progress_callback: Callable[[int, int], None] = None,
        timeout: Optional[int] = None
    ) -> List[TaskResult]:
        """
        タスクをカテゴリ別に並列実行 (Worker Loop パターン)
        """
        if not tasks:
            return []

        import time
        import collections
        
        results: List[TaskResult] = []
        total_tasks = len(tasks)
        completed_tasks = 0
        
        # 1. カテゴリ別にタスクを整理
        queue_by_category = collections.defaultdict(list)
        for t in tasks:
            queue_by_category[t.category].append(t)

        def _execute_task_sync(ptask: ParallelTask) -> TaskResult:
            limiter = self._get_rate_limiter(ptask.category)
            target = ptask.kwargs.get("target") or (ptask.args[0] if ptask.args else None)
            limiter.wait(str(target) if target else None)
            
            task_start_time = time.time()
            try:
                res = ptask.func(*ptask.args, **ptask.kwargs)
                elapsed = time.time() - task_start_time
                status_code = 200
                if isinstance(res, dict):
                    status_code = res.get("status", res.get("status_code", 200))
                
                limiter.on_response(status_code, target=str(target) if target else None)
                return TaskResult(ptask.id, True, res, "", elapsed, ptask.category)
            except Exception as e:
                elapsed = time.time() - task_start_time
                logger.error(f"Task {ptask.id} failed: {e}")
                return TaskResult(ptask.id, False, None, str(e), elapsed, ptask.category)

        async def _run_task(ptask: ParallelTask):
            nonlocal completed_tasks
            sem = self._get_semaphore(ptask.category)
            
            async with sem:
                loop = asyncio.get_running_loop()
                res = await loop.run_in_executor(self._executor, _execute_task_sync, ptask)
                
                results.append(res)
                with self._lock:
                    self._results.append(res)
                
                completed_tasks += 1
                if progress_callback:
                    progress_callback(completed_tasks, total_tasks)
            return res

        # 2. 全タスクを開始
        task_futures = [asyncio.create_task(_run_task(t)) for t in tasks]

        # 3. 待機
        timeout_val = timeout if timeout is not None else getattr(settings, "parallel_batch_timeout", 600)
        try:
            await asyncio.wait(task_futures, timeout=timeout_val)
        except Exception as e:
            logger.error(f"Batch execution failed: {e}")
        finally:
            for tf in task_futures:
                if not tf.done():
                    tf.cancel()
        
        return results

        return results


def create_parallel_task(
    task_id: str,
    func: Callable,
    *args,
    category: str = "default",
    **kwargs
) -> ParallelTask:
    """並列タスク作成ヘルパー"""
    return ParallelTask(
        id=task_id,
        func=func,
        args=args,
        kwargs=kwargs,
        category=category
    )
