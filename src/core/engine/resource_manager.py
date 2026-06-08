"""
System Resource Manager - 自律的リソース管理

システムリソース (CPU/メモリ) とタスク遅延を監視し、
ParallelOrchestrator の並列数とレート制限を動的に調整する。
"""

import logging
import threading
import time
import gc
from typing import Optional
from dataclasses import dataclass

import psutil

from src.config import settings
from src.core.engine.parallel_orchestrator import ParallelOrchestrator

logger = logging.getLogger(__name__)


@dataclass
class ResourceMetrics:
    """リソースメトリクス"""
    cpu_percent: float
    memory_percent: float
    timestamp: float


class SystemResourceManager:
    """
    システムリソースマネージャー (Singleton)

    責務:
    1. システム全体のヘルスチェック (CPU/Memory)
    2. メモリ不足時の緊急ブレーキ (OOM 回避)
    3. 余裕がある時のアクセル (スループット向上)
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(SystemResourceManager, cls).__new__(cls)
        return cls._instance

    def __init__(self, orchestrator: Optional[ParallelOrchestrator] = None):
        if hasattr(self, "_initialized"):
            if orchestrator:
                self.orchestrator = orchestrator
            return

        self._initialized = True
        self.orchestrator = orchestrator
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # 設定
        self.check_interval = 5.0  # 秒
        self.memory_threshold_critical = 85.0  # % (緊急ブレーキ)
        self.memory_threshold_high = 75.0      # % (スケールダウン開始)
        self.cpu_threshold_high = 80.0         # %

        # レイテンシ目標 (秒)
        self.target_latency = 1.0

        # 状態
        self.last_metrics: Optional[ResourceMetrics] = None
        self._consecutive_high_load = 0
        self._current_suggested_concurrency = 5  # 初期値
        self._last_update_time = 0

    @classmethod
    def get_instance(cls) -> 'SystemResourceManager':
        if cls._instance is None:
            cls._instance = SystemResourceManager()
        return cls._instance

    def get_suggested_concurrency(self) -> int:
        """
        現在のシステム状況に基づいた推奨同時実行数（バッチサイズ）を返す。
        """
        return self._current_suggested_concurrency

    def start(self):
        """監視ループを開始"""
        if not psutil: # psutil is now a hard dependency, so this check is technically redundant if it's always installed.
            logger.warning("psutil not found. Resource monitoring disabled.")
            return

        if self.running:
            return

        self.running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, name="ResourceManager", daemon=True)
        self._thread.start()
        logger.info("SystemResourceManager started.")

    def stop(self):
        """監視ループを停止"""
        self.running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)  # タイムアウトを延長
            if self._thread.is_alive():
                logger.warning("ResourceManager thread did not terminate gracefully")
        logger.info("SystemResourceManager stopped.")

    def set_orchestrator(self, orchestrator) -> None:
        """オーケストレーターを登録し、動的スケールを有効化"""
        self.orchestrator = orchestrator
        logger.info("ParallelOrchestrator linked to SystemResourceManager")

    def _monitor_loop(self):
        """監視メインループ"""
        while not self._stop_event.is_set():
            try:
                self._check_and_tune()
            except Exception as e:
                logger.error("Error in system monitoring loop: %s", e)

            self._stop_event.wait(self.check_interval)

    def _check_and_tune(self):
        """リソースチェックとチューニング実行"""
        # psutil is now a hard dependency, so this check is technically redundant if it's always installed.
        # However, keeping it for robustness in case of unexpected psutil issues.
        if not psutil:
            return

        # 1. リソース取得
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent

        self.last_metrics = ResourceMetrics(cpu, mem, time.time())

        # 2. 推奨並列数の動的調整
        self._adjust_global_concurrency(cpu, mem)

        # 3. 緊急ブレーキ判定
        if mem > self.memory_threshold_critical:
            self._emergency_brake(mem)
            return

        if not self.orchestrator:
            return

        # 4. 通常の Orchestrator カテゴリ調整
        self._tune_orchestrator(cpu, mem)

    def _adjust_global_concurrency(self, cpu: float, mem: float):
        """
        システム全体のスループット（Conductor のバッチサイズ）を調整
        """
        now = time.time()
        if now - self._last_update_time < 10: # 10 秒ごとの調整
            return

        old_val = self._current_suggested_concurrency

        # 上限を 15 に制限（LLM API 呼び出しの殺到防止）
        MAX_CONCURRENCY = 15

        # Scale UP: 余裕がある場合
        if cpu < 50.0 and mem < 70.0:
            new_val = min(MAX_CONCURRENCY, self._current_suggested_concurrency + 2)
            if new_val != self._current_suggested_concurrency:
                self._current_suggested_concurrency = new_val
                logger.info("🚀 Increasing global concurrency: %d -> %d", old_val, self._current_suggested_concurrency)

        # Scale DOWN: 負荷が高い場合
        elif cpu > 85.0 or mem > 85.0:
            self._current_suggested_concurrency = max(2, self._current_suggested_concurrency // 2)
            if old_val != self._current_suggested_concurrency:
                logger.warning("⚠️ Decreasing global concurrency due to load: %d -> %d", old_val, self._current_suggested_concurrency)

        self._last_update_time = now

    def _emergency_brake(self, mem_percent: float):
        """
        緊急ブレーキ：メモリ不足時の対応

        - GC 強制実行
        - 全カテゴリの並列数を半減
        - 推奨並列数を最小にする
        """
        logger.warning(f"CRITICAL MEMORY USAGE: {mem_percent}%. Engaging emergency brake!")

        # 1. GC 実行
        gc.collect()

        # 2. 推奨並列数を抑制
        self._current_suggested_concurrency = 2

        # 3. 並列数削減
        if self.orchestrator:
            for category, config in self.orchestrator.configs.items():
                if config.workers > 1:
                    new_workers = max(1, config.workers // 2)
                    self.orchestrator.update_config(category, workers=new_workers)
                    logger.warning(f"  [Brake] {category}: workers {config.workers} -> {new_workers}")

    def _tune_orchestrator(self, cpu: float, mem: float):
        """
        現状の負荷とレイテンシに基づいて並列数を微調整
        """
        if not hasattr(self.orchestrator, "configs"):
            return

        high_load = (cpu > self.cpu_threshold_high) or (mem > self.memory_threshold_high)

        if high_load:
            self._consecutive_high_load += 1
        else:
            self._consecutive_high_load = 0

        for category, config in self.orchestrator.configs.items():
            if category == "local" and high_load:
                continue

            metrics = self.orchestrator.get_category_metrics(category)
            if not metrics:
                continue

            avg_latency = metrics.get("avg_latency", 0.0)
            throttled = metrics.get("throttle_rate", 0.0) > 0.1

            # --- Tuning Logic ---

            # Case 1: Scale Down (負荷増 or 遅延大 or 429 多発)
            if high_load or (avg_latency > self.target_latency * 1.5) or throttled:
                if config.workers > config.min_workers:
                    if self._should_change(category, "down"):
                        new_workers = max(config.min_workers, config.workers - 1)
                        self.orchestrator.update_config(category, workers=new_workers)
                        logger.info(f"Scale DOWN {category}: {new_workers} (Lat: {avg_latency:.2f}s)")

            # Case 2: Scale Up (余裕あり & 低遅延)
            elif not high_load and (avg_latency < self.target_latency * 0.5) and not throttled:
                if config.workers < config.max_workers:
                    if self._should_change(category, "up"):
                        new_workers = min(config.max_workers, config.workers + 1)
                        self.orchestrator.update_config(category, workers=new_workers)
                        logger.info(f"Scale UP {category}: {new_workers} (Lat: {avg_latency:.2f}s)")

        # 4. 全体的な高負荷時の追加抑制
        if self._consecutive_high_load > 3:
            logger.warning("Consecutive High Load detected. Throttling all categories.")
            for category, config in self.orchestrator.configs.items():
                if config.workers > config.min_workers:
                    new_workers = max(config.min_workers, config.workers - 1)
                    self.orchestrator.update_config(category, workers=new_workers)
            self._consecutive_high_load = 0

    def _should_change(self, category: str, direction: str) -> bool:
        """ハンチング防止"""
        # 実装簡略化のため、現在は Cooldown チェックをスキップ
        return True
