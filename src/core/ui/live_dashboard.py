"""
LiveDashboard: リアルタイム実行ダッシュボード

Rich Liveコンポーネントを使用してCLI実行状況をリアルタイム表示する。
EventBusからイベントを購読し、UIを更新する。

Phase 5: リアルタイム実行モニタリング
"""
from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from queue import Queue
from typing import Optional

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from src.core.infra.event_bus import Event, EventBus, EventType, get_event_bus

logger = logging.getLogger(__name__)


@dataclass
class ActivityLogEntry:
    """アクティビティログエントリ"""
    timestamp: float
    category: str  # TASK, RECON, LLM, SPECIALIST, ERROR
    message: str
    level: str = "info"  # info, warning, error
    
    def formatted_time(self) -> str:
        """フォーマットされた時刻を返す"""
        return datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S")


class LiveDashboard:
    """
    リアルタイム実行ダッシュボード
    
    EventBusからイベントを購読し、Richを使用してターミナルにリアルタイム表示する。
    
    使用例:
        dashboard = LiveDashboard()
        await dashboard.start()
        # ... 実行 ...
        await dashboard.stop()
    """
    
    MAX_LOG_ENTRIES = 15
    
    def __init__(self, event_bus: Optional[EventBus] = None):
        """
        初期化
        
        Args:
            event_bus: EventBusインスタンス（Noneの場合はシングルトンを使用）
        """
        self.event_bus = event_bus or get_event_bus()
        self.console = Console()
        
        # 状態管理
        self.activity_log: list[ActivityLogEntry] = []
        self.current_task: Optional[str] = None
        self.current_agent: Optional[str] = None
        self.current_target: Optional[str] = None
        self.llm_status: str = "待機中"
        self.llm_last_call: Optional[float] = None
        self.errors: list[str] = []
        
        # 統計
        self.task_count: int = 0
        self.completed_count: int = 0
        self.finding_count: int = 0
        self.findings_list: list[dict] = []
        
        # スレッド間通信用キュー
        self._event_queue: Queue[Event] = Queue()
        
        # 制御フラグ
        self._running: bool = False
        self._live: Optional[Live] = None
        self._update_thread: Optional[threading.Thread] = None
    
    def _add_log(self, category: str, message: str, level: str = "info") -> None:
        """アクティビティログにエントリを追加"""
        entry = ActivityLogEntry(
            timestamp=time.time(),
            category=category,
            message=message,
            level=level,
        )
        self.activity_log.append(entry)
        
        # 最大件数を超えたら古いものを削除
        if len(self.activity_log) > self.MAX_LOG_ENTRIES:
            self.activity_log = self.activity_log[-self.MAX_LOG_ENTRIES:]
    
    async def _handle_event(self, event: Event) -> None:
        """イベントを処理してUIを更新"""
        self._event_queue.put(event)
    
    def _process_event(self, event: Event) -> None:
        """イベントを処理（メインスレッド）"""
        event_type = event.type
        payload = event.payload
        
        # タスク開始
        if event_type == EventType.TASK_STARTED:
            self.current_task = payload.get("task_name", "Unknown")
            self.current_agent = payload.get("agent", "")
            self.current_target = payload.get("target", "")
            self.task_count += 1
            self._add_log("TASK", f"開始: {self.current_task} → {self.current_agent}")
        
        # タスク完了
        elif event_type == EventType.TASK_COMPLETED:
            task_name = payload.get("task_name", "Unknown")
            self.completed_count += 1
            self._add_log("TASK", f"完了: {task_name}")
            self.current_task = None
        
        # タスク失敗
        elif event_type == EventType.TASK_FAILED:
            task_name = payload.get("task_name", "Unknown")
            error = payload.get("error", "")
            failure_category = str(payload.get("failure_category", "") or "")
            category_suffix = f" [{failure_category}]" if failure_category else ""
            self._add_log("TASK", f"失敗: {task_name}{category_suffix} - {error}", level="error")
            self.current_task = None
        
        # LLMコール開始
        elif event_type == EventType.LLM_CALL_START:
            model = payload.get("model", "Unknown")
            self.llm_status = f"実行中: {model}"
            self.llm_last_call = time.time()
            self._add_log("LLM", f"呼出し開始: {model}")
        
        # LLMコール終了
        elif event_type == EventType.LLM_CALL_END:
            model = payload.get("model", "Unknown")
            duration = payload.get("duration", 0)
            self.llm_status = f"完了 ({duration:.1f}s)"
            self._add_log("LLM", f"呼出し完了: {model} ({duration:.1f}s)")
        
        # LLMエラー
        elif event_type == EventType.LLM_ERROR:
            error = payload.get("error", "Unknown error")
            self.llm_status = f"⚠️ エラー"
            self.errors.append(error)
            self._add_log("LLM", f"エラー: {error}", level="error")
        
        # 意思決定
        elif event_type == EventType.DECISION_MADE:
            decision = payload.get("decision", "")
            reason = payload.get("reason", "")
            self._add_log("判断", f"{decision}: {reason}")
        
        # Reconステップ開始
        elif event_type == EventType.RECON_STEP_START:
            step = payload.get("step", "?")
            name = payload.get("name", "Unknown")
            self._add_log("RECON", f"Step {step} 開始: {name}")
        
        # Reconステップ終了
        elif event_type == EventType.RECON_STEP_END:
            step = payload.get("step", "?")
            name = payload.get("name", "Unknown")
            result = payload.get("result", "")
            self._add_log("RECON", f"Step {step} 完了: {result}")
        
        # Specialist実行
        elif event_type == EventType.SPECIALIST_EXECUTE:
            specialist = payload.get("specialist", "Unknown")
            target = payload.get("target", "")
            self._add_log("SPEC", f"{specialist} → {target[:50]}")
        
        # 脆弱性発見
        elif event_type == EventType.VULN_FOUND:
            severity = payload.get("severity", "").upper()
            title = payload.get("title", "Unknown")
            schema_severity = str(payload.get("schema_severity", "") or "")
            schema_note = f" schema={schema_severity}" if schema_severity and schema_severity != "none" else ""
            self.finding_count += 1
            self.findings_list.append({"severity": severity, "title": title})
            self._add_log("発見", f"🔥 [{severity}] {title}{schema_note}", level="warning")
        
        # アセット発見
        elif event_type == EventType.ASSET_FOUND:
            url = payload.get("url", "")
            self._add_log("発見", f"アセット: {url[:60]}")
        
        # エラー
        elif event_type == EventType.ERROR_OCCURRED:
            error = payload.get("error", "Unknown error")
            self.errors.append(error)
            self._add_log("ERROR", error, level="error")
        elif event_type == EventType.FLAKY_QUARANTINE_RELEASED:
            who = str(payload.get("who", "unknown") or "unknown")
            why = str(payload.get("why", "unknown") or "unknown")
            self._add_log("TASK", f"隔離解除: {who} ({why})")
    
    def _build_layout(self) -> Layout:
        """Richレイアウトを構築"""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=5),
            Layout(name="main_area", ratio=1),
            Layout(name="footer", size=3),
        )
        
        layout["main_area"].split_row(
            Layout(name="main", ratio=2),
            Layout(name="side", ratio=1),
        )
        
        # ヘッダー: 現在のタスク
        if self.current_task:
            task_text = Text()
            task_text.append("▶ ", style="green bold")
            task_text.append(self.current_task, style="white bold")
            if self.current_agent:
                task_text.append(f" → ", style="dim")
                task_text.append(self.current_agent, style="cyan")
            if self.current_target:
                task_text.append(f"\n  Target: ", style="dim")
                task_text.append(self.current_target[:60], style="yellow")
        else:
            task_text = Text("待機中...", style="dim italic")
        
        header_panel = Panel(
            task_text,
            title="[bold blue]Current Task[/bold blue]",
            border_style="blue",
        )
        layout["header"].update(header_panel)
        
        # メイン: アクティビティログ
        log_table = Table(show_header=False, expand=True, box=None)
        log_table.add_column("Time", width=8, style="dim")
        log_table.add_column("Category", width=8)
        log_table.add_column("Message", ratio=1)
        
        for entry in reversed(self.activity_log[-self.MAX_LOG_ENTRIES:]):
            # カテゴリの色分け
            cat_style = {
                "TASK": "cyan",
                "RECON": "green",
                "LLM": "magenta",
                "SPEC": "yellow",
                "判断": "blue",
                "発見": "red bold",
                "ERROR": "red",
            }.get(entry.category, "white")
            
            # レベルによるメッセージスタイル
            msg_style = {
                "info": "white",
                "warning": "yellow",
                "error": "red",
            }.get(entry.level, "white")
            
            log_table.add_row(
                entry.formatted_time(),
                Text(entry.category, style=cat_style),
                Text(entry.message, style=msg_style),
            )
        
        main_panel = Panel(
            log_table,
            title="[bold green]Activity Log[/bold green]",
            border_style="green",
        )
        layout["main"].update(main_panel)
        
        # サイド: 脆弱性ツリー
        vuln_tree = Tree("Exploit Chains & Findings")
        if not self.findings_list:
            vuln_tree.add(Text("No vulnerabilities found yet.", style="dim italic"))
        else:
            # 簡略化のためフラットに表示（本来はRelated Findingsからツリーを組む）
            for vuln in self.findings_list:
                sev = vuln["severity"].lower()
                color = {
                    "critical": "red bold", "high": "orange1", 
                    "medium": "yellow", "low": "green", "info": "blue"
                }.get(sev, "white")
                vuln_tree.add(Text(f"[{vuln['severity']}] {vuln['title']}", style=color))
                
        side_panel = Panel(
            vuln_tree,
            title="[bold red]Vulnerabilities[/bold red]",
            border_style="red",
        )
        layout["side"].update(side_panel)
        
        # フッター: 統計とLLMステータス
        stats_text = Text()
        stats_text.append(f"Tasks: {self.completed_count}/{self.task_count}", style="cyan")
        stats_text.append(" | ", style="dim")
        stats_text.append(f"Findings: {self.finding_count}", style="red" if self.finding_count > 0 else "dim")
        stats_text.append(" | ", style="dim")
        
        # LLMステータスの色分け
        if "エラー" in self.llm_status:
            llm_style = "red bold"
        elif "実行中" in self.llm_status:
            llm_style = "yellow"
        else:
            llm_style = "green"
        stats_text.append(f"LLM: {self.llm_status}", style=llm_style)
        
        footer_panel = Panel(
            stats_text,
            title="[bold yellow]Stats[/bold yellow]",
            border_style="yellow",
        )
        layout["footer"].update(footer_panel)
        
        return layout
    
    def _update_loop(self) -> None:
        """UIを定期的に更新するスレッド"""
        while self._running:
            # キューからイベントを処理
            while not self._event_queue.empty():
                try:
                    event = self._event_queue.get_nowait()
                    self._process_event(event)
                except Exception:
                    pass
            
            # UI更新
            if self._live:
                try:
                    self._live.update(self._build_layout())
                except Exception as e:
                    logger.debug("Dashboard update error: %s", e)
            
            time.sleep(0.5)  # 500msごとに更新
    
    async def start(self) -> None:
        """ダッシュボードを開始"""
        if self._running:
            return
        
        self._running = True
        
        # イベント購読を設定（同期コールバックも対応）
        event_types = [
            EventType.TASK_STARTED,
            EventType.TASK_COMPLETED,
            EventType.TASK_FAILED,
            EventType.LLM_CALL_START,
            EventType.LLM_CALL_END,
            EventType.LLM_ERROR,
            EventType.DECISION_MADE,
            EventType.RECON_STEP_START,
            EventType.RECON_STEP_END,
            EventType.SPECIALIST_EXECUTE,
            EventType.VULN_FOUND,
            EventType.ASSET_FOUND,
            EventType.ERROR_OCCURRED,
            EventType.FLAKY_QUARANTINE_RELEASED,
        ]
        
        for event_type in event_types:
            self.event_bus.subscribe(event_type, self._handle_event)
        
        # EventBusの同期イベント購読（emit_sync対応）
        # EventBusにsync_subscribersを追加して直接呼び出す
        self._register_sync_handlers()
        
        # Richのライブ表示を開始
        self._live = Live(
            self._build_layout(),
            console=self.console,
            refresh_per_second=2,
            screen=False,  # スクリーンモードを使用しない（ログと共存）
        )
        self._live.start()
        
        # 更新スレッド開始
        self._update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self._update_thread.start()
        
        logger.info("LiveDashboard started")
    
    def _register_sync_handlers(self) -> None:
        """EventBusに同期ハンドラを登録（emit_sync対応）"""
        # EventBusにsync_emit_observerを追加
        if not hasattr(self.event_bus, '_sync_observers'):
            self.event_bus._sync_observers = []  # type: ignore
        self.event_bus._sync_observers.append(self._queue_event_sync)  # type: ignore
    
    def _queue_event_sync(self, event: Event) -> None:
        """同期的にイベントをキューに追加"""
        self._event_queue.put(event)
    
    async def stop(self) -> None:
        """ダッシュボードを停止"""
        self._running = False
        
        # 更新スレッド停止を待機
        if self._update_thread and self._update_thread.is_alive():
            self._update_thread.join(timeout=2.0)
        
        # Richのライブ表示を停止
        if self._live:
            self._live.stop()
            self._live = None
        
        # sync_observersから登録解除
        if hasattr(self.event_bus, '_sync_observers'):
            try:
                self.event_bus._sync_observers.remove(self._queue_event_sync)  # type: ignore
            except ValueError:
                pass
        
        logger.info("LiveDashboard stopped")
    
    def start_sync(self) -> None:
        """同期的にダッシュボードを開始（非asyncコンテキスト用）"""
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.start())
        finally:
            loop.close()
    
    def stop_sync(self) -> None:
        """同期的にダッシュボードを停止（非asyncコンテキスト用）"""
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.stop())
        finally:
            loop.close()


# シングルトンインスタンス（オプション）
_default_dashboard: Optional[LiveDashboard] = None


def get_live_dashboard() -> LiveDashboard:
    """デフォルトのLiveDashboardインスタンスを取得"""
    global _default_dashboard  # noqa: PLW0603
    if _default_dashboard is None:
        _default_dashboard = LiveDashboard()
    return _default_dashboard
