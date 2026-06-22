"""
External Tool Monitoring Dashboard

Phase E-2 Sprint 4: リアルタイム監視ダッシュボード
- セマフォ統計表示
- エラー率集計
- パフォーマンス推移
"""

import asyncio
import json
import time
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text

from src.cli.messages import msg

logger = logging.getLogger(__name__)


class MonitoringDashboard:
    """リアルタイム監視ダッシュボード"""
    
    def __init__(self, refresh_interval: float = 1.0):
        self.console = Console()
        self.refresh_interval = refresh_interval
        self.history: List[Dict] = []
        self.max_history = 100

    @staticmethod
    def _avg_wait_ms(stats: Dict) -> float:
        """正規キーから平均待機時間(ms)を返す。旧キーは期限付き互換。"""
        if "avg_waiting_time_ms" in stats:
            return float(stats.get("avg_waiting_time_ms", 0.0))
        if "avg_wait_ms" in stats:
            logger.warning(
                "Legacy stats key 'avg_wait_ms' is deprecated; use 'avg_waiting_time_ms' (removal target: 2026-08-31)."
            )
            return float(stats.get("avg_wait_ms", 0.0))
        return 0.0
        
    def create_semaphore_table(self, stats: Dict) -> Table:
        """セマフォ統計テーブル"""
        table = Table(
            title=msg("dashboard.semaphore_title"),
            header_style="bold cyan",
            border_style="dim"
        )
        
        table.add_column(msg("dashboard.col_metric"), style="cyan")
        table.add_column(msg("dashboard.col_value"), justify="right")
        table.add_column(msg("dashboard.col_status"))
        
        enabled = stats.get("enabled", False)
        max_concurrent = stats.get("max_concurrent", 0)
        current_active = stats.get("current_active", 0)
        total_executed = stats.get("total_executed", 0)
        avg_wait_ms = self._avg_wait_ms(stats)
        error_rate = stats.get("error_rate", 0.0)
        
        # 使用率
        utilization = (current_active / max_concurrent * 100) if max_concurrent > 0 else 0
        
        table.add_row(
            "Enabled",
            str(enabled),
            msg("dashboard.active") if enabled else msg("dashboard.disabled")
        )
        table.add_row(
            "Max Concurrent",
            str(max_concurrent),
            ""
        )
        table.add_row(
            "Current Active",
            str(current_active),
            f"{utilization:.1f}%"
        )
        table.add_row(
            "Total Executed",
            str(total_executed),
            ""
        )
        
        # 待ち時間（警告閾値: 500ms）
        wait_status = msg("dashboard.ok") if avg_wait_ms < 500 else msg("dashboard.high") if avg_wait_ms < 1000 else msg("dashboard.critical")
        table.add_row(
            "Avg Wait Time",
            f"{avg_wait_ms:.1f}ms",
            wait_status
        )
        
        # エラー率（警告閾値: 5%）
        error_status = msg("dashboard.ok") if error_rate < 0.05 else msg("dashboard.warning") if error_rate < 0.10 else msg("dashboard.critical")
        table.add_row(
            "Error Rate",
            f"{error_rate:.1%}",
            error_status
        )
        
        return table
    
    def create_tool_stats_table(self) -> Table:
        """ツール別統計テーブル"""
        table = Table(
            title=msg("dashboard.tool_stats_title"),
            header_style="bold green",
            border_style="dim"
        )
        
        table.add_column(msg("dashboard.col_tool"), style="green")
        table.add_column(msg("dashboard.col_executions"), justify="right")
        table.add_column(msg("dashboard.col_success_rate"), justify="right")
        table.add_column(msg("dashboard.col_avg_time"), justify="right")
        table.add_column(msg("dashboard.col_status"))
        
        # ツール別集計（履歴から）
        tool_stats = defaultdict(lambda: {"total": 0, "success": 0, "total_time": 0})
        
        for entry in self.history:
            tool = entry.get("tool", "unknown")
            tool_stats[tool]["total"] += 1
            if entry.get("success"):
                tool_stats[tool]["success"] += 1
            tool_stats[tool]["total_time"] += entry.get("time_ms", 0)
        
        for tool, stats in sorted(tool_stats.items()):
            total = stats["total"]
            success = stats["success"]
            success_rate = success / total * 100 if total > 0 else 0
            avg_time = stats["total_time"] / total if total > 0 else 0
            
            status = msg("dashboard.ok") if success_rate >= 95 else msg("dashboard.warning") if success_rate >= 80 else msg("dashboard.critical")
            
            table.add_row(
                tool,
                str(total),
                f"{success_rate:.1f}%",
                f"{avg_time:.0f}ms",
                status
            )
        
        if not tool_stats:
            table.add_row(msg("dashboard.no_data"), "-", "-", "-", "⏳")
        
        return table
    
    def create_recent_executions_table(self) -> Table:
        """最近の実行テーブル"""
        table = Table(
            title=msg("dashboard.recent_title"),
            header_style="bold yellow",
            border_style="dim"
        )
        
        table.add_column(msg("dashboard.col_time"), style="dim")
        table.add_column(msg("dashboard.col_tool"), style="yellow")
        table.add_column(msg("dashboard.col_target"), max_width=30)
        table.add_column(msg("dashboard.col_result"))
        table.add_column(msg("dashboard.col_duration"), justify="right")
        
        recent = list(reversed(self.history[-10:]))
        
        for entry in recent:
            time_str = datetime.fromtimestamp(entry.get("timestamp", 0)).strftime("%H:%M:%S")
            status = msg("dashboard.ok") if entry.get("success") else msg("dashboard.critical")
            
            table.add_row(
                time_str,
                entry.get("tool", "?"),
                entry.get("target", "?")[:30],
                f"{status} {entry.get('status', '?')}",
                f"{entry.get('time_ms', 0):.0f}ms"
            )
        
        if not recent:
            table.add_row("-", "-", msg("dashboard.no_recent"), "-", "-")
        
        return table
    
    def create_alert_panel(self, stats: Dict) -> Panel:
        """アラートパネル"""
        alerts = []
        
        # セマフォ待ち時間警告
        avg_wait_ms = self._avg_wait_ms(stats)
        if avg_wait_ms > 500:
            alerts.append(msg("dashboard.alert_high_wait", time=avg_wait_ms))
            alerts.append(msg("dashboard.alert_high_wait_hint"))
        
        # エラー率警告
        error_rate = stats.get("error_rate", 0)
        if error_rate > 0.05:
            alerts.append(msg("dashboard.alert_high_error", rate=error_rate))
            alerts.append(msg("dashboard.alert_high_error_hint"))
        
        # 使用率警告
        max_concurrent = stats.get("max_concurrent", 1)
        current_active = stats.get("current_active", 0)
        utilization = current_active / max_concurrent if max_concurrent > 0 else 0
        if utilization > 0.8:
            alerts.append(msg("dashboard.alert_high_utilization", utilization=utilization))
            alerts.append(msg("dashboard.alert_high_utilization_hint"))
        
        if not alerts:
            content = Text(msg("dashboard.alert_all_ok"), style="green")
        else:
            content = Text("\n".join(alerts), style="yellow")
        
        return Panel(
            content,
            title="Alerts",
            border_style="yellow" if alerts else "green"
        )
    
    def get_current_stats(self) -> Dict:
        """現在の統計を取得"""
        try:
            from src.core.adapters.external.external_tool_executor import get_global_executor
            executor = get_global_executor()
            return executor.get_semaphore_stats()
        except Exception as e:
            return {
                "enabled": False,
                "error": str(e)
            }
    
    def update(self) -> Layout:
        """画面レイアウトを更新"""
        stats = self.get_current_stats()
        
        # セマフォテーブル
        semaphore_table = self.create_semaphore_table(stats)
        
        # ツール統計
        tool_table = self.create_tool_stats_table()
        
        # 最近の実行
        recent_table = self.create_recent_executions_table()
        
        # アラート
        alert_panel = self.create_alert_panel(stats)
        
        # レイアウト構築
        layout = Layout()
        
        # 左列: セマフォ統計
        layout.split_column(
            Layout(name="upper"),
            Layout(name="lower")
        )
        
        layout["upper"].split_row(
            Layout(semaphore_table, name="semaphore"),
            Layout(tool_table, name="tools")
        )
        
        layout["lower"].split_row(
            Layout(recent_table, name="recent"),
            Layout(alert_panel, name="alerts")
        )
        
        return layout
    
    def record_execution(self, tool: str, target: str, status: str, success: bool, time_ms: float):
        """実行履歴を記録"""
        self.history.append({
            "timestamp": time.time(),
            "tool": tool,
            "target": target,
            "status": status,
            "success": success,
            "time_ms": time_ms
        })
        
        # 履歴制限
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history:]
    
    async def run_live(self, duration: Optional[float] = None):
        """ライブダッシュボードを実行"""
        self.console.print(msg("dashboard.header"))
        self.console.print(msg("dashboard.exit_hint") + "\n")
        
        start_time = time.time()
        
        with Live(self.update(), refresh_per_second=1/self.refresh_interval) as live:
            try:
                while True:
                    await asyncio.sleep(self.refresh_interval)
                    live.update(self.update())
                    
                    # 時間制限チェック
                    if duration and (time.time() - start_time) > duration:
                        break
                        
            except KeyboardInterrupt:
                self.console.print("\n" + msg("dashboard.stopped"))
    
    def export_report(self, filepath: str):
        """レポートをエクスポート"""
        stats = self.get_current_stats()
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "semaphore_stats": stats,
            "tool_statistics": self._calculate_tool_stats(),
            "recent_executions": self.history[-20:],
            "alerts": self._generate_alerts_list(stats)
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.console.print(msg("dashboard.exported", path=filepath))
    
    def _calculate_tool_stats(self) -> Dict:
        """ツール別統計を計算"""
        tool_stats = defaultdict(lambda: {"total": 0, "success": 0, "total_time": 0})
        
        for entry in self.history:
            tool = entry.get("tool", "unknown")
            tool_stats[tool]["total"] += 1
            if entry.get("success"):
                tool_stats[tool]["success"] += 1
            tool_stats[tool]["total_time"] += entry.get("time_ms", 0)
        
        # 平均計算
        result = {}
        for tool, stats in tool_stats.items():
            total = stats["total"]
            result[tool] = {
                "total": total,
                "success": stats["success"],
                "success_rate": stats["success"] / total if total > 0 else 0,
                "avg_time_ms": stats["total_time"] / total if total > 0 else 0
            }
        
        return result
    
    def _generate_alerts_list(self, stats: Dict) -> List[str]:
        """アラートリストを生成"""
        alerts = []
        
        avg_wait_ms = self._avg_wait_ms(stats)
        if avg_wait_ms > 500:
            alerts.append(f"HIGH_WAIT_TIME: {avg_wait_ms:.1f}ms > 500ms")
        
        error_rate = stats.get("error_rate", 0)
        if error_rate > 0.05:
            alerts.append(f"HIGH_ERROR_RATE: {error_rate:.1%} > 5%")
        
        return alerts


# CLI実行用
if __name__ == "__main__":
    import sys
    
    dashboard = MonitoringDashboard(refresh_interval=1.0)
    
    # コマンドライン引数
    if len(sys.argv) > 1 and sys.argv[1] == "--export":
        # 単発レポート出力
        dashboard.export_report("monitoring_report.json")
    else:
        # ライブモード
        try:
            asyncio.run(dashboard.run_live())
        except KeyboardInterrupt:
            print(msg("dashboard.exiting"))
