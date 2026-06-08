from typing import List, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from src.core.engine.master_conductor import Task, TaskState

class ExecutionSummary:
    """
    実行結果の詳細なサマリーを表示するクラス。
    各タスクで何が実行され、どのような結果になったかを一覧表示する。
    """
    def __init__(self, completed_tasks: List[Task], context: Any):
        self.completed_tasks = completed_tasks
        self.context = context
        self.console = Console()

    def display(self):
        """サマリーをコンソールに表示"""
        self._print_header()
        self._print_stats()
        self._print_task_table()
        self._print_findings()

    def _print_header(self):
        """ヘッダー表示"""
        self.console.print("\n")
        self.console.print(Panel("[bold cyan]🛡️  SHIGOKU Execution Report[/bold cyan]", border_style="cyan"))

    def _print_stats(self):
        """統計情報表示"""
        total = len(self.completed_tasks)
        success = len([t for t in self.completed_tasks if t.state == TaskState.SUCCESS])
        failed = len([t for t in self.completed_tasks if t.state == TaskState.FAILED])
        
        # 簡易的な統計
        # grid = Table.grid(expand=True)
        # grid.add_column()
        # grid.add_column(justify="right")
        # grid.add_row("[bold]Total Tasks:[/bold]", str(total))
        # grid.add_row("[bold green]Success:[/bold green]", str(success))
        # grid.add_row("[bold red]Failed:[/bold red]", str(failed))
        
        self.console.print(f"Total: [bold]{total}[/bold] | Success: [bold green]{success}[/bold green] | Failed: [bold red]{failed}[/bold red]")
        self.console.print("\n")

    def _print_task_table(self):
        """詳細タスクテーブル表示"""
        table = Table(title="Task Execution Details", show_lines=True, header_style="bold magenta")
        
        table.add_column("Task ID", style="dim", width=20)
        table.add_column("Action / Command", style="cyan")
        table.add_column("Result / LLM Conclusion", style="white")
        table.add_column("Status", width=10)

        for task in self.completed_tasks:
            # Action (コマンド) の抽出
            action_summary = self._extract_action(task)
            
            # Result (LLMの結論) の抽出
            result_summary = self._extract_result(task)
            
            # Status Style
            status_style = "green" if task.state == TaskState.SUCCESS else "red"
            status_text = f"[{status_style}]{task.state.value}[/{status_style}]"

            table.add_row(
                task.id,
                action_summary,
                result_summary,
                status_text
            )
        
        self.console.print(table)

    def _extract_action(self, task: Task) -> str:
        """タスクから実行されたアクション（コマンド等）を抽出"""
        # 1. ログからコマンドを探す (簡易実装: result.dataにコマンドが含まれていると仮定)
        # TODO: よりstructuredな保存方法があればそこから取る
        
        # Task ParamsからActionの意図を取得
        if task.params and "instruction" in task.params:
             # 長すぎる場合は切り詰め
            instr = task.params["instruction"].split('\n')[0]
            return f"[italic]{instr}[/italic]"
        
        return "N/A"

    def _extract_result(self, task: Task) -> str:
        """タスクの結果（LLMの応答やエラー）を抽出"""
        if task.error:
            return f"[red]{task.error}[/red]"
        
        if task.result:
            data = None
            # オブジェクトの場合
            if hasattr(task.result, 'data'):
                data = task.result.data
            # 辞書の場合 (JSONロード時)
            elif isinstance(task.result, dict) and "data" in task.result:
                data = task.result["data"]
            # その他の場合 (result自体がデータかも)
            elif isinstance(task.result, (str, int, float, bool)):
                data = task.result
                
            if data:
                notes = self._extract_injection_notes(task)
                data_str = str(data)

                if notes:
                    max_total = 300
                    note_block = f"\n{notes}"
                    reserved = len(note_block)
                    max_data_len = max(60, max_total - reserved)
                    if len(data_str) > max_data_len:
                        data_str = data_str[:max_data_len] + "..."
                    return f"{data_str}{note_block}"

                # エージェントの応答テキストを抽出
                # 通常、LLMの応答は長いので要約するか、重要な部分だけ抜粋したい
                # ここではシンプルに先頭200文字
                if len(data_str) > 300:
                    return data_str[:300] + "..."
                return data_str
        
        return "[dim]No output[/dim]"

    def _extract_injection_notes(self, task: Task) -> str:
        """Injection 実行ログから tested_params / blind / authz 差分を抽出して短く表示"""
        original_result_obj = task.result
        result_obj = original_result_obj
        if hasattr(result_obj, "data"):
            result_obj = result_obj.data

        if not isinstance(result_obj, dict):
            return ""

        data = result_obj.get("data", result_obj)
        if not isinstance(data, dict):
            return ""

        execution_log = data.get("execution_log", [])
        if not isinstance(execution_log, list):
            return ""

        tested_parts: List[str] = []
        blind_parts: List[str] = []
        for entry in execution_log:
            if not isinstance(entry, dict):
                continue
            url_results = entry.get("url_results", [])
            if not isinstance(url_results, list):
                continue
            for item in url_results:
                if not isinstance(item, dict):
                    continue

                url = item.get("url", "")
                tested_params = item.get("tested_params", [])
                if tested_params:
                    params_str = ", ".join(str(p) for p in tested_params)
                    tested_parts.append(f"{url} [{params_str}]")

                blind_correlation = item.get("blind_correlation", {})
                blind_summary = self._format_blind_summary(blind_correlation)
                if blind_summary:
                    blind_parts.append(f"{url} ({blind_summary})")

        authz_parts = self._extract_authz_differential_notes(original_result_obj, data)
        timeout_kpi = self._extract_timeout_kpi_note(execution_log)

        notes: List[str] = []
        if tested_parts:
            notes.append("tested_params: " + " | ".join(tested_parts[:2]))
        if blind_parts:
            notes.append("blind: " + " | ".join(blind_parts[:2]))
        if authz_parts:
            notes.append("authz_diff: " + " | ".join(authz_parts[:2]))
        if timeout_kpi:
            notes.append(timeout_kpi)

        if not notes:
            return ""

        return "\n".join(notes)

    def _extract_timeout_kpi_note(self, execution_log: Any) -> str:
        if not isinstance(execution_log, list):
            return ""

        total = 0
        timeout = 0
        completed = 0
        error = 0
        retry_total = 0

        for entry in execution_log:
            if not isinstance(entry, dict):
                continue
            url_results = entry.get("url_results", [])
            if not isinstance(url_results, list):
                continue
            for item in url_results:
                if not isinstance(item, dict):
                    continue
                total += 1
                status = str(item.get("status", "")).lower()
                if status == "timeout":
                    timeout += 1
                elif status in {"completed", "cache_hit"}:
                    completed += 1
                elif status == "error":
                    error += 1
                retry_total += int(item.get("retry_count", 0) or 0)

        if total == 0:
            return ""

        timeout_rate = (timeout / total) * 100.0
        avg_retry = retry_total / total
        return (
            f"timeout_kpi: total={total}, completed={completed}, timeout={timeout}, "
            f"error={error}, timeout_rate={timeout_rate:.1f}%, avg_retry={avg_retry:.2f}"
        )

    def _format_blind_summary(self, blind_correlation: Any) -> str:
        if not isinstance(blind_correlation, dict) or not blind_correlation:
            return ""

        time_based = blind_correlation.get("time_based", {}) if isinstance(blind_correlation.get("time_based"), dict) else {}
        oob = blind_correlation.get("oob", {}) if isinstance(blind_correlation.get("oob"), dict) else {}
        correlated = bool(blind_correlation.get("correlated"))

        parts: List[str] = []
        parts.append("T✅" if time_based.get("confirmed") else "T❌")
        parts.append("O✅" if oob.get("confirmed") else "O❌")

        observed_latency = time_based.get("observed_latency_seconds")
        if observed_latency is not None:
            parts.append(f"lat={observed_latency}s")
        hits = oob.get("hits", []) if isinstance(oob.get("hits"), list) else []
        if hits:
            parts.append(f"hits={len(hits)}")
        if correlated:
            parts.append("correlated")

        return "; ".join(parts)

    def _extract_authz_differential_notes(self, result_obj: Any, data: Any) -> List[str]:
        findings: List[Any] = []

        # 1) top-level result object (dict shape from serialized sessions)
        if isinstance(result_obj, dict):
            top_findings = result_obj.get("findings", [])
            if isinstance(top_findings, list):
                findings.extend(top_findings)

        # 2) object shape (SwarmResult-like)
        obj_findings = getattr(result_obj, "findings", None)
        if isinstance(obj_findings, list):
            findings.extend(obj_findings)

        # 3) nested data payload
        if isinstance(data, dict):
            data_findings = data.get("findings", [])
            if isinstance(data_findings, list):
                findings.extend(data_findings)

        authz_parts: List[str] = []
        for finding in findings:
            if isinstance(finding, dict):
                additional_info = finding.get("additional_info", {})
            else:
                additional_info = getattr(finding, "additional_info", {})
            if not isinstance(additional_info, dict):
                continue
            differential = additional_info.get("authz_differential", {})
            if not isinstance(differential, dict) or not differential:
                continue

            scenario = differential.get("scenario", "authz_differential")
            confidence = differential.get("confidence")
            original_id = differential.get("original_id")
            test_id = differential.get("test_id")
            baseline_status = differential.get("baseline_status")
            test_status = differential.get("test_status")

            detail_tokens: List[str] = []
            if confidence is not None:
                detail_tokens.append(f"score={confidence}")
            if original_id is not None or test_id is not None:
                detail_tokens.append(f"id={original_id}->{test_id}")
            if baseline_status is not None or test_status is not None:
                detail_tokens.append(f"status={baseline_status}->{test_status}")

            signals = self._normalize_authz_signals(differential.get("signals", []))
            if signals:
                detail_tokens.append(f"signals={','.join(signals)}")

            if detail_tokens:
                authz_parts.append(f"{scenario} ({', '.join(detail_tokens)})")
            else:
                authz_parts.append(str(scenario))

        return authz_parts

    def _normalize_authz_signals(self, raw_signals: Any) -> List[str]:
        if not isinstance(raw_signals, list):
            return []

        normalized: List[str] = []
        for signal in raw_signals:
            if isinstance(signal, str):
                token = signal.strip()
                if token:
                    normalized.append(token)
                continue

            if isinstance(signal, dict):
                name = str(signal.get("name", "") or "").strip()
                if name:
                    normalized.append(name)

        deduped: List[str] = []
        for token in normalized:
            if token not in deduped:
                deduped.append(token)

        return deduped

    def _print_findings(self):
        """発見された脆弱性（もしあれば）"""
        # 現状、MasterConductorのcontextからfindingsを取る必要があるが
        # 簡易的に実装
        pass

def print_execution_summary(completed_tasks: List[Task], context: Any):
    """ヘルパー関数"""
    summary = ExecutionSummary(completed_tasks, context)
    summary.display()
