"""
RunNarrativeFormatter: S1 Run Ledger データから日本語 Markdown レポートを生成

セッション JSON → run_narrative.md への変換を行う。
すべてのセクションは日本語で記述され、欠損データに対しては
フォールバックメッセージを表示し、決してクラッシュしない。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from src.reporting.finding_extractor import extract_all_findings

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover - fallback only
    ZoneInfo = None

# ---------------------------------------------------------------------------
# Event type → Japanese label mapping
# ---------------------------------------------------------------------------

_EVENT_TYPE_JA: Dict[str, str] = {
    "decision_made": "意思決定",
    "swarm_dispatched": "Swarm派遣",
    "swarm_completed": "Swarm完了",
    "swarm_failed": "Swarm失敗",
    "swarm_merged": "Swarm統合",
    "swarm_skipped": "Swarmスキップ",
    "tool_executed": "ツール実行",
    "error_occurred": "エラー発生",
    "finding_created": "発見登録",
    "hitl_requested": "HITL要求",
    "hitl_resolved": "HITL解決",
    "llm_called": "LLM呼出",
    "llm_retry": "LLM再試行",
    "llm_failed": "LLM失敗",
    "llm_cache_hit": "LLMキャッシュHit",
    "provider_fallback": "Provider切替",
}

# ---------------------------------------------------------------------------
# Decision type → Japanese label mapping
# ---------------------------------------------------------------------------

_DECISION_TYPE_JA: Dict[str, str] = {
    "recon_dispatch": "偵察派遣選択",
    "vuln_hunter_dispatch": "脆弱性探索選択",
    "recipe_injection": "レシピ注入",
    "replan": "再計画",
    "priority_boost": "優先度上昇",
    "target_escalate": "ターゲット拡大",
    "skip_task": "タスクスキップ",
    "fallback": "フォールバック",
    # Phase 6 (SGK-2026-0315): Task pruning lifecycle — retired-like types
    "task_retired": "退役",
    "task_superseded": "差替",
    "task_invalidated": "無効化",
}

# ---------------------------------------------------------------------------
# Failed/retry event types for Section 6
# ---------------------------------------------------------------------------

_FAILURE_EVENT_TYPES = frozenset({"swarm_failed", "llm_failed", "error_occurred"})
_RETRY_EVENT_TYPES = frozenset({"llm_retry"})


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------

class RunNarrativeFormatter:
    """セッション JSON データを日本語 run_narrative.md へ変換するフォーマッタ"""

    def __init__(self) -> None:
        pass

    @staticmethod
    def _now_jst() -> datetime:
        if ZoneInfo is not None:
            try:
                return datetime.now(ZoneInfo("Asia/Tokyo"))
            except Exception:
                pass
        return datetime.now(timezone(timedelta(hours=9)))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def format(self, session_data: dict) -> str:
        """セッション JSON 辞書から run_narrative.md 文字列を生成する。

        Args:
            session_data: build_async_session_payload が生成したセッション辞書。

        Returns:
            Markdown 文字列（日本語）。
        """
        sd: Dict[str, Any] = session_data if isinstance(session_data, dict) else {}
        sections: List[str] = []

        sections.append(self._section_1_executive_summary(sd))
        sections.append(self._section_2_llm_usage(sd))
        sections.append(self._section_3_timeline(sd))
        sections.append(self._section_4_decision_traces(sd))
        sections.append(self._section_5_swarm_tool_execution(sd))
        sections.append(self._section_6_failures_and_retries(sd))
        sections.append(self._section_7_findings(sd))
        sections.append(self._section_8_next_actions(sd))
        sections.append(self._section_9_incomplete(sd))

        # Generate timestamp footer
        generated_at = self._now_jst().strftime("%Y-%m-%d %H:%M:%S JST")
        sections.append(f"---\n\n*Report generated at {generated_at} by SHIGOKU RunNarrativeFormatter*")

        return "\n\n".join(sections)

    # ------------------------------------------------------------------
    # Section 1: 実行概要
    # ------------------------------------------------------------------

    def _section_1_executive_summary(self, sd: Dict[str, Any]) -> str:
        lines = ["# 実行概要", ""]

        start_time = sd.get("start_time")
        timestamp = sd.get("timestamp")
        run_id = sd.get("run_id") or sd.get("context", {}).get("target_info", {}).get("run_id")
        if run_id:
            lines.append(f"- **実行ID**: `{run_id}`")

        if start_time is not None and timestamp is not None:
            try:
                start_dt = datetime.fromtimestamp(float(start_time), tz=timezone.utc)
                end_dt = datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
                duration = end_dt - start_dt
                jst_start = start_dt.astimezone(timezone(timedelta(hours=9)))
                jst_end = end_dt.astimezone(timezone(timedelta(hours=9)))
                lines.append(
                    f"- **セッション期間**: {jst_start.strftime('%Y-%m-%d %H:%M:%S')} 〜 "
                    f"{jst_end.strftime('%Y-%m-%d %H:%M:%S')} "
                    f"({self._format_duration(duration)})"
                )
            except (TypeError, ValueError, OSError):
                lines.append(f"- **セッション期間**: start={start_time}, end={timestamp}")

        # Phases (from unique run_ledger phases or completed_tasks phases)
        phases = self._collect_phases(sd)
        if phases:
            lines.append(f"- **フェーズ数**: {len(phases)} ({', '.join(sorted(phases))})")

        completed_tasks = sd.get("completed_tasks", [])
        if isinstance(completed_tasks, list):
            lines.append(f"- **完了タスク数**: {len(completed_tasks)}")

        all_findings = extract_all_findings(sd)
        if len(all_findings) > 0:
            lines.append(f"- **発見事項数**: {len(all_findings)}")
        else:
            lines.append(f"- **発見事項数**: 0")

        task_queue = sd.get("task_queue", [])
        if isinstance(task_queue, list) and task_queue:
            lines.append(f"- **未完了タスク数**: {len(task_queue)}")

        run_ledger = sd.get("run_ledger")
        if not isinstance(run_ledger, list):
            lines.append("")
            lines.append("> **注記**: S1 Run Ledgerデータが存在しません。基本的な実行概要のみ表示します。")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section 2: LLM使用量
    # ------------------------------------------------------------------

    def _section_2_llm_usage(self, sd: Dict[str, Any]) -> str:
        lines = ["## LLM使用量", ""]

        llm_summary = sd.get("llm_usage_summary")
        if not isinstance(llm_summary, dict) or not llm_summary:
            lines.append("LLM使用量データなし (No data in source session)")
            return "\n".join(lines)

        by_model = llm_summary.get("by_model", {})
        has_by_model = isinstance(by_model, dict) and len(by_model) > 0
        totals = llm_summary.get("totals", {})
        has_totals = isinstance(totals, dict) and any(
            int(totals.get(k, 0) or 0) > 0
            for k in ("input_tokens", "output_tokens", "input_cache_tokens", "call_count")
        )
        unknown_count = int(llm_summary.get("unknown_count", 0) or 0)
        estimated_count = int(llm_summary.get("estimated_count", 0) or 0)
        has_meta = unknown_count > 0 or estimated_count > 0

        if not has_by_model and not has_totals and not has_meta:
            lines.append("LLM使用量データなし (No data in source session)")
            return "\n".join(lines)

        if has_by_model:
            lines.append("| モデル | Input Tokens | Output Tokens | Cache Hit Tokens | 呼出回数 |")
            lines.append("|--------|-------------|---------------|------------------|---------|")
            for model, stats in sorted(by_model.items()):
                if not isinstance(stats, dict):
                    continue
                it = int(stats.get("input_tokens", 0) or 0)
                ot = int(stats.get("output_tokens", 0) or 0)
                ct = int(stats.get("input_cache_tokens", 0) or 0)
                cc = int(stats.get("call_count", 0) or 0)
                lines.append(f"| `{model}` | {it:,} | {ot:,} | {ct:,} | {cc:,} |")
            lines.append("")

        if isinstance(totals, dict):
            total_input = int(totals.get("input_tokens", 0) or 0)
            total_output = int(totals.get("output_tokens", 0) or 0)
            total_cache = int(totals.get("input_cache_tokens", 0) or 0)
            total_calls = int(totals.get("call_count", 0) or 0)

            cache_hit_ratio = float(llm_summary.get("cache_hit_ratio", 0.0) or 0.0)
            total_all_tokens = total_input + total_output + total_cache

            lines.append(f"- **総呼出回数**: {total_calls:,} 回")
            lines.append(f"- **総トークン数**: {total_all_tokens:,} (input={total_input:,} / output={total_output:,} / cache={total_cache:,})")
            lines.append(f"- **キャッシュヒット率**: {cache_hit_ratio * 100:.1f}%")

        if unknown_count > 0:
            lines.append(f"- **使用量不明の呼出**: {unknown_count} 回 (No data from provider)")
        if estimated_count > 0:
            lines.append(f"- **推定値の呼出**: {estimated_count} 回（推定）")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section 3: 実行時系列
    # ------------------------------------------------------------------

    def _section_3_timeline(self, sd: Dict[str, Any]) -> str:
        lines = ["## 実行時系列", ""]

        run_ledger = sd.get("run_ledger")
        if isinstance(run_ledger, list) and run_ledger:
            return self._section_3_from_run_ledger(lines, run_ledger)

        completed_tasks = sd.get("completed_tasks", [])
        if isinstance(completed_tasks, list) and completed_tasks:
            return self._section_3_from_completed_tasks(lines, completed_tasks)

        lines.append("詳細な時系列データなし (No data in source session)")
        return "\n".join(lines)

    def _section_3_from_run_ledger(self, lines: List[str], run_ledger: list) -> str:
        lines.append("| 時刻 | Event ID | イベント種別 | フェーズ | アクター | 概要 | 結果 |")
        lines.append("|------|----------|-------------|---------|---------|------|------|")

        for evt in run_ledger:
            if not isinstance(evt, dict):
                continue
            ts = self._safe_str(evt.get("timestamp", ""))
            # Shorten timestamp
            ts_short = self._shorten_timestamp(ts)
            event_id = self._safe_str(evt.get("event_id", "-"))
            event_type = self._safe_str(evt.get("event_type", ""))
            event_type_ja = _EVENT_TYPE_JA.get(event_type, event_type)
            phase = self._safe_str(evt.get("phase", "-"))
            actor = self._safe_str(evt.get("actor_name", evt.get("actor_type", "-")))
            action = self._safe_str(evt.get("action", ""))
            result = self._safe_str(evt.get("result", ""))
            summary_text = action or "-"
            result_text = result or "-"

            # 「推定」マーク
            inference = self._safe_str(evt.get("inference_level", ""))
            if inference and inference.lower() != "high":
                event_type_ja += "（推定）"

            lines.append(
                f"| {ts_short} | `{event_id}` | {event_type_ja} | {phase} | {actor} | {summary_text} | {result_text} |"
            )

        return "\n".join(lines)

    def _section_3_from_completed_tasks(self, lines: List[str], completed_tasks: list) -> str:
        lines.append("> **注記**: Run Ledger データが存在しないため、完了タスクから簡易時系列を表示します。")
        lines.append("")
        lines.append("| Task ID | タスク名 | エージェント | アクション | 状態 | 結果 |")
        lines.append("|---------|---------|-------------|-----------|------|------|")

        for task in completed_tasks:
            if not isinstance(task, dict):
                continue
            tid = self._safe_str(task.get("id", "-"))
            name = self._safe_str(task.get("name", "-"))
            agent = self._safe_str(task.get("agent_type", "-"))
            action = self._safe_str(task.get("action", "-"))
            state = self._safe_str(task.get("state", "-"))
            result = self._summarize_task_result(task)

            lines.append(f"| `{tid}` | {name} | {agent} | {action} | {state} | {result} |")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section 4: 判断根拠
    # ------------------------------------------------------------------

    # Phase 6 (SGK-2026-0315): decision types that represent task
    # retirement / invalidation — displayed separately under
    # 「未実施（不要化）」subsection.
    _RETIRED_LIKE_DECISION_TYPES: frozenset = frozenset(
        {"task_retired", "task_superseded", "task_invalidated"}
    )

    def _section_4_decision_traces(self, sd: Dict[str, Any]) -> str:
        lines = ["## 判断根拠", ""]

        decision_traces = sd.get("decision_traces")
        if not isinstance(decision_traces, list) or not decision_traces:
            lines.append("判断根拠データなし (No data in source session)")
            return "\n".join(lines)

        # Split decisions into active (non-retired-like) and retired-like
        active: List[Dict[str, Any]] = []
        retired_like: List[Dict[str, Any]] = []
        for dt in decision_traces:
            if not isinstance(dt, dict):
                continue
            dtype = self._safe_str(dt.get("decision_type", ""))
            if dtype in self._RETIRED_LIKE_DECISION_TYPES:
                retired_like.append(dt)
            else:
                active.append(dt)

        # Render active decisions (sequentially numbered)
        for i, dt in enumerate(active, 1):
            self._render_one_decision(lines, i, dt)

        # If there are active AND retired-like decisions, add a separator
        if active and retired_like:
            lines.append("---")
            lines.append("")

        # Render retired-like decisions under 「未実施（不要化）」subsection
        if retired_like:
            lines.append("### 未実施（不要化）")
            lines.append("")
            for dt in retired_like:
                decision_id = self._safe_str(dt.get("decision_id", "-"))
                decision_type = self._safe_str(dt.get("decision_type", "unknown"))
                decision_type_ja = _DECISION_TYPE_JA.get(decision_type, decision_type)
                reasoning = self._safe_str(dt.get("reasoning", "-"))
                outcome = self._safe_str(dt.get("outcome", "-"))
                related_task_id = self._safe_str(dt.get("related_task_id", ""))
                lines.append(f"- **`{decision_id}`** ({decision_type_ja}): {outcome}")
                if reasoning:
                    lines.append(f"  - 理由: {reasoning}")
                if related_task_id:
                    lines.append(f"  - 関連タスク: `{related_task_id}`")
            lines.append("")

        return "\n".join(lines)

    def _render_one_decision(
        self, lines: List[str], idx: int, dt: Dict[str, Any]
    ) -> None:
        """Render a single active decision trace entry."""
        decision_id = self._safe_str(dt.get("decision_id", f"dec_{idx:04d}"))
        decision_type = self._safe_str(dt.get("decision_type", "unknown"))
        decision_type_ja = _DECISION_TYPE_JA.get(decision_type, decision_type)
        reasoning = self._safe_str(dt.get("reasoning", "-"))
        selected_option = self._safe_str(dt.get("selected_option", "-"))
        outcome = self._safe_str(dt.get("outcome", "-"))
        was_successful = dt.get("was_successful")
        related_task_id = self._safe_str(dt.get("related_task_id", ""))

        lines.append(f"### 判断 {idx}: `{decision_id}`")
        lines.append("")
        lines.append(f"- **判断種別**: {decision_type_ja}")
        lines.append(f"- **選択肢**: {selected_option}")
        lines.append(f"- **判断根拠**: {reasoning}")
        lines.append(f"- **結果**: {outcome}")
        if was_successful is not None:
            success_label = "成功" if was_successful else "失敗"
            lines.append(f"- **成否**: {success_label}")
        if related_task_id:
            lines.append(f"- **関連タスク**: `{related_task_id}`")

        # Available options
        options = dt.get("available_options", [])
        if isinstance(options, list) and options:
            lines.append("- **利用可能な選択肢**:")
            for opt in options:
                if isinstance(opt, dict):
                    lines.append(f"  - {self._safe_str(opt.get('label', opt.get('name', str(opt))))}")
                else:
                    lines.append(f"  - {self._safe_str(str(opt))}")

        lines.append("")

    # ------------------------------------------------------------------
    # Section 5: Swarm・ツール実行
    # ------------------------------------------------------------------

    def _section_5_swarm_tool_execution(self, sd: Dict[str, Any]) -> str:
        lines = ["## Swarm・ツール実行", ""]

        run_ledger = sd.get("run_ledger")
        task_execution_records = sd.get("task_execution_records")
        completed_tasks = sd.get("completed_tasks", [])

        swarm_tool_events: List[Dict[str, Any]] = []
        if isinstance(run_ledger, list):
            for evt in run_ledger:
                if not isinstance(evt, dict):
                    continue
                et = self._safe_str(evt.get("event_type", ""))
                if et in {"swarm_dispatched", "swarm_completed", "swarm_failed", "swarm_merged", "swarm_skipped", "tool_executed"}:
                    swarm_tool_events.append(evt)

        task_records_by_id: Dict[str, Dict[str, Any]] = {}
        if isinstance(task_execution_records, list):
            for rec in task_execution_records:
                if isinstance(rec, dict):
                    tid = self._safe_str(rec.get("task_id", ""))
                    if tid:
                        task_records_by_id[tid] = rec

        if swarm_tool_events:
            return self._section_5_from_events(lines, swarm_tool_events, task_records_by_id)

        if isinstance(completed_tasks, list) and completed_tasks:
            return self._section_5_from_completed_tasks(lines, completed_tasks)

        lines.append("Swarm/ツール実行データなし (No data in source session)")
        return "\n".join(lines)

    def _section_5_from_events(
        self,
        lines: List[str],
        events: List[Dict[str, Any]],
        task_records: Dict[str, Dict[str, Any]],
    ) -> str:
        # Group by task_id
        by_task: Dict[str, List[Dict[str, Any]]] = {}
        for evt in events:
            tid = self._safe_str(evt.get("task_id", "") or "_no_task_")
            by_task.setdefault(tid, []).append(evt)

        lines.append("| Task ID | エージェント | アクション | イベント種別 | Event ID | 結果 | 所要時間 |")
        lines.append("|---------|-------------|-----------|-------------|----------|------|---------|")

        for tid in sorted(by_task.keys()):
            evt_list = by_task[tid]
            agent_type = self._safe_str(evt_list[0].get("actor_name", evt_list[0].get("actor_type", "-")))
            action = self._safe_str(evt_list[0].get("action", "-"))

            # Duration from task_execution_records
            duration_str = "-"
            if tid in task_records:
                rec = task_records[tid]
                dur = rec.get("duration_seconds")
                if dur is not None:
                    try:
                        duration_str = f"{float(dur):.1f}s"
                    except (TypeError, ValueError):
                        duration_str = str(dur)

            for evt in evt_list:
                eid = self._safe_str(evt.get("event_id", "-"))
                et = self._safe_str(evt.get("event_type", ""))
                et_ja = _EVENT_TYPE_JA.get(et, et)
                result = self._safe_str(evt.get("result", "-"))
                # Only show first line for brevity
                if result and len(result) > 60:
                    result = result[:57] + "..."

                inference = self._safe_str(evt.get("inference_level", ""))
                if inference and inference.lower() != "high":
                    et_ja += "（推定）"

                lines.append(f"| `{tid}` | {agent_type} | {action} | {et_ja} | `{eid}` | {result} | {duration_str} |")
                # Clear agent/action/duration for subsequent rows of same task
                agent_type = ""
                action = ""
                duration_str = ""

        return "\n".join(lines)

    def _section_5_from_completed_tasks(self, lines: List[str], completed_tasks: list) -> str:
        lines.append("> **注記**: Run Ledger データが存在しないため、完了タスクから表示します。")
        lines.append("")
        lines.append("| Task ID | タスク名 | エージェント | アクション | 状態 | 結果 |")
        lines.append("|---------|---------|-------------|-----------|------|------|")

        for task in completed_tasks:
            if not isinstance(task, dict):
                continue
            tid = self._safe_str(task.get("id", "-"))
            name = self._safe_str(task.get("name", "-"))
            agent = self._safe_str(task.get("agent_type", "-"))
            action = self._safe_str(task.get("action", "-"))
            state = self._safe_str(task.get("state", "-"))
            result = self._summarize_task_result(task)

            lines.append(f"| `{tid}` | {name} | {agent} | {action} | {state} | {result} |")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section 6: 失敗・再試行
    # ------------------------------------------------------------------

    def _section_6_failures_and_retries(self, sd: Dict[str, Any]) -> str:
        lines = ["## 失敗・再試行", ""]

        run_ledger = sd.get("run_ledger")
        completed_tasks = sd.get("completed_tasks", [])

        failures: List[Dict[str, Any]] = []
        retries: List[Dict[str, Any]] = []

        if isinstance(run_ledger, list):
            for evt in run_ledger:
                if not isinstance(evt, dict):
                    continue
                et = self._safe_str(evt.get("event_type", ""))
                if et in _FAILURE_EVENT_TYPES:
                    failures.append(evt)
                elif et in _RETRY_EVENT_TYPES:
                    retries.append(evt)

        if not failures and not retries:
            # Check completed_tasks for failed tasks
            if isinstance(completed_tasks, list):
                for task in completed_tasks:
                    if isinstance(task, dict) and self._safe_str(task.get("state", "")) == "failed":
                        failures.append(task)  # type: ignore[arg-type]

        if not failures and not retries:
            lines.append("失敗・再試行はありません")
            return "\n".join(lines)

        if failures:
            lines.append("### 失敗イベント")
            lines.append("")
            lines.append("| Event ID | Task ID | イベント種別 | フェーズ | エラー |")
            lines.append("|----------|---------|-------------|---------|-------|")
            for evt in failures:
                eid = self._safe_str(evt.get("event_id", "-"))
                tid = self._safe_str(evt.get("task_id", evt.get("id", "-")))
                et = self._safe_str(evt.get("event_type", evt.get("state", "failure")))
                et_ja = _EVENT_TYPE_JA.get(et, et)
                phase = self._safe_str(evt.get("phase", evt.get("failure_phase", "-")))
                error = self._safe_str(evt.get("error", evt.get("failure_reason", "-")))

                inference = self._safe_str(evt.get("inference_level", ""))
                if inference and inference.lower() != "high":
                    et_ja += "（推定）"

                lines.append(f"| `{eid}` | `{tid}` | {et_ja} | {phase} | {error} |")
            lines.append("")

        if retries:
            lines.append("### 再試行イベント")
            lines.append("")
            lines.append(f"- **再試行回数**: {len(retries)}")
            lines.append("")
            lines.append("| Event ID | Task ID | アクター | 概要 |")
            lines.append("|----------|---------|---------|------|")
            for evt in retries:
                eid = self._safe_str(evt.get("event_id", "-"))
                tid = self._safe_str(evt.get("task_id", "-"))
                actor = self._safe_str(evt.get("actor_name", evt.get("actor_type", "-")))
                action = self._safe_str(evt.get("action", "-"))

                lines.append(f"| `{eid}` | `{tid}` | {actor} | {action} |")
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section 7: 発見事項
    # ------------------------------------------------------------------

    def _section_7_findings(self, sd: Dict[str, Any]) -> str:
        lines = ["## 発見事項", ""]

        all_vulns: List[Dict[str, Any]] = extract_all_findings(sd)

        if not all_vulns:
            lines.append("発見事項なし")
            return "\n".join(lines)

        lines.append(f"**発見数**: {len(all_vulns)}")
        lines.append("")
        lines.append("| # | 脆弱性種別 | 深刻度 | 対象URL | 概要 |")
        lines.append("|---|-----------|--------|--------|------|")

        for i, vuln in enumerate(all_vulns, 1):
            if not isinstance(vuln, dict):
                continue
            vuln_type = self._safe_str(vuln.get("vuln_type", vuln.get("type", "-")))
            severity = self._safe_str(vuln.get("severity", "-"))
            target = self._mask_url(self._safe_str(vuln.get("target_url", vuln.get("target", "-"))))
            title = self._safe_str(vuln.get("title", vuln.get("summary", vuln.get("name", "-"))))
            if title and len(title) > 80:
                title = title[:77] + "..."

            lines.append(f"| {i} | {vuln_type} | {severity} | `{target}` | {title} |")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section 8: 次判断・推奨
    # ------------------------------------------------------------------

    def _section_8_next_actions(self, sd: Dict[str, Any]) -> str:
        lines = ["## 次判断・推奨", ""]

        has_content = False

        # Pending HITL items
        pending_hitl = sd.get("pending_hitl") or sd.get("context", {}).get("pending_hitl", [])
        if isinstance(pending_hitl, list) and pending_hitl:
            has_content = True
            lines.append("### 保留中のHITL要求")
            lines.append("")
            for item in pending_hitl:
                if isinstance(item, dict):
                    ticket_id = self._safe_str(item.get("ticket_id", "-"))
                    task_info = item.get("task", {})
                    task_id = self._safe_str(task_info.get("id", "-")) if isinstance(task_info, dict) else "-"
                    lines.append(f"- チケット `{ticket_id}` / タスク `{task_id}`")
            lines.append("")

        # Incomplete tasks from task_queue
        task_queue = sd.get("task_queue", [])
        if isinstance(task_queue, list) and task_queue:
            has_content = True
            lines.append("### 未完了タスク")
            lines.append("")
            lines.append("| Task ID | タスク名 | エージェント | アクション | 優先度 |")
            lines.append("|---------|---------|-------------|-----------|-------|")
            for task in task_queue:
                if not isinstance(task, dict):
                    continue
                tid = self._safe_str(task.get("id", "-"))
                name = self._safe_str(task.get("name", "-"))
                agent = self._safe_str(task.get("agent_type", "-"))
                action = self._safe_str(task.get("action", "-"))
                priority = task.get("priority", "-")

                lines.append(f"| `{tid}` | {name} | {agent} | {action} | {priority} |")
            lines.append("")

        # Missing scenarios
        scenario_coverage = sd.get("scenario_coverage") or sd.get("context", {}).get("scenario_coverage", {})
        if isinstance(scenario_coverage, dict):
            missing = scenario_coverage.get("missing_scenarios", [])
            if isinstance(missing, list) and missing:
                has_content = True
                lines.append("### 未カバーのシナリオ")
                lines.append("")
                for sid in missing:
                    lines.append(f"- `{sid}`")
                lines.append("")

        if not has_content:
            lines.append("すべてのタスクが完了しています")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section 9: 未完了事項
    # ------------------------------------------------------------------

    def _section_9_incomplete(self, sd: Dict[str, Any]) -> str:
        lines = ["## 未完了事項", ""]

        has_content = False

        # Pending task_queue
        task_queue = sd.get("task_queue", [])
        if isinstance(task_queue, list) and task_queue:
            has_content = True
            lines.append("### 保留中タスクキュー")
            lines.append("")
            for task in task_queue:
                if not isinstance(task, dict):
                    continue
                tid = self._safe_str(task.get("id", "-"))
                name = self._safe_str(task.get("name", ""))
                state = self._safe_str(task.get("state", ""))
                line = f"- `{tid}`: {name}" if name else f"- `{tid}`"
                if state:
                    line += f" ({state})"
                lines.append(line)
            lines.append("")

        # Missing scenarios
        scenario_coverage = sd.get("scenario_coverage") or sd.get("context", {}).get("scenario_coverage", {})
        if isinstance(scenario_coverage, dict):
            missing = scenario_coverage.get("missing_scenarios", [])
            if isinstance(missing, list) and missing:
                has_content = True
                lines.append("### 未カバーシナリオ")
                lines.append("")
                for sid in missing:
                    lines.append(f"- `{sid}`")
                lines.append("")

        if not has_content:
            lines.append("未完了事項なし")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_str(value: Any) -> str:
        """値を安全に文字列化する。None や非文字列も安全に扱う。"""
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        return str(value)

    @staticmethod
    def _summarize_task_result(task: dict) -> str:
        """タスク結果の概要文字列を生成する。生の辞書ダンプを回避。

        canonical な session 形式（result.success, result.data.status,
        result.data.findings 等）を含め、あらゆるパターンで要約を試みる。
        """
        if not isinstance(task, dict):
            return "-"
        result_val = task.get("result")
        parts: list[str] = []

        if isinstance(result_val, dict):
            # --- top-level result fields ---
            status = str(result_val.get("status", result_val.get("state", "")))
            if status:
                parts.append(f"status={status}")
            success = result_val.get("success")
            if isinstance(success, bool):
                parts.append(f"success={success}")
            agent = str(result_val.get("agent", ""))
            if agent:
                parts.append(f"agent={agent}")
            findings = result_val.get("findings", [])
            fc = len(findings) if isinstance(findings, list) else 0
            if fc > 0:
                parts.append(f"findings={fc}")
            finding = result_val.get("finding")
            if finding and fc == 0:
                parts.append("finding=1")
            vuln = result_val.get("vulnerability")
            if vuln and fc == 0 and finding is None:
                parts.append("vulnerability=1")

            # --- result.data sub-dict ---
            data_val = result_val.get("data", {}) if isinstance(result_val, dict) else {}
            if isinstance(data_val, dict):
                data_status = str(data_val.get("status", data_val.get("state", "")))
                if data_status:
                    parts.append(f"data_status={data_status}")
                data_findings = data_val.get("findings", [])
                dfc = len(data_findings) if isinstance(data_findings, list) else 0
                if dfc > 0 and fc == 0:
                    parts.append(f"data_findings={dfc}")
                data_finding = data_val.get("finding")
                if data_finding and fc == 0 and dfc == 0 and finding is None:
                    parts.append("data_finding=1")
                data_result = str(data_val.get("result", ""))
                if data_result and fc == 0 and dfc == 0 and finding is None and data_finding is None:
                    parts.append(f"data_result={data_result[:60]}")

            if parts:
                return ", ".join(parts)
            # Last-resort: no known keys found — summarize key count
            key_count = len(result_val)
            return f"dict_keys={key_count}"

        if isinstance(result_val, str):
            return result_val[:120]
        return str(result_val)[:80] if result_val is not None else "-"

    @staticmethod
    def _format_duration(delta: timedelta) -> str:
        """timedelta を人間可読な形式に変換する。"""
        total_seconds = int(delta.total_seconds())
        if total_seconds < 60:
            return f"{total_seconds}秒"
        if total_seconds < 3600:
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            return f"{minutes}分{seconds}秒"
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        return f"{hours}時間{minutes}分"

    @staticmethod
    def _shorten_timestamp(ts: str) -> str:
        """ISO タイムスタンプを HH:MM:SS に短縮する。"""
        if not ts:
            return "-"
        # Try to extract time portion from ISO format
        for sep in ("T", " "):
            if sep in ts:
                time_part = ts.split(sep, 1)[1]
                # Remove timezone suffix
                for tz_sep in ("+", "-", "Z"):
                    if tz_sep in time_part:
                        time_part = time_part.split(tz_sep, 1)[0]
                        break
                # Take HH:MM:SS
                if len(time_part) >= 8:
                    return time_part[:8]
                return time_part
        # If no T separator, try parsing as unix timestamp
        try:
            dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
            jst = dt.astimezone(timezone(timedelta(hours=9)))
            return jst.strftime("%H:%M:%S")
        except (TypeError, ValueError, OSError):
            return ts[:8] if len(ts) >= 8 else ts

    @staticmethod
    def _mask_url(url: str) -> str:
        """URL のクエリパラメータを除去し、機密情報をマスクする。

        APIキーやトークンなどの機密パラメータを含むクエリ文字列は完全に除去し、
        ドメイン+パスのみを返す。
        """
        if not url:
            return url
        try:
            split = urlsplit(url)
            if not split.scheme and not split.netloc:
                return url
            # Remove query params entirely for safety (may contain tokens)
            masked = urlunsplit((split.scheme.lower(), split.netloc, split.path or "/", "", split.fragment))
            return masked
        except Exception:
            return url

    @staticmethod
    def _collect_phases(sd: Dict[str, Any]) -> set:
        """run_ledger または completed_tasks から全フェーズを収集する。"""
        phases: set = set()
        run_ledger = sd.get("run_ledger")
        if isinstance(run_ledger, list):
            for evt in run_ledger:
                if isinstance(evt, dict):
                    phase = evt.get("phase", "")
                    if phase:
                        phases.add(str(phase))
        if not phases:
            completed_tasks = sd.get("completed_tasks", [])
            if isinstance(completed_tasks, list):
                for task in completed_tasks:
                    if isinstance(task, dict):
                        phase = task.get("phase", "")
                        if phase:
                            phases.add(str(phase))
        return phases


