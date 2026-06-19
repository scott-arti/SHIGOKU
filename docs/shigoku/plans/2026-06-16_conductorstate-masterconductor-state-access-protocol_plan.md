---
task_id: SGK-2026-0289
doc_type: plan
status: done
parent_task_id: SGK-2026-0264
related_docs:
- docs/shigoku/subtasks/2026-06-13_masterconductor-execution-loop-deep-extraction_subtask_plan.md
- docs/shigoku/reports/2026-06-16_sgk-2026-0287_phase1-2_work_report.md
- docs/shigoku/worklogs/2026-06-16_sgk-2026-0287_work_log.md
title: 'ConductorState 導入: MasterConductor state access protocol と深層抽出前提整備'
created_at: '2026-06-16'
updated_at: '2026-06-18'
tags:
- shigoku
target: src/core/engine/master_conductor_facade.py, src/core/engine/master_conductor_dependencies.py,
  src/core/engine/master_conductor_state.py
---

# 実装計画書：ConductorState state access protocol 導入

## 1. 背景

SGK-2026-0287 で facade は 5885 行まで縮小したが、残る hotspot（`_add_tasks` 137行、`handle_finding` 117行、`_observe_and_rethink` 155行）は全て `self.task_queue` / `self.completed_tasks` / `self._state_lock` / `self.context` / `self.execution_log` / `self.pending_hitl` / `self.event_bus` の直接操作を含む state mutation glue であり、これ以上の抽出には state access protocol が必要。

## 2. 完了条件

- [x] `ConductorState` dataclass を `master_conductor_state.py` に導入し、facade が `self.state` で mutable state を所有。
- [x] `task_queue`, `completed_tasks`, `pending_hitl`, `context`, `event_bus` の access を `self.state.*` 経由に移行開始（preflight で一部完了。react 系は `_react_field`/`_set_react_field` compat helper で bridge。全統一は child slice へ）。
- [x] `_add_tasks` (137→46)、`handle_finding` (117→82)、`_observe_and_rethink` (155→71) の 3 hotspot を抽出。
- [ ] `master_conductor_facade.py` を 5200台以下 に削減（0289 単体では不可 → **child slice に移管**。現 5921 lines）。

**結果: 3/4 achieved。5200台以下は child slice (SGK-TBD) に移管。0289 done。**

## 3. アーキテクチャ

```
ConductorState (dataclass, master_conductor_state.py)
├── task_queue: DynamicTaskQueue
├── completed_tasks: list[Task]
├── pending_hitl: list[dict]
├── context: ExecutionContext
├── execution_log: TaskExecutionLog
├── event_bus: EventBus
└── _state_lock: threading.RLock

RuntimeAccessor (Protocol or helper class)
├── dequeue_batch(n) → list[Task]
├── enqueue_tasks(tasks, source) → int
├── record_failure(task, phase, reason) → None
├── mark_completed(tasks) → None
└── emit_event(event_type, payload) → None
```

facade は `ConductorState` を所有し、coordinator には `RuntimeAccessor` 経由で読み取り専用 view + 安全な mutation interface を提供する。

## 4. 実装ステップ（順序固定）

### Step 1: ConductorState dataclass 導入
- [x] `master_conductor_state.py` を新規作成
- [x] `ConductorState` dataclass を定義
- [x] facade `__init__` で `self.state = ConductorState(...)` を生成
- [x] `self.state.*` に全 mutable state を束ね（dual-reference）

### Step 2: _add_tasks を state-aware helper 化
- [x] `_enrich_task_before_enqueue(task, source, aggressive_targets)` 抽出 (69 lines)。strategy/priority/intervention/booster/aggressive の全 enrichment を集約
- [x] `_add_tasks` 137→46 lines (-91)。loop body が dedup + enrich + queue mutation のみに

### Step 3: handle_finding 抽出
- [x] `_emit_finding_vuln_event(finding, target_url)` 抽出 (31 lines)。event_bus emit + notifier notify を集約
- [x] `handle_finding` 117→82 lines (-35)

### Step 4: _observe_and_rethink 抽出
- [x] Step 4a: react 系フィールドを `self._react_*` → compat helper (`_react_field`/`_set_react_field`) 経由に統一
- [x] Step 4b: `_should_observe()` 全 legacy `getattr(self, "_react_*")` を compat helper に統一
- [x] Step 4c: `_generate_react_suggestions()` 抽出 (64 lines)。RAG/LLM/cache を集約
- [x] Step 4d: `_build_react_followup_tasks()` 抽出 (23 lines)。task generation を集約。`_observe_and_rethink` 155→71 lines (-84)

## 5. 検証

```bash
.venv/bin/pytest -q tests/core/engine/test_master_conductor_character.py
.venv/bin/pytest -q tests/core/engine/test_master_conductor_session_service.py
.venv/bin/pytest -q tests/core/engine/test_mc_intelligence_integration.py
.venv/bin/pytest -q tests/core/engine/test_master_conductor_intervention_gate.py
```

## 6. リスクと対策

| 懸念点 | 発生確率 | 影響度 | 対策 |
|---|---|---|---|
| ConductorState 導入で `self.*` 参照の移行漏れ | 高 | 大 | character tests + targeted tests で全参照を検証 |
| state access protocol が過剰抽象化 | 中 | 中 | 最小限の interface から始め、必要に応じて拡張 |
| `_observe_and_rethink` の react cache 移行で副作用順崩れ | 中 | 大 | Step 4 着手前に `_add_tasks` + `handle_finding` の抽出結果で protocol を安定化 |
