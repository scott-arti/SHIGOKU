---
task_id: SGK-2026-0291
doc_type: plan
status: done
parent_task_id: SGK-2026-0264
related_docs:
- docs/shigoku/reports/2026-06-16_sgk-2026-0287_phase1-2_work_report.md
- docs/shigoku/subtasks/2026-06-13_masterconductor-execution-loop-deep-extraction_subtask_plan.md
- docs/shigoku/plans/2026-06-16_conductorstate-masterconductor-state-access-protocol_plan.md
title: 'MasterConductor facade size gate retry: finding/observation helper extraction'
created_at: '2026-06-16'
updated_at: '2026-06-18'
tags:
- shigoku
target: src/core/engine/master_conductor_facade.py
---

# 実装計画書：facade size gate 再挑戦

## 1. 背景

SGK-2026-0287 で全 hotspot <100 lines 達成（5956 lines）。
0289 で ConductorState 導入 + 3 hotspot 深層抽出。
0290 で plan/replan 抽出。
残課題: facade 5956→下げる。finding/observation helpers を service に外出しして純減を狙う。

## 2. 完了条件

- [ ] `_emit_finding_vuln_event` (31 lines) を `master_conductor_finding_service.py` に抽出
- [ ] `_build_react_followup_tasks` (23 lines) を `master_conductor_finding_service.py` に抽出
- [ ] `master_conductor_facade.py` を 5956 → 5900 未満に削減
- [ ] targeted tests 121/121 pass

## 3. 実装ステップ

### Step 1: finding service 新規作成
- [ ] `master_conductor_finding_service.py` 作成
- [ ] `emit_finding_vuln_event()` pure function 抽出
- [ ] `build_react_followup_tasks()` pure function 抽出

### Step 2: facade を thin wrapper 化
- [ ] `handle_finding._emit_finding_vuln_event` → service call
- [ ] `_observe_and_rethink._build_react_followup_tasks` → service call
- [ ] facade の helper method 定義を削除

## 4. 検証

```bash
.venv/bin/pytest -q tests/core/engine/test_master_conductor_character.py
.venv/bin/pytest -q tests/core/engine/test_mc_intelligence_integration.py
.venv/bin/pytest -q tests/core/engine/test_react_redundancy.py
```
