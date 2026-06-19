---
task_id: SGK-2026-0290
doc_type: plan
doc_usage: implementation_plan
status: done
parent_task_id: SGK-2026-0264
related_docs:
- docs/shigoku/reports/2026-06-16_sgk-2026-0287_phase1-2_work_report.md
- docs/shigoku/plans/2026-06-16_conductorstate-masterconductor-state-access-protocol_plan.md
- docs/shigoku/worklogs/2026-06-16_sgk-2026-0287_work_log.md
title: 'MasterConductor planning flow extraction: plan/replan coordinator split'
created_at: '2026-06-16'
updated_at: '2026-06-18'
tags:
- shigoku
target: src/core/engine/master_conductor_facade.py, src/core/engine/master_conductor_state.py,
  src/core/engine/master_conductor_execution_plan_service.py
---

# 実装計画書：plan/replan coordinator split

## 1. 背景

SGK-2026-0289 で ConductorState 導入 + 3 hotspot 深層抽出が完了（facade 5921 lines）。
残 hotspot の中で `plan` (123 lines) + `replan` (109 lines) = 232 lines が次にライン削減効率が良い。
execution_plan_service は既存で、pure 部分は一部抽出済み。

## 2. 完了条件

- [x] `plan` の pure parts（pending fuzz / static task list）を facade helper に抽出
- [x] `replan` の fallback decision matrix を `_build_replan_fallback_tasks` に分離
- [x] facade には `task_queue.clear/add_batch` や最終 mutation だけ残す
- [x] `execute_with_replan` 155→88 lines（`_execute_single_batch` 抽出）
- [ ] `master_conductor_facade.py` を 5700台 に削減（現 5956。helper 追加 > 抽出削減のため未達。詳細は work_report 参照）

## 3. 実装ステップ（順序固定）

### Step 1: plan の character test 追加
- [ ] `test_master_conductor_phase1_step14.py` / `test_master_conductor_phase1_step15.py` の拡充
- [ ] plan 入力/出力の golden fixture 追加

### Step 2: plan から pure parts 抽出
- [x] `_plan_pending_fuzz_tasks()` 抽出 (41 lines)
- [x] `_build_static_plan_tasks()` 抽出 (49 lines)
- [x] `plan` 123→25 lines

### Step 3: replan から fallback matrix 分離
- [x] `_build_replan_fallback_tasks()` 抽出 (60 lines)
- [x] `replan` 109→64 lines

### Step 4: execution tail 追加抽出
- [x] `_execute_single_batch()` 抽出 (79 lines)
- [x] `execute_with_replan` 155→88 lines

## 4. 検証

```bash
.venv/bin/pytest -q \
  tests/core/engine/test_master_conductor_character.py \
  tests/core/engine/test_master_conductor_phase1_step14.py \
  tests/core/engine/test_master_conductor_phase1_step15.py \
  tests/core/engine/test_mc_intelligence_integration.py \
  tests/unit/core/engine/test_error_replanner_integration.py
```

## 5. 次 slice 候補

plan/replan slice 完了後は `execute_with_replan` (155 lines) + `_execute_single_task_full_flow` (98 lines) = execution tail slice。
0289 + 0290 + execution tail で facade の純減が効き始め、0287 の done 判定が可能になる。
