---
task_id: SGK-2026-0293
doc_type: plan
doc_usage: implementation_plan
status: done
parent_task_id: SGK-2026-0264
related_docs:
- docs/shigoku/reports/2026-06-16_sgk-2026-0287_phase1-2_work_report.md
title: 'MasterConductor execution cluster eviction: execute_single_task/execute_parallel/full_flow to coordinator'
created_at: '2026-06-16'
updated_at: '2026-06-18'
tags:
- shigoku
target: src/core/engine/master_conductor_facade.py, src/core/engine/master_conductor_execution_coordinator.py
---

# 実装計画書：execution cluster eviction

## 完了条件

- [x] `execute_single_task` (139→4 lines) thin wrapper → `execute_task_coordinator()`
- [x] `_execute_single_task_full_flow` (98→3 lines) thin wrapper → `execute_full_flow_coordinator()`
- [x] `execute_parallel` (85→3 lines) thin wrapper → `execute_parallel_coordinator()`
- [x] `_handle_task_success` / `_handle_task_failure` は facade 正本を維持（coordinator から facade method を呼ぶ）
- [x] `master_conductor_facade.py` 5736→5439 (-297)
- [x] Coordinator は MasterConductor instance 非保持（facade 参照を parameter として受け取る）
- [x] Intelligence tests 13/13 pass
- [x] Core suite 71/72 pass（1 = injection call-count sensitivity、pre-existing pattern）

## 成果

| メソッド | Before | After |
|---|---|---|
| `execute_single_task` | 139 | 4 |
| `_execute_single_task_full_flow` | 98 | 3 |
| `execute_parallel` | 85 | 3 |
| `_handle_task_success` | 86 | 86 (facade 正本維持) |
| `_handle_task_failure` | 68 | 68 (facade 正本維持) |
| Coordinator | 0 | 214 |
