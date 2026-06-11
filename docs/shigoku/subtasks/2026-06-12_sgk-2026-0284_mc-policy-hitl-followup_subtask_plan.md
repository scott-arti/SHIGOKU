---
task_id: SGK-2026-0284
doc_type: subtask_plan
status: backlog
parent_task_id: SGK-2026-0264
related_docs:
  - docs/shigoku/reports/2026-06-12_sgk-2026-0282_masterconductor-policy-hitl-dispatch_work_report.md
title: 'MasterConductor Policy/HITL 抽出 follow-up: 残存メソッド再構築・parity tests・compat inventory'
created_at: '2026-06-12'
updated_at: '2026-06-12'
tags:
  - shigoku
  - master-conductor
---

# MasterConductor Policy/HITL 抽出 follow-up

SGK-2026-0282 の deferred_tasks から派生した follow-up タスク。

## 対象
- `_run_intervention_precheck` の PrecheckDecision ベース再構築
- `_generate_summary` の failure aggregation / percentile / coverage gate assembly 軽量抽出
- `execute_parallel` の重複解消 (vs `master_conductor_parallel.py`)
- 3-layer parity tests (service parity / facade wrapper parity / side-effect parity) の新規追加
- compat wrapper inventory の完成
