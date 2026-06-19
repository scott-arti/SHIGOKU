---
task_id: SGK-2026-0285
doc_type: subtask_plan
doc_usage: execution_plan
status: backlog
parent_task_id: SGK-2026-0264
related_docs:
  - docs/shigoku/reports/2026-06-12_sgk-2026-0282_masterconductor-policy-hitl-dispatch_work_report.md
title: 'MasterConductor _dispatch 本体抽出: character tests・branch routing matrix・contextvar reset 検証'
created_at: '2026-06-12'
updated_at: '2026-06-12'
tags:
  - shigoku
  - master-conductor
---

# MasterConductor _dispatch 本体抽出

SGK-2026-0282 の deferred_tasks D02/D07 から派生したタスク。

## 前提条件（着手条件）
- scope fast path, post-exploit guard, CTF filter, worker, swarm, recon, recipe, AgentFactory fallback の branch 単位 character tests を追加
- routing order matrix の fixture 化
- cookie/header contextvar reset の全 exit path branch test 追加

## 対象
- `_dispatch` (561行) の branch 単位 service 抽出
