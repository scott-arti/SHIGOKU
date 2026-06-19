---
task_id: SGK-2026-0292
doc_type: plan
status: done
parent_task_id: SGK-2026-0264
related_docs:
- docs/shigoku/reports/2026-06-16_sgk-2026-0287_phase1-2_work_report.md
title: 'MasterConductor service extraction batch 2: react/enrich/batch helpers to pure services'
created_at: '2026-06-16'
updated_at: '2026-06-18'
tags:
- shigoku
target: src/core/engine/master_conductor_facade.py, src/core/engine/master_conductor_finding_service.py,
  src/core/engine/master_conductor_enrichment_service.py, src/core/engine/master_conductor_execution_service.py
---

# 実装計画書：service extraction batch 2

## 完了条件

- [x] `_generate_react_suggestions` (64 lines) → `generate_react_suggestions()` in finding_service
- [x] `_enrich_task_before_enqueue` (69 lines) → `enrich_task_for_enqueue()` in enrichment_service  
- [x] `_execute_single_batch` (79 lines) → `execute_single_batch()` in execution_service
- [x] `master_conductor_facade.py` 5920→5736 (-184)
- [x] 全 service は MasterConductor instance 非保持（parameter injection）
- [x] Core tests 76/76 pass

## 成果

| 抽出 | Facade 削減 | Service 追加 |
|---|---|---|
| `_generate_react_suggestions` | -64 | finding_service +59 |
| `_enrich_task_before_enqueue` | -69 | enrichment_service +96 |
| `_execute_single_batch` | -79 | execution_service +111 |
| **Net** | **-184** (5920→5736) | **+266** (3 new service files) |
