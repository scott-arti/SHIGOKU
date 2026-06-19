---
task_id: SGK-2026-0295
doc_type: plan
status: done
parent_task_id: SGK-2026-0264
related_docs:
- docs/shigoku/reports/2026-06-16_sgk-2026-0287_phase1-2_work_report.md
title: 'MasterConductor lifecycle session wrapper retirement: shutdown/session/checkpoint to coordinator'
created_at: '2026-06-16'
updated_at: '2026-06-18'
tags:
- shigoku
target: src/core/engine/master_conductor_facade.py
---

# lifecycle/session/wrapper retirement

## 成果

- [x] `_async_shutdown` (90 lines) → `shutdown_coordinator()`
- [x] `_finalize_execution_summary` (195 lines) → `finalize_summary_coordinator()`
- [x] `_checkpoint` (21 lines) → `checkpoint_coordinator()`
- [x] `resume_session` (35 lines) → `resume_session_coordinator()`
- [x] lifecycle_coordinator: 237 lines、facade 非保持
- [x] facade: 5559→5432 (-127)
- [x] Tests: 38/38 pass
