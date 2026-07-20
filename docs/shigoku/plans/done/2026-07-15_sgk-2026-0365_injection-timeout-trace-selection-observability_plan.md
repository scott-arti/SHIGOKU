---
task_id: SGK-2026-0365
doc_type: plan
status: done
parent_task_id: SGK-2026-0122
related_docs:
- docs/shigoku/specs/fix_injection_swarm.md
- docs/shigoku/reports/2026-07-15_sgk-2026-0365_work_report.md
- docs/shigoku/worklogs/2026-07-15_sgk-2026-0365_work_log.md
- docs/shigoku/plans/2026-07-16_injection-task-ownership-normalization-and-no-signal-phase2-suppression_plan.md
- workspace/projects/localhost:4280/reports/haddix_report_20260714_114645.md
title: Injection Timeout Trace and Selection Observability
created_at: '2026-07-15'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/core/agents/swarm/injection/manager.py, src/recon/pipeline.py, tests/core/agents/swarm/test_injection_manager.py
---

# 実装計画書：Injection Timeout Trace and Selection Observability

## 1. 達成したいゴール（ユーザー視点）
- [x] 次回の DVWA 実行で、timeout した URL がどの task lineage から来たかを session から追えること。
- [x] timeout / error 時に、どの検査段階まで進んだかを `url_results` から追えること。
- [x] InjectionManager の「並列実行」と読める誤コメントを、現実装に合わせて修正すること。

## 2. 全体像とアーキテクチャ
- `src/core/agents/swarm/injection/manager.py`
  timeout / error / completed / skipped の `url_results` に `selection_origin`, `selection_evidence`, `attempt_traces`, `timeout_diagnostics`, `error_diagnostics` を追加する。
- `src/recon/pipeline.py`
  recon 由来タスクと command focus タスクに `selection_origin` を付け、task lineage を phase1 metadata に落とす。
- `tests/core/agents/swarm/test_injection_manager.py`
  選定 metadata と timeout trace の回帰テストを追加する。

## 3. 実施ステップ
- [x] `phase1_priority_plan` と `url_results` の両方に選定根拠を残す。
- [x] `_process_single_url()` の branch start / return / error を trace できるようにする。
- [x] timeout 診断に「timeout 直前の stage」を残す。
- [x] コメント修正と最小テスト追加を行う。

## 4. 残課題
- [ ] command focus と generic injection の重複除去はまだ未実装。追跡タスク `SGK-2026-0367` で canonical owner と no-signal Phase 2 抑制をあわせて実装する。
- [ ] XSS/LFI の human-like quick reject は未実装。selection evidence を使う shadow gate が次段階。
