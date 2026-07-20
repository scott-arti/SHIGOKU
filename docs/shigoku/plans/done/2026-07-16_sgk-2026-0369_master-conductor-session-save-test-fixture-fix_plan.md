---
task_id: SGK-2026-0369
doc_type: plan
status: done
parent_task_id: SGK-2026-0366
related_docs:
- docs/shigoku/reports/2026-07-16_sgk-2026-0369_work_report.md
- docs/shigoku/worklogs/2026-07-16_sgk-2026-0369_work_log.md
- docs/shigoku/plans/done/2026-07-16_sgk-2026-0366_skipped-task-reason-visibility-and-shutdown-cancellation-cleanup_plan.md
- docs/shigoku/reports/2026-07-16_sgk-2026-0366_work_report.md
title: MasterConductor session save regression test fixture fix
created_at: '2026-07-16'
updated_at: '2026-07-21'
tags:
- shigoku
target: tests/core/engine/test_master_conductor_failure_reason_codes.py
---

# 実装計画書: MasterConductor session save regression test fixture fix

## 1. 達成したいゴール（ユーザー視点）
- [x] `tests/core/engine/test_master_conductor_failure_reason_codes.py` の session save 回帰テストが、fixture 不足で落ちずに本来確認したい `failure_reason_code` 永続化を検証できること。
- [x] 既に通っている docs validator / consistency checker の状態を崩さず、修正範囲をテスト補助に限定すること。

## 2. 全体像とアーキテクチャ
- `tests/core/engine/test_master_conductor_failure_reason_codes.py`
  - `MasterConductor.__new__()` ベースの最小 fixture に、session payload builder が前提とする `ExecutionContext` 互換属性を補う。
- `src/core/engine/master_conductor_session_service.py`
  - 既存の `build_async_session_payload()` が `context._total_attempts` / `context._successful_attempts` を読む前提を確認し、production code ではなく test fixture の不足として扱う。

## 3. 具体的な仕様と制約条件
- production code の挙動変更は行わない。
- 追加するのは `_new_mc_with_min_context()` に必要最小限の属性のみとする。
- 検証はまず targeted pytest を優先し、その後 docs validator / consistency checker の再確認を行う。

## 4. 実装ステップ
- [x] ステップ1: failing pytest の stack trace と `build_async_session_payload()` の要求属性を照合する。
- [x] ステップ2: `_new_mc_with_min_context()` に不足している `_total_attempts` / `_successful_attempts` を追加する。
- [x] ステップ3: targeted pytest と必要な docs/report checks を再実行し、回帰が解消したことを確認する。

## 5. 既知のリスクと申し送り
- [x] targeted pytest の再実行で `5 passed` を確認した。
- [x] `python3 scripts/sync_shigoku_updated_at.py` / `python3 scripts/validate_shigoku_docs.py` / `python3 scripts/verify_report_session_consistency.py --report ...151429.md` は成功し、docs と report/session pair の整合が保たれている。
