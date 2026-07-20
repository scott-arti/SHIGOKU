---
task_id: SGK-2026-0366
doc_type: plan
status: done
parent_task_id: SGK-2026-0364
related_docs:
- docs/shigoku/reports/2026-07-16_sgk-2026-0366_work_report.md
- docs/shigoku/worklogs/2026-07-16_sgk-2026-0366_work_log.md
- docs/shigoku/plans/done/2026-07-15_sgk-2026-0364_derived-task-admission-policy-cleanup_plan.md
- docs/shigoku/reports/2026-07-15_sgk-2026-0364_work_report.md
title: Skipped Task Reason Visibility and Shutdown Cancellation Cleanup
created_at: '2026-07-16'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/core/engine/master_conductor.py, tests/core/engine/test_master_conductor_failure_reason_codes.py, tests/core/engine/test_master_conductor_shutdown.py
---

# 実装計画書: Skipped Task Reason Visibility and Shutdown Cancellation Cleanup

## 1. 達成したいゴール（ユーザー視点）
- [x] `SKIPPED` になったタスクの理由を、最終サマリーと session 保存物から追えること。
- [x] 正常終了後の shutdown cleanup で発生する `CancelledError()` を、誤って実行失敗ログとして扱わないこと。

## 2. 全体像とアーキテクチャ
- `src/core/engine/master_conductor.py`
  - skip/failure reason code の正規化を補強する。
  - session 保存前に `FAILED` / `SKIPPED` タスクの reason code を埋める。
  - 最終 summary に `Skipped` と `Skipped Reasons` を追加する。
  - normal completion 後の shutdown cancellation は error ではなく debug/info 扱いにする。
- `tests/core/engine/test_master_conductor_failure_reason_codes.py`
  - skipped reason summary と session 保存時の reason code 永続化を検証する。
- `tests/core/engine/test_master_conductor_shutdown.py`
  - 正常 shutdown 時の `CancelledError` が error ログにならないことを検証する。

## 3. 具体的な仕様と制約条件
- `SKIPPED` 理由は、既存の `failure_reason_code` フィールドを流用し、新しい永続化 schema は増やさない。
- skip reason が未設定でも `TASK_SKIPPED` などの fallback を与えて summary の空欄を避ける。
- shutdown は本当に異常な例外だけ error とし、想定済み cancellation は fail 扱いしない。

## 4. 実装ステップ
- [x] ステップ1: summary / save_session / shutdown の現行コードを確認し、skip reason code の欠落経路を洗い出す。
- [x] ステップ2: `master_conductor.py` に skip reason 可視化と shutdown cancellation cleanup を実装する。
- [x] ステップ3: 回帰テストを追加し、関連診断を確認する。

## 5. 既知のリスクと申し送り
- [ ] 現行環境では runner が壊れており、pytest と SHIGOKU docs validator の実行が再び blocked になる可能性が高い。
- [ ] 実行済み session JSON の直読みは環境制約で再現できない可能性があるため、今回は再発防止として runtime observability の改善を優先する。
