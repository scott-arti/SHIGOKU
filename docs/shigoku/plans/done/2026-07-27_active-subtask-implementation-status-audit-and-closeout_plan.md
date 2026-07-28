---
task_id: SGK-2026-0395
doc_type: plan
status: done
parent_task_id: null
related_docs:
- docs/shigoku/subtasks/done/2026-07-25_dvwa-low-expected-detection-matrix_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-21_authprobe-relative-redirect-handling-follow-up_subtask_plan.md
- docs/shigoku/reports/2026-07-27_sgk-2026-0395_active-subtask-implementation-status-audit-and-closeout_work_report.md
- docs/shigoku/worklogs/2026-07-27_sgk-2026-0395_active-subtask-implementation-status-audit-and-closeout_work_log.md
title: Active subtask implementation status audit and closeout
created_at: '2026-07-27'
updated_at: '2026-07-28'
tags:
- shigoku
target: docs/shigoku/subtasks active status audit
---

# 実装計画書：Active subtask implementation status audit and closeout

## 1. 達成したいゴール（ユーザー視点）

`docs/shigoku/subtasks/` にある active な計画を、実装・検証の証拠に基づいて分類し、完了済みのものだけを `done/` へ移す。継続監視・未実装の計画は active のまま残す。

## 2. 対象と判断方法

- 対象: `docs/shigoku/subtasks/` の直下にある active な `subtask_plan`。
- 根拠: 計画の完了チェック、対応する作業報告書・作業ログ、実装箇所と検証記録。
- 完了へ移す: SGK-2026-0371、SGK-2026-0386〜0391。
- active のまま残す: SGK-2026-0257、0260〜0262、0282、0308、0336、0392。これらは継続監視、将来作業、または未実装である。

## 3. 制約

- 実装証拠のない計画は、完了にしない。
- 移動後は、台帳・親計画・作業報告書・作業ログの参照先を同時に更新する。
- 既存の未対応項目は消さず、元のタスクまたは親タスクに残す。

## 4. 実施結果

- [x] active なサブタスク計画と対応する実装・作業報告書・作業ログを照合した。
- [x] 証拠がある SGK-2026-0371、SGK-2026-0386〜0391 を done に更新し、`subtasks/done/` へ移した。
- [x] 台帳と相互参照を更新し、ドキュメント検証を実行した。

## 5. 既知のリスクと次回の申し送り

- `SGK-2026-0392` は実装証拠がないため active のまま残した。
- 旧タスク SGK-2026-0258 の欠損した計画ファイルは今回の範囲外であり、ドキュメント検証の既知エラーとして残る。
