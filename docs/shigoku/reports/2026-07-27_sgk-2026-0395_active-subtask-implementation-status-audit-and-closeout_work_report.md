---
task_id: SGK-2026-0395
doc_type: work_report
status: done
parent_task_id: null
related_docs:
- docs/shigoku/plans/done/2026-07-27_active-subtask-implementation-status-audit-and-closeout_plan.md
- docs/shigoku/worklogs/2026-07-27_sgk-2026-0395_active-subtask-implementation-status-audit-and-closeout_work_log.md
created_at: '2026-07-27'
updated_at: '2026-07-28'
tags:
- shigoku
target: docs/shigoku/subtasks active status audit
---

# 作業報告書：active subtask implementation status audit and closeout

## 実施内容

- active なサブタスク計画を、実装・検証・作業記録の有無で照合した。
- 実装済みの SGK-2026-0371、SGK-2026-0386〜0391 を done に更新し、`subtasks/done/` へ移した。
- 親計画、作業報告書、作業ログ、タスク台帳、タスク登録簿の参照先を更新した。

## 判断理由

計画のファイルが active のまま残っていることだけを根拠に未完了と扱うと、同じ実装を再着手する危険がある。一方で、未実装または継続監視の計画は、完了扱いにせず active のまま残した。

## 検証

- `python3 scripts/sync_shigoku_updated_at.py`
- `python3 scripts/validate_shigoku_docs.py`
- `rg -n 'docs/shigoku/subtasks/(2026-07-21_authprobe-relative-redirect-handling-follow-up|2026-07-25_dvwa-low-(expected-detection-matrix|regression-finding-restoration|sqli-and-lfi-evidence-promotion|command-injection-evidence-promotion|browser-backed-xss-evidence-promotion|file-upload-and-authswarm-skipped-result-recovery))' docs/shigoku`

## リスク

- SGK-2026-0392 は専用検知の実装証拠がないため active のまま残した。
- SGK-2026-0258 の欠損計画ファイルは今回の範囲外であり、ドキュメント検証の既知エラーとして残る。

## deferred_tasks

- task_id: SGK-2026-0392
  reason: Brute Force / CAPTCHA / CSP の専用検知は未実装であり、完了へ移していない。
