---
task_id: SGK-2026-0346
doc_type: plan
status: backlog
parent_task_id: SGK-2026-0345
related_docs:
  - docs/shigoku/plans/done/2026-07-07_haddix-submission-internal-ja-first-report-plan_plan.md
  - docs/shigoku/reports/2026-07-07_sgk-2026-0345_haddix-submission-internal-ja-first-report_work_report.md
created_at: '2026-07-07'
updated_at: '2026-07-21'
tags:
  - shigoku
  - haddix
  - reporting
  - deferred
---

# SGK-2026-0346: Evidence quality enforcement 移行とP2検出範囲拡張

本タスクは SGK-2026-0345 の deferred_tasks として起票された継続監視タスクである。
詳細な実装計画書は別途作成する。

## Deferred scope (from SGK-2026-0345)

1. **Evidence quality enforcement mode への移行**  
   P1 shadow mode の verdict を enforcement に切り替え、確認済み/候補の分割に反映する。
   切り替え前に実 artifact で shadow verdict 差分を検証する。

2. **P2 検出範囲拡張**  
   Command Injection タイムアウト原因調査、DOM XSS / Open Redirect / Weak Session IDs の
   検出・検証追加、DVWA low coverage 評価。

3. **Severity normalization 導入**  
   DVWA 学習環境の検出評価 severity と提出用 severity を分離する。
   severity decision table を `vuln type` × `execution context` × `affected role` ×
   `data sensitivity` × `exploit preconditions` で定義する。

## Blocking dependencies
- SGK-2026-0345 完了後の shadow verdict 差分検証
- 実 artifact (session / report pair) での enforcement impact 事前確認
