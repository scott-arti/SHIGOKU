---
task_id: SGK-2026-0378
doc_type: work_log
status: done
parent_task_id: SGK-2026-0377
related_docs:
- docs/shigoku/subtasks/done/2026-07-23_signal-legacy-supplement-url-level-merge-fix_subtask_plan.md
- docs/shigoku/reports/2026-07-23_sgk-2026-0378_signal-legacy-supplement-url-level-merge-fix_work_report.md
created_at: '2026-07-23'
updated_at: '2026-07-28'
title: SGK-2026-0378 Signal legacy supplement URL-level merge fix 作業ログ
---

# SGK-2026-0378 作業ログ

## 2026-07-23

- 最新レポート `haddix_report_20260723_032328.md` とセッション `session_20260723_032328.json` の整合性を確認した。
- 49件の内訳を集計し、signal-first が同カテゴリの legacy tagged 補強をカテゴリ単位で抑止していることを確認した。
- 回帰テストを追加し、現行コードでは同じカテゴリ内の tagged-only URL が落ちることを RED で確認した。
- `src/core/engine/master_conductor.py` を修正し、signal-first 実行済みURLだけを除外し、未実行URLは legacy supplement として残すようにした。
- 対象テストと重複所有テストを実行した。

## 次アクション

- ユーザー環境で Docker compose run による DVWA low 再実行を行い、Total Tasks と Scenario Coverage の増加を確認する。
- 83件との差分として残る alias重複・aggregate task の扱いは、必要なら別タスクで判断する。
