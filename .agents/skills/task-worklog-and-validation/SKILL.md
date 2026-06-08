---
name: task-worklog-and-validation
description: "作業ログを記録し、台帳反映後にドキュメント整合チェックを実行する。Use after plan/report updates to close a task cycle."
---

# Task Worklog and Validation

## Mandatory Steps
1. `docs/shigoku/worklogs/` のログを作成/更新。
2. Front Matter に `task_id`, `doc_type: work_log`, `status`, `parent_task_id`, `related_docs`, `created_at`, `updated_at` を設定（`created_at/updated_at` は `YYYY-MM-DD`）。
3. ログに日付・変更要約・参照先（計画書/報告書）・次アクションを記載。
   - 継続監視が残る場合は「親タスクを done、監視タスクを active で分離追跡」したことを記録する。
4. `task_registry.yaml` と `task_ledger.*` を反映。
5. `python3 scripts/sync_shigoku_updated_at.py` を実行して変更ドキュメントの `updated_at` を当日付へ揃える。
6. 整合チェックを実行。

## Final Check
- `python3 scripts/sync_shigoku_updated_at.py`
- `python3 scripts/validate_shigoku_docs.py`
