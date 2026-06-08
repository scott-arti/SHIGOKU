---
name: task-work-reporting
description: 実装完了時に作業報告書を作成し、台帳ステータス更新と関連ドキュメント更新を行う。Use when finishing implementation work for a task ID.
---

# Task Work Reporting

## Mandatory Steps
1. `task_id` を台帳と一致確認。
2. `docs/shigoku/reports/` に報告書を作成/更新。
3. Front Matter に `task_id`, `doc_type: work_report`, `status: done`, `parent_task_id`, `related_docs`, `created_at`, `updated_at` を設定（`created_at/updated_at` は `YYYY-MM-DD`）。
4. 実装内容 / 判断理由 / リスク / 未対応事項(`deferred_tasks`)を記載。
   - `deferred_tasks` に継続監視を記録する場合は、対応する追跡タスクID（`SGK-YYYY-NNNN`）を必ず併記する。
   - 追跡タスクが未作成なら、`done` 化の前に `plan` / `subtask_plan` を起票して関連付ける。
5. `task_registry.yaml` と `task_ledger.*` の status を更新。

## Final Check
- `python3 scripts/sync_shigoku_updated_at.py`
- `python3 scripts/validate_shigoku_docs.py`
