---
name: task-bootstrap-and-planning
description: 新規タスク開始時に、台帳確認・新ID採番・台帳追加・計画書ひな形生成を実行する。Use when starting any new implementation task in SHIGOKU docs workflow.
---

# Task Bootstrap and Planning

## Mandatory Steps
1. 台帳確認:
   - `docs/shigoku/registry/task_registry.yaml`
   - `docs/shigoku/registry/task_ledger.md`
2. 計画書は必ずPython生成を使う（手書き新規作成は禁止）:
   - 新規 `plan` / `subtask_plan` は必ず `create_shigoku_task.py` から作成する
   - YAML Front Matter と本文テンプレートはスクリプトの出力を正本とし、作成経路を統一する
3. 1コマンド実行:
   - `plan` の場合: `python3 scripts/create_shigoku_task.py --title "<task title>" --doc-type plan --status active --run-validate`
   - `subtask_plan` の場合: `python3 scripts/create_shigoku_task.py --title "<task title>" --doc-type subtask_plan --status active --run-validate`
   - `create_shigoku_task.py` は内部で `sync_shigoku_updated_at.py` を自動実行するため、追加コマンドは不要
4. 必要に応じて追加オプション:
   - `--parent-task-id SGK-2026-0001`
   - `--related-doc docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md` (複数回指定可)
   - `--target "<module-or-scope>"`
5. 生成結果確認:
   - 新規 `task_id` が `task_registry.yaml` と `task_ledger.*` に反映
   - `plan` は `docs/shigoku/plans/`、`subtask_plan` は `docs/shigoku/subtasks/` に作成
   - 計画書 Front Matter に `task_id`, `doc_type`, `status`, `parent_task_id`, `related_docs`, `created_at`, `updated_at` を設定（`created_at/updated_at` は `YYYY-MM-DD`）
6. 継続監視用タスクの起票時:
   - 親タスクの `deferred_tasks` で参照する `SGK-YYYY-NNNN` をこの手順で起票する。
   - `--parent-task-id` と `--related-doc` を設定し、親タスクとのトレーサビリティを必ず確保する。

## Final Check
- `python3 scripts/validate_shigoku_docs.py`
