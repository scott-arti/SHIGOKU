---
name: task-work-reporting
description: Use when closing out implementation work for a task ID by recording the work report, work log, registry updates, and final documentation validation.
---

# Task Work Reporting

## Mandatory Steps
1. `task_id` を台帳と一致確認。
2. `docs/shigoku/reports/` に報告書を作成/更新。
3. Front Matter に `task_id`, `doc_type: work_report`, `status: done`, `parent_task_id`, `related_docs`, `created_at`, `updated_at` を設定（`created_at/updated_at` は `YYYY-MM-DD`）。
4. 実装内容 / 判断理由 / リスク / 未対応事項(`deferred_tasks`)を記載。
   - `deferred_tasks` に継続監視を記録する場合は、対応する追跡タスクID（`SGK-YYYY-NNNN`）を必ず併記する。
   - 追跡タスクが未作成なら、`done` 化の前に `plan` / `subtask_plan` を起票して関連付ける。
5. `docs/shigoku/worklogs/` のログを作成/更新。
6. Front Matter に `task_id`, `doc_type: work_log`, `status`, `parent_task_id`, `related_docs`, `created_at`, `updated_at` を設定（`created_at/updated_at` は `YYYY-MM-DD`）。
7. ログに日付・変更要約・参照先（計画書/報告書）・次アクションを記載。
   - 継続監視が残る場合は「親タスクを `done`、監視タスクを `active` で分離追跡」したことを記録する。
8. 対応する計画書をクローズする場合の格納場所ルール:
   - `plan` が `done` になるときは、計画書を `docs/shigoku/plans/done/` へ移動する。
   - `subtask_plan` が `done` になるときは、計画書を `docs/shigoku/subtasks/done/` へ移動する。
   - `active` の計画書は引き続き `docs/shigoku/plans/` または `docs/shigoku/subtasks/` 直下で管理する。
   - 移動後は `task_registry.yaml`, `task_ledger.*`, `related_docs`, 本文リンクを必ず新パスへ更新する。
   - 計画書ファイル名は移動前後とも `YYYY-MM-DD_<task_id lowercase>_<slug>.md` を維持し、`status` はファイル名に含めない。
9. `task_registry.yaml` と `task_ledger.*` の status を更新し、`work_report` / `work_log` / 計画書移動後パスを反映する。
10. `python3 scripts/sync_shigoku_updated_at.py` を実行して変更ドキュメントの `updated_at` を当日付へ揃える。
11. `python3 scripts/validate_shigoku_docs.py` を実行して整合チェックを完了する。
12. 変更されたコード、作業報告書、作業ログ、台帳ファイルを一括でステージング・コミットする。
   コマンド:
   git add .
   git commit -m "task([タスクID]): 成果物追加と台帳クローズ"
13. コミットしたブランチをGitHubへ送信する。
   コマンド: git push origin feature/[タスクID]
14. 送信後、GitHub上でPull Requestの作成準備が整った旨を、タスク完了報告（作業報告書の内容）と共にユーザーに提示する。



## Final Check
- `python3 scripts/sync_shigoku_updated_at.py`
- `python3 scripts/validate_shigoku_docs.py`
