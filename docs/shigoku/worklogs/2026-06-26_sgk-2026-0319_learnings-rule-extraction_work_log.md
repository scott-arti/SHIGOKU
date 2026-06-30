---
task_id: SGK-2026-0319
doc_type: work_log
status: done
parent_task_id: SGK-2026-0289
related_docs:
  - docs/shigoku/subtasks/done/2026-06-26_learnings-agent-rule_subtask_plan.md
  - docs/shigoku/reports/2026-06-26_sgk-2026-0319_learnings-rule-extraction_work_report.md
  - docs/shigoku/learnings.md
title: 'SGK-2026-0319 作業ログ: learnings の恒久ルール昇格と agent rule 接続'
created_at: '2026-06-26'
updated_at: '2026-06-30'
tags:
  - shigoku
---

# SGK-2026-0319 作業ログ

## 2026-06-26

### 作業内容
1. `docs/shigoku/learnings.md`、`rules/*.md`、`AGENTS.md`、task ledger 関連ファイルを読み、恒久ルール化の反映先を整理した。
2. `python3 scripts/create_shigoku_task.py --title "learnings の恒久ルール昇格と agent rule 接続" --doc-type subtask_plan --status active --parent-task-id SGK-2026-0289 --related-doc docs/shigoku/learnings.md --related-doc rules/lessons.md --related-doc AGENTS.md --target "docs/shigoku, rules, AGENTS.md" --run-validate` を実行し、`SGK-2026-0319` を起票した。
3. 起票時の validator 出力から `docs/shigoku/learnings.md` の Front Matter 欠落を検知し、今回のスコープに Front Matter 正規化を含める判断を行った。
4. `rules/lessons.md`、`rules/shigoku-docs.md`、`rules/report-session-consistency.md`、`rules/python-tests.md`、`AGENTS.md` を更新し、project-specific learnings を恒久ルールへ昇格した。
5. `docs/shigoku/learnings.md` に昇格済みルール索引を追加し、raw learnings の一次保管場所としての役割を明記した。
6. 作業報告書と本作業ログを作成し、subtask plan を `done/` へ移して台帳を `done` へ更新した。
7. `python3 scripts/sync_shigoku_updated_at.py` と `python3 scripts/validate_shigoku_docs.py` を実行し、`FRONT_MATTER_ISSUES=0 / BROKEN_LINKS=0 / REGISTRY_ISSUES=0 / DEFERRED_LINK_ISSUES=0` を確認した。

### 次アクション

- 新しい learning が複数回再発した場合は、まず `rules/lessons.md` への昇格要否を確認する。
- `create_shigoku_task.py` の命名規約差分は必要なら別タスクで整理する。
