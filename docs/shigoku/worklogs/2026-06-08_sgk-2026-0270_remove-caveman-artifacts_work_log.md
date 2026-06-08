---
task_id: SGK-2026-0270
doc_type: work_log
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/plans/2026-06-08_remove-unused-caveman-skill-artifacts_plan.md
- docs/shigoku/reports/2026-06-08_sgk-2026-0270_remove-caveman-artifacts_work_report.md
title: "作業ログ: Remove unused Caveman skill artifacts"
created_at: "2026-06-08"
updated_at: '2026-06-08'
---

# 作業ログ

1. `.agents/skills/` と `skills-lock.json` を調べ、repo 内の Caveman 系 skill 実体と参照箇所を特定した。
2. SHIGOKU 台帳に `SGK-2026-0270` を起票し、作業計画書を生成した。
3. `AGENTS.md` から Caveman 指示を削除し、`skills-lock.json` を空の `skills` マップへ更新した。
4. `.agents/skills/cavecrew` と `.agents/skills/caveman*` のファイル群を削除し、空ディレクトリも整理した。
5. 作業報告書と作業ログを追加し、タスク状態を `done` にそろえた。
6. `python3 scripts/sync_shigoku_updated_at.py` と `python3 scripts/validate_shigoku_docs.py` を実行して、ドキュメント整合性を確認する。

## 次アクション
- 必要なら別タスクで、グローバル環境に残る Caveman plugin のアンインストール手順も整理する。
