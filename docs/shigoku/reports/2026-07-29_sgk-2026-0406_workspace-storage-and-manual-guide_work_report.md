---
task_id: SGK-2026-0406
doc_type: work_report
status: done
parent_task_id: null
related_docs:
  - docs/shigoku/plans/done/2026-07-29_sgk-2026-0406_workspace-storage-and-manual-guide_plan.md
  - docs/shigoku/manuals/WORKSPACE_STORAGE_AND_MANUAL_GUIDE.md
created_at: '2026-07-29'
updated_at: '2026-08-07'
---

# SGK-2026-0406 作業報告

## 実施内容

- `workspace/` と `workspace/projects/<対象>/` の保存物をコードから確認し、用途を文書化した。
- 現行の標準保存先、互換・履歴用の保存先、通常実行では不要な旧保存先を区別した。
- `manuals/` の現行文書と `manual_legacy/` の過去資料を、読む目的ごとに分類した。

## 検証

- `python3 scripts/validate_shigoku_docs.py` を実行し、新規文書のFront Matterと台帳リンクを確認した。

## リスク

- 既存文書にリンク切れと台帳不整合が残っている。今回の追加で新しい不整合は作らない。
- root 所有の旧保存物は、この作業では削除できない。
