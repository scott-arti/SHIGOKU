---
task_id: SGK-2026-0372
doc_type: work_report
status: done
parent_task_id: null
related_docs:
- docs/shigoku/plans/done/2026-07-22_sgk-2026-0372_signal-first-attack-task-expansion-regression-fix_plan.md
- docs/shigoku/worklogs/2026-07-22_sgk-2026-0372_signal-first-attack-task-expansion-regression-fix_work_log.md
created_at: '2026-07-22'
updated_at: '2026-07-28'
---

# SGK-2026-0372 作業完了報告

## 実装内容

- signal-first 経路のタスクを、既存の URL 単位展開と優先付けへ接続した。
- 複数 URL を含む signal-first 入力が、URL ごとの子タスクになる回帰テストを追加した。

## 判断理由

signal-first 経路だけが早期終了し、`TaskExpander` を通らなかったため、DVWA 実行時に 18 URL が 7 件のまとめタスクとして扱われていた。

## 検証

- `.venv/bin/pytest -q tests/core/engine/test_master_conductor_signal_recipe_routing.py tests/core/engine/test_task_expander.py tests/core/engine/test_master_conductor_pruning.py`
  - 30 passed
- `.venv/bin/shigoku-ops --json validate pytest --test tests/core/engine/test_master_conductor_signal_recipe_routing.py --test tests/core/engine/test_task_expander.py --quiet`
  - 22 passed

## リスク

実行済みの DVWA session を再生成してはいないため、実環境でのタスク数回復は次回の認可済み実行で確認が必要。signal-first が扱えないカテゴリを従来 fallback で補う設計は、本タスクの対象外である。

## 未対応事項

なし。
