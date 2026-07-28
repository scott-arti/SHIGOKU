---
task_id: SGK-2026-0378
doc_type: work_report
status: done
parent_task_id: SGK-2026-0377
related_docs:
- docs/shigoku/subtasks/done/2026-07-23_signal-legacy-supplement-url-level-merge-fix_subtask_plan.md
- docs/shigoku/worklogs/2026-07-23_sgk-2026-0378_signal-legacy-supplement-url-level-merge-fix_work_log.md
created_at: '2026-07-23'
updated_at: '2026-07-28'
title: SGK-2026-0378 Signal legacy supplement URL-level merge fix 作業報告
---

# SGK-2026-0378 作業報告

## 概要

2026-07-23 03:23:28 実行の DVWA low 結果で、Total Tasks が 49 件まで増えたものの、機能追加前の 83 件と比べてまだ少ない問題を調査した。

整合性チェックでは `haddix_report_20260723_032328.md` と `session_20260723_032328.json` は一致しており、表示ずれではなく実セッションのタスク生成数が少ないことを確認した。

## 原因

`MasterConductor._create_attack_tasks_from_recon()` で signal-first routing 後の legacy `tagged_*` 補強がカテゴリ単位で除外されていた。

そのため、たとえば `id_param` が signal-first で一部URLだけタスク化されると、同じ `tagged_id_param` ファイルに残る別URLまで丸ごと補強対象から外れていた。

## 変更内容

- `src/core/engine/master_conductor.py`
  - signal-first で実行済みのURLをカテゴリ別に記録する処理を追加。
  - legacy `tagged_*` 補強では、同じカテゴリでも signal-first で実行済みのURLだけ除外し、未実行URLは補強タスクに残すよう変更。
  - history replay の除外URLにも signal-first 実行済みURLを渡し、同じURLの二重実行を避けるよう変更。
- `tests/core/engine/test_master_conductor_signal_recipe_routing.py`
  - 同じカテゴリ内で signal に無い tagged URL が補強されることを確認する回帰テストを追加。

## 検証

- RED:
  - `.venv/bin/pytest tests/core/engine/test_master_conductor_signal_recipe_routing.py::test_create_attack_tasks_from_recon_supplements_same_category_urls_missing_from_signal_bundle -q`
  - 期待通り失敗し、`legacy_extra_tasks` が空であることを確認。
- GREEN:
  - `.venv/bin/pytest tests/core/engine/test_master_conductor_signal_recipe_routing.py::test_create_attack_tasks_from_recon_supplements_same_category_urls_missing_from_signal_bundle -q`
  - `1 passed`
- 対象ファイル全体:
  - `.venv/bin/pytest tests/core/engine/test_master_conductor_signal_recipe_routing.py -q`
  - `23 passed`
- 重複所有テスト:
  - `.venv/bin/pytest tests/core/engine/test_injection_ownership_dedup.py -q`
  - `23 passed`
- 実セッション材料でのタスク生成見積もり:
  - `session_20260723_032328.json` の recon results からローカル再計算し、`id_param` / `file_param` / `auth` / `redirect_param` の legacy URL gap が補強対象になることを確認。

## 残リスク

- 83件時代との差分には、`localhost` と `127.0.0.1` のalias重複や aggregate task の有無も含まれる。今回の修正は「同カテゴリで漏れたURLの復元」に限定した。
- `tests/core/engine/test_master_conductor_scenario_probes.py` は既存の bugbounty guard 前提差分により複数失敗する。今回のURL補強修正とは別件として扱う。
- 実際の Total Tasks は Docker compose run の再実行結果で確認する必要がある。

## deferred_tasks

[]
