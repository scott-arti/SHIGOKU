---
task_id: SGK-2026-0376
doc_type: work_report
status: done
parent_task_id: SGK-2026-0375
related_docs:
- docs/shigoku/plans/done/2026-07-23_signal-first-tagged-replay-attack-task-restoration_plan.md
- docs/shigoku/worklogs/2026-07-23_sgk-2026-0376_signal-first-tagged-replay-attack-task-restoration_work_log.md
- docs/shigoku/plans/done/2026-07-22_sgk-2026-0375_scenario-probe-ownership-dedup-recovery_plan.md
created_at: '2026-07-23'
updated_at: '2026-07-28'
title: Signal-first tagged replay attack task restoration work report
---

# SGK-2026-0376 作業報告

## 変更内容

- `src/core/engine/master_conductor.py` で、signal-first routing が成功した場合でも、signal bundle に含まれていない legacy `tagged_*` カテゴリだけを fallback 生成するようにした。
- recipe routing で処理済みの signal category も `signal_routed_categories` に記録し、同じカテゴリの二重生成を避けるようにした。
- `tests/core/engine/test_master_conductor_signal_recipe_routing.py` に、signal bundle に無い `tagged_admin` が落ちない回帰テストを追加した。

## 調査結果

- 最新 run `haddix_report_20260723_000300.md` と `session_20260723_000300.json` は consistency `consistent`。
- SCN08/10/12 は未生成ではなく、`scenario_probe_08`, `scenario_probe_10`, `scenario_probe_12` が作成された後、`INTERVENTION_DEFERRED_MANUAL` で skipped になっていた。
- 83件 baseline との差分は、旧 `tagged_*` 起点のタスク群が signal-first 成功時に fallback から除外されることが大きな原因だった。
- 現在の 20260722 tagged ファイルだけを legacy-only で見積もると約46件であり、83件への完全復帰はこの修正だけでは期待しない。

## 判断理由

- signal-first の完全無効化は、SGK-2026-0261 以降の設計を戻しすぎる。
- そのため、signal-first が扱ったカテゴリは維持し、未カバーの tagged カテゴリだけ補う最小差分にした。
- SCN08/10/12 の手動保留ポリシーは安全判断の領域なので、この作業では変更しない。

## 検証

- `env -u PYTHONHOME -u PYTHONPATH .venv/bin/pytest tests/core/engine/test_master_conductor_signal_recipe_routing.py::test_create_attack_tasks_from_recon_supplements_tagged_categories_missing_from_signal_bundle -q`
  - RED: 変更前に `admin_tasks` が空で失敗。
  - GREEN: 変更後 `1 passed`。
- `env -u PYTHONHOME -u PYTHONPATH .venv/bin/pytest tests/core/engine/test_master_conductor_signal_recipe_routing.py tests/core/engine/test_master_conductor_scenario_probes.py::test_add_tasks_keeps_distinct_scenario_probe_tasks_on_same_target tests/core/engine/test_master_conductor_scenario_probes.py::test_create_missing_core_scenario_probe_tasks_does_not_treat_inferred_planned_signals_as_covered tests/core/engine/test_master_conductor_scenario_probes.py::test_create_missing_core_scenario_probe_tasks_respects_explicit_scn06_coverage tests/core/engine/test_injection_ownership_dedup.py tests/core/engine/test_program_overrides_tdd_red.py -q`
  - `53 passed in 1.17s`。
- 実 tagged ファイルを使った見積もり:
  - legacy-only: 約46タスク。
  - signal-first + 未カバー tagged 補強: signal bundle に無い `tagged_cors_candidate`, `tagged_redirect_param`, promoted 系カテゴリを補強。

## 残っているリスク

- SCN08/10/12 は引き続き Ver.1 手動保留ポリシーで skipped になる。
- full `tests/core/engine/test_master_conductor_scenario_probes.py` は既存の `compiled_guard policy_unavailable` 系で9件失敗する。今回追加した関連テストは通過済み。
- 作業開始時の `create_shigoku_task.py --run-validate` と docs validate は既存の `task_268_missing_file` で失敗する。

## deferred_tasks

deferred_tasks: []
