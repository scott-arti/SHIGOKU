---
task_id: SGK-2026-0377
doc_type: work_report
status: done
parent_task_id: SGK-2026-0376
related_docs:
- docs/shigoku/plans/done/2026-07-23_vulntest-mode-compiled-guard-fallback-alignment_plan.md
- docs/shigoku/plans/done/2026-07-23_signal-first-tagged-replay-attack-task-restoration_plan.md
- docs/shigoku/worklogs/2026-07-23_sgk-2026-0377_vulntest-mode-compiled-guard-fallback-alignment_work_log.md
created_at: '2026-07-23'
updated_at: '2026-07-28'
---

# SGK-2026-0377 作業報告: Vulntest mode compiled guard fallback alignment

## 実装内容

- 最新 `haddix_report_20260723_015237.md` と `session_20260723_015237.json` の整合性を確認した。
- 最新 session では `target_info.mode` が `vulntest` なのに、legacy tagged 補強カテゴリが `bugbounty` 用 compiled guard の `policy_unavailable` で落ちる経路を再現した。
- `MasterConductor._create_attack_tasks_from_recon()` の compiled guard 適用判定を、`self.mode` 直読みから `_resolve_current_mode_name()` に変更した。
- `target_info["mode"]="vulntest"` かつ `self.mode="bugbounty"` の回帰テストを追加した。

## 判断理由

`_resolve_current_mode_name()` は `context.target_info["mode"]` を優先する既存の単一正本であり、session start 時に保存された実行モードを正しく反映する。補強タスク生成だけ `self.mode` を直読みすると、`vulntest` 実行が `bugbounty` と誤判定され、compiled guard の policy 未設定時に `tagged_redirect_param` / `tagged_admin` / `tagged_meta_observability` が生成されない。

## 検証

- RED:
  - `env -u PYTHONHOME -u PYTHONPATH .venv/bin/pytest tests/core/engine/test_master_conductor_signal_recipe_routing.py::test_create_attack_tasks_from_recon_uses_context_mode_for_legacy_supplement_guard -q`
  - 期待通り `compiled_guard_block:policy_unavailable` で失敗。
- GREEN:
  - 同テストが `1 passed`。
- 関連テスト:
  - `env -u PYTHONHOME -u PYTHONPATH .venv/bin/pytest tests/core/engine/test_master_conductor_signal_recipe_routing.py tests/core/engine/test_master_conductor_scenario_probes.py::test_add_tasks_keeps_distinct_scenario_probe_tasks_on_same_target tests/core/engine/test_master_conductor_scenario_probes.py::test_create_missing_core_scenario_probe_tasks_does_not_treat_inferred_planned_signals_as_covered tests/core/engine/test_master_conductor_scenario_probes.py::test_create_missing_core_scenario_probe_tasks_respects_explicit_scn06_coverage tests/core/engine/test_injection_ownership_dedup.py tests/core/engine/test_program_overrides_tdd_red.py -q`
  - `54 passed in 1.28s`。
- 実artifact:
  - `haddix_report_20260723_015237.md` に対して `shigoku-ops report consistency` と `verify_report_session_consistency.py` がともに `status=consistent`。
  - 最新 session の recon 結果を修正版コードへ再投入し、`resolved_mode=vulntest` で `tagged_cors_candidate` / `tagged_redirect_param` / `tagged_admin` / `tagged_meta_observability` の補強タスク復元を確認。

## リスク

- 実DVWA再実行はユーザー環境での確認が必要。今回の検証は単体テストと保存済み session artifact の再投入で実施した。
- `SCN08` / `SCN10` / `SCN12` は `INTERVENTION_DEFERRED_MANUAL` の対象であり、タスク生成とは別に手動保留として残る可能性がある。

## deferred_tasks

[]
