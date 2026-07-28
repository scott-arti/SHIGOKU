---
task_id: SGK-2026-0374
doc_type: work_report
status: done
parent_task_id: SGK-2026-0373
related_docs:
- docs/shigoku/plans/done/2026-07-22_sgk-2026-0374_scenario-probe-and-data-exposure-coverage-recovery_plan.md
- docs/shigoku/worklogs/2026-07-22_sgk-2026-0374_scenario-probe-and-data-exposure-coverage-recovery_work_log.md
created_at: '2026-07-22'
updated_at: '2026-07-28'
---

# SGK-2026-0374 作業完了報告

## 実装内容

- `src/core/engine/master_conductor.py` の `_create_missing_core_scenario_probe_tasks()` で、planned task の scenario coverage 判定に `infer_if_missing=False` を適用した。
- これにより、generic な説明文や intervention policy の推論だけで `SCN05 / SCN10` などが「既に covered」と誤判定される経路を止めた。
- `tests/core/engine/test_master_conductor_scenario_probes.py` に、planned task の推論文言で probe が消えないことを確認する回帰テストを追加した。
- 同テストヘルパーに `mode = "bugbounty"` を追加し、現行 `MasterConductor` の必須属性に追随させた。

## 判断理由

2026-07-22 の最新 run（`haddix_report_20260722_155830.md` と対応 session）では、scenario coverage が 6/12 に落ち込み、`SCN05 / SCN06 / SCN08 / SCN10 / SCN11 / SCN12` が未到達のままだった。

コードを追うと、scenario probe planner は `existing_tasks` を coverage 判定に使っていたが、その判定が intervention policy の推論まで含めていた。結果として、まだ専用 probe を作っていない段階なのに、planned task の文言だけで `SCN05` や `SCN10` が covered 扱いになり、専用 task が生成されなくなっていた。

## 検証

- `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260722_155830.md`
  - `status: consistent`
- `env -u PYTHONHOME -u PYTHONPATH .venv/bin/pytest tests/core/engine/test_master_conductor_scenario_probes.py::test_create_missing_core_scenario_probe_tasks_does_not_treat_inferred_planned_signals_as_covered tests/core/engine/test_master_conductor_scenario_probes.py::test_create_missing_core_scenario_probe_tasks_respects_explicit_scn06_coverage tests/core/engine/test_master_conductor_phase1_step15.py tests/core/engine/test_program_overrides_tdd_red.py`
  - `13 passed`
- `env -u PYTHONHOME -u PYTHONPATH .venv/bin/python - <<'PY' ...`
  - synthetic 再現で `probe_ids` に `scn_05_rate_limit_resilience`, `scn_06_data_exposure_diff`, `scn_08_oob_external_channel_flow`, `scn_10_semantic_business_logic`, `scn_11_multi_vector_chain`, `scn_12_advanced_ssrf_internal_topology` が含まれることを確認

## リスク

- `tests/core/engine/test_master_conductor_scenario_probes.py` 全体実行では、今回の修正とは別件の compiled guard `policy_unavailable` による失敗が残っている。
- 実 DVWA Security=low の rerun はまだ実施していないため、実 task 数が 34 からどこまで回復するかは実行確認が必要。

## 未対応事項

なし。
