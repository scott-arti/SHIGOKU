---
task_id: SGK-2026-0375
doc_type: work_report
status: done
parent_task_id: SGK-2026-0374
related_docs:
- docs/shigoku/plans/done/2026-07-22_sgk-2026-0375_scenario-probe-ownership-dedup-recovery_plan.md
- docs/shigoku/worklogs/2026-07-22_sgk-2026-0375_scenario-probe-ownership-dedup-recovery_work_log.md
created_at: '2026-07-22'
updated_at: '2026-07-28'
---

# SGK-2026-0375 作業完了報告

## 実装内容

- `src/core/engine/master_conductor.py` の scenario probe task 生成で、`selection_origin` に `scenario_probe_planner:<scenario_id>` を設定した。
- これにより、同じ URL に向く scenario probe でも、SCN ごとに ownership dedup の識別子が分かれるようにした。
- `tests/core/engine/test_master_conductor_scenario_probes.py` に、same-target の scenario probe 9 本が `_add_tasks()` 後も消えない回帰テストを追加した。

## 判断理由

2026-07-22 23:12 run の source-of-truth session では、`scenario_probe_planner` が完了/スキップとして残っているのは `SCN01` と `SCN08` だけだった。

再現すると、scenario probe は 9 本生成されていたが、queue へ入る段階で `_check_and_claim_ownership()` により後続が suppress されていた。原因は scenario probe task の `selection_origin` が空で、同じ URL 上の別 SCN が同一 execution path と見なされていたことだった。

## 検証

- `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260722_231221.md`
  - `status: consistent`
- `env -u PYTHONHOME -u PYTHONPATH .venv/bin/pytest tests/core/engine/test_master_conductor_scenario_probes.py::test_create_missing_core_scenario_probe_tasks_does_not_treat_inferred_planned_signals_as_covered tests/core/engine/test_master_conductor_scenario_probes.py::test_create_missing_core_scenario_probe_tasks_respects_explicit_scn06_coverage tests/core/engine/test_master_conductor_scenario_probes.py::test_add_tasks_keeps_distinct_scenario_probe_tasks_on_same_target tests/core/engine/test_master_conductor_phase1_step15.py tests/core/engine/test_program_overrides_tdd_red.py`
  - `14 passed`
- `env -u PYTHONHOME -u PYTHONPATH .venv/bin/python - <<'PY' ...`
  - synthetic 再現で、generated 9 本 / added 9 本 / queued 9 本、かつ `selection_origin` が `scenario_probe_planner:scn_*` になることを確認

## リスク

- 実 DVWA rerun はまだ行っていないため、実 session の task 数と scenario coverage がどこまで回復するかは未確認。
- `validate_shigoku_docs.py` は今回変更と無関係の既知不整合 `task_268_missing_file:docs/shigoku/subtasks/2026-06-03_sgk-2026-0258_temporal-followup_subtask_plan.md` で失敗する。

## 未対応事項

なし。
