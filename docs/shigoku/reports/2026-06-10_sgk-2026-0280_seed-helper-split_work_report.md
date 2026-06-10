---
task_id: SGK-2026-0280
doc_type: work_report
status: done
parent_task_id: SGK-2026-0264
related_docs:
- docs/shigoku/subtasks/2026-06-09_masterconductor-seed-helper-priority-split_subtask_plan.md
- docs/shigoku/plans/2026-06-05_master-conductor-split-plan_plan.md
- docs/shigoku/reports/2026-06-09_master-conductor-split_work_report.md
created_at: '2026-06-10'
updated_at: '2026-06-11'
title: '作業報告書: MasterConductor seed/path helper 優先抽出 (SGK-2026-0280)'
---

# 作業報告書: MasterConductor seed/path helper 優先抽出 (SGK-2026-0280)

## 1. 実施内容

### 手順1: baseline 確立
- 全67 targeted tests および 20 phase0 tests が変更前から通過することを確認。
- `MasterConductor.__new__(MasterConductor)` パターンでの method 呼び出し互換を確認。

### 手順4-9: ReconSeedTargetService 作成
- `src/core/engine/master_conductor_recon_seed_target_service.py` を新規作成 (1118行)。
- 内部境界:
  - `_UrlScopeResolver`: `normalize_url_candidate`, `extract_host_candidate`, `is_target_url_in_scope`, `resolve_task_target`
  - `_SeedTargetSelector`: `score_csrf_seed_candidate`, `score_xss_seed_candidate`, `is_low_value_backfill_target`, `should_enable_phase2_on_empty_for_backfill`, `apply_phase2_on_empty_policy`
  - `ReconSeedTargetService`: 上記2境界を統合し、path resolver、seed collector/refiner、scenario seed helper を提供。
- 全20メソッドを service に移行。MasterConductor instance 参照なし。

### facade wrapper 化
- `master_conductor.py` の全20メソッド本体を thin wrapper に置換 (各1-5行)。
- `_seed_service` property を毎回新規生成で追加 (`__new__` 互換対応: `getattr` で欠損属性を安全処理)。state 更新 (set_project_manager / initialize_workspace) 後も常に最新の project_manager / workspace を参照する。
- 既存 import path 互換を維持。

### 行数削減
- `master_conductor.py`: 8317行 → 7406行 (-911行, -10.9%)
- `master_conductor_recon_seed_target_service.py`: +1222行

## 2. 検証結果

```bash
# targeted tests (67 passed)
.venv/bin/pytest -q tests/core/engine/test_master_conductor_api_candidate_routing.py tests/core/engine/test_master_conductor_scenario_probes.py tests/core/intelligence/test_phase0_risk_clearance_checklist.py
# 67 passed

# character / parity
.venv/bin/pytest -q tests/core/engine/test_master_conductor_api_candidate_routing.py::test_score_csrf_seed_candidate_skips_http_404_seed
# 1 passed

# related tests (12 passed)
.venv/bin/pytest -q tests/core/engine/test_master_conductor_vuln_family_gate.py tests/core/engine/test_master_conductor_recon_nonblocking.py tests/core/engine/test_master_conductor_realtime_budget.py
# 12 passed

# broader tests (36 passed)
.venv/bin/pytest -q tests/core/engine/test_master_conductor_bugfix.py tests/core/engine/test_master_conductor_failure_reason_codes.py tests/core/engine/test_master_conductor_finding_normalization.py tests/core/engine/test_master_conductor_hitl_priority.py tests/core/engine/test_master_conductor_phase1_step15.py tests/core/engine/test_master_conductor_recipe_contracts.py tests/core/engine/test_master_conductor_timeout_policy.py tests/core/engine/test_master_conductor_react_observation_policy.py tests/core/engine/test_master_conductor_intervention_gate.py tests/core/engine/test_master_conductor_scope_fast_path.py
# 36 passed

# graphify
graphify update .
# 947 nodes, 2502 edges, 52 communities

# SHIGOKU docs
python3 scripts/validate_shigoku_docs.py
# MD_FILES=360, FRONT_MATTER_ISSUES=0, BROKEN_LINKS=0, REGISTRY_ISSUES=0
```

## 3. 完了条件の確認

- [x] `master_conductor.py` から 800 行以上削減 (実績 911 行)
- [x] 旧 private method 名は残り、既存 tests の monkeypatch が引き続き動く
- [x] seed service は `task_queue`, `pending_hitl`, `completed_tasks` を直接 mutation しない
- [x] `ReconAttackTaskPlanner` の task output が分割前後で一致 (全 tests 通過)
- [x] `ReconSeedTargetService` は `MasterConductor` instance を保持しない
- [x] selected URLs、evidence map、score reasons の output parity が確認されている
- [x] targeted tests が失敗した状態で related / broad validation に進んでいない
- [x] `graphify update .` と SHIGOKU docs validation が通る

## 4. deferred_tasks

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0280-D01
    title: "MasterConductor dispatch service 本格実装"
    reason: "_dispatch は scope guard / worker / swarm / recon / AgentFactory を含むため、seed/path helper 分割とは別に character tests が必要"
    impact: high
    tracking_task_id: SGK-2026-0264
    recommended_next_action: "seed service 完了、targeted / related tests 通過、service から facade 逆参照なしを確認後、dispatch 専用 character tests を追加して master_conductor_dispatch_service.py へ移行する"

  - deferred_id: SGK-2026-0280-D02
    title: "MasterConductor execution loop 分割"
    reason: "execute_with_replan と _execute_single_task_full_flow は状態更新が多く、seed/path helper 抽出後の後続作業にする"
    impact: medium
    tracking_task_id: SGK-2026-0264
    recommended_next_action: "dispatch / recon execution 境界を固定後、execution loop service の計画を起票する"

  - deferred_id: SGK-2026-0280-D03
    title: "MasterConductor compatibility wrapper 削除候補の整理"
    reason: "今回の分割では旧 private method 名を残すため、恒久的な wrapper 増加を防ぐ追跡が必要"
    impact: medium
    tracking_task_id: SGK-2026-0264
    recommended_next_action: "wrapper 利用箇所と monkeypatch 依存テストを棚卸しし、削除可能な wrapper を別 task で段階削除する"

  - deferred_id: SGK-2026-0280-D04
    title: "coverage guard task 生成の分離"
    reason: "global guard task 生成は seed target 取得と task queue mutation が混在するため、今回の seed/path helper 分割から外した"
    impact: medium
    tracking_task_id: SGK-2026-0264
    recommended_next_action: "coverage_guard_service などの境界候補を設計し、queue mutation を facade に残すか service 化するかを別計画で決める"
```

## 5. 変更内容一覧

| ファイル | 変更 | 行数変化 |
|---|---|---|
| `src/core/engine/master_conductor.py` | 20 methods を thin wrapper に、`_seed_service` property 追加 | -911 行 |
| `src/core/engine/master_conductor_recon_seed_target_service.py` | 新規作成 | +1222 行 |
| `tests/core/engine/test_master_conductor_scenario_probes.py` | 回帰テスト追加 (stale dependency 再現) | +14 行 |
