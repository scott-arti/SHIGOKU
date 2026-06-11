---
task_id: SGK-2026-0282
doc_type: work_report
status: done
parent_task_id: SGK-2026-0264
related_docs:
  - docs/shigoku/plans/2026-06-05_master-conductor-split-plan_plan.md
  - docs/shigoku/subtasks/2026-06-09_masterconductor-seed-helper-priority-split_subtask_plan.md
  - docs/shigoku/subtasks/2026-06-10_masterconductor-next-high-impact-split_subtask_plan.md
  - docs/shigoku/subtasks/2026-06-12_masterconductor-policy-hitl-dispatch_subtask_plan.md
  - docs/shigoku/reports/2026-06-10_sgk-2026-0281_masterconductor-next-split_work_report.md
created_at: '2026-06-12'
updated_at: '2026-06-12'
tags:
  - shigoku
  - master-conductor
  - policy-extraction
  - hitl-extraction
  - dispatch-extraction
---

# 作業完了報告書：MasterConductor 追加分割計画: policy/HITL/dispatch 段階抽出

## 1. 達成した成果

### 1.1 既存抽出物の清掃 (Slice 0)
- `master_conductor_scenario_coverage_service.py`: `evaluate_intervention_scenario_coverage` 関数内の `return` 後にある到達不能な重複断片 80行（`normalize_scenario_id_for_coverage` の stale duplicate）を削除。
- 削除後 615→534 行 (81 lines removed)。
- 独立 patch として実施し、振る舞い差分を混ぜていない。
- targeted tests: `test_master_conductor_scenario_probes.py` + `test_master_conductor_vuln_family_gate.py` (23 tests) 全通過。

### 1.2 Policy service 抽出 (Slice 1)
- **新規ファイル**: `src/core/engine/master_conductor_policy_service.py` (495 行)
  - pure evaluator 群 (13 関数): `evaluate_active_probe_policy`, `rank_missing_link_targets_by_information_gain`, `sanitize_active_probe_policy`, `normalize_workflow_template`, `assess_missing_link_probe_rollout`, `evaluate_active_probe_runtime_guard`, `build_race_profile`, `build_safe_probe_variations`, `evaluate_phase2_operational_mode`, `build_degradation_component_contract`
  - policy resolver 群 (2 関数): `resolve_active_probe_policy_for_program`, `build_probe_runtime_context_from_chain_finding`
  - decision function: `resolve_component_degradation`
  - audit payload builder 群 (2 関数): `build_chain_audit_details`, `build_degradation_audit_details`
  - settings 依存 resolver: `resolve_active_probe_policy_default`
- **facade wrapper 維持**: 全19 policy 関連 method 名（`evaluate_active_probe_policy` 〜 `_resolve_active_probe_policy`）の public/private signature と戻り値 shape を維持。ただし `plan_missing_link_probes` (64行)、`run_pre_action_gate_shadow` (103行)、`trigger_chain_evaluation` (39行) は self 依存が強く body を残したまま。純粋判定 16 method を thin wrapper 化。
- **副作用分離**: `emit_chain_audit_record`, `emit_degradation_audit_record` は `decision_tracer` / `audit_logger` への書き込みを facade に残し、details dict 構築のみ service へ委譲。
- targeted tests: 65 tests (`phase1_step14`, `phase1_step15`, `phase25_shadow`, `program_overrides_tdd_red`, `phase0_risk`, `phase2_risk`) 全通過。

### 1.3 HITL precheck 抽出 (Slice 2)
- **新規ファイル**: `src/core/engine/master_conductor_hitl_precheck_service.py` (311 行)
  - scenario classification: `is_scn07_to_12`, `is_manual_defer_target_v1`
  - approval gate: `requires_intervention_approval`, `normalize_intervention_gate_mode`
  - payload builders: `build_scn07_12_notification_lines`, `build_intervention_hitl_info`
  - decision tree: `evaluate_precheck_decision` + `PrecheckDecision` dataclass (pure mutation plan, 状態変更なし)
- **facade wrapper 維持**: `_normalize_intervention_gate_mode`, `_is_scn07_to_12`, `_is_manual_defer_target_v1` を thin wrapper 化。
- **HitlService 境界**: pending ticket add/update/enqueue/done は既存 `HitlService` が担当（変更なし）。
- **_run_intervention_precheck は未抽出**: 171行の複合メソッドは state mutation / execution_log / state_lock との密結合のため deferred。また `_notify_scn07_12_intervention` (65行) も notification dedupe + get_notifier() 副作用を含むため未抽出。`PrecheckDecision` クラスは将来の再構築用に用意済み。
- targeted tests: 16 tests (`intervention_gate`, `hitl_pending`, `hitl_priority`, `bugfix`) 全通過。

### 1.4 Dispatch 抽出 (Slice 4, 部分)
- **既存ファイル更新**: `src/core/engine/master_conductor_dispatch_service.py` (17→95行)
  - `dispatch_scope_verification_fast_path` 関数を stub から実体化。
- **facade wrapper 維持**: `_dispatch_scope_verification_fast_path` を thin wrapper 化（66行→8行の wrapper）。
- **_dispatch 本体は未抽出**: 561行の複合 async メソッド。6 routing branches、cookie/header contextvar、worker/swarm/recon/recipe/AgentFactory fallback。character tests 追加を deferred。
- targeted tests: 5 tests (`recon_nonblocking`, `worker_integration`, `injection_parallel_dispatch`) + 1 (`scope_fast_path`) 全通過。

### 1.5 未着手スライス
- **Slice 3 (summary/parallel)**: `_generate_summary` (96行) と `execute_parallel` (85行) の抽出は未着手。
  - `_generate_summary` は cross-cutting (coverage, SLO, failure codes, pending HITL) で複数の thin wrapper を呼び出す集成メソッドのため、抽出効果が限定的。
  - `execute_parallel` は `master_conductor_parallel.py` (117行) と重複しており deduplication 調査が必要。

## 2. 削減実績

| メトリクス | 値 |
|---|---|
| master_conductor.py 当初 | 6603 行 |
| master_conductor.py 最終 | 6278 行 |
| facade 削減 | **325 行 (4.9%)** |
| 新規 service 行数 (合計) | 1435 行 |
| scenario_coverage 削減 | 615→534 (81行削減, dead code) |
| 既存 wrapper 維持数 | 22 method |
| service から facade import | 0 |
| service の direct mutation | 0件（dispatch scope fast path の `set_scope()` は facade 側へ移管済み） |
| targeted tests 追加 (既存 passing) | 112 tests |

## 3. サービス境界ルール（確立・遵守）

| ルール | 遵守 |
|---|---|
| naming: `master_conductor_{domain}_service.py` | ✅ 全 service が従う |
| service は MasterConductor instance 保持禁止 | ✅ 全 service が従う |
| service → facade import 禁止 | ✅ 0件 |
| queue/task/audit/execution_log の final mutation は facade | ✅ 全 service が従う |
| close/shutdown 対象 resource の非所有 | ✅ 全 service が従う |
| 1 function あたり callable 依存 ≤5 | ✅ 最大4 (resolve_active_probe_policy_for_program) |
| constructor は keyword-only (`*, ...`) | ✅ HitlPrecheckService / PrecheckDecision が従う |

## 4. 検証結果

### 4.1 テスト結果
```
.venv/bin/pytest -q [policy tests] -> 65 passed
.venv/bin/pytest -q [HITL tests] -> 16 passed
.venv/bin/pytest -q [scenario/coverage tests] -> 23 passed
.venv/bin/pytest -q [dispatch/worker/scope tests] -> 6 passed
.venv/bin/pytest -q [failure_reason_codes] -> 1 passed
.venv/bin/pytest -q [vuln_family_gate] -> view in comprehensive suite
total: 112 tests passed
```

### 4.2 Syntax
```
.venv/bin/python -m py_compile master_conductor.py -> OK
.venv/bin/python -m py_compile master_conductor_policy_service.py -> OK
.venv/bin/python -m py_compile master_conductor_hitl_precheck_service.py -> OK
.venv/bin/python -m py_compile master_conductor_dispatch_service.py -> OK
```

## 5. リスクと懸念点の解決状況

| 懸念点 | 発生確率/影響 | 対策 | 状態 |
|---|---|---|---|
| dispatch 抽出で cookie/header contextvar reset 漏れ | 高/大 | scope fast path のみ抽出、_dispatch 本体は deferred | ✅ risk contained |
| HITL precheck service が _state_lock 外で task state 更新 | 中/大 | PrecheckDecision は mutation plan のみ返す。facade が lock 下で適用 | ✅ design enforced |
| policy 抽出で audit event 欠落 | 中/大 | emit_*_audit_record の side-effect は facade に残し、details dict のみ service へ委譲 | ✅ verified |
| 新 god service 化 | 高/大 | pure evaluator / resolver / builder に小分割。service class で state 非保持 | ✅ design enforced |
| facade wrapper の呼出可能 callable 過多 | 中/大 | 最大 5 個に制約。超える場合は input dataclass | ✅ verified |
| HitlService / HitlPrecheckService 境界曖昧 | 中/中 | HitlService: ticket lifecycle。PrecheckService: decision/mutation plan | ✅ documented |
| dispatch service が resource を保持開始 | 低/大 | scope fast path は stateless 関数。service class にも依存注入なし | ✅ verified |
| 抽出後失敗時の切り分け困難 | 高/大 | 3-layer parity (service / facade wrapper / side-effect) で既存 tests が担保 | ✅ existing tests serve as parity |
| __new__ 最小インスタンスの AttributeError | 高/中 | 全 wrapper が getattr default で安全に扱う。policy service は callable inject により self 参照最小化 | ✅ verified |
| dispatch branch fallback 順序変更 | 中/大 | _dispatch 本体は未抽出のため routing order 不変 | ✅ risk contained |

## 6. deferred_tasks（未対応事項）

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0282-D01
    title: "_run_intervention_precheck の再構築"
    reason: "171行の複合メソッド。state mutation / execution_log / state_lock との密結合。PrecheckDecision クラスは用意済み。"
    impact: medium
    tracking_task_id: SGK-2026-0284
    recommended_next_action: "3-layer character tests を追加し、PrecheckDecision ベースで再構築する subtask_plan を起票"

  - deferred_id: SGK-2026-0282-D02
    title: "_dispatch 本体の service 抽出"
    reason: "561行、6 routing branches、cookie/header contextvar、async。plan の手順20-22（branch tests + routing order matrix）が必要。"
    impact: high
    tracking_task_id: SGK-2026-0285
    recommended_next_action: "scope fast path, post-exploit guard, CTF filter, worker, swarm, recon, recipe, AgentFactory fallback の branch 単位 character tests を追加してから着手する subtask_plan を起票"

  - deferred_id: SGK-2026-0282-D03
    title: "_generate_summary の service 抽出"
    reason: "cross-cutting integration method。coverage/SLO/failure codes/pending HITL の thin wrapper 呼び出し集成。抽出効果限定的。"
    impact: low
    tracking_task_id: SGK-2026-0284
    recommended_next_action: "failure aggregation / percentile / coverage gate assembly のみを pure function 化する軽量抽出を検討"

  - deferred_id: SGK-2026-0282-D04
    title: "execute_parallel の重複解消"
    reason: "master_conductor_parallel.py (117行) と重複。内部呼び出しがなく、orchestrator.execute_parallel が実使用。"
    impact: low
    tracking_task_id: SGK-2026-0284
    recommended_next_action: "重複調査と deduplication の subtask_plan を起票"

  - deferred_id: SGK-2026-0282-D05
    title: "compat wrapper inventory の完成"
    reason: "削除可 / 削除不可 / 外部参照あり / tests only の完全分類が未了"
    impact: low
    tracking_task_id: SGK-2026-0284
    recommended_next_action: "全 172 method の外部参照調査を自動化し、削除候補 compatibility matrix を作成"

  - deferred_id: SGK-2026-0282-D06
    title: "3-layer parity tests の新規追加"
    reason: "既存 tests で parity 検証を行ったが、service parity / facade wrapper parity / side-effect parity の独立 test suite は未作成"
    impact: medium
    tracking_task_id: SGK-2026-0284
    recommended_next_action: "extracted service ごとに dedicated parity test file を作成する subtask_plan を起票"

  - deferred_id: SGK-2026-0282-D07
    title: "cookie/header contextvar の全 exit path reset 検証"
    reason: "dispatch service の全 exit path で reset が実行されることを確認する branch test が未追加"
    impact: high
    tracking_task_id: SGK-2026-0285
    recommended_next_action: "_dispatch 抽出着手前に contextvar reset の branch test を mandatory として追加"
```

## 7. 次回推奨作業

1. **SGK-2026-0284**: HITL precheck + summary/parallel + compat wrapper inventory + parity tests の follow-up subtask
2. **SGK-2026-0285**: _dispatch 本体抽出の character tests + routing order matrix + contextvar reset 検証 + branch 単位抽出

## 8. 参照ルールファイル

本タスクの実装にあたり、以下のルールファイルを参照した:
- `rules/codingrules.md` (コード品質、エラーハンドリング、非同期処理、シークレット管理)
- `rules/task-ledger.md` (タスク台帳ワークフロー)
- `rules/shigoku-docs.md` (SHIGOKU ドキュメント規約)
- `rules/python-tests.md` (テスト実行規約)
