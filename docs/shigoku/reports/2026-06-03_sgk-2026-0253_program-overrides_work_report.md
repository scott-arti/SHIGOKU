---
task_id: SGK-2026-0253
doc_type: work_report
status: done
parent_task_id: SGK-2026-0251
related_docs:
- docs/shigoku/subtasks/2026-06-02_sgk-2026-0253_program-overrides_subtask_plan.md
- docs/shigoku/plans/2026-06-01_sgk-2026-0251_task_plan.md
- docs/shigoku/subtasks/2026-06-03_sgk-2026-0256_program-overrides_subtask_plan.md
- docs/shigoku/worklogs/2026-06-03_sgk-2026-0253_program-overrides_work_log.md
title: SGK-2026-0253 program overrides 実装完了報告
created_at: '2026-06-03'
updated_at: '2026-06-30'
---

# SGK-2026-0253 program overrides 実装完了報告

## 実装内容
- `data/attack_chain_rules.json` に `dsl_version`、業種別 rule、`workflow_templates`、`program_overrides` を追加し、common/industry/workflow/program override の実データ配置を反映した。
- `src/core/intelligence/chain_builder.py` の industry / workflow / tactical policy 解決を前提に、`src/core/engine/master_conductor.py` へ policy 正規化、workflow template 正規化、chain finding からの runtime context 変換、rollout 判定を追加した。
- `tests/core/engine/test_master_conductor_phase1_step14.py` に precedence matrix、invalid key 監査、resolved context 一致、rollout/read-only 切り戻しのテストを追加した。
- `tests/core/intelligence/test_chain_builder.py` に default rules 配置確認と `chain_builder` / `master_conductor` の resolved result 一致確認を追加した。
- `docs/shigoku/subtasks/2026-06-02_sgk-2026-0253_program-overrides_subtask_plan.md` を更新し、`Step 2/4/9/10/11/11A`、Done条件、懸念点と対策、着手順整理を完了状態へ反映した。

## 判断理由
- rule / workflow 解決の正本は `chain_builder`、runtime guard / rollout 判定の正本は `master_conductor` に固定し、責務重複を避けた。
- workflow template は引き続き read-only metadata 扱いを維持し、safety gate を上書きしない形で段階導入とした。
- precedence matrix は source ごとの勝者をテスト名と assert message に固定し、将来の回帰切り分けを容易にした。
- rollout 判定は `blocked/defer ratio`、planned task 差分、QPS cap hit 差分の3軸で read-only 切り戻しを判断できる形にした。

## 検証
- `.venv/bin/pytest -q tests/core/engine/test_master_conductor_phase1_step14.py tests/core/intelligence/test_chain_builder.py`
  - 結果: `28 passed`
- `.venv/bin/pytest -q tests/core/engine/test_program_overrides_tdd_red.py tests/core/engine/test_master_conductor_phase1_step14.py tests/core/engine/test_master_conductor_phase1_step15.py tests/core/engine/test_master_conductor_scenario_probes.py tests/core/intelligence/test_chain_builder.py tests/core/intelligence/test_program_overrides_subtask_plan_checklist.py tests/core/engine/test_mc_intelligence_integration.py`
  - 結果: `66 passed`

## Step 11 反映内容
- precedence matrix の結果として、`program override > runtime flag > config default` と invalid key ignore を `tests/core/engine/test_master_conductor_phase1_step14.py` で固定した。
- audit 観測項目として `applied_override_keys`、`blocked_reason`、`defer_reason`、`qps_cap_hit`、`planned_task_count_before_override`、`planned_task_count_after_override`、`qps_cap_target` を保持・検証した。
- 統合一致結果として、`chain_builder` の `resolved_workflow_template` / `resolved_tactical_policy` と、`master_conductor` の runtime context 変換結果が一致することをテストで確認した。
- 切り戻し条件として、`blocked/defer ratio`、planned task 差分、QPS cap hit 差分の閾値超過時に `workflow_template_mode=read_only` へ戻す判定を追加した。

## Step 11A 反映内容
- 選択精度: `industry` 付き rule と common fallback を実データ + テストで固定し、program 文脈に合う rule/policy を優先適用できるようにした。
- 安全性: `blocked` / `defer` 優先、WAF/5xx、dependency failure、budget/QPS 制約を override より優先する設計を維持した。
- 説明可能性: source 付き policy、workflow template source、audit 項目、rollout 判定理由により「なぜその probe 判断になったか」を追跡可能にした。
- 非目標維持: 新しい probe 戦略は追加せず、既存戦略に対する rule / workflow / policy 解決順序と安全適用のみを整備した。
- release gate 候補: `schema test` と `sample rules` を継続課題として backlog に残した。

## リスク
- `program_override` の許可キーは現状 `allow` / `deny` / `per_asset_qps_cap` / `global_probe_budget` 中心であり、`race_mode` / `dry_run` / `fail_closed` の program-level 解決を広げる場合は別途明示実装が必要。
- 親タスク `SGK-2026-0251` は引き続き `active` であり、他 subtask (`SGK-2026-0254`, `SGK-2026-0255`) の完了待ちが残る。

## deferred_tasks
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0253-D01
    title: "program overrides 運用観測の継続監視"
    reason: "実装は完了したため、以降は rollout 指標と audit 完全性の経過観察フェーズへ移行する"
    impact: medium
    tracking_task_id: SGK-2026-0256
    recommended_next_action: "定期レビューで blocked/defer ratio、planned task 差分、QPS cap hit、audit completeness を確認し、逸脱時は修正タスクを分離起票する"
  - deferred_id: SGK-2026-0253-D02
    title: "sample rules / schema test の技術的負債追跡"
    reason: "実装スコープは完了したが、保守性向上のための sample rules と schema test 整備は別タスクで継続する"
    impact: medium
    tracking_task_id: SGK-2026-0257
    recommended_next_action: "rules データ増加時の回帰を防ぐため、sample rules と schema test の対象範囲を確定し、回帰テストとして常設する"
```
