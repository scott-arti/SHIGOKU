---
task_id: SGK-2026-0279
doc_type: work_report
status: done
parent_task_id: SGK-2026-0265
related_docs:
  - docs/shigoku/subtasks/2026-06-09_injectionmanager-additional-split-plan_subtask_plan.md
  - docs/shigoku/plans/2026-06-05_injection-manager-split-plan_plan.md
  - docs/shigoku/reports/2026-06-09_sgk-2026-0277_api-probe-runner-extraction_work_report.md
created_at: '2026-06-09'
updated_at: '2026-06-11'
---

# Work Report: SGK-2026-0279 InjectionManager 追加分割

## 実装内容

### 修正ファイル
- `src/core/agents/swarm/injection/manager.py`
  - 2382行 → 2029行 → 1887行 → **1710行 (-672行, -28.2%)**
  - `run_*_hunter` メソッド群（10件）を thin wrapper 化、実装本体を `tool_runners.py` へ移設
  - `_process_single_url` (251行) の branch 実行を `process_url_dispatcher.py` へ移設、cache owner は facade に維持
  - `_run_unknown_hypothesis_scans` (77行) を `unknown_scan_runner.py` へ移設
  - `_initialize_specialists` を `specialist_factory.create_specialists()` へ委譲
  - `_register_manager_tools` / `_register_initial_tools` を `tool_registration.py` へ移設
  - 各 wrapper は deps dict を組み立て runner 関数に委譲

### 新規ファイル
- `src/core/agents/swarm/injection/manager_internal/process_url_dispatcher.py` (49→222行)
  - `dispatch_vuln_type_branch()` — vuln_type分岐全13ブランチ + normalize_findings
- `src/core/agents/swarm/injection/manager_internal/unknown_scan_runner.py` (98行)
  - `run_unknown_hypothesis_scans()` — specialist loop 実行本体
- `src/core/agents/swarm/injection/manager_internal/specialist_factory.py` (78行)
  - `create_specialists(config)` — 全 specialist の lazy import と初期化
- `src/core/agents/swarm/injection/manager_internal/tool_registration.py` (131行)
  - `register_manager_tool_scans()` / `register_initial_tools()` — tool 登録実装本体

### 修正ファイル（既存拡張）
- `src/core/agents/swarm/injection/manager_internal/tool_runners.py` (135→621行)
  - 10 runner 関数 + 4 共通 helper
- `src/core/agents/swarm/injection/manager_internal/models.py`
  - `HunterRunnerDependencies` TypedDict（7 fields）追加
- `tests/core/agents/swarm/injection/test_graphql_pipeline.py`
  - `patch` target を `unknown_scan_runner.build_unknown_hypotheses` に更新

## テスト結果

| テスト群 | 結果 | 備考 |
|---------|------|------|
| `test_injection_manager.py` | 63/65 pass | 2 pre-existing (blind_correlation shape mismatch) |
| `test_graphql_pipeline.py` | 全 pass | patch target 更新後 |
| `test_crlf_pipeline.py` | 全 pass | |
| `test_manager_phase2_lane2_integration.py` | 5/5 pass (timeout/circuit/lane2) | |
| `test_manager_p1_metadata.py` | 全 pass | |
| injection/ 全件 | **470/472 pass, 18 errors (live)** | baseline と一致、新規 regression 0 |

## 完了条件チェックリスト

- [x] `manager.py` の行数が削減されている（2382 → 1887, **-495 lines**）
- [x] `run_*_hunter` 群の public wrapper 互換が全テストで確認
- [x] `dispatch` 丸ごと移動を行っていない
- [x] `manager_internal` の新規/変更モジュールが `InjectionManagerAgent` 全体を import していない（rg 確認）
- [x] 新規/変更 `manager_internal/*` が network client owner になっていない（rg 確認: 0 matches）
- [x] baseline failure（2件）は pre-existing であり、新規 regression は 0 件
- [x] Phase1 finding count、tested_params、evidence shape の互換が行数削減より優先されている

## リスクと保留事項

### deferred_tasks

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0279-D01
    title: "_process_single_url の branch 実行を process_url_dispatcher.py へ外出し"
    reason: "251行の高リスク抽出。cache shape、IDOR fallback、probe metadata、例外時 cache が絡む。wrapper 必須"
    impact: high
    tracking_task_id: SGK-2026-0265
    recommended_next_action: "cache 書き込みは facade owner に残したまま branch 実行のみ抽出する"

  - deferred_id: SGK-2026-0279-D02
    title: "dispatch Phase2 gate の純粋 helper 抽出"
    reason: "664行の最大塊。Phase1 loop、timeout retry、circuit breaker は facade に残し、Phase2 gate / result builder のみ抽出"
    impact: high
    tracking_task_id: SGK-2026-0265

  - deferred_id: SGK-2026-0279-D03
    title: "helper/policy wrapper 群の外出し"
    reason: "cache_policy, tool_param_normalizer, phase1_signals の純粋 helper は低リスクだが未着手"
    impact: medium
    tracking_task_id: SGK-2026-0265

  - deferred_id: SGK-2026-0279-D04
    title: "_run_unknown_hypothesis_scans の unknown_scan_runner.py への外出し"
    reason: "77行の低〜中リスク抽出。specialist loop 順序、merged tested_params、findings slice 互換が必要"
    impact: medium
    tracking_task_id: SGK-2026-0265

  - deferred_id: SGK-2026-0279-D05
    title: "tool_runners.py の二次分割"
    reason: "621行で500行制限を超過。blind-correlation / simple-retry / custom の責務別分割候補"
    impact: medium
    tracking_task_id: SGK-2026-0265

  - deferred_id: SGK-2026-0279-D06
    title: "継続監視: InjectionManager 追加分割後の Phase1/Phase2 互換性"
    reason: "run_*_hunter と specialist factory / tool registration を外出ししても、Phase1 result shape と Phase2 tool use の観測が必要"
    impact: medium
    tracking_task_id: SGK-2026-0265
    recommended_next_action: "代表セッションで timeout_count, phase2_forced_count, cache_hit_count, validated_rejected_ratio を分割前後比較する"
```
