---
task_id: SGK-2026-0225
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: SGK-2026-0215
related_docs:
  - docs/shigoku/plans/remaining_bugs_plan.md
created_at: '2026-05-22'
updated_at: '2026-05-22'
---

# Specification: `_should_observe` Observation Policy

## 1. Purpose

`MasterConductor` における ReAct 観察実行判定を標準化し、実装差分・運用差分・テスト差分を防ぐ。

## 2. Scope

- Target: `src/core/engine/master_conductor.py`
- Target Function:
  - `_should_observe(task, result) -> tuple[bool, ObservationReason]`
  - `_observe_and_rethink(task, result)` の呼び出し前ゲート
- Non-Target:
  - ReAct プロンプト本文最適化
  - LLM モデル選定ロジックの変更

## 3. Interface Contract

- Input:
  - `task: Task`
  - `result: dict`
- Output:
  - `tuple[bool, ObservationReason]`
    - `bool`: execute decision
    - `ObservationReason`: reason code enum
- Rule:
  - `_observe_and_rethink` の全呼び出し経路で必ず `_should_observe` を実行する。

## 4. Decision Order (MUST)

判定は以下の順で実施し、最初に確定した結果を返す。

1. Global Switch Check
- `enable_react_observation` が `False` の場合: `(False, "SKIP_DISABLED")`

2. Runtime Dependency Check
- `llm_client` 未初期化: `(False, "SKIP_NO_LLM_CLIENT")`

3. Circuit Breaker / Capacity Check
- circuit breaker open 中: `(False, "SKIP_CIRCUIT_OPEN")`
- retry 予算枯渇: `(False, "SKIP_BUDGET_EXCEEDED")`
- queue 上限超過: `(False, "SKIP_QUEUE_OVERFLOW")`
- inflight 上限超過: `(False, "SKIP_BUDGET_EXCEEDED")`

4. Result Validity Check
- `result.success` 不在/False: `(False, "SKIP_NOT_SUCCESS")`
- `result.data` が空かつ `findings` なし: `(False, "SKIP_NO_SIGNAL")`

5. Task Class Filter
- 低価値タスク（単純I/O、定型処理、観察価値の低い固定アクション）:
  `(False, "SKIP_LOW_VALUE_TASK")`

6. Budget Guard
- run/target 単位の call 上限超過:
  `(False, "SKIP_BUDGET_EXCEEDED")`

7. High-Value Signal Check
- findings あり、または重要キーワード一致:
  `(True, "ALLOW_HIGH_VALUE_SIGNAL")`

8. Sampling Check
- 同種タスク連続時の sampling 許可に該当しない:
  `(False, "SKIP_SAMPLING_POLICY")`
- 該当する:
  `(True, "ALLOW_SAMPLED")`

## 5. Reason Code Dictionary

### Skip Codes
- `SKIP_DISABLED`
- `SKIP_NO_LLM_CLIENT`
- `SKIP_NOT_SUCCESS`
- `SKIP_NO_SIGNAL`
- `SKIP_LOW_VALUE_TASK`
- `SKIP_BUDGET_EXCEEDED`
- `SKIP_CIRCUIT_OPEN`
- `SKIP_QUEUE_OVERFLOW`
- `SKIP_SAMPLING_POLICY`

### Allow Codes
- `ALLOW_HIGH_VALUE_SIGNAL`
- `ALLOW_SAMPLED`

## 6. Observability Requirements

以下を構造化ログおよびメトリクスで記録する。

- decision: allow/skip
- reason_code
- task_id
- task.agent_type
- budget_snapshot (calls_used, calls_limit, tokens_used, tokens_limit)

Required metrics:
- `context.metrics["react_observation"].attempted`
- `context.metrics["react_observation"].executed`
- `context.metrics["react_observation"].skipped`
- `context.metrics["react_observation"].skip_reasons`
- `context.metrics["react_observation"].retry_used`
- `context.metrics["react_observation"].inflight`
- `context.metrics["react_observation"].queue_depth`
- `context.metrics["react_observation"].circuit_open_until`

## 7. Configuration Parameters

最低限、以下の設定を持つこと。

- `react_observation_max_calls_per_run`
- `react_observation_max_calls_per_target`
- `react_observation_sampling_rate`
- `react_observation_low_value_task_patterns`
- `react_observation_retry_budget_per_run`
- `react_observation_queue_maxsize`
- `max_inflight_react_requests_global`
- `react_observation_circuit_breaker_threshold`
- `react_observation_circuit_breaker_cooldown_seconds`
- `react_observation_circuit_breaker_latency_seconds`

## 8. Test Requirements

### Unit Tests
- switch off
- no llm client
- success false / no signal
- low value task skip
- budget exceeded skip
- high value allow
- sampling skip / allow

### Integration Tests
- 通常フローで `react_executed_total / successful_tasks` が目標削減率を満たす。
- 高価値 finding ケースで `ALLOW_HIGH_VALUE_SIGNAL` が発火する。

## 9. Compatibility and Migration

- 既存 `_observe_and_rethink` の機能本体は保持し、ゲート追加を先行する。
- 既存キャッシュロジック（`_react_cache`）は維持する。
- 呼び出し導線差分（通常実行/対話実行）をこの spec に合わせて統一する。

## 10. Definition of Done

- `_should_observe` が本 spec の判定順序と reason code を満たす。
- 呼び出し全経路が `_should_observe` を通過する。
- Unit/Integration テストが追加され、主要分岐が検証される。
- メトリクスが収集され、ダッシュボードで可視化可能。
