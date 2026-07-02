---
task_id: SGK-2026-0335
doc_type: spec
status: active
parent_task_id: SGK-2026-0282
related_docs:
  - docs/shigoku/specs/2026-07-01_sgk-2026-0335_bug-bounty-program-bundle-guard-policy-contract.md
  - docs/shigoku/subtasks/done/2026-07-01_bug-bounty-scope-bundle-guard-policy-compile_subtask_plan.md
created_at: '2026-07-02'
updated_at: '2026-07-02'
---

# Specification: Enforcement Points, Insertion Order, Fail-Closed, and Kill Switch

## 1. Purpose

SGK-2026-0335 Step 8 の成果物。MC / manager / worker / 外部アクセスモジュールの
enforcement point を棚卸しし、shared evaluator の差し込み順、layer ごとの fail-closed 条件、
rollback/kill switch 接続点を確定する。

この文書は実装の正本であり、コード上の enforcement point 一覧、層別の動作保証、
および rollout 制御機構の完全な仕様を含む。

## 2. Enforcement Layer Architecture

### 2.1 Layer Definitions

| Layer | Label (code) | Scope | Source File |
|-------|-------------|-------|-------------|
| Master Conductor (MC) | `mc` | Task 生成前の全判定、preflight bundle 解決、post-exploit dispatch gate | `src/core/engine/master_conductor.py` |
| Manager | `worker` | MC から流れてきた派生 task の再確認、manager 層 tool 呼び出し前 | `src/core/agents/swarm/base_manager.py` |
| External Tool / Subprocess | `external` | 外部ツール・サブプロセス実行前 | `src/core/adapters/external/base_external_adapter.py`, `src/core/tools/context_runner.py` |
| Network (HTTP) | `network` | 実 HTTP 送信直前（最終的な fail-closed 防御線） | `src/core/infra/network_client.py` |

### 2.2 Insertion Order

各 layer での guard 評価は以下の共通構造に従う：

1. Policy 解決: `guard_enforcement.resolve_policy_from_context()` または shared context から
2. `GuarInput` 構築: 各 layer が自身の `host`, `target`, `phase`, `attack_class`, `requested_action`, `proposed_tool`, `enforcement_layer` を設定
3. `guard_enforcement.evaluate_at_layer(policy, gi, layer, stage)` で shared evaluator に判定を委譲
4. 結果に応じて実行継続 / 中断

共有コードパス：
```
MC 起動時:
  bundle_manager.run_preflight() → bundle 解決
  → guard_enforcement.set_shared_guard_context({policy, stage})
  → MC._dispatch() / _trigger_post_exploit() → evaluate_at_layer(layer="mc")

MC dispatch 後:
  network_client.request() → guard context 解決 → evaluate_at_layer(layer="network")
  base_manager._execute_tool() → guard context 解決 → evaluate_at_layer(layer="worker")
  base_external_adapter.run_with_validation() → guard context 解決 → evaluate_at_layer(layer="external")
  context_runner.run_tool() → guard context 解決 → evaluate_at_layer(layer="external")
```

shared guard context は MC が `set_shared_guard_context()` で設定し、
各 enforcement point はそれを参照する（または `resolve_policy_from_context()` で
独立に解決する）。

### 2.3 Enforcement Points: Detailed Inventory

#### 2.3.1 MC Layer: `src/core/engine/master_conductor.py`

| Enforcement Point | Lines | Trigger | Decision on `block` |
|---|---|---|---|
| `_try_resolve_bugbounty_bundle()` | 8356–8447 | Run preflight: `--program` / `--bundle-id` / `--bundle-dir` 解決後 | `clear_shared_guard_context()`, preflight error, run 不開始 |
| `_dispatch_scope_verification_fast_path()` | 8268–8354 | scope_parser task dispatch 時 | 後続 task 生成を停止, `scope_source="compiled_guard_policy"` を設定 |
| `_dispatch()` post-exploit gate | 8449–8546 | task.agent_type が `post_exploit`/`secret_looter`/`internal_recon`/`pivot_scan` のとき | task スキップ, `{"skipped": true}` を返す |
| `_trigger_post_exploit()` | 7361–7449 | finding から post-exploit task を生成する前 | task 生成を skip |

MC 層の fail-closed：
- bundle 解決失敗 → `GuardLoadError` → run 開始しない（`clear_shared_guard_context()`）
- `compile_status != ready` → run 開始しない
- active bundle / compiled policy の hash 不一致 → run 開始しない
- post-exploit 評価で `decision == "block"` → task スキップ

#### 2.3.2 Manager Layer: `src/core/agents/swarm/base_manager.py`

| Enforcement Point | Lines | Trigger | Decision on `block` |
|---|---|---|---|
| `_execute_tool()` | 446–497 | manager が tool を実行する直前 | `RuntimeError("Blocked by compiled guard: <reason_code>")` |

Manager 層の fail-closed：
- shared guard context / `_guard_context` 未設定 → `policy=None` で `evaluate_at_layer()` へ → fail-closed block
- `evaluate_at_layer()` は `policy is None` なら rollout stage に関わらず常に block を返す

#### 2.3.3 External Tool Layer: `src/core/adapters/external/base_external_adapter.py`

| Enforcement Point | Lines | Trigger | Decision on `block` |
|---|---|---|---|
| `run_with_validation()` guard block | 220–265 | adapter の `execute()` 呼び出し前 | `ToolResult(status=ERROR, error_message="Blocked by compiled guard: <reason_code>")` |

External adapter 層の fail-closed：
- shared guard context / `_guard_context` 未設定 → `policy=None` で `evaluate_at_layer()` へ → fail-closed block
- CTF mode → 常に skip（`_mode != "bugbounty"`）

#### 2.3.4 External Tool Layer: `src/core/tools/context_runner.py`

| Enforcement Point | Lines | Trigger | Decision on `block` |
|---|---|---|---|
| `run_tool()` compiled guard | 144–181 | `subprocess.run()` の実行前 | `ExecutionResult(success=False, error="Blocked by compiled guard: <reason_code>")` |

Context runner 層の fail-closed：
- `mode != "bugbounty"` → guard skip
- guard_context / shared context 未設定 → `policy=None` で `evaluate_at_layer()` へ → fail-closed block

#### 2.3.5 Network Layer: `src/core/infra/network_client.py`

| Enforcement Point | Lines | Trigger | Decision on `block` |
|---|---|---|---|
| `request()` compiled guard | 334–383 | 実 HTTP 送信の直前（`aiohttp` 呼び出し前） | `NetworkClientError("Request blocked by compiled guard: <reason_code>")` |

Network client 層の fail-closed：
- `mode != "bugbounty"` → guard skip（CTF, other modes unaffected）
- shared guard context / kwarg 未設定 → `policy=None` で `evaluate_at_layer()` へ → fail-closed block
- `policy is None` は rollout stage に関わらず常に block（fail-closed first）

`SmartRequest` (`src/core/infra/smart_request.py`) は enforcement layer ではない。
`guard_context` を解決し `network_client.request()` の `guard_context` kwarg に伝達する
薄い adapter として動作する。独自の guard 判定は行わない。

## 3. Rollout Stages (Kill Switch)

### 3.1 EnforcementStage Enum

`src/core/security/guard_enforcement.py:EnforcementStage`:

| Stage | Value | MC blocks? | Worker blocks? | Network blocks? | External blocks? |
|---|---|---|---|---|---|
| Shadow (read-only) | `shadow_read_only` | ❌ | ❌ | ❌ | ❌ |
| MC Only | `mc_only` | ✅ | ❌ | ❌ | ❌ |
| Hard (all layers) | `worker_external_hard` | ✅ | ✅ | ✅ | ✅ |

Default: `mc_only`

### 3.2 Stage Resolution Priority

`guard_enforcement.resolve_enforcement_stage()`:

1. 明示的引数 (`explicit` parameter) — CLI または per-run override
2. `context["target_info"]["guard_enforcement_stage"]` — 設定ファイルまたは run context
3. 環境変数 `SHIGOKU_GUARD_ENFORCEMENT_STAGE`
4. Default: `mc_only`

### 3.3 Shadow Mode Semantics

`shadow_read_only` では **valid policy が block と判定した場合のみ** shadow-allow に変換する：

- evaluator は判定を実行する（metrics / logging 用）
- valid policy による `decision == "block"` → shadow-allow に変換（`reason_code` は `shadow_<original_code>`）
- **policy 不在（`policy is None`）は rollout stage に関わらず常に fail-closed block** — shadow 化しない
- logger は info レベルで「would have blocked」を記録（valid-policy block のみ）

これにより、段階的 rollout の各段階で guard の動作を観測しながら、
実際の実行を妨げずに信頼性を確認できる。policy 不在は安全側へ倒し、
shadow でも素通りを許さない。

### 3.4 Kill Switch Paths

| Kill Switch | 操作 | 効果 |
|---|---|---|
| Stage downgrade | `SHIGOKU_GUARD_ENFORCEMENT_STAGE=shadow_read_only` または context で `guard_enforcement_stage: shadow_read_only` | 全層の block を即時無効化 |
| Rollback to old bundle | `shigoku bugbounty bundle activate --bundle-id <old-id>` | 前バージョンの compiled policy に戻す |
| Clear shared context | `guard_enforcement.clear_shared_guard_context()` | network client / manager / adapter の guard を解除 |
| CTF mode bypass | `--mode ctf` | 全 guard 層を skip（非 bugbounty mode） |

### 3.5 Stage Boundaries (per-layer control)

`stage_allows_block(stage, layer)`:

```
shadow_read_only: すべて False
mc_only:          layer == "mc" のみ True
worker_external_hard: すべて True
```

layer 引数に使われる値：
- `mc` — MasterConductor 層
- `worker` — base_manager 層
- `network` — network_client 層
- `external` — context_runner + base_external_adapter 層

## 4. Shared Guard Context Propagation

### 4.1 Context Set and Clear

MC が `set_shared_guard_context()` で module-level 変数に policy + stage を設定する。
全 enforcement point がこれを読み取り、独立に policy を解決する必要をなくす。

```python
# set by MC at preflight (master_conductor.py:8428-8437)
set_shared_guard_context({
    "policy": resolved,          # LoadedGuardPolicy
    "stage": enforcement_stage,  # EnforcementStage enum
    "host": None,                # layer 側で上書き
})
```

```python
# called by MC at shutdown / rollback / mode change
clear_shared_guard_context()
```

### 4.2 Consumption by Enforcement Layers

| Layer | Context Source |
|---|---|
| MC | 自身で設定済みの `context.target_info` から `resolve_policy_from_context()` |
| Network client | `_shared_guard_context` または `request(guard_context=...)` kwarg. Missing → `policy=None` → fail-closed |
| SmartRequest | `_get_guard_context()` → `client.request(guard_context=...)` に伝達 |
| Base Manager | `self._guard_context` → `get_shared_guard_context()` → `policy=None` で `evaluate_at_layer()` へ. Missing → fail-closed |
| Context Runner | `self.guard_context` → `get_shared_guard_context()` → `policy=None` で `evaluate_at_layer()` へ. Missing → fail-closed |
| External Adapter | `self._guard_context` → `get_shared_guard_context()` → `policy=None` で `evaluate_at_layer()` へ. Missing → fail-closed |

全 enforcement point は `evaluate_at_layer()` を唯一の判定経路として使用する。
`resolve_policy_from_context()` は MC のみが preflight で使用し、
他レイヤは shared context 経由で policy を受け取るか、存在しなければ
`policy=None` で `evaluate_at_layer()` に委ねる（fail-closed）。

### 4.3 Mode Isolation

- CTF モード (`mode="ctf"`) では shared guard context を無視する
- `AsyncNetworkClient(mode="ctf")` は guard を skip
- `BaseExternalAdapter` subclasses は `self._mode == "ctf"` なら guard を skip
- `ContextToolRunner(mode="ctf")` は guard を skip
- ただし、`set_shared_guard_context()` 自体は CTF/他モード切り替えで `clear_shared_guard_context()` を明示的に呼ぶ必要がある（MC が行う）

## 5. Fail-Closed Contract

### 5.1 Fail-Closed Triggers (全層共通)

以下のいずれかが発生した場合、`GuardDecision.block(fail_closed=True)` が返される：

| Condition | Reason Code | Source |
|---|---|---|
| Policy 未解決 (bundle missing) | `policy_unavailable` | `evaluate_with_loader_error()` |
| Policy `compile_status != ready` | `policy_not_ready` | `compiled_guard_loader` |
| Policy hash 不一致 | `policy_integrity_error` | `compiled_guard_loader` |
| Schema version unsupported | `policy_schema_unsupported` | `compiled_guard_loader` |
| Bundle directory missing | `active_bundle_missing` | `compiled_guard_loader` |
| Program alias mismatch | `bundle_program_mismatch` | `compiled_guard_loader` |
| active_bundle.json required field missing | `active_bundle_reference_missing` | `compiled_guard_loader` |

### 5.2 Layer-Specific Fail-Closed Behaviour

| Layer | Fail-Closed Behaviour | Recovery |
|---|---|---|
| MC | Run を開始しない。`clear_shared_guard_context()` | Bundle 再 import / re-activate |
| Manager | `RuntimeError` を raise | task 失敗として handling |
| External Adapter | `ToolResult(status=ERROR)` を返却 | caller が handling |
| Context Runner | `ExecutionResult(success=False)` を返却 | caller が handling |
| Network Client | `NetworkClientError` を raise | caller が retry / abort |

### 5.3 Prohibited Patterns

- ❌ `except Exception: pass` による guard error の握り潰し
- ❌ fail-closed decision を local allow に上書き
- ❌ layer ごとに異なる rule engine を使用
- ❌ runtime 中に raw source を読み直す
- ❌ bug bounty mode での `--scope` legacy interface 使用

## 6. Metrics and Observability Hooks

### 6.1 Key Counters (spec section 13.11)

| Metric | Source | Purpose |
|---|---|---|---|
| `guard_decision_total{layer,decision,reason_code}` | `evaluate_at_layer()` の各呼び出し | block 比率、reason 分布、shadow 判定数（`reason_code=shadow_*` label で代替） |
| `active_bundle_read_failure_total` | `compiled_guard_loader` の各 failure path | インフラ異常検知 |
| `policy_fail_closed_total` | `GuardDecision.fail_closed == True` | fail-closed 発生頻度 |
| `compile_failed_total` | bundle_manager コンパイル失敗 | compile quality |
| `manual_review_required_total` | compile_status=manual_review_required | manual review 比率 |

### 6.2 Audit Trace Fields

各 `GuardDecision` は以下を含む：
- `decision_trace_id`: deterministic hash（SHA256 先頭 12 文字、`gd-` prefix）
- `reason_code`: machine-readable コード
- `matched_rule_ids`: 該当した runtime rule ID
- `matched_rule_origin_ids`: audit 用 origin ID
- `enforcement_layer`: 判定を行った層
- `fail_closed`: fail-closed かどうか

## 7. Rollback and Recovery

### 7.1 Bundle Rollback

```bash
# rollback = old bundle を再 activate
shigoku bugbounty bundle activate --program tiktok --bundle-id <previous-bundle-id>
```

activation 時点で次を検証する：
- old bundle の `compile_status=ready`
- compiled policy hash 一致
- provider / program alias 一致

### 7.2 Runtime Hot Reload (Prohibited in V1)

実行中に active bundle が切り替わっても、既存 run の policy は変更しない。
次回 run から新 bundle を使用する。

### 7.3 Recovery from Corrupted Artifacts

1. `active_bundle.json` 破損 → bundle registry から再生成
2. `compiled_guard_policy.yaml` 破損 → `bundle compile` で再生成
3. bundle directory 欠落 → `bundle import` し直し
4. program alias 不整合 → `bundle activate` で再バインド

## 8. Implementation Verification

### 8.1 Code Coverage

全 6 つの enforcement point が実装済み・テスト済み：

- [x] MC: `_dispatch()` post-exploit gate → `test_post_exploit_task_blocked_by_compiled_policy`
- [x] MC: `_trigger_post_exploit()` → `test_trigger_post_exploit_recon_denies_when_policy_blocks`
- [x] Network: `AsyncNetworkClient.request()` → `test_network_client_blocks_out_of_scope_in_hard_mode`
- [x] SmartRequest: context passthrough → `test_smart_request_passes_guard_context`
- [x] External Adapter: `run_with_validation()` → `test_external_adapter_blocks_in_hard_mode`
- [x] Context Runner: `run_tool()` → `test_context_runner_blocks_tool_in_hard_mode`
- [x] Base Manager: `_execute_tool()` → `test_base_manager_runtime_error_on_block`

### 8.2 Rollout Stage Coverage

- [x] `shadow_read_only`: evaluate but never block → `test_shadow_stage_never_blocks`
- [x] `mc_only`: backward compat, only MC blocks → `test_mc_only_evaluator_returns_*`
- [x] `worker_external_hard`: all layers block → all `*_blocks_*_in_hard_mode` tests

### 8.3 Shared Context Coverage

- [x] Shared context propagation to new clients → `test_new_network_client_picks_up_shared_context`
- [x] Late shared context picked up by existing SmartRequest → `test_existing_smart_request_picks_up_late_shared_context`
- [x] Shared context picked up by BaseManager → `test_base_manager_picks_up_shared_context`
- [x] Update propagation → `test_shared_context_update_propagates_to_existing_client`
- [x] Clear propagation → `test_shared_context_clear_propagates_to_existing_client`

### 8.4 Mode Isolation Coverage

- [x] CTF client ignores shared guard → `test_shared_context_does_not_block_ctf_client`
- [x] CTF verify_scope clears shared context → `test_ctf_verify_scope_clears_shared_context`
- [x] CTF adapter skips shared guard → `test_concrete_adapter_ctf_mode_skips_shared_guard`
- [x] CTF ContextRunner skips shared guard → `test_context_runner_ctf_skips_shared_guard`

## 9. Acceptance Criteria (Step 8)

- [x] MC / manager / worker / 外部アクセス層の enforcement point がすべて棚卸しされ、文書化されている
- [x] shared evaluator の差し込み順が確定している（MC → manager/worker → network/external）
- [x] layer ごとの fail-closed 条件が定義されている（policy unavailable / integrity error / schema unsupported / compile_status != ready）
- [x] rollback/kill switch 接続点が確定している（EnforcementStage / SHIGOKU_GUARD_ENFORCEMENT_STAGE / bundle activate）
- [x] 全 enforcement point が tests/core/security/test_guard_enforcement_phase2.py 33 テストでカバーされている
- [x] 同一 policy で層をまたいでも一貫した判定が行われる（shared evaluator の単一契約）
- [x] shadow → mc_only → worker_external_hard の段階的 rollout が EnforcementStage で制御可能
- [x] CTF モードで guard がリークしない（mode isolation 全テスト通過）
