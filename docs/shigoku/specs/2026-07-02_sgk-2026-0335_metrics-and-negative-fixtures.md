---
task_id: SGK-2026-0335
doc_type: spec
status: active
parent_task_id: SGK-2026-0282
related_docs:
  - docs/shigoku/specs/2026-07-01_sgk-2026-0335_bug-bounty-program-bundle-guard-policy-contract.md
  - docs/shigoku/specs/2026-07-02_sgk-2026-0335_enforcement-points-and-killswitch.md
  - docs/shigoku/subtasks/done/2026-07-01_bug-bounty-scope-bundle-guard-policy-compile_subtask_plan.md
created_at: '2026-07-02'
updated_at: '2026-07-02'
---

# Specification: Guard Metrics and Negative Fixtures (Steps 9-10)

## 1. Purpose

SGK-2026-0335 Steps 9 と 10 の成果物。guard enforcement の metrics/observability 実装と、
負例 fixture による品質検証の契約を定義する。

## 2. Step 9: Metrics and Observability

### 2.1 Metrics Module

**`src/core/security/guard_metrics.py`** — 軽量 in-process metrics collector。

6 つの counter/histogram を実装（spec section 13.11 準拠）：

| Metric | Type | Labels | Hook point |
|---|---|---|---|
| `guard_decision_total` | LabeledCounter | `layer`, `decision`, `reason_code` | `evaluate_at_layer()` |
| `policy_fail_closed_total` | SimpleCounter | — | `evaluate_at_layer()` (fail_closed=True) |
| `active_bundle_read_failure_total` | SimpleCounter | — | `load_active_policy_from_bundle_dir()` |
| `compile_failed_total` | SimpleCounter | — | `compile_guard_policy()` |
| `manual_review_required_total` | SimpleCounter | — | `compile_guard_policy()` |
| `bundle_import_to_ready_seconds` | SimpleHistogram | — | `bundle_manager.compile_bundle()` (ready 時) |

### 2.2 Hook Points

| File | Hook | Metric |
|---|---|---|
| `guard_enforcement.py:evaluate_at_layer()` | 全 evaluation path の後 | `guard_decision_total`, `policy_fail_closed_total` |
| `compiled_guard_loader.py:load_active_policy_from_bundle_dir()` | GuardLoadError return 時 | `active_bundle_read_failure_total` |
| `compiled_guard_compiler.py:compile_guard_policy()` | compile_status 決定時 | `compile_failed_total`, `manual_review_required_total` |

### 2.3 Architecture

- **Singleton**: `get_guard_metrics()` / `reset_guard_metrics()`
- **Thread-safe**: `threading.Lock` による排他制御
- **Best-effort**: metrics 記録失敗が enforcement に影響しない（try/except pass）
- **Export**: `snapshot()` メソッドで dict 形式の snapshot を取得可能。V1 では text-based export のみ（Prometheus endpoint は未実装）

### 2.4 Observability Requirements Met

- [x] `guard_decision_total{layer,decision,reason_code}` — block/allow/shadow 全決定を層別に記録
- [x] `policy_fail_closed_total` — fail-closed 発生頻度
- [x] `active_bundle_read_failure_total` — active bundle / compiled artifact 読み出し失敗
- [x] `compile_failed_total` — compile failure 発生頻度
- [x] `manual_review_required_total` — manual review 比率
- [x] `bundle_import_to_ready_seconds` — import から ready までの時間
- [x] `decision_trace_id` と `rule_origin_id` の追跡性（Step 5 で実装済み）
- [x] layer 別 block reason の偏り（`guard_decision_total` の label dimension）

### 2.5 Coverage

`tests/core/security/test_guard_metrics.py` — 23 tests:

- 15 unit tests（LabeledCounter, SimpleCounter, SimpleHistogram, thread safety, singleton, snapshot）
- 4 integration tests（evaluate_at_layer hooks: fail-closed, block, shadow, allow）
- 1 integration test（loader failure records active_bundle_read_failure）
- 2 integration tests（compiler records compile_failed / manual_review_required）
- 1 integration test（bundle_import_to_ready_seconds recorded by compile_bundle）

## 3. Step 10: Negative Fixtures

### 3.1 Fixture Directory Structure

```
tests/fixtures/program_bundle/
  tiktok/                          # [existing] positive: HackerOne TikTok
  fireblocks/                      # [existing] positive: Bugcrowd Fireblocks
  tiktok_incomplete/               # [existing] empty placeholder
  fireblocks_incomplete/           # [existing] empty placeholder
  invalid_timezone/                # [new] invalid default_timezone
    source_manifest.yaml           #   timezone: "Mars/Colony5"
    policy.md
    scope_assets.csv
  wildcard_deny_conflict/          # [new] same-specificity allow+deny
    source_manifest.yaml
    policy.md                      #   "in scope and out of scope"
    scope_assets.csv               #   *.example.com (allow) + example.com (deny)
  secret_contamination/            # [new] credential-like values in policy
    source_manifest.yaml
    policy.md                      #   "SuperSecret123!", "sk-live-..."
    scope_assets.csv
  empty_scope_assets/              # [new] empty directory placeholder

tests/fixtures/bugbounty_guard/
  tiktok/                          # [existing] compiled guard policy
  fireblocks/                      # [existing] compiled guard policy
  corrupted_policy/                # [new] directory for corruption testing
```

### 3.2 Test Coverage

| Test Class | Tests | What it verifies |
|---|---|---|
| `TestInvalidTimezone` | 1 | Invalid timezone does not crash adapter |
| `TestWildcardDenyConflict` | 1 | Exact deny wins over wildcard allow → ready (deny precedence verified) |
| `TestSecretContamination` | 1 | Credential values excluded from compiled output |
| `TestActiveBundleMissing` | 2 | Loader fail-closed for missing dir / missing active_bundle.json |
| `TestEmptyScopeAssets` | 1 | 0 in-scope assets → compile_failed |
| `TestSameBundleSameHash` | 4 | Deterministic hash: same bundle twice → same hash, different bundles → different hash, time-stable |

**10 tests total** in `tests/core/security/test_negative_fixtures.py`.

### 3.3 Snapshot Verification

同一 bundle の再 compile で hash が安定することの検証:
- TikTok bundle × 2 → `compiled_policy_hash` 一致
- Fireblocks bundle × 2 → `compiled_policy_hash` 一致
- TikTok ≠ Fireblocks → hash 衝突なし
- 時間経過（`time.sleep(0.1)`）後も hash 不変

### 3.4 Secret Contamination Guard

`secret_contamination` fixture の policy.md には `SuperSecret123!` と `sk-live-1234567890abcdef` が含まれる。
compile 後の `compiled_guard_policy.yaml` にこれらの生値が出力されないことを確認。

## 4. Implementation Verification

### 4.1 Test Results

```
tests/core/security/test_guard_enforcement_phase2.py ... 40 passed
tests/core/security/test_guard_metrics.py ............... 23 passed
tests/core/security/test_negative_fixtures.py ........... 10 passed
tests/core/security/test_compiled_guard_evaluator.py .... 20 passed
tests/core/security/test_compiled_guard_loader.py ....... 20 passed
tests/core/security/test_compiled_guard_compiler.py ..... 47 passed
                                                       ---
                                                       160 passed
```

### 4.2 Acceptance Criteria (Steps 9+10)

- [x] 6 metrics counters が実装され、3 箇所の pipeline hook で記録される
- [x] `guard_decision_total` が layer/decision/reason_code の label 付きで記録される
- [x] Thread-safe singleton パターンで実装
- [x] Metrics best-effort（記録失敗が enforcement に影響しない）
- [x] 5 種類の負例 fixture が disk 上に存在
- [x] 10 件の負例 + snapshot テストが全 pass
- [x] 同一 bundle → 同一 hash が検証済み
- [x] Secret 値が compiled output に漏洩しない
- [x] Active bundle 欠落 → fail-closed
- [x] 0 in-scope assets → compile_failed
