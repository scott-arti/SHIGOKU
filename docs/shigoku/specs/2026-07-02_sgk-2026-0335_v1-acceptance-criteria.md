---
task_id: SGK-2026-0335
doc_type: spec
status: active
parent_task_id: SGK-2026-0282
related_docs:
  - docs/shigoku/specs/2026-07-01_sgk-2026-0335_bug-bounty-program-bundle-guard-policy-contract.md
  - docs/shigoku/specs/2026-07-02_sgk-2026-0335_enforcement-points-and-killswitch.md
  - docs/shigoku/specs/2026-07-02_sgk-2026-0335_metrics-and-negative-fixtures.md
  - docs/shigoku/manuals/2026-07-02_sgk-2026-0335_bugbounty-bundle-operator-runbook.md
  - docs/shigoku/subtasks/done/2026-07-01_bug-bounty-scope-bundle-guard-policy-compile_subtask_plan.md
created_at: '2026-07-02'
updated_at: '2026-07-02'
---

# V1 Acceptance Criteria: Bug Bounty Program Bundle and Guard Policy

## 1. Purpose

SGK-2026-0335 の V1 受け入れ条件を最終確定する。
本ドキュメントは実装完了判定の正本であり、compile 成功率、manual review 比率、
false block 許容率、import-to-ready 時間などの評価軸を明文化する。

## 2. Functional Acceptance (Must-Pass)

### 2.1 Compile Gate

| # | Criterion | Verification |
|---|---|---|
| AC-01 | TikTok HackerOne bundle が `policy.md` + `scope_assets.csv` から compile 可能であること | `test_compile_tiktok_produces_ready_status` (PASS) |
| AC-02 | Fireblocks Bugcrowd bundle が `policy.md` + `scope_assets.txt` から compile 可能であること | `test_compile_fireblocks_exact_hosts` (PASS) |
| AC-03 | `compile_status != ready` の policy では Bug Bounty run を開始しないこと | `test_compile_status_not_ready` (PASS), `test_activate_bundle_rejects_non_ready` (PASS) |
| AC-04 | `--mode bugbounty` で legacy `--scope` を渡すと preflight error になること | Blocked at CLI level (spec section 11.1 で定義済み) |
| AC-05 | 同一 bundle を再 compile したとき `normalized_facts_hash` と `compiled_policy_hash` が安定して一致すること | `test_compile_idempotent`, `test_hash_determinism_across_time` (PASS) |

### 2.2 Scope and Guard Enforcement

| # | Criterion | Verification |
|---|---|---|
| AC-06 | 同一の out-of-scope host / action が MC、manager/worker、外部アクセス層で一貫して block されること | `test_post_exploit_task_blocked_by_compiled_policy` (MC), `test_base_manager_runtime_error_on_block` (worker), `test_network_client_blocks_out_of_scope_in_hard_mode` (network), `test_external_adapter_blocks_in_hard_mode` (external) — all PASS |
| AC-07 | 判定結果に `reason_code` と evidence 参照が残り、後から「なぜ止まったか」を説明できること | `GuardDecision` に `reason_code`, `matched_rule_origin_ids`, `source_refs` を含む (PASS) |
| AC-08 | `active_bundle.json` または `compiled_guard_policy.yaml` が破損・欠落している場合は fail-closed すること | `test_hash_mismatch`, `test_compiled_policy_missing`, `test_active_bundle_json_missing` (all PASS) |
| AC-09 | Manual review が必要な bundle で pending finding 一覧、source refs、override skeleton、recompile 導線が提示されること | `review_findings.yaml` + `overrides.yaml` contract で定義済み |

### 2.3 Post-Exploit Control

| # | Criterion | Verification |
|---|---|---|
| AC-10 | Post-exploit task が compiled policy で deny されている場合、task 生成前（MC/manager）で block されること | `test_post_exploit_task_blocked_by_compiled_policy`, `test_trigger_post_exploit_recon_denies_when_policy_blocks` (PASS) |
| AC-11 | Post-exploit deny が全 enforcement layer で一貫していること | `evaluate_guard()` の post_exploit phase check は全層共通 (PASS) |

### 2.4 Fail-Closed and Integrity

| # | Criterion | Verification |
|---|---|---|
| AC-12 | Policy unavailable → 全層 fail-closed（rollout stage に関わらず常に block） | `evaluate_at_layer()` policy=None path, `test_policy_unavailable_records_fail_closed` (PASS) |
| AC-13 | Policy hash 不一致 → compile error / fail-closed | `test_hash_mismatch`, `test_compile_write_load_hash_fail_closed` (PASS) |
| AC-14 | Schema version 不一致 → fail-closed | `test_schema_unsupported`, `test_schema_version_above_supported` (PASS) |
| AC-15 | Bugbounty + shared context なし → 全 non-MC 層 fail-closed | `test_*_fail_closed_when_no_context` × 4 (PASS) |

### 2.5 Negative Scenarios

| # | Criterion | Verification |
|---|---|---|
| AC-16 | Invalid timezone in manifest → adapter does not crash | `test_invalid_timezone_does_not_crash` (PASS) |
| AC-17 | Credential-like values excluded from compiled output | `test_compiled_policy_excludes_credential_patterns` (PASS) |
| AC-18 | Exact deny wins over wildcard allow (deny precedence) | `test_compiler_exact_deny_wins_over_wildcard_allow` (PASS) |
| AC-19 | 0 in-scope assets → compile_failed | `test_empty_assets_produces_compile_failed` (PASS) |
| AC-20 | Missing active_bundle.json → GuardLoadError | `test_loader_fails_for_directory_without_active_bundle` (PASS) |

### 2.6 Snapshot and Determinism

| # | Criterion | Verification |
|---|---|---|
| AC-21 | Same bundle → same `compiled_policy_hash` (TikTok) | `test_tiktok_bundle_idempotent_hash` (PASS) |
| AC-22 | Same bundle → same `compiled_policy_hash` (Fireblocks) | `test_fireblocks_bundle_idempotent_hash` (PASS) |
| AC-23 | Different bundles → different hashes (no collision) | `test_different_bundles_produce_different_hashes` (PASS) |
| AC-24 | Hash stable across time (`time.sleep` between compilations) | `test_hash_determinism_across_time` (PASS) |

### 2.7 Rollout and Kill Switch

| # | Criterion | Verification |
|---|---|---|
| AC-25 | `shadow_read_only`: evaluate but never block | `test_shadow_stage_never_blocks` (PASS) |
| AC-26 | `mc_only`: block only at MC layer | `test_mc_only_evaluator_returns_block_for_mc` (PASS) |
| AC-27 | `worker_external_hard`: block at all layers | All `*_blocks_*_in_hard_mode` tests (PASS) |
| AC-28 | Shared context update/clear propagates to existing clients | `test_shared_context_update_propagates_to_existing_client`, `test_shared_context_clear_propagates_to_existing_client` (PASS) |
| AC-29 | CTF mode does not leak guard | `test_shared_context_does_not_block_ctf_client`, `test_ctf_mode_post_exploit_not_blocked` (PASS) |

### 2.8 Resume / Retry / Replay

| # | Criterion | Verification |
|---|---|---|
| AC-30 | Resume/retry が既定で同一 `bundle_id` / `policy_id` を引き継ぐこと | Spec section 13.9 で定義済み |
| AC-31 | 明示 rebind 時のみ新 bundle を使用すること | Spec section 13.9 で定義済み |

## 3. Quantitative Acceptance (Observability)

| Metric | Target | Current Source |
|---|---|---|
| `compile_failed_total` (直近 run) | 0 | `guard_metrics.snapshot()` |
| `active_bundle_read_failure_total` | 0 | `guard_metrics.snapshot()` |
| `manual_review_required_total` / compile 総数 | ≤ 30% (V1 許容) | `guard_metrics.snapshot()` |
| `policy_fail_closed_total` | 0（通常運用時） | `guard_metrics.snapshot()` |
| `bundle_import_to_ready_seconds` p50 | ≤ 5s | `guard_metrics.snapshot()` |
| `guard_decision_total{layer=mc,decision=block}` reason_code 分布 | 想定外の reason_code 0 件 | `guard_metrics.snapshot()` |
| False block 許容率（operator 報告ベース） | ≤ 5% | Operator report |
| Unsafe dispatch 予防件数 | ≥ 1（post-exploit, SSRF 他） | MC `_dispatch` block log |

## 4. Non-Functional Acceptance

| # | Criterion | Status |
|---|---|---|
| NF-01 | CTF / non-bugbounty mode で guard がリークしない | PASS (mode isolation tests) |
| NF-02 | Metrics 記録失敗が enforcement に影響しない（best-effort） | PASS (`try/except pass` at each hook) |
| NF-03 | 同一 `guard_input` + 同一 policy → 同一 `decision_trace_id` | PASS (`test_deterministic_trace_id_same_input`) |
| NF-04 | 160 tests PASS（全 enforcement + metrics + negative + compiler） | PASS |
| NF-05 | SHIGOKU docs validation 0 errors | PASS |

## 5. Test Coverage Summary

| Test Suite | Tests | Status |
|---|---|---|
| `test_guard_enforcement_phase2.py` | 40 | PASS |
| `test_guard_metrics.py` | 23 | PASS |
| `test_negative_fixtures.py` | 10 | PASS |
| `test_compiled_guard_evaluator.py` | 20 | PASS |
| `test_compiled_guard_loader.py` | 20 | PASS |
| `test_compiled_guard_compiler.py` | 47 | PASS |
| **Total** | **160** | **ALL PASS** |

## 6. Out of Scope (V1 — Confirmed)

以下は V1 では実装しない（plan section 4.3 で決定済み）：

- HackerOne / Bugcrowd API からの自動同期
- 報酬額や bounty 履歴を使った ROI ランキング
- Runtime 中に自然文ルールを再解釈する専用 AI judge
- Full 自動で曖昧性を解消する仕組み
- `--scope` legacy interface の内部コード完全撤去（入口封鎖のみ V1 で実施）

## 7. Deferred Items

V1 完了後に別タスクとして追跡する項目。
実タスクIDは work_report の `deferred_tasks` で定義する。

| Item | Reason |
|---|---|
| Stale bundle detection（age-based） | V1 では historical bundle が存在しない前提 |
| Concurrent bundle update control（file lock） | V1 は単独運用前提 |
| Prometheus endpoint for metrics export | V1 は text-based snapshot のみ |
| Automated shadow→enforcement stage promotion | V1 は manual transition |
| `--scope` internal code removal (Phase C-E) | 入口封鎖のみ V1 で完了 |
