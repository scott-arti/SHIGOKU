---
task_id: SGK-2026-0283
doc_type: work_report
parent_task_id: SGK-2026-0278
created_at: '2026-06-24'
updated_at: '2026-06-30'
tags:
  - shigoku
  - takeover
  - recipe
status: done
related_docs:
  - docs/shigoku/subtasks/done/2026-06-21_sgk-2026-0283_subdomain-takeover-v2_subtask_plan.md
  - docs/shigoku/plans/2026-06-20_sgk-2026-0278_ver-2-planning-bundle-dev-mode-recon_plan.md
---

# Subdomain Takeover高度化 作業報告書（最終）

## 状態注記
- 2026-06-24 時点で Phase 1-4 の基盤実装を完了。
- 2026-06-25 に Phase 5-8（plan steps 3-18）の統合・正規化・ゲート・レポート・ロールアウト実装を完了。
- D02（ReconPipeline統合）、D03（正規化層）は本実装で解決済み。
- D01（provider matrix 定期更新）は継続監視として deferred に残す。

## 1. 完了した実装

### Phase 1: Schema整合
- `ALLOWED_RECIPE_STEP_ACTIONS` に `check_takeover`, `dns_check`, `cname_resolve`, `http_probe`, `takeover_scan` を追加
- `validate_recipe_schema()` 関数を新設（0-step検出、unsupported action検出）
- `RecipeLoader.load_recipe()` に選択前検証ゲートを実装
- `recipes/recon/takeover.yaml` を loader 契約に準拠するよう再構築

### Phase 2: Selector契約
- `TakeoverCandidate` dataclass
- `RecipeCandidate` dataclass: score, reasons, signals, evidence, manual_review_required, trace
- `match_recipes_to_context()` を signal-based selection に強化
- `compute_freshness_score()`: 経過日数ベースの陳腐化スコア
- `extract_signals()`: TakeoverCandidate → flat signal dict の変換

### Phase 3: Provider matrix
- `ProviderEntry` + `ProviderMatrixLoader` + `TakeoverProviderMatrix`
- CNAME/error token fingerprint matching
- `resolve_tool_chain()`: provider別ツール優先順
- `config/providers/takeover_provider_matrix.yaml` (aws_s3, github_pages, heroku, azure_websites)
- **2026-06-25追加**: matrix metadata検証（version, updated_at, source_note必須化）、`rollback_target` フィールド

### Phase 4: Success gate強化
- `_finalize_results()`: 0-step success禁止
- `compute_takeover_verdict()`: confirmed/high_priority_manual_check/manual_review_required/no_finding
- `classify_takeover_result()`, `is_candidate_stale()`

### Phase 5: ReconPipeline統合 (D02解決)
- `TakeoverCandidate` 拡張スキーマ: candidate_id, observed_at, cname_chain, provider_guess, required_signals, raw_evidence
- 安定 candidate_id 生成 (subdomain + cname_chain の SHA256)
- 既存 session からの first_seen_dead 継承
- 後方互換: legacy NXDOMAIN dict → TakeoverCandidate 変換

### Phase 6: MasterConductor context injection
- `_build_takeover_candidates_from_recon()`: ReconPipeline出力 → TakeoverCandidate リスト
- `_load_recipe_tasks()` に `context["takeover_candidates"]` 注入
- Legacy format 互換変換

### Phase 7: Scope policy + 正規化層 (D03解決)
- `TakeoverScopePolicy`: takeover_allowed, claim_action_allowed (常にfalse)
- `evaluate_scope_signals()`: selector/gate 統合用ブロッキングシグナル
- `takeover_tool_result_adapter.py`: subjack/subzy/nuclei/manual_curl → `NormalizedTakeoverToolResult`
- 全パーサ: empty/stderr/partial JSON/duplicate provider hit 対応

### Phase 8: Infrastructure / Verdict / Trace / Report / Shadow
- `InfrastructureState`: tool_unavailable/probe_failed/resolver_degraded/timeout/missing_binary
- `classify_infrastructure_state()`: step error code → infrastructure_state
- `check_tool_availability()`: preflight binary check
- `compute_verdict_reasons()`: 7種の構造化reason code
- `TakeoverCandidate` trace: source_line, producer_step, session_id, artifact_hash
- Recipe `success_condition` / `stop_condition`
- `takeover_step_executors.py`: cname_resolve, http_probe, check_takeover
- `takeover_report_normalizer.py`: takeover_verdict / global_confirmed分離
- `high_priority_manual_check` 判定（旧 likely_reclaimable）
- `takeover_probe_budget.py`: ProbeCache, ProbeBudget, DedupeWindow
- `takeover_feature_flags.py`: TAKEOVER_V2_ENABLED/SHADOW/KILLSWITCH

## 2. テスト結果
- **新規テスト**: 331件（全takeover関連テスト）
- **既存テスト**: 全件パス（レグレッションなし）
- **全体**: 729 passed, 5 pre-existing failures（tests/recon/のStep6/8統合テスト、本タスクとは無関係）

## 3. 変更ファイル一覧（全フェーズ）

| ファイル | 変更種別 |
|---|---|
| `src/core/engine/recipe_contracts.py` | 改修 |
| `src/core/engine/recipe_loader.py` | 全面改修 |
| `src/core/engine/optimized_runner.py` | 改修（finalize, verdict, reasons, infra_state, trace） |
| `src/core/engine/master_conductor.py` | 改修（context injection, _build_takeover_candidates） |
| `src/core/engine/takeover_step_executors.py` | **新規** |
| `src/core/engine/takeover_probe_budget.py` | **新規** |
| `src/core/engine/takeover_feature_flags.py` | **新規** |
| `src/core/adapters/external/takeover_provider_matrix_adapter.py` | 新規→改修 |
| `src/core/adapters/external/takeover_tool_result_adapter.py` | **新規** |
| `src/core/policy/__init__.py` | **新規** |
| `src/core/policy/takeover_scope_policy.py` | **新規** |
| `src/reporting/takeover_report_normalizer.py` | **新規** |
| `src/recon/pipeline.py` | 改修（TakeoverCandidate統合） |
| `recipes/recon/takeover.yaml` | 改修（success/stop condition追加） |
| `config/providers/takeover_provider_matrix.yaml` | 新規→改修 |
| `tests/unit/engine/test_*` | 12ファイル新規/拡張 |
| `tests/unit/adapters/test_takeover_*` | 2ファイル新規/拡張 |
| `tests/unit/reporting/test_takeover_report_normalizer.py` | **新規** |
| `tests/recon/test_takeover_candidate_integration.py` | **新規** |

## 4. 成果物

| 成果物 | 状態 |
|---|---|
| takeover Recipe YAML schema整合 + executor | ✅ |
| RecipeCandidate + signal-based selector | ✅ |
| Provider matrix データ + ローダー + 検証 | ✅ |
| Success gate 0-step/stale/HITL/verdict reasons | ✅ |
| ReconPipeline → TakeoverCandidate 統合 (D02) | ✅ |
| subjack/subzy 正規化層 (D03) | ✅ |
| MC context injection | ✅ |
| Scope policy blocking signal | ✅ |
| Infrastructure state guardrails | ✅ |
| Trace schema (source_line/producer_step/session_id/artifact_hash) | ✅ |
| Report 正規化層 (takeover_verdict / global_confirmed 分離) | ✅ |
| high_priority_manual_check 判定 | ✅ |
| Probe budget / dedupe / cache | ✅ |
| Shadow mode / feature flag / kill switch | 🔶 helper implemented, runtime wiring deferred |
| 全テストパス (331件) | ✅ |
| 後方互換性（非signal Recipeの動作維持） | ✅ |

## deferred_tasks

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0283-D01
    title: "継続監視: provider matrix の定期更新"
    reason: "provider 側サービス仕様変更に追従するため定期的なシグネチャ更新が必要"
    impact: medium
    tracking_task_id: SGK-2026-0308
    recommended_next_action: "provider matrix 更新用のCIパイプラインまたは定期レビューを plan として起票する"
    status: active

  - deferred_id: SGK-2026-0283-D02
    title: "ReconPipelineへの候補スキーマ接続"
    reason: "本実装で解決済み（2026-06-25）"
    impact: medium
    tracking_task_id: SGK-2026-0278
    status: resolved

  - deferred_id: SGK-2026-0283-D03
    title: "subjack/subzy 正規化層の実装"
    reason: "本実装で解決済み（2026-06-25）"
    impact: medium
    tracking_task_id: SGK-2026-0278
    status: resolved

  - deferred_id: SGK-2026-0283-D04
    title: "継続監視: takeover step executor の aiohttp/dns.resolver 依存"
    reason: "cname_resolve/http_probe は stdlib socket を使用しているが、本番DNS/HTTP検証には aiohttp/dnspython が望ましい"
    impact: low
    tracking_task_id: SGK-2026-0308
    recommended_next_action: "OptionalDeps として aiohttp/dnspython を導入し、存在時に強化パスを使うよう executor を改良する"
    status: active

  - deferred_id: SGK-2026-0283-D05
    title: "Shadow mode runtime wiring"
    reason: "shadow_compare_results() helper is implemented but legacy result path for comparison does not exist yet"
    impact: low
    tracking_task_id: SGK-2026-0308
    recommended_next_action: "legacy takeover path の結果を収集できるようになった時点で shadow_compare_results() を runtime に接続する"
    status: active
```
