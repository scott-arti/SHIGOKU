---
task_id: SGK-2026-0420
doc_type: work_report
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0420_vdp-capability-driven-hypothesis-generation-shadow-workflow_subtask_plan.md
- docs/shigoku/plans/done/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0419_vdp-evidence-schema-safety-budget-and-recovery-foundation_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0421_vdp-evidence-gap-driven-verification-and-safe-follow-up_subtask_plan.md
title: VDP capability driven hypothesis generation shadow workflow 作業完了報告
created_at: '2026-08-03'
updated_at: '2026-08-07'
tags:
- shigoku
target: src/core/engine,src/core/models,src/core/intelligence
---

# 作業完了報告書：SGK-2026-0420 VDP capability driven hypothesis generation shadow workflow

## 1. 成果概要

SGK-2026-0420の全チェック項目を実装し、**418件のテストが全件成功**した（新規97件+拡張/回帰321件）。製品名・既知URL・既知脆弱性を使わないcapability-driven仮説生成を、runtime LLM・実通信なしの決定論的純粋関数で実装した。record-only / shadowの2段階を実装し、既存の攻撃キュー・通信・finding・優先順位を一切変更しないadditive hookとしてMasterConductorへ接続した。

## 2. 実装内容

### 2.1 安全な観測取り込み (`src/core/engine/vdp_observation_adapter.py`)
- `normalize_url()`: userinfo拒否、query値破棄、fragment除去、秘密パス要素（UUID・長hex・token-*等のプレフィックス付き値）を `:opaque` へ正規化。例外文にraw URLを含めない。
- secret値は生成器への入力境界で破棄し、`has_auth_header` / `has_cookie` / `has_second_actor_evidence` / `has_admin_evidence` の安全な真偽値だけを生成器へ渡す。
- 観測IDはUUID・時刻を含まないcanonical JSONのSHA-256から決定論的に生成。
- `ObservationSourceKind`（9種）で観測源を識別。

### 2.2 決定論的仮説生成 (`src/core/engine/vdp_hypothesis_generator.py`)
- 9クラスのcapability分類（object r/w/d、auth/session/token、role/permission/ownership、state transition、file upload、external URL、render/store/template、async job/webhook、time/order）を汎用keywordで決定論的に実装。
- 仮説ID・dedup key・diversity bucket・verdict ID・next action IDはcanonical JSONのSHA-256で生成。UUID・現在時刻・乱数を決定結果へ混ぜない。
- `validate_proposal_dict()`: LLM提案を模した偽dictを決定論的validatorで検証（runtime LLMは呼び出さない）。
- label leakageは汎用マーカー（flag/ctf/CVE）と設定由来denylistで検出。製品名をruntimeコードへ埋め込まない。
- `build_unavailable_source_inventory()`: 未接続7観測源をSGK-2026-0421追跡ID付きで記録。

### 2.3 契約拡張 (`src/core/models/vdp_contract.py`)
- `HypothesisRecord` に additive field（resource_owner, dedup_key, generator_version, risk_class, scope_verdict, budget_estimate, observation_ids）を追加。既存v1 validator・旧session互換は維持。
- `validate_hypothesis_record_v0420()`: 0420生成record専用validator（controls baseline/attack/inverse、success/falsification、required evidence、actors、priority traceを必須化）。

### 2.4 公開vocabulary (`src/core/engine/recipe_contracts.py`)
- `VDP_ACTION_CLASSES` / `VDP_RISK_CLASSES` / `VDP_STOP_CONDITIONS` / `VDP_SCOPE_VERDICTS` / `VDP_REASON_CODES` / `validate_vdp_action_class()` をadditive追加。generatorはprivate `_VALID_*` の代わりに公開vocabularyを使用。

### 2.5 MasterConductor接続 (`src/core/engine/master_conductor.py`)
- recon結果の統合後・既存attack task生成前のadditive hook `_generate_vdp_hypotheses()` を追加。
- vdp.mode=off（既定）で即時return。record_onlyで仮説のみ、shadowでcandidate verdict + NextAction提案（queue非投入）。
- 非off実行では全経路でVDP状態を置換。generator例外は捕捉してdegraded reasonをdecision traceへ保存し、既存attack task生成を継続。
- 仮説0件でも7観測源のunavailable記録をdecision traceへ保存。`vdp_active=True`は有効なHypothesisRecordが1件以上ある場合のみ。

### 2.6 設定 (`src/core/config/settings.py` / `config/shigoku.yaml`)
- `VdpModeSettings`（mode: off|record_only|shadow、不正値はoffへfail-safe、label_leakage_denylist）を追加。既定値off。

## 3. 検証結果

### 実測テスト（418件 ALL PASS）

| テストファイル | 件数 | 結果 |
|---|---|---|
| test_vdp_contract.py | 77 | PASS |
| test_vdp_budget.py | 30 | PASS |
| test_vdp_admission.py | 29 | PASS |
| test_vdp_infrastructure.py | 44 | PASS |
| test_vdp_resilience.py | 18 | PASS |
| test_vdp_auth_cache.py | 9 | PASS |
| test_vdp_real_integration.py | 44 | PASS |
| test_vdp_observation_adapter.py | 35 | PASS |
| test_vdp_hypothesis_generator.py | 48 | PASS |
| test_recipe_contracts.py | 28 | PASS |
| test_vdp_mode_settings.py | 16 | PASS |
| test_master_conductor_vdp_hypothesis.py | 28 | PASS |
| test_master_conductor_recipe_contracts.py | 2 | PASS |
| test_master_conductor_failure_reason_codes.py | 4 | PASS |
| test_master_conductor_hitl_pending.py | 4 | PASS |
| **合計** | **418** | **ALL PASS** |

### 完了条件監査（計画書Sec.8）

| 条件 | 状態 | 根拠 |
|---|---|---|
| M1 record-only + M2 shadow受入条件 | PASS | TestVdpHookRecordOnly / TestVdpHookShadowMode / TestVdpStateReplacement |
| 対象非依存fixtureで能力意味維持 | PASS | TestCapabilityClassification / permuted endpoint fixture |
| known answer leakage 0件 | PASS | TestLabelLeakage（flag/CVE/denylist拒否） |
| scope逸脱task 0件 / 理由不明仮説0件 | PASS | queue不変・全仮説にdedup+priority_trace |
| 既存通信数・finding判定に差なし | PASS | socket mock 0接続・LLM生成0回・queue/finding不変 |
| 0421が消費可能なrecord保存 | PASS | session save→load→復元（実async_save_session経由） |
| 決定論（UUID/時刻/順序変化で不変） | PASS | TestDeterministicHypothesisId / TestActorEvidenceDeterminism / TestIdempotency |
| 秘密値不在（入力・record・session全段） | PASS | TestThreeStageSecretAbsence / TestSecretStripping |
| 旧v1互換（0419 recordがM0通過） | PASS | TestHypothesisRecordValidator.test_old_record_passes_v1_not_v0420 |
| scope/budgetは既存機構から導出 | PASS | TestScopeVerdict / budget_model=ExecutionBudgetV1でclamp |
| 観測0件でもunavailable記録 | PASS | TestUnavailableSourceRecording（7観測源・SGK-2026-0421） |
| 実recon接続点→save→M0実経路 | PASS | TestRealDispatchConnection（_dispatch→本番hook→async_save_session→M0） |

### 最終監査（3回目）対応
- I-01〜I-08（2回目指摘）およびI-03b / I-08（3回目指摘）の全in_scope_blockerを修正済み。最終判定は in_scope_blocker 0件。

## 4. 親タスクとの関係
- SGK-2026-0418（親タスク）はactiveのまま維持
- SGK-2026-0420はM1 record-only / M2 shadowの基盤として完了。SGK-2026-0421（evidence gap駆動の検証・follow-up）が仮説・candidate verdict・NextActionを消費可能。
- SGK-2026-0422（report/gate）・SGK-2026-0423（holdout/rollout）は予定どおり後続。

## 5. 未完了事項
なし。全チェック項目を実装完了。

## 6. 残存リスク
- 未接続観測源（crawler/form/js/api_schema/graphql/browser/proxy）の実接続はSGK-2026-0421の範囲（D-01）。
- 検証はユニット+統合+実経路（_dispatch経由）テスト。実VDP対象での運用検証は0423のshadow rolloutで実施予定。

## 7. deferred_tasks

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0420-D01
    title: "未接続観測源（crawler/form/javascript/api_schema/graphql/browser_traffic/proxy_history）のadapter実接続"
    reason: "SGK-2026-0420ではrecon_signal_bundleのみを接続し、その他の7観測源はObservationSourceKind識別とunavailable記録（SGK-2026-0421追跡ID付き）までを実装した。各観測源の実データ接続とfreshness計算はSGK-2026-0421のadapter拡張範囲"
    impact: medium
    tracking_task_id: SGK-2026-0421
    recommended_next_action: "SGK-2026-0421の対象（src/core/engine）でbuild_unavailable_source_inventory()の各sourceを実接続へ置換する"
```
