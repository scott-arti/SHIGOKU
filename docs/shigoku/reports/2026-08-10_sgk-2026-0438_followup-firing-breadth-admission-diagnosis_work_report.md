---
task_id: SGK-2026-0438
doc_type: work_report
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/plans/done/2026-08-10_sgk-2026-0438_followup-firing-breadth-admission-diagnosis.md
- docs/shigoku/reports/2026-08-10_sgk-2026-0431_off-main-vdp-drain-main-threadization_work_report.md
- docs/shigoku/reports/2026-08-08_sgk-2026-0434_payload-mismatch-funnel-truth_work_report.md
- docs/shigoku/plans/2026-08-08_sgk-2026-0436_timing-live-acquisition-and-harness-ownership_plan.md
- docs/shigoku/worklogs/2026-08-10_sgk-2026-0438_followup-firing-breadth-admission-diagnosis_work_log.md
title: 発射される follow-up の広さ診断（5案中1発しか撃たない原因）作業完了報告
created_at: '2026-08-10'
updated_at: '2026-08-11'
tags:
- shigoku
- vdp
- anti-curve-fitting
target: src/core/engine/master_conductor.py,tests/unit/engine
deferred_tasks:
  - deferred_id: SGK-2026-0438-D01
    title: "untested_no_second_account は queue 時に authA_authB / owned_resources precondition 不充足で保留のまま"
    reason: "比較型 gap の3番目のメンバーは plan の required_preconditions（authA_authB, owned_resources）が queue 時の available_preconditions（master_conductor.py の公開集合）に無く、設計どおり manual_review 保留。本 run の封印候補2案（authz_impact_not_proven / semantic_diff_owner_permission_sensitive_field）は解放対象であり、これは残る設計上の制約として記録"
    impact: low
    tracking_task_id: SGK-2026-0418
    recommended_next_action: "第二アカウント証拠が queue 時に得られる経路（recon での所有リソース特定）が将来実装されたら再評価"
---

# 作業完了報告: SGK-2026-0438（発射される follow-up の広さ診断）

## 0. 成果物サマリ

- **一次診断**: 5案中1発しか撃たない原因は **admission gate（S05）ではなく、
  queue 時の exact-replay skip**（master_conductor.py `_queue_vdp_follow_ups`
  L11690-11696）であることを一次証拠（shadow_diff + diagnostics events）で確定。
  budget（max_follow_ups 50・使用 0）も原因ではない。
- **(D) 最小修正**: 比較型 gap（`_COMPARISON_GAPS`）に限り param 値破棄でも
  queue 可能に変更（counterfactual で proven 化済み）。
- **封印 run 実測**: **attempted 1 → 3**（同種の別対象が実際に発射）。
  confirmed は指標にしない（0 のまま・正しい hold は hold のまま）。

## 1. 一次診断結果（session_20260810_012214・修正前）

### 5 案 × 非発射理由 × 分類

| # | capability（gap） | queue 判定（一次証拠: shadow_diff） | 非発射理由 | 分類 |
|---|---|---|---|---|
| #1 | time_order（`insufficient_timing_validation`） | `shadow_only/pending` | param 付き観測で exact-replay skip + 測定基盤未完成 | **(C)** → 既存 0436 |
| #2 | object_rw（`authz_impact_not_proven`） | `shadow_only/pending` | param 付き観測（`?name`）で exact-replay skip | **(D) → 修正** |
| #3 | render（`payload_request_mismatch`） | `enforced` → **S07 block** | `exact_request_material_unavailable`（0434 設計どおり・正当） | **(H)** |
| #4 | object_rw（`authz_impact_not_proven`） | `enforced` → **発射** | 唯一 param なし（ルート）→ 比較実行 → 越境なし hold | **(H)** 正しい hold |
| #5 | render（`semantic_diff_owner_permission_sensitive_field`） | `shadow_only/pending` | param 付き観測（`?q`）で exact-replay skip | **(D) → 修正** |

### 根拠（admission 仮説の棄却）

- S05 blocked イベント **0 件**・`admission_rejected` 0 件（vdp_admission.py は
  何も弾いていない。実行された follow-up は task レベルで全て success）。
- budget_snapshot: `max_follow_ups: 50, follow_ups_used: 0`。
- 真の絞り込み: `observation.param_names or param_locations or
  has_auth_header or has_cookie` → `continue`（param 値は観測時に破棄される
  ため exact replay 不能、という 0425 §5.1 由来の fail-closed 設計）。

## 2. (D) 修正（最小・承認済み設計）

### 変更内容（master_conductor.py `_queue_vdp_follow_ups`・単一 hunk 13+/5-）

```python
if observation.has_auth_header or observation.has_cookie:
    continue  # auth context discarded; replay unsafe for every gap
if (
    (observation.param_names or observation.param_locations)
    and gap not in _COMPARISON_GAPS
):
    continue  # values discarded; exact replay required for non-comparison gaps
```

- **解放**: 比較型 gap（`authz_impact_not_proven` /
  `semantic_diff_owner_permission_sensitive_field`）では param 値破棄でも queue。
- **fail-closed 維持**: `has_auth_header` / `has_cookie` は全 gap で skip。
  非比較 gap（payload_request_mismatch / timing 系）は param 付き skip 維持。
  observation None・precondition 不充足・S05 admission は無変更。
- **なぜ read-only 安全か**: A/B 比較は同一 URL を2アカウントで GET して
  応答差分を記録する。param 値が欠けても両アカウント同一リクエストなので
  差分は真の差分・同一応答（400 等）は「越境なし」を正しく記録。
  Evidence Validator（`authz_impact_proven` + `semantic_diff_observed` 必須）は
  無変更のため false confirmed は構造的に発生しない。

### counterfactual proven 化（必須・pre-fix で失敗を確認）

`tests/unit/engine/test_vdp_comparison_param_skip_release.py`:
- pre-fix: **1 failed**（`test_comparison_gap_with_param_names_is_queued_with_auth_ids`
  が skip により queue されず `assert 0 >= 1` で RED）→ 解放が効くことの証明。
- post-fix: **5 passed**（comparison+param → queue され auth ids 注入 /
  非比較+param → 依然 skip / comparison+cookie → 依然 skip /
  comparison+param なし → 従来どおり queue / executor 実送信で
  param 付き URL を2回送信・cross_account_compared=true）。

## 3. 封印 run 実測（session_20260810_154740・修正後）

| 指標 | 修正前（012214） | 修正後（154740） |
|---|---|---|
| attempted | 1 | **3** |
| evidence_records | 1 | **3** |
| shadow_diff: #2/#5 | shadow_only | **enforced / matched_shadow** |
| confirmed | 0 | 0（指標にしない） |

- 発射された3案は全て `cross_account_compared=true`・`account_a/b_status=200`・
  `owner_record_accessible_to_non_owner=false`・`request_count=2`
  （ev-87cbedb909e33a28 / ev-764dbbd018ad2777 / ev-466a780d0c5873c1）。
  → **正しい hold（越境なし）を3案分独立に記録**。confirmed 0・Validator 不変。
- #1（timing）は非比較 gap として引き続き skip（shadow_only）。
- #3（payload_request_mismatch）は S07 `exact_request_material_unavailable` で
  block（0434 設計どおり）。
- verdicts: 発射3案は `vdp-evidence-validator-0.1.0` で
  `success_condition_not_proven`（実 Validator 判定）。未発射2案は
  shadow の `generated_candidate`。

## 4. 不変条件の実証

- **PCR-P1**: task_queue.py diff **0 行**（assert 無改変）。
- **admission 安全判定**: 無変更（S05 は元々何も弾いていない。
  解放したのは「read-only で安全に実行可能な比較型 gap の param skip」のみ）。
- **Evidence Validator / 閾値 / marker 語彙**: 無変更。
- **preflight**: `check_vdp_product_independence.py` → **pass / exit 0**
  （1 ファイル走査・token hit 0）。
- **secret redaction**: run 成果物で **0 件**（auth_setup は digest のみ・
  session_env 0600）。
- **状態変更 0**: m3a run は GET のみ（run_stdout メソッド集計 GET のみ）。
  auth-setup POST は guard 内のみ。
- **§8 consistency gate**: **consistent**（reason_codes 空・coverage 8/12）。
- **所有権**: session 644 bbb:bbb / haddix report 600 bbb:bbb /
  session_env 0600 bbb。
- **実行1回**: single-run guard・config snapshot 復元（byte-identical）。
- **docs opaque**: report/worklog に endpoint/product 名なし。

## 5. 完了条件判定（計画書対比）

| 完了条件 | 判定 | 根拠 |
|---|---|---|
| 1. 5案の非発射理由を一次証拠で確定・(H)/(D)/(C) 分類 | PASS | §1 表（shadow_diff + diagnostics + admission 0 rejection） |
| 2. (D) 最小修正 → 封印 run で attempted 増加を実測 | PASS | 1 → 3（counterfactual proven・正しい hold は hold のまま） |
| 3. PCR-P1 無改変 / Validator・閾値不変 / preflight exit 0 / docs opaque / validator 0 / 安全0 / 実行1回 / consistent | PASS | §4 参照 |

**in_scope_blocker 0 件**。deferred_followup: D01（SGK-2026-0418 へ実ID紐付け・
`untested_no_second_account` の precondition 制約は設計どおりの記録）。
non_blocking_observation: なし。本タスクを **done** とする。
