---
task_id: SGK-2026-0434
doc_type: work_report
status: done
parent_task_id: SGK-2026-0432
related_docs:
- docs/shigoku/plans/done/2026-08-08_sgk-2026-0434_payload-mismatch-funnel-truth_plan.md
- docs/shigoku/reports/2026-08-08_sgk-2026-0432_gap-closure-causal-diagnosis_work_report.md
- docs/shigoku/worklogs/2026-08-09_sgk-2026-0434_payload-mismatch-funnel-truth_work_log.md
- config/diagnostics/counterfactual_sgk2026_0434_attempt.json
title: payload_request_mismatch probe の funnel-truth 改善 完了報告
created_at: '2026-08-09'
updated_at: '2026-08-09'
tags:
- shigoku
target: src/core/engine
---

# 作業完了報告: SGK-2026-0434（payload_request_mismatch probe の funnel-truth 改善）

## 0. 目的

0432 診断で判明した副次所見（D02）の解消: 攻撃 payload は診断層で値破棄される（0425 §5.1）ため `payload_request_mismatch` gap は原攻撃を再現できない。にもかかわらず、現状はペイロード無し probe を送り、正常 200 による誤解を招く S08/S10/S11 到達を生んでいた（0430 row 3: hyp-305c4372・att-c97b248b・ev-5c538d82）。本タスクは再現材が無い gap に probe を送らず S07 `exact_request_material_unavailable` で block し、funnel を正直化する（fabricated request 禁止契約の強化。証拠条件の緩和ではない）。

## 1. 変更内容

### 1a. executor（src/core/engine/vdp_follow_up_executor.py）
- S07 exact-material 判定を「material 有なら block」から **`payload_request_mismatch` は無条件 S07 block** に変更（:495-513）。
- 根拠: 当該 gap は「hypothesis payload が観測 request に一致しない」ことを意味し、payload 値は観測境界で常に破棄される → exact request material は**構造的に再構成不能**。param 空（破棄材ケース）でも probe は fabricated generic request になるため、従来 material 有のみを block していた条件では param 空が穴となっていた。
- 不要になった `urlparse` import を削除。

### 1b. generator（src/core/engine/vdp_hypothesis_generator.py）
- observation が破棄材を持つ（`param_names` / `param_locations` / `has_auth_header` / `has_cookie` のいずれか有＝queue gate と同じ署名）場合、`required_evidence[0] == payload_request_mismatch` なら **先頭 gap から外して末尾へ**（:521-544）。
- これにより m3a の first-gap 発行が payload_request_mismatch にならず、次の required evidence（例: semantic_diff_owner_permission_sensitive_field）へ進む。**required_evidence の集合は不変**（Evidence Validator・証拠条件は未変更）。

### 1c. テスト
- 新規: `TestFunnelTruthPayloadMismatch`（破棄材 param 空→S07 blocked・probe 未送信・budget/evidence 0・healthy gap は probe 実行）、generator の gap 発行条件 3 件、sealed-case funnel（S07 blocked→first_failure S07・downstream_not_reached）、counterfactual 2 件。
- 既存 fixture の gap 変更: 汎用 replay 機構テストの `_spec()` デフォルトを payload_request_mismatch → **authz_impact_not_proven**（healthy な single-request fallback）へ。payload 固有テストは明示 gap に変更。drill/realpath/rollout 統合テストは同一タスクの gap を healthy に差し替えて dispatch 機構の検証を維持。
- 新規 artifact: `config/diagnostics/counterfactual_sgk2026_0434_attempt.json`（changed_variable=attempt）。

## 2. 実測（must-test 3・4）

**funnel first-failure の変化（実測）** — 0430 実 artifact（session_20260807_153606.json・OPAQUE-XSS-01）:
- control（0430）: first_failure **S12**（S08/S10/S11 に誤到達）
- treatment（0434 修正後）: first_failure **S07**（downstream_not_reached: S08/S09/S10/S11/S12）

**counterfactual（must-test 4）** — `config/diagnostics/counterfactual_sgk2026_0434_attempt.json`:
- changed_variable=**attempt**（probe_sent → probe_blocked_s07）、他変数不変・frozen_input_hash 一致・safety 0 で validate エラー 0
- stage delta: S07..S11 の誤到達が除去され（regressed）、improved 0 → attribution **supported**（harness は到達削減を regression と評価するが、除去されたのは fabricated reach であり honestification そのもの）

## 3. 不変条件の実証

| 条件 | 結果 |
|---|---|
| 証拠条件/Evidence Validator/閾値 | 未変更（vdp_evidence_validator.py・haddix_evidence_quality.py・vdp_readonly_guard.py 無改変） |
| confirmed 件数を成功指標にしない | 変更は誤到達の除去のみ（比較実測は行わず、confirmed 増減なし） |
| PCR-P1（task_queue.py） | **diff 0 行**（assert 5 箇所現存） |
| 反 curve-fitting | preflight **verdict pass / exit 0**・token hit 0（製品token を code/session/report/docs に入れない） |
| schema additive（§12） | 追加は generator 内部のローカル変数のみ・schema フィールド変更なし |
| healthy ケース回帰 0 | authz_impact_not_proven / insufficient_timing_validation / 比較 gap は従来どおり probe（テストで担保） |
| 通信 | 本タスクはライブ通信なし（既存 artifact＋unit テスト＋counterfactual で完結） |

## 4. 検証

```text
unit:   tests/unit/engine/ + tests/unit/reporting/ → 2744 passed, 1 skipped
        （新規 82 tests 含む: executor 3・generator 3・sealed funnel 1・counterfactual 2・既存改修）
preflight: check_vdp_product_independence.py → verdict pass / exit 0 / token hits 0
PCR-P1:  task_queue.py diff 0 行
docs:    sync → validate（後述）
git:     git diff --check clean（src/ tests/）
```

カバレッジ: 実 artifact（0430 session・funnel 再評価）+ unit テスト両方。

## 5. 完了条件判定（計画書との対応）

1. 破棄材ケースで S07 blocked・probe 未送信（self-checking テスト）✓ `test_param_empty_payload_mismatch_blocks_at_s07_no_probe`（修正前は RED＝穴の実証→修正後 GREEN）
2. healthy ケースは従来どおり probe 実行（回帰 0）✓ authz/timing 系 71 件＋統合テスト green
3. funnel first-failure が S08（誤到達）→ S07（正直な block）に変わることを実測 ✓ 上記 §2（artifact 実測で S12→S07）
4. counterfactual（changed_variable=attempt）で probe 送信有→無の単一変数変化による funnel 正直化を提示 ✓ artifact＋validate 0
5. 安全 0・PCR-P1 diff 0・preflight exit 0・docs validator 0 ✓ §3・§4

**in_scope_blocker 0 件**。deferred_followup なし（計画上の NOT in scope: 0430 再実測・タイミング/第2アカウントは 0433/0436 で追跡済み）。本タスクを **done** とする。
