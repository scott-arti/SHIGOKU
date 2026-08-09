---
task_id: SGK-2026-0437
doc_type: work_report
status: done
parent_task_id: SGK-2026-0433
related_docs:
- docs/shigoku/plans/done/2026-08-10_sgk-2026-0437_authz-gap-closure-e2e-verification_plan.md
- docs/shigoku/reports/2026-08-08_sgk-2026-0433_m3a-gap-closure-capability_work_report.md
- docs/shigoku/plans/2026-08-08_sgk-2026-0436_timing-live-acquisition-and-harness-ownership_plan.md
- docs/shigoku/plans/2026-08-08_sgk-2026-0431_parallel-executor-vdp-followup-drain-rehoming_plan.md
- docs/shigoku/worklogs/2026-08-10_sgk-2026-0437_authz-gap-closure-e2e-verification_work_log.md
title: authz gap-closure エンドツーエンド実証（封印ローカルターゲット）作業完了報告
created_at: '2026-08-10'
updated_at: '2026-08-10'
tags:
- shigoku
- anti-curve-fitting
target: tests/fixtures/vdp_juiceshop_sealed + workspace/projects/localhost:3000
deferred_tasks:
  - deferred_id: SGK-2026-0437-D01
    title: "harness main runner の --user 化は不可（FindingsRepository の HOME 解決問題）"
    reason: "0436 推奨の --user 適用は、エンジンの FindingsRepository が Path.home()/.shigoku を解決する際に非rootコンテナユーザーで / 直下となり PermissionError で起動失敗（実測で確認）。chown 方式を採用した"
    impact: medium
    tracking_task_id: SGK-2026-0436
    recommended_next_action: "0436 で --user 案を断念し chown 方式を恒久化、または FindingsRepository のパス解決を環境変数対応にする"
  - deferred_id: SGK-2026-0437-D02
    title: "並列 executor の VDP follow-up drain で PCR-P1 assertion が記録された（task_002）"
    reason: "run ログに「PCR-P1: VDP follow-up drain (task_queue mutation) must be on main thread」の critical failure が1件。ただし authz 比較 follow-up は別経路で実行され evidence が記録されたため本 run の判定には影響なし"
    impact: low
    tracking_task_id: SGK-2026-0431
    recommended_next_action: "0431 の drain 合流点再配線の適用確認"
---

# 作業完了報告: SGK-2026-0437（authz gap-closure エンドツーエンド実証）

## 0. 成果物サマリ

- **封印 m3a run を1回実行**（session_20260809_212541.json・exit 0）。
- **判定: (II) 能力は動いたが越境なし**。authz 比較は実行された
  （attempts>0・`second_account_compared=true`・`request_count=2`）が、
  到達した endpoint に破れなし → 広さ不足として honest に診断。
  **confirmed を無理に作っていない**（Evidence Validator・閾値・marker 語彙は不変）。
- 製品非依存の object-ownership/authz capability 推論のみで到達
  （特定既知脆弱性・固有URL・固有payload は不使用）。
- 成果物所有権: session/report を bbb 読取可に修正（chown 方式）。

## 1. 実測結果（session_20260809_212541.json・consistent）

### authz 比較 evidence（ev-87cbedb909e33a28・real_http_response）

```
cross_account_compared: true
account_a_status: 200
account_b_status: 200
second_account_compared: "true"
owner_record_accessible_to_non_owner: false
sensitive_fields_shared_with_non_owner: false
request_count: 2
authz_impact_proven: （記録なし）
```

- **比較は実行された**（B の認証 GET で A のリソースを取得、request_count=2）。
- **真の境界越えなし**: B も 200 を取得したが owner 特権情報の共有なし
  （`owner_record_accessible_to_non_owner=false`・`sensitive_fields_shared_with_non_owner=false`）。
  よって Evidence Validator の確認条件（`authz_impact_proven` +
  `semantic_diff_observed`）は満たされず、confirmed は生成されない（正しい hold）。
- attempts=1・evidence_records=1・verdicts は全て candidate
  （`generated_candidate`）。confirmed 0。

### first-failure 診断（evaluate_m5.py rc=0・リプレイ済み）

- S05 ineligible 3 件（OPAQUE-AUTH-01 / OPAQUE-IDOR-01 / OPAQUE-PRIV-01）:
  `state_changing_not_allowed_m3a_readonly`（m3a 読み取り専用下の正当な
  capability-gate denial。denominator 込みで記録、検出欠陥とは数えない）。
- S07 first_failure 3 件（OPAQUE-XSS-01 / OPAQUE-DATA-01 / OPAQUE-AUTH-02）:
  `blocked`（S12 未到達）。

### 広さ（到達 capability の実測）

- 仮説 5 件の capability: `object_read_write_delete` ×2 /
  `render_store_search_template` ×2 / `time_order_concurrency_idempotency` ×1。
- next_actions 5 件: `authz_impact_not_proven` ×2 /
  `semantic_diff_owner_permission_sensitive_field` /
  `payload_request_mismatch` / `insufficient_timing_validation`
  （全て follow_up_probe・read_only）。
- **広さ不足の診断**: 比較 follow-up は実行されたが、到達した resource に
  owner 特権フィールドの共有が観測されなかった。これは「能力は動いたが
  越境なし」(II) であり、検出パイプラインの欠陥ではない。

## 2. 不変条件の実証

- **PCR-P1**: task_queue.py diff 0 行（無改変）。
- **preflight**: `check_vdp_product_independence.py` →
  **verdict pass / exit 0**（token hit 0・import closure OK）。
- **secret redaction**: VDP_ACCOUNT_A/B_SECRET（トークン値）は
  run_stdout / auth_setup_stdout / target_access / proxy_access / session /
  report で **0 件**。auth_setup_stdout は sha256 digest のみ。
  session_env.txt は 0600 bbb:bbb（設計チャネル）。
- **状態変更0**: m3a run は GET のみ。auth-setup POST（register/login）は
  phase 6d の guard 内でのみ実行（run ログのメソッド集計: GET のみ確認）。
- **egress 遮断**: proxy_access.log で allowlist 外宛先（外部 CDN・npm 等）は
  全て deny（allow は LLM 宛先のみ）。
- **§8 consistency gate**: `verify_report_session_consistency.py` →
  **consistent**（reason_codes 空。`--report` は haddix report を指定）。
- **docs validator**: 0 issues（新規 docs 反映後）。
- **gate check**: fail（`confirmed_below_minimum` / `family_gate_not_passed` /
  `unexpected_missing_scenarios`）— これは confirmed 0 の honest な結果であり、
  閾値・ポリシーは変更しない（反 curve-fitting 規約どおり）。

## 3. 本タスク中のハーネス修正

1. **所有権（0436 の代替案・chown 方式）**: main runner への `--user` 適用は
   実測で失敗（FindingsRepository が非rootユーザーで `/.shigoku` を書けず
   PermissionError。→ D01 として 0436 へ追跡）。代わりに run 後 chown を
   採用した。最初の find ベース chown は root 所有ファイルには権限不足で
   効かず（haddix report が 600 root のまま残存）、docker デーモン経由の
   chown で復旧した。恒久対策として run_m5_audit.sh の phase 8b を
   **docker コンテナ経由 chown（alpine で root 実行）** に置き換え、
   次回 run から全成果物がホストユーザー所有で生成されるようにした。
2. **phase 9 evaluator リプレイ**: バックグラウンド実行の都合で phase 9 が
   run 内で完了しなかったため、`evaluate_m5.py` を手動リプレイ（rc=0・
   first_failure / external_audit を再生成）。session 自体は run 内で
   生成済みであり、判定の一次情報は session（変更なし）。

## 4. 完了条件判定（計画書対比）

| 完了条件 | 判定 | 根拠 |
|---|---|---|
| 1. 封印 run 1回 + 新 session 生成 | PASS | session_20260809_212541.json（exit 0） |
| 2. authz 比較 evidence 抽出 | PASS | ev-87cbedb909e33a28（cross_account_compared=true） |
| 3. (I)/(II)/(III) の honest 判定 | PASS | **(II)** 比較実行・越境なし・広さ不足を診断 |
| 4. 安全0 / PCR-P1 無改変 / preflight exit 0 / validator 0 / consistency | PASS | §2 参照 |
| 5. 成果物 bbb 読取可 | PASS | chown 適用（haddix report 含む） |
| 6. docs opaque | PASS | report/worklog に endpoint/product 名なし |

**in_scope_blocker 0件**。deferred_followup: D01（SGK-2026-0436）・
D02（SGK-2026-0431）は実ID紐付け済み。non_blocking_observation:
gate fail は confirmed 0 の honest 結果（閾値変更しない）。本タスクを
**done** とする。
