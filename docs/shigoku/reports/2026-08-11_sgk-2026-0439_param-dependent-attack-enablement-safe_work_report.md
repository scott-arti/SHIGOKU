---
task_id: SGK-2026-0439
doc_type: work_report
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/plans/done/2026-08-11_sgk-2026-0439_param-dependent-attack-enablement-safe.md
- docs/shigoku/reports/2026-08-10_sgk-2026-0438_followup-firing-breadth-admission-diagnosis_work_report.md
- docs/shigoku/worklogs/2026-08-11_sgk-2026-0439_param-dependent-attack-enablement-safe_work_log.md
title: param 依存攻撃（注入系）を「マスク＆復元」設計に合わせて安全に撃てるようにする 作業完了報告
created_at: '2026-08-11'
updated_at: '2026-08-11'
tags:
- shigoku
- vdp
- security-sensitive
target: src/core/security/pii_masker.py,src/core/engine/vdp_observation_adapter.py,src/core/engine/master_conductor.py,src/core/engine/vdp_follow_up_executor.py,src/core/engine/vdp_hypothesis_generator.py,src/core/infra/network_client.py
deferred_tasks:
  - deferred_id: SGK-2026-0439-D01
    title: "M0 復元の evidence_set_mismatch 厳密一致契約に起因する既存テスト2件（pre-existing）の修復"
    reason: "0439 起因ではなく HEAD（0438 verified）で再現を確認（stash 検証）。confirmed verdict の evaluated evidence set と session 全体の evidence set の厳密一致を M0 gate が要求する契約に起因し、複数証跡ラインを持つフルパステストで extra 証跡が不一致になる。本タスクの変更では発生せず in_scope 外"
    impact: low
    tracking_task_id: SGK-2026-0418
    recommended_next_action: "M0 復元契約の意図（fail-closed）を保ったまま証跡セット照合の柔軟性（許容される extra の定義）を別タスクで設計・修正し、両テストをグリーン化"
---

# 作業完了報告: SGK-2026-0439（param 依存攻撃の「マスク＆復元」化）

## 0. 成果物サマリ

- **診断（一次証拠）**: 注入系が撃たれない機構は **3重関門**（観測境界の値破棄 →
  queue skip → S07 block）と **payload 生成経路の欠如**。注入に必要なのは
  「元の param 値の復元」であることを実証（S07 の rationale 自体が
  「値破棄のせいで exact material を再構築できない。名前だけの probe は
  捏造された generic リクエスト」と明言）。
- **承認済み設計どおり実装**: VDP 攻撃経路を PIIMasker（マスク＆復元）に統合。
  記録はマスク形のみ・token_map は run スコープメモリ内・実行直前に復元。
- **封印 run 実測**: **attempts 3 → 5・evidence_records 3 → 5**。
  注入系（payload_request_mismatch）と timing 系が実際に発射・実行。
  GET-only・安全0・秘密漏洩 0・consistent。

## 1. 診断結果（exp-1 / exp-2・一次証拠）

| 関門 | 根拠（file:line） | 内容 |
|---|---|---|
| 観測境界の値破棄 | vdp_observation_adapter.py:189-190, 262-294, 332-383 | query 値は名前のみ残し破棄・auth 値は boolean 化・値スロットなし |
| queue skip | master_conductor.py:11700-11704 | 非比較 gap の param 付き観測は skip（0438 時点） |
| S07 block | vdp_follow_up_executor.py:495-513 | exact_request_material_unavailable → MANUAL_REVIEW（0434 設計） |
| payload 生成なし | vdp_follow_up_executor.py:1030-1085 | replay のみ・body/param 挿入なし |
| **生 URL（値入り）はメモリ上に存在** | vdp_observation_adapter.py:451-454 / recon pipeline.py:3267,3334 | 破棄の前段で raw_url が取得可能 → マスクで置換可能 |
| 観測ID決定性 | vdp_observation_adapter.py:316-329, 489 | ID ハッシュに値は非参加 → 値保持でも決定性不変 |
| PIIMasker は fail-open | pii_masker.py:66-171, 233-234 | 未認識値は素通し（test_pii_masker.py:15-21 が実証）→ deny-by-default プリミティブが必要 |
| token_map 非永続化 | repo 全体 grep | serialization 経路ゼロ・メモリ内のみ |

**切り分け結論**: 「param 名＋生成 payload の注入」では不十分。
fingerprint は名のみバインド（executor L200-223）だが、S07 gate は
値破棄を理由に名前のみの probe を「捏造された generic リクエスト」として
block する。**元値のマスク保持→実行直前復元が必須**（payload 変異生成は
将来機能・NOT in scope）。

## 2. 統合設計（承認済み・死守事項の実装対応）

| 死守 | 実装 |
|---|---|
| マスク箇所 | `ObservationAdapter` に run スコープ masker を注入し `adapt_endpoint_signal` で生 URL を `mask_url_query_values()` によりマスク（破棄の置換） |
| token_map 所在 | MasterConductor が run 専用 `PIIMasker` インスタンスを lazy init（LLM singleton とは分離）・**メモリ内のみ・永続化ゼロ**（既存 token_map 機構を再利用・新機構なし） |
| 復元点 | `_send_read_request` の送信境界（network_client.request 直前・fingerprint チェックの後）で unmask → 元値付き GET。fingerprint/budget/証跡は値なし正規化 URL のまま |
| fail-closed | 未解決トークン残存（復元不能・例: 再開 session）は送信せず MANUAL_REVIEW（`masked_request_material_unresolvable`）・値なき spec は従来どおり S07 block |
| deny-by-default | PIIMasker に `mask_url_query_values()` 追加: 既知秘密型は既存 PATTERNS で型付け、**未認識値は全体トークン化**（fail-closed）。既存 mask/unmask/token_map 無改変 |
| 決定性 | Observation に additive `masked_request_url` を追加するも **canonical payload に含めない** → 観測ID不変（単体テストで証明） |
| ログ/記録リーク封鎖 | network_client `log_safe_url`（全リクエストライフサイクルのログ/イベント/例外・キャッシュキー含む）・SESSION_EXPIRED イベント additive `log_safe_url` + MC のログ/台帳は safe_url・reauth orchestrator は raw URL のまま（契約不変） |

## 3. 封印 run 実測（session_20260811_002205・修正後）

| 指標 | 0438（154740） | 0439（002205） |
|---|---|---|
| attempts | 3 | **5** |
| evidence_records | 3 | **5** |
| payload_request_mismatch（注入系） | S07 block 0 回発射 | **発射・実行**（S07 block イベント 0・stage_sets に S07 不在） |
| insufficient_timing_validation | 未発射（shadow） | **発射・実行**（timing_measurement・8 リクエスト） |
| 発射の実測 | — | run_stdout で payload/timing follow-up の dispatch+result 受領を確認 |
| GET-only | 全 GET | session 内 method 38 件全て GET（POST/PUT/DELETE 0） |
| 安全0 | state_change marker 0 | 同 0（m3b_authorized/hitl 実行 0） |
| 秘密 | redaction 0 | spec は `[PII:VALUE:...]` マスク形のみ・credential フィールド値 0・ログにトークン/元値 0・auth_setup digest only・session_env 0600 |

## 4. 不変条件の実証

- **PCR-P1**: task_queue.py diff **0 行**（HEAD 対比）。
- **Evidence Validator / 閾値 / admission 安全判定**: 無変更
  （vdp_evidence_validator.py / vdp_admission.py / admission_policy.py /
  src/reporting/ の diff 0）。
- **観測ID決定性**: 単体テスト `observation_id` 同一（masked_request_url 有無で不変）。
- **preflight**: `check_vdp_product_independence.py` → **pass / exit 0**
  （6 files scanned・total_token_hits 0・import_closure ok）。
- **consistency gate**: `verify_report_session_consistency.py` →
  **consistent**（reason_codes 空・S08 reached 2 / S10/S11 reached 1）。
- **実行1回**: single-run marker・config snapshot byte-identical 復元・
  runtime surface（src/config/prompts）byte-identical。
- **docs opaque**: report/worklog に endpoint/product 名なし・
  封印ターゲットの artifact のみ。
- **所有権**: session 644 bbb:bbb / report 600 bbb:bbb / session_env 0600 bbb。

## 5. 完了条件判定（計画書対比）

| 完了条件 | 判定 | 根拠 |
|---|---|---|
| 1. 注入系 follow-up が封印 run で実際に撃たれる（payload が param に載る実測） | PASS | attempts 3→5・payload_request_mismatch が S07 block なく実行・元値復元 URL で送信（masked_request_url 保持 + 送信境界 unmask を単体テストで実証） |
| 2. 秘密漏洩 0（secret-scan 実証） | PASS | §3 参照（マスク形のみ・ログ/台帳/例外/イベント全経路を log_safe_url で封鎖・token_map 非永続化） |
| 3. 観測ID決定性不変 | PASS | 単体テスト・canonical payload 不変 |
| 4. Validator/閾値/admission/PCR-P1 無改変・preflight exit 0・docs opaque・validator 0・安全0・実行1回・consistent | PASS | §4 参照 |
| 5. false confirmed を生まない根拠 | PASS | Evidence Validator・証拠条件・閾値・admission 無変更（confirmed 生成条件は構造的に不変）。発射された証跡はすべて正しい hold（confirmed 0） |

**in_scope_blocker 0 件**。deferred_followup: D01（M0 evidence_set_mismatch
厳密一致契約に起因する既存テスト2件・0439 起因でないことを stash で実証済み。
追跡先 SGK-2026-0418）。non_blocking_observation: なし。
本タスクを **done** とする。
