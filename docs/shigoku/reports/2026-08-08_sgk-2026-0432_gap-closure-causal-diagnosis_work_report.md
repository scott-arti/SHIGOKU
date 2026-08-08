---
task_id: SGK-2026-0432
doc_type: work_report
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/subtasks/done/2026-08-08_sgk-2026-0432_gap-closure-causal-diagnosis_subtask_plan.md
- docs/shigoku/reports/2026-08-07_sgk-2026-0430_sealed-live-rerun-verification_work_report.md
- docs/shigoku/plans/done/2026-08-08_sgk-2026-0433_m3a-gap-closure-capability_plan.md
- docs/shigoku/plans/2026-08-08_sgk-2026-0434_payload-mismatch-funnel-truth_plan.md
- docs/shigoku/worklogs/2026-08-08_sgk-2026-0432_gap-closure-causal-diagnosis_work_log.md
title: candidate→confirmed gap-closure 因果診断 完了報告
created_at: '2026-08-08'
updated_at: '2026-08-08'
tags:
- shigoku
target: workspace/projects/localhost:3000
deferred_tasks:
  - deferred_id: SGK-2026-0432-D01
    title: "m3a gap-closure能力拡張（第2アカウント比較・タイミング基盤）"
    reason: "(C) insufficient_timing_validation（タイミング基盤）と (H) authz_impact_not_proven の前提（第2アカウント比較）は m3a read-only 範囲外。閉塞には基盤提供が必要"
    impact: medium
    tracking_task_id: SGK-2026-0433
    recommended_next_action: "0433でテストアカウントA/B注入・認証済み比較follow-up・タイミング再現基盤をGET限定で実装"
  - deferred_id: SGK-2026-0432-D02
    title: "payload_request_mismatch probe の funnel-truth 改善（S07 exact_request_material_unavailable 化）"
    reason: "ペイロード再現不能な gap にペイロード無しprobeを実行するのは誤解を招く S08/S10/S11 到達を生む（(H)分類の副次所見）。任意改善"
    impact: low
    tracking_task_id: SGK-2026-0434
    recommended_next_action: "0434で executor S07 判定と generator の gap 発行条件を修正し、funnel を正直化（fabricated request 禁止契約の強化）"
---

# 作業完了報告: SGK-2026-0432（candidate→confirmed gap-closure 因果診断）

## 0. 診断対象と方法

0430実測（session_20260807_153606・run_id fa1dbed6）の 6 candidate を **hypothesis → verdict → next_action → attempt → evidence の同一ID系列**で追跡し、各 gap が「なぜ閉じなかったか」を機械可読に確定。**コード変更なし（診断ファースト）**。

## 1. candidate×stage first-failure 表（6行・分類＋根拠ID）

| # | verdict_id | hypothesis_id | 対象asset | gap | 閉塞状態 | gap-closure の到達/停止 | 分類 | 根拠ID |
|---|---|---|---|---|---|---|---|---|
| 1 | vrd-398a98d… | hyp-55baadc… | opaque-ep（object-history query param） | insufficient_timing_validation | shadow_only（未queue） | S05（admission非投入・m3a非実行可能plan） | **C** | nxt-7a78f55a shadow_only/pending |
| 2 | vrd-f9312f2… | hyp-084aab9… | opaque-ep（api list filter param） | authz_impact_not_proven | shadow_only（param破棄） | S05（値破棄→exact replay不能） | **H** | nxt-353ab50 shadow_only/pending |
| 3 | vrd-18b274ae… | hyp-305c4372… | opaque-ep（search template param） | payload_request_mismatch | enforced→**probe実行** | S08/S10/S11到達・成功条件未達 | **H**（(D)疑いをreq/resで反証） | att-c97b248b + ev-5c538d82 |
| 4 | vrd-b73c764f… | hyp-64807e37… | opaque-ep（root index） | authz_impact_not_proven | enforced→**probe実行** | S08/S10/S11到達・成功条件未達 | **H** | att-d5b8fd7c + ev-87cbedb9 |
| 5 | vrd-173501be… | hyp-ab68264d… | opaque-ep（search query param） | payload_request_mismatch | shadow_only（param破棄） | S05（値破棄→exact replay不能） | **H** | nxt-cbf06f91 shadow_only/pending |
| 6 | vrd-daf8335a… | hyp-1421d95f… | opaque-ep（admin/version-disclosure endpoint） | authz_impact_not_proven | enforced→**probe実行** | S08/S10/S11到達・成功条件未達 | **H** | att-e709c53a + ev-08e4bc22 |

**集計: H×5（authz×3・payload×2）／C×1（timing）／D×0。**

## 2. payload_request_mismatch の具体 req/res（(D)疑いの検証）

- **att-c97b248b（nxt-057896e4・hyp-305c4372 opaque-ep search template param）**: probe = **ペイロード無し GET** → 200 `<opaque JSON: 正常な list-shape 応答・注入信号なし>`（ev-5c538d82、real_http_response）。hypothesis（search-template render 注入クラス）に必要な攻撃ペイロードは**観測時に値破棄**（0425 §5.1安全契約: 値/body/credentialは診断へ入れない）→ follow-up fingerprint が原attemptと不一致（= gap payload_request_mismatch）→ **probeはペイロード無しで実行され、注入信号なし・正常応答のみ** → success_condition_not_proven。
- **判定**: **(D)疑いは反証**。probe は実行された（S08 reached・evidence記録済み＝ループは回った）。非閉塞は**構造的**（値破棄による再現不能）であり、パイプラインの drop ではなく**設計上正しい安全 hold（(H)）**。S06 attempt の質の問題（ペイロード無し再送）の根因は値破棄契約にある。
- **副次所見（D02へ追跡）**: 再現不能と分かっている gap にペイロード無し probe を実行するのは、誤解を招く S08/S10/S11 到達を生む（funnel-truth 改善: S07 `exact_request_material_unavailable` で block 化を0434で検討。fabricated request 禁止契約の強化であり証拠条件緩和ではない）。

## 3. 各分類の根拠

- **(H) authz ×3**: 2件は probe 実行済み（ev-87cbedb9＝root index HTML・ev-08e4bc22＝`<opaque version-string 200>`）。success condition（authz_impact）は**owner vs non-owner の比較**が必要（0425 §3.2 independent evidence）＝m3a read-only・第2アカウント無しでは原理的に証明不能。1件（nxt-353ab50）はparam破棄でqueue非投入（exact replay不能＝安全hold）。**前提条件（明記）**: `VDP_ACCOUNT_A/B_ID` 設定＋認証済み比較基盤（→0433）。
- **(H) payload ×2**: 上記§2（値破棄による構造的閉塞不能）。
- **(C) timing ×1**: insufficient_timing_validation は m3a の plan 分類で non-executable（shadow_only）。タイミング差の再現・統計反復基盤が m3a 範囲外（→0433）。

## 4. 不変条件の実証

- **confirmed件数を成功指標にしない**: 本タスクは分類・原因確定のみ。confirmed化施策なし。
- **証拠条件/Evidence Validator は未変更**（DVWA-low hold と同思想。無理な confirmed 化なし）。
- **preflight: verdict pass / exit 0**（changed_files_input 0＝本タスクはproductionコード変更0）。
- **PCR-P1: 無改変**（task_queue.py は本タスク未編集。diff は SGK-2026-0421 導入分の未コミット行のみ・assert 5箇所（:382/426/554/603/648）現存確認）。
- **追加ライブrunなし**（既存 artifact のみで診断。安全0件）。
- **反curve-fitting**: 製品token 0・sealed opaque のみ（本表は opaque ID で記述）。

## 5. (D)判定と修正

**(D)=0** のため、counterfactual・コード修正・回帰テストは**実施しない**（invariant: proven でない原因ではコードを変えない。診断ファーストの帰結）。D02（funnel-truth改善）は任意改善として0434へ追跡（現状の挙動は安全契約の範囲内で正しい hold であり blocker ではない）。

## 6. 検証

```text
lineage追跡: session_20260807_153606.json（hypothesis/verdict/next_action/attempt/evidence/shadow_diff を同一IDで突合）
preflight:   check_vdp_product_independence.py → verdict pass / exit 0
PCR-P1:      task_queue.py 無改変（16箇所のPCR-P1参照・assert 5箇所現存）
docs:        sync → validate 全0（REGISTRY 437・DEFERRED 0）
git:         git diff --check clean
```

カバレッジ: 実artifactのみ（本タスクは既存実測の再診断。テスト・ライブrunなし）。

## 7. 完了条件判定

1. 6 candidate 全行が H/D/C に根拠ID付きで分類 ✓ 2. payload_request_mismatch の req/res 具体化 ✓ 3. (D)=0 → コード変更0・その旨明記 ✓ 4. preflight exit 0・PCR-P1無改変・docs validator 0 ✓。

**in_scope_blocker 0件**。deferred_followup: D01（0433・能力拡張）・D02（0434・funnel-truth改善）。non_blocking_observation: ペイロード無しprobeのfunnel-truth問題（D02で追跡。安全契約の範囲内）。本タスクを **done** とする。
