---
task_id: SGK-2026-0438
doc_type: plan
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/reports/2026-08-10_sgk-2026-0431_off-main-vdp-drain-main-threadization_work_report.md
- docs/shigoku/reports/2026-08-08_sgk-2026-0432_gap-closure-causal-diagnosis_work_report.md
created_at: '2026-08-10'
updated_at: '2026-08-11'
tags:
- shigoku
- vdp
target: src/core/engine/vdp_admission.py,src/core/engine/vdp_follow_up_executor.py,src/core/engine/vdp_hypothesis_generator.py
---

# 実装計画: 発射される follow-up の広さ診断（5案中1発しか撃たない原因）

## 背景 / 観測（0431 修正後の run: session_20260810_012214）

- 攻撃アイデア 5 / 実際に撃った 1 / confirmed 0。5案は**全て別対象・別 dedup key**（重複ではない）。
- 内訳:
  - #1 timing（opaque-ep A：object-history query）: 測定基盤未完成で実行不可 → 既存 SGK-2026-0436。
  - #3 injection（opaque-ep B：search template）: 材料復元不能で正しく S07 block → SGK-2026-0434 の設計どおり（正当）。
  - #4 authz object_read_write_delete（ルート /）: **唯一 admission を通過し発射**。
  - **#2 authz object_read_write_delete（opaque-ep C：api list filter）・#5 render/permission（opaque-ep D：search query）: admission(S05) 等で発射されていない。**
- 予算は能力ごと max_follow_ups 2〜3 で「上限1」ではない。絞っているのは **admission gate（vdp_admission.py）**の可能性が高い
  （capability matrix: allowed/confirmation_required/prohibited/unavailable、OUT_OF_SCOPE、HITL 要承認 等）。

## 目的

**#4 は読み取り専用で撃てているのに、同種の #2・#5 が撃たれない理由を精密に特定し、正当でない保留だけを解放して、
"実行可能な別対象の攻撃"を確実に発射させる。** confirmed 件数を成功指標にしない。証拠条件・Evidence Validator は緩めない。

## スコープ（診断ファースト → 正当でない保留のみ最小修正）

1. 5案（特に #2/#5）について、attempt にならなかった**正確な stage と reason_code**を一次証拠で確定
   （admission_rejected の reason: confirmation_required / prohibited / unavailable / out_of_scope / scope_revalidation のどれか）。
2. 各保留を分類:
   - (H) 正当な保留（m3a read-only で原理的に不可・真に要HITL・真にスコープ外）→ 触らない。必要条件を記録。
   - (D) 過剰・誤判定（#4 と同型の read-only authz probe なのに弾いている等、admission の粒度/条件の不整合）→ 最小修正。
   - (C) 能力不足（別基盤が要る）→ 別タスクへ。
3. (D) は counterfactual で proven 化してから最小修正し、**同種の複数対象が発射される**ことを実測（封印 run）。

## 認可エンベロープ（0433/0437 と同一）

- 封印ローカル Juice Shop のみ・攻撃 follow-up は GET のみ・auth-setup は A/B register/login のみ・実行1回・snapshot 復元・安全0。
- 実VDP外部・状態変更・m3b 以上は対象外。

## 完了条件

1. 5案の非発射理由が一次証拠で確定・(H)/(D)/(C) 分類。
2. (D) があれば最小修正 → 封印 run で **attempted が増える**ことを実測（confirmed は指標にしない・正しい hold は hold のまま）。
3. PCR-P1 無改変・Evidence Validator/閾値不変・preflight exit 0・docs opaque・validator 0・安全0。

## NOT in scope

- 証拠条件/閾値の緩和・confirmed 件数の指標化。
- 未到達 scenario カテゴリ（別軸）・注入系分類の細分化（別タスク）。
- admission の安全判定（真の prohibited/HITL）を弱めること。

## 参照

- `src/core/engine/vdp_admission.py`（reason codes）、`vdp_follow_up_executor.py`（S05 admission 呼び出し 602-615）、`vdp_hypothesis_generator.py`（first_gap 854・capability budget 171-179）。
- session_20260810_012214（5案の実データ）。
