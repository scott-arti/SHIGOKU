---
task_id: SGK-2026-0449
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-13_sgk-2026-0449_confirm-real-sqli-mechanical-impact.md
- docs/shigoku/reports/2026-08-14_sgk-2026-0449_confirm-real-sqli-mechanical-impact_work_report.md
created_at: '2026-08-14'
updated_at: '2026-08-14'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- confirmation
---

# 作業ログ: SGK-2026-0449 — D01: SQLi 候補への impact 機械充填

| 日付 | 内容 | 参照 |
|---|---|---|
| 2026-08-14 | フェーズ0（コード変更なし）: 封印 run `session_20260814_001700`。0448 実 SQLi 候補 `b41d9c6e47cd` を実 gate で評価 → reason=`missing_impact`（前4条件通過）機械確認。GET リプレイ 3/3 で 500+SQLITE_ERROR＝決定的再発火。impact 充填のみでは再現チェッカーが `not_run`（fingerprint mismatch）と判明 → Evidence 実観測記録のスコープ拡張をユーザー承認（§19） | 計画書 フェーズ0結果 |
| 2026-08-14 | STEP 2 実装: 新規 `injection_evidence_fields.py`（機械充填＋observed evidence・fail-closed）＋ `smart_sqli.py` の Finding に実観測リクエスト記録。`payout_grade.py`/`sealed_reproduction_checker.py` diff 0 | 報告書 §1 |
| 2026-08-14 | STEP 3 確定 run `session_20260814_014342`（オプトイン ON）: confirmed=0。原因は検出の非決定性（LLM Phase-2 90s タイムアウト×5・sql_error 候補未生成）。ターゲット挙動は決定的 | 報告書 §1 |
| 2026-08-14 | 独立検証（オーケストレータ）: 0448 実候補に新コード充填 → 実 `evaluate_payout_grade` `payout_grade_satisfied` / 実 `SealedReproductionChecker` `matched:sql_error`。＝3条件 AND 充足を end-to-end 実証。テスト 12+567 passed・製品非依存 exit 0・consistent・GET-only・docs 0 | 報告書 §2 |
| 2026-08-14 | 完了判定: ユーザー判断で done（機構完成・確定を実証済み）。検出決定化は SGK-2026-0450 で継続。run 副作用 vuln_roi_db.json は revert | 報告書 §4・§5 |
