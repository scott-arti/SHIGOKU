---
task_id: SGK-2026-0430
doc_type: work_log
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/reports/2026-08-07_sgk-2026-0430_sealed-live-rerun-verification_work_report.md
- docs/shigoku/subtasks/2026-08-07_sgk-2026-0430_sealed-live-rerun-verification_subtask_plan.md
- docs/shigoku/reports/2026-08-06_sgk-2026-0426_vdp-product-independent-improvement_work_report.md
created_at: '2026-08-07'
updated_at: '2026-08-08'
tags:
- shigoku
target: tests/fixtures/vdp_juiceshop_sealed,src/core/engine,src/reporting
---

# 作業ログ: SGK-2026-0430（封印ライブ実効確認）

## 実施経過

1. 台帳: SGK-2026-0430 採番・登録・subtask_plan作成。
2. Q2b checker拡張: `_session_fail_open`（run_health degraded+attempts 0からfail-open検出）＋テスト → **実0427ペアで consistent[]→inconsistent[vdp_run_failed_not_reflected] を実測**。
3. **run #1**（eval v2・session_20260807_152745）: W2 drain live成功（S05 reached・4件投入）を確認するも **S07 blocked（scope_block_incorrect）** で attempts 0。
4. 実測診断: F1=execute_parallel内drainがoff-mainでassert発火（fail-closedが検出）→ off-mainコールサイト除去。F2=scope snapshotがrate limit 0を引き継ぎ「0/min exceeded」で全follow-up false-block → snapshot fallback 60へ修正＋テスト4件（unitでlive URL許可を再現）。
5. **run #2**（eval v2b・ユーザー承認・session_20260807_153606）: **attempts 3・S08 reached×2・S10/S11 reached** — F2 live確認完了。
6. Q2a: run #2のreport/consistency consistent・11 events反映・confirmed 0。
7. 安全: secret 0・egress allow 1/deny 11・config byte-identical復元・preflight前後exit 0・PCR-P1 assert無改変。
8. 成果物: first_failure_juiceshop_v2.json（S07/supported）・v2b.json（S12/suspected）をconfig/diagnosticsへ配置。
9. docs: work_report/log・plan done化・validator 0・graphify更新。

## 主要決定

- 「1回実行」契約は維持しつつ、F2のlive確認はユーザー承認を得て2回目run（eval v2b）を実施（参考回帰）。
- F1はfail-closed assertが実配線の欠陥を検出した証跡として記録（assert削除・緩和なし）。
- F2はrate-limitをfast-path契約値60へフォールバック（明示値尊重）。validation緩和ではなくscope snapshotの欠落修正。
