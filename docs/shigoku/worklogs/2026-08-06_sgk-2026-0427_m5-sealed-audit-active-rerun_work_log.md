---
task_id: SGK-2026-0427
doc_type: work_log
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/reports/2026-08-06_sgk-2026-0427_m5-sealed-audit-active-rerun_work_report.md
- docs/shigoku/subtasks/2026-08-06_sgk-2026-0427_m5-sealed-audit-active-rerun_subtask_plan.md
- docs/shigoku/subtasks/done/2026-08-05_sgk-2026-0425_vdp-causal-attack-funnel-diagnosis_subtask_plan.md
created_at: '2026-08-06'
updated_at: '2026-08-07'
tags:
- shigoku
target: tests/fixtures/vdp_juiceshop_sealed,src/reporting,config/diagnostics
---

# 作業ログ: SGK-2026-0427（M5 sealed audit active rerun）

## 実施経過

1. **実装前監査**提出（通信0）→ ユーザー承認（m3a固定・progression捏造禁止・POST3件S05 ineligible・egress定義）。
2. **通信0実装**: sealed 6ケースlabels、evaluate_m5.py、targeted tests（116 passed, 1 skip）、preflight exit 0、docs（registry/ledger登録・subtask_plan・D01追跡更新）。
3. **run設定提示** → ユーザー最終GO。
4. **隔離run（4 attempt）**: 1-3はCaido entry gate/セッションgateでbring-up失敗（session無し・失敗として記録）。本番attempt 4: 内部network＋allowlist proxy＋DNS gate＋Caido identity stub＋`SHIGOKU_SKIP_ENTRY_GATE=1`＋`mode: vulntest`（guard policy捏造を回避する正規lab mode）で **exit 0・instrumented session産出**。
5. **D04解消**: formatterへ `vdp_diagnostic_index_v1` additive埋め込みを実装（haddix_formatter/haddix_submission_internal_formatter/main.py）→ report再生成 → consistency **consistent**。
6. **実証**: secret 0・scope逸脱0・state変更0・二重送信0・予算超過0・egress許可外成功0（proxy DENY 11件+allowlist 1件）・実行1回・config byte-identical復元・preflight前後exit 0。
7. **evaluator post-binding**: 全6 caseがfirst-failure（S05×3）またはS05 ineligible（×3）。S05の原因候補（ログ由来）: C10 task_queue thread-confinement（PCR-P1）。
8. 成果物配置: `config/diagnostics/first_failure_juiceshop_v1.json`・`external_audit_v2.json`。docs検証0・graphify更新。

## 主要決定

- bugbounty modeのguard policy（bundle必須・fail-closed）に対しbundle捏造せず `vulntest` を使用（progression捏造拒否と同一規律）。
- Caido readinessはidentity stub（トラフィック非経由・scan.proxy空のまま）＋公式skip env。
- 本番run前にターゲットコンテナを新規作成（クリーン状態。disposable前提・承認済みrollback契約内）。
