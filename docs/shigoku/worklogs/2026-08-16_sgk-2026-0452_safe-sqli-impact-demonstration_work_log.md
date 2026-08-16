---
task_id: SGK-2026-0452
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-15_sgk-2026-0452_safe-sqli-impact-demonstration.md
- docs/shigoku/reports/2026-08-16_sgk-2026-0452_safe-sqli-impact-demonstration_work_report.md
created_at: '2026-08-16'
updated_at: '2026-08-16'
tags:
- shigoku
- vdp
- security-sensitive
---

# 作業ログ: SGK-2026-0452

## 2026-08-15 〜 2026-08-16（実装は DeepSeek・独立検証とドキュメント/コミットはオーケストレータ）

- フェーズ0調査（DeepSeek）→ オーケストレータが candidate_ledger の実 refs で真因を裏取り（ai_counter_evidence＝証拠チェーン矛盾）。STEP 2 承認。
- STEP 2 実装（DeepSeek）: smart_sqli の証拠チェーン整合＋安全実証プローブ（boolean 差分＋非機微 sqlite_version 抽出）／injection_evidence_fields 加法拡張／settings フラグ／manager 記録配線。
- STEP 3 で連続的に別々のブロッカーが判明し、その都度オーケストレータが実 artifact/コードで裏取りして承認:
  - judge の壊れた JSON → 承認 C: manager.py にパース失敗時1回再試行（fail-closed・基準不変）。
  - reproduction_pending → 誤診（budget）を排し、真因 network_client 未注入をコードで確定 → `_resolve_request_client()` フォールバック。
  - lifecycle 初回 needs_more 契約 → verdict==CONFIRMED 時のみ初回 confirmed に精緻化（承認）。
  - funnel F6 emit 未実装 → CONFIRMED 遷移時のみ emit。
  - report Confirmed 集計が ledger confirmed を拾わない → `_split_findings_by_confirmation` ほかで hybrid_final_state=="confirmed" のみ confirmed（ledger source-of-truth・捏造なし）。
- DeepSeek の中間報告に過大点（「B6/B7 とも confirmed」「report 反映済み」）があり、オーケストレータが実 artifact で訂正（F6=1 は当初1 run のみ・report は Confirmed:0 のまま）。report 集計修正後に再実証を指示。
- **B9（session_20260816_223550 / report_223552）で end-to-end 実証**: Confirmed:1・F6=1・ledger confirmed・バー4点＋PCR-P1 diff0・GET-only・consistency=consistent・product-independence=pass(token0)・docs 0。オーケストレータが全項目を自身で再実行して確認。
- judge 非決定性（B8 reject）は gaming せず記録し D01 として deferred。実害実証の防御回避未実装は D02 として deferred。
- 完了条件2は「連続3回」→ ユーザー合意の枠組みで再解釈（genuine confirmed end-to-end＋機構の決定性）。§19: in_scope_blocker 0 → done。
- オーケストレータが検証後にコミット（run 副作用 vuln_roi_db.json 等は対象外）。push はユーザー。
