---
task_id: SGK-2026-0455
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-20_sgk-2026-0455_dom-xss-confirmation-routing.md
- docs/shigoku/worklogs/2026-08-21_sgk-2026-0455_dom-xss-confirmation-routing_work_log.md
- docs/shigoku/plans/done/2026-08-21_sgk-2026-0456_xss-dom-fragment-firing-path.md
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
created_at: '2026-08-21'
updated_at: '2026-08-22'
tags:
- shigoku
- vdp
- xss
- dom
- confirmation
- browser
---

# SGK-2026-0455 作業完了報告 — DOM XSS のブラウザ実行証拠を確定まで運ぶ（confirmation routing 是正）

## 結論

確定バーを1バイトも緩めずに、本物のブラウザ実行証拠を持つ DOM XSS を **confirmed** まで運ぶ経路是正を完了した。C1（実走行で confirmed>=1・整合 consistent）は、上流の発火経路是正 [SGK-2026-0456] と組み合わせて **実証済み**。Claude が実 session/report・ledger・整合ゲートで直接確認した。

## 完了契約の結果（C1-C5）

- **C1（confirmed>=1・整合）**: 達成。正本 `sessions/session_20260821_232237.json` / `reports/haddix_report_20260821_232239.md` で XSS confirmed=3（`851fb54fd94b`/`49a880b3fa9a`/`356becc69a9a`、いずれも `hybrid_confirmed`・`dialog_observed=true`・`test_url=http://localhost:3000/#/search?q=...`）。`verify_report_session_consistency` = `consistent`/`rerun_required=false`。**うち `851fb54fd94b` は resurrection（res=1）で復活して確定** ＝ 本タスクの復活配線が端から端まで実働した実証。
- **C2（本物のブラウザ実行証拠・偽陽性なし）**: 達成。確定は実 dialog 発火に基づく。非発火は `dialog_observed` を付けず confirmed に至らない（偽陽性防止の回帰テスト T2/T2b）。
- **C3（reproduction gate のみ拡張＋poc_judge への実発火証拠可視化のみ・承認済み）**: 達成。
  - (a) `sealed_reproduction_checker.py` に DOM 経路（`variant=="dom"` でブラウザ再実行→`matched`/`mismatched`/`not_run`）。反射型 HTTP 経路は無改変。
  - (b) `finding_validator.py` の `_build_user_payload` に `browser_execution`（事実サブフィールドのみ・マスク経由）を追加（+19行）。判定ルール 200-233・閾値・`poc_judge.md` プロンプトは無改変。
- **C4（製品非依存）**: 達成。`check_vdp_product_independence.py` verdict=pass・token_hits=0。
- **C5（テスト）**: 達成。新規/変更ユニット全 pass、注入テスト群 586 passed。HEAD 既知失敗（`test_validate_xss_success`・`test_pool_exhaustion_handling`）以外に新規失敗なし。

## 実装内容（本タスク分）

- `sealed_reproduction_checker.py`: DOM XSS 用ブラウザ再実行経路（案A・2026-08-20 承認）。
- `playwright_validator.py`: `validate_xss_sync` 同期ラッパ追加（既存 async 挙動不変）。
- `manager.py`: resurrection 配線（`_t3_run_hybrid_pass` で `lifecycle.revisit`）、`_t3_browser_evidence_trigger` を実スキーマ（`dialog_observed`/`dom_mutation_observed`/`event==dom_sink_reflection`）対応。
- `finding_validator.py`: `_build_user_payload` に実発火証拠を可視化（C3(b)・2026-08-21 承認）。

## 無改変（凍結バー）

`payout_grade.py` / `poc_judge.md`（プロンプト本文）/ `task_queue.py(PCR-P1)` は各 `git diff --quiet HEAD` = exit0。`finding_validator.py` は `_build_user_payload` の証拠追加のみ（判定ルール本体は無改変）。

## 独立検証（Claude・DeepSeek 報告は額面で信用しない）

- バー diff（3点 exit0・finding_validator は +19 のみ）、ユニット 94 pass・注入群 586 pass を Claude が実行して確認。
- 実走行（Caido 8081・`SHIGOKU_T3_HYBRID_ENABLED=1`）の正本で confirmed=3・`dialog_observed=true`・整合 consistent を確認。フラグメント URL の実発火は Claude が直接 playwright で再確認（`#/search?q=<img ... onerror=alert(1)>` → True）。
- confirmed は3つの異なるエンドポイント（`/search?q=`・`/orders/history?query=`・`/rest/products/search?q=`）由来で、特定ルート焼き込みなし（製品非依存）。

## 診断の是正記録（正直な開示）

- 当初仮説（F3 phase2 昇格ロジックが原因）は誤り。実診断で真因は (1) reproduction gate の HTTP 再送が `#`フラグメント DOM XSS を構造的に却下、(2) `resurrect_matching` 未配線、と特定。
- 案A実装後の実走行で、さらに真因が上流に存在すると判明: poc_judge が `browser_execution` を見ず `ai_no_prize_grade` で却下（→ C3(b) で是正）、resurrection のフィールド食い違いバグ（`dialog_observed` のみ判定→実スキーマ対応で是正）。
- 最終的に、実発火 finding 生成の欠落（ハンターが SPA フラグメント発火点に届かない）が C1 未達の残因と判明し、[SGK-2026-0456] へ分離。0456 完了により C1 を実証。

## 参照

- 計画書: `docs/shigoku/plans/done/2026-08-20_sgk-2026-0455_dom-xss-confirmation-routing.md`
- 作業ログ: `docs/shigoku/worklogs/2026-08-21_sgk-2026-0455_dom-xss-confirmation-routing_work_log.md`
- 後続（C1実証の発火経路）: `docs/shigoku/plans/done/2026-08-21_sgk-2026-0456_xss-dom-fragment-firing-path.md`
