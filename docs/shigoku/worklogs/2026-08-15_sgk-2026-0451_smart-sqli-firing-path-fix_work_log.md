---
task_id: SGK-2026-0451
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-14_sgk-2026-0450_deterministic-error-based-sqli-detection.md
- docs/shigoku/plans/done/2026-08-15_sgk-2026-0451_smart-sqli-firing-path-fix.md
- docs/shigoku/reports/2026-08-15_sgk-2026-0451_smart-sqli-firing-path-fix_work_report.md
created_at: '2026-08-15'
updated_at: '2026-08-15'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- reliability
---

# 作業ログ: SGK-2026-0451 — SmartSQLiHunter 発火経路の修正（発見パラメータへ error-based プローブを確実に送る）

## 経緯

1. **STEP 1（フェーズ0・実装前調査）**: `smart_sqli.py` decide/act と phase1 検出経路を実コードで追跡し、0450 の 3 session（083119/084844/090008）の url_result・run_ledger spool（llm_called 実測）・実コード再現から真因 (b) 主因＋(a)(d) を実データで特定。(c) 非該当。計画書「フェーズ0結果」節に追記し設計承認を取得（2026-08-15）。
2. **STEP 2（実装・汎用のみ）**: `settings.py`（フラグ）・`smart_sqli.py`（メタ/ノイズ除外・URL 実在優先・決定的発火・記録・候補生成）・`manager.py`（記録配線のみ）。新規単体テスト 13 件。回帰 596 passed。
3. **実環境ミニ検証**: Caido 8081（実フォワーディング確認）経由で発火経路を実測。`?q=` の空値クエリが `parse_qs` 既定で落ちる問題を発見し `keep_blank_values` 対応を追加（フラグ ON 時のみ）。
4. **STEP 3（封印 run 連続 3 回・本物 Caido 8081・本物 Juice Shop・GET-only・オプトイン全 ON・ledger クリーン）**:
   - run A1: session_20260815_121901 / A2: 123531 / A3: 125303。
   - 3 run とも probe_sent=True×3・poc_request 非空・sqli finding 1（/rest/products/search?q=・sql_error=syntax）・funnel F5>0（4 エントリ）・誤確定 0（sqli 候補は poc_judge が needs_more で正しく確定させず）。GET-only・secret 0・consistency consistent×3。
   - 調査で判明した注意点: ①T3 ハイブリッドライフサイクルは `diagnostics.enabled`（funnel 収集）と candidate_ledger のクリーン状態が必要（既存 ledger の同 finding_id 終端レコードで無音スキップされる）②sql_error_fire 経路は payloads_used 記録が必須（0449 充填の payload 要件）— いずれも汎用の記録追加で対処。
5. **閉鎖**: 計画書 done/ へ移動・work_report/work_log 作成・台帳更新・docs 検証 0 エラー。commit/push はオーケストレータ検証後（本タスクでは実施しない）。

## 主要コマンド（検証）

- `.venv/bin/pytest tests/unit/test_smart_sqli_firing_path.py tests/unit/test_smart_sqli_tool_calling.py tests/core/agents/swarm/injection/ tests/unit/agents/swarm/test_base_manager_tool_calling.py -q` → 596 passed
- `.venv/bin/python scripts/check_vdp_product_independence.py --manifest config/diagnostics/product_independence_manifest_v1.json --denylist config/diagnostics/sealed_product_denylist.txt` → verdict=pass, total_token_hits 0
- `git diff --quiet HEAD -- payout_grade.py sealed_reproduction_checker.py injection_evidence_fields.py finding_validator.py` → exit 0（保護 diff 0）
- 実 run: `env SHIGOKU_CAIDO__URL=http://127.0.0.1:8081 SHIGOKU_TOOL_CALLING_ENABLED=1 SHIGOKU_DEDUP_GUARD_ENABLED=1 SHIGOKU_SEALED_RUN_GET_ONLY=1 SHIGOKU_T3_HYBRID_ENABLED=1 SHIGOKU_SQLI_FIRING_PATH_ENABLED=1 SHIGOKU_DIAGNOSTICS__ENABLED=1 .venv/bin/python -m src.main --target http://localhost:3000 --mode vulntest`（×3・各 run 前 ledger クリーン）
- `python3 scripts/verify_report_session_consistency.py --report <haddix_report>` → 3 ペアとも status=consistent
- `python3 scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py` → 0 エラー

## 参考ルール

rules/lessons.md（stub 検証・0450 STEP3 検証エントリ・スコープ固定）、rules/codingrules.md（fail-closed・局所変更・バイト等価）、rules/report-session-consistency.md（consistent 判定・F5 解釈）、rules/shigoku-docs.md、rules/task-ledger.md、rules/python-tests.md、docs/shigoku/learnings.md（0450 STEP3・LLM tool ループ・probe_sent 検証エントリ）。

## 残課題（deferred）

- SGK-2026-0442 配下: 実害の安全な実証（GET-only データ抽出）— live confirmed に必要。poc_judge は緩めない。
- オーケストレータ検証後のコミット（本タスクでは未実施）。
