---
task_id: SGK-2026-0450
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-14_sgk-2026-0450_deterministic-error-based-sqli-detection.md
- docs/shigoku/reports/2026-08-15_sgk-2026-0450_ai-hunter-toolcalling-dedup_work_report.md
created_at: '2026-08-15'
updated_at: '2026-08-15'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- reliability
---

# 作業ログ: SGK-2026-0450 — AI ハンターの信頼化（tool-calling ＋ 重複排除）

## 経緯

1. **STEP 1（フェーズ0・承認済み）**: 自由テキスト ReAct 呼び出し箇所マップ（M1-M3 manager / S1-S2 smart_sqli / S3 他 specialist）、A/B 最小差分設計、flash 化封印 run 観測（空引数・繰り返し再現）を計画書に記載し承認取得。
2. **STEP 2（実装）**: `llm.py`(+28) tool_loop / `settings.py`(+4) オプトインフラグ / `base_manager.py`(+243) スキーマ機械生成・tool-calling 経路・重複排除ガード / `smart_sqli.py`(+111) specialist スキーマ・decide 分岐。保護3ファイル diff 0。
3. **STEP 3（実 run 3回）**: session_20260815_083119 / 084844 / 090008。空引数 Action 消滅・繰り返し低減を確認。しかし funnel F5=0・SQLi finding 0。
4. **独立検証（Claude）**: 保護3ファイル diff 0、新規20＋injection 567 passed、product-independence verdict=pass（token hits 0）、既定 OFF＝byte-equal。**3 run とも probe_sent=True が全 sqli url_result で 0**＝発火 payload 未送信を確定（第4根本原因）。`q=',` は Python repr の誤認で実 payload でないことも確認。
5. **判定・再スコープ**: 完了条件3（F5>0×3）未達＝in_scope_blocker。silent-done は §19 違反として却下。ユーザーに選択肢提示 → **「A+B コミット＋発火欠陥を新タスク化」を選択**。条件3を SGK-2026-0451 へ carve-out、0450 は A+B 範囲で done。

## 主要コマンド（検証）

- `.venv/bin/pytest tests/unit/test_llm_tool_loop.py tests/unit/test_smart_sqli_tool_calling.py tests/unit/agents/swarm/test_base_manager_tool_calling.py -q` → 20 passed
- `.venv/bin/pytest tests/core/agents/swarm/injection/ -q` → 567 passed
- `git diff --stat <保護3ファイル>` → exit 0（diff 0）
- `python3 scripts/check_vdp_product_independence.py --manifest ... --denylist ... --changed-files ...` → verdict=pass, total_token_hits 0
- session 実データ検査（probe_sent / poc_request / funnel F5）→ 3 run とも probe_sent True=0, F5=0

## 参考ルール

rules/lessons.md（stub 検証・URL 正規化）、rules/codingrules.md（fail-closed・局所変更）、rules/report-session-consistency.md（consistent 判定）、rules/shigoku-docs.md、rules/task-ledger.md、rules/python-tests.md。

## 残課題（deferred）

- SGK-2026-0451: 発火経路の汎用修正（probe_sent=0 の真因を直し F5>0×3）。
- SGK-2026-0442 配下: 実害の安全な実証（データ抽出）。poc_judge は緩めない。
