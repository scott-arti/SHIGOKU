---
task_id: SGK-2026-0456
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-21_sgk-2026-0456_xss-dom-fragment-firing-path.md
- docs/shigoku/reports/2026-08-21_sgk-2026-0456_xss-dom-fragment-firing-path_work_report.md
- docs/shigoku/plans/done/2026-08-20_sgk-2026-0455_dom-xss-confirmation-routing.md
title: DOM XSSの発火経路をフラグメント(hash)クライアント側ソースへ拡張 作業ログ
created_at: '2026-08-21'
updated_at: '2026-08-22'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- xss
- dom
- browser
- firing-path
---

# SGK-2026-0456 作業ログ

## 2026-08-21（フェーズ0 診断 → 設計承認 → 実装 → 検証 → 実走行）

### フェーズ0（診断・引用特定・設計提出）

- **候補 URL 構築の所有コードを引用特定**（lessons 2026-08: 一ファイルの挙動を仕様と断定しない）:
  - 構築: `smart_xss.py:_validate_dom_runtime_xss`（L466-474 ベース3候補、L476-490 0454 の fragment 内 query 注入）。
  - 呼び出し元: `smart_xss.py:1135-1166`（`_should_attempt_dom_browser_validation` L253-269 を経由して DOM 検証へ escalate）。
  - 所有コード: `PlaywrightValidator.validate_xss`（`playwright_validator.py:138`）・`validate_xss_sync`（`:239`）。finding 反映は `smart_xss.py:767-816`、0455 の resurrection トリガーは `manager.py:1274-1299`。
  - **真因確定**: サーバ側 target では `urlparse(target).fragment` が空のため 0454 の fragment 内 query 注入が不発動で、SPA の実際の発火点 `#/search?q=<payload>` が生成されない。
- **設計提出・ユーザー承認**: 一般 hash 注入（target の path+query をフラグメントへ移す候補を追加・置換しない）。ユーザー追加要件を受理: ①強い証拠（dialog_observed）優先 ②DOM mutation のみでは param ループを打ち切らない ③ループ後に最良 mutation を採用（従来動作・偽陽性なし）④製品非依存の一般則（param 名・ルート名を名指ししない）。

### 実装（fixer 委譲・設計確定済み）

- `smart_xss.py` にフラグメント候補生成 + 打ち切り制御を実装（+48/-1）。
- テスト 5 件追加（T1 / T2a / T2b / T3a / T3b）。
- バー5点・playwright_validator.py は無改変。

### 検証（独立実施・額面で信用しない）

- フェーズ0 引用確認: 実コード精読で all 一致。
- ユニット: `test_smart_xss_logic.py` 11 passed、`tests/core/agents/swarm/injection/` 586 passed（既知 HEAD 失敗以外に新規失敗なし）。
- 製品非依存: `check_vdp_product_independence.py` verdict=pass / token_hits=0。
- T3 実走行: `env SHIGOKU_CAIDO__URL=http://127.0.0.1:8081 SHIGOKU_T3_HYBRID_ENABLED=1 SHIGOKU_SEALED_RUN_GET_ONLY=1 SHIGOKU_DIAGNOSTICS__ENABLED=1 SHIGOKU_TOOL_CALLING_ENABLED=1 SHIGOKU_DEDUP_GUARD_ENABLED=1 .venv/bin/python -m src.main --target http://localhost:3000 --mode vulntest`
  - 正本: `session_20260821_232237.json` / `haddix_report_20260821_232239.md` → **consistent / rerun_required=false**。
  - `dialog_observed=true` ×24（全フラグメント形式）・XSS confirmed=3・funnel F5/F6=3。
  - REAL target 到達: Caido 8081 経由 `/api/Challenges/` が実データを返すことを直接確認（スタブではない）。

### 次アクション

- SGK-2026-0455 の正式クローズ（C1 実証済み）。commit は検証後の成果物、push はユーザー。

## 参考ルール

rules/lessons.md（一ファイルの挙動を仕様と断定しない・sealed run の REAL target 到達検証・スコープ固定）、rules/codingrules.md（局所変更・偽陽性防止）、rules/task-ledger.md、rules/shigoku-docs.md、rules/python-tests.md。
