---
task_id: SGK-2026-0456
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-21_sgk-2026-0456_xss-dom-fragment-firing-path.md
- docs/shigoku/worklogs/2026-08-21_sgk-2026-0456_xss-dom-fragment-firing-path_work_log.md
- docs/shigoku/plans/done/2026-08-20_sgk-2026-0455_dom-xss-confirmation-routing.md
- docs/shigoku/plans/done/2026-08-18_sgk-2026-0454_xss-dom-runtime-firing-path.md
title: DOM XSSの発火経路をフラグメント(hash)クライアント側ソースへ拡張 作業完了報告
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
target: src/core/agents/swarm/injection/smart_xss.py,tests/core/agents/swarm/injection/test_smart_xss_logic.py
---

# SGK-2026-0456 作業完了報告 — DOM XSS の発火経路をフラグメント(hash)クライアント側ソースへ拡張

## What（何をしたか）

SmartXSSHunter の DOM 検証候補 URL 構築に、**製品非依存のフラグメント(hash)候補**を追加した。サーバ側 URL（例 `/search?q=test&name=x`）の `path+query` をそのまま URL フラグメントへ移した形（`http://host/#/search?q=test&name=<payload>`）を生成し、SPA のクライアント側ルーティングで実際に発火する DOM sink へ payload を届ける。既存のサーバ側クエリ経路は**置換でなく追加**（`test_urls.insert(0, ...)`）。

- `src/core/agents/swarm/injection/smart_xss.py`（+48/-1、5箇所）:
  - `__init__`（L192）: `self._best_dom_mutation_evidence` 追加。
  - `run_as_tool`（L853）: run 冒頭でリセット（param 間・run 間の持ち越し防止）。
  - `_validate_dom_runtime_xss`（L479-488）: target の `path`+注入済み `query` から `_replace(path="/", query="", fragment=f"{path}?{query_encoded}")` でフラグメント候補を先頭挿入。製品非依存（target 自身の構造からのみ導出・特定ルート焼き込み禁止）。
  - DOM 検証ブロック（L1169-1203）: **強い証拠優先**。`dialog_observed` truthy → 従来どおり break／非観測（`dom_mutation_observed` / `event=="dom_sink_reflection"` 等の弱い証拠）→ `_best_dom_mutation_evidence` に保存して **break しない**（次の param / payload で実 dialog 発火を探し続ける）。
  - param ループ後（L1220-1228）: 全 param で dialog 非発火の場合のみ最良 mutation を採用（従来動作・`dialog_observed` は付けない＝偽陽性なし）。
- 確定バー（`payout_grade.py` / `poc_judge.md` / `task_queue.py` / `finding_validator.py` 判定ルール本体 / `sealed_reproduction_checker.py` 判定基準）は**無改変**（検出側のみ）。`playwright_validator.py` も無改変（`validate_xss` / `validate_xss_sync` を再利用）。

## Why（なぜ）

0455 の確定経路（reproduction DOM 経路＋resurrection＋poc_judge 実発火証拠可視化）は完成済みだが、2回の実走行で全 XSS finding が `dialog_observed=None`・`dom_mutation_observed=true`・`event=dom_sink_reflection` のままで、実 alert 発火 finding がゼロだった。Claude 直接検証で発火点を切り分けた結果、Juice Shop は `#/search?q=<payload>`（フラグメントルート）で実発火するが、ハンターが叩くサーバ側 `/search?q=...&name=<payload>` は非発火。真因は**ハンターがフラグメント発火点に届いていない上流の発火経路**であり、0455 の確定経路の欠陥ではない。本タスクで検出側の発火経路を是正した。

## Validation（検証・独立実施）

- **フェーズ0（診断・引用特定）**: 候補 URL 構築は `smart_xss.py:_validate_dom_runtime_xss`（L466-490）が単一所有。呼び出し元は `:1135-1166`（`_should_attempt_dom_browser_validation` → `_validate_dom_runtime_xss`）。サーバ側 target では `urlparse(target).fragment` が空のため 0454 の fragment 内 query 注入（`#/search?q=` 形式）が不発動で、`#/search?q=<payload>` が生成されないことを実コードで確認。**ユーザー追加要件**（強い証拠優先・DOM mutation のみでは param ループを打ち切らない・ループ後に最良 mutation 採用・製品非依存の一般則）を設計に反映し、承認後に実装。
- **T1/T2 ユニット**（`tests/core/agents/swarm/injection/test_smart_xss_logic.py` に 5 件追加）: フラグメント候補生成（任意ルートで `#/path?param=<payload>` を生成）・dialog 観測時のみ `dialog_observed=true`・非観測時は付加しない（偽陽性回帰）・弱い証拠では break しない（mutation のみ→継続、最終 param 後に採用）。**11 passed**（既存6+新規5）。
- **回帰**: `tests/core/agents/swarm/injection/` **586 passed**。既知 HEAD 失敗（`test_validate_xss_success` / `test_pool_exhaustion_handling`）は実ブラウザ・プール依存の既存失敗で本変更由来の新規失敗ゼロ。
- **製品非依存**: `scripts/check_vdp_product_independence.py` **verdict=pass**・total_token_hits=0（6チェック全て ok、denylist 14 token、changed 6 files、closure 31 files）。
- **T3 実走行**（Caido 8081・`SHIGOKU_T3_HYBRID_ENABLED=1`・Juice Shop 3000・`--mode vulntest`・GET-only・diagnostics 有効）:
  - 正本: `workspace/projects/localhost:3000/sessions/session_20260821_232237.json` / `reports/haddix_report_20260821_232239.md`。整合チェッカ **consistent / rerun_required=false**。
  - **`dialog_observed=true` の browser_execution を 24 件観測**（全てフラグメント形式 `http://localhost:3000/#/search?q=%3Cimg...%3E` 等・`event=dom_runtime_execution`・実 dialog `alert message=1`）。
  - finding 実体（session 直読）: `851fb54fd94b` ほか XSS in parameter 'q' — `dialog_observed=True`・`test_url=http://localhost:3000/#/search?q=<img src=x onerror=alert(1)>`・`hybrid_final_state=confirmed`・`response_status=200`。
  - **0455 経路で confirmed=3**（ledger: `851fb54fd94b` / `49a880b3fa9a` / `356becc69a9a` = XSS confirmed）。funnel: F5=3 / F6=3 reached。
  - **REAL target 到達確認**（lessons 2026-08 スタブ握り潰しチェック）: Caido 8081 経由 `/api/Challenges/` が実データ（`{"status":"success","data":[...]}`）を返すことを直接 curl で確認。スタブ `caido-probe-stub` の canned 文字列ではない。
- バー diff: `payout_grade.py` / `task_queue.py` / `poc_judge.md` = `git diff --quiet HEAD` exit0。`finding_validator.py` は 0455 の `_build_user_payload` 追加のみ（+19行・判定ルール 200-233 無改変・本タスク未変更）。`sealed_reproduction_checker.py` は 0455 作業ツリーの変更（本タスク未変更）。

## Risks / 未達（正直な開示）

- **偽陽性を作らない設計は維持**: `dialog_observed=true` は実 dialog 観測時のみ付与。DOM mutation のみの候補は従来どおり `dom_mutation_observed` のまま（0455 の reproduction gate が実再発火で `matched`/`mismatched` を判定）。非発火候補が confirmed になる経路は無い。
- フラグメント候補は「サーバ側 URL の path+query がそのまま SPA の hash ルートに対応する」という**一般則**に基づく追加候補であり、SPA ルートがサーバパスと異なる構成のアプリでは発火しない場合がある（候補として試行されるだけで、既存のサーバ側クエリ経路を阻害しない）。特定ルートの焼き込みは無し。
- 実走行で `confirmed=3` のうち 3 件とも `q` パラメータ由来（`#/search?q=`・`#/orders/history?query=test&q=`・`#/rest/products/search?q=`）。products/search 等は Juice Shop 固有エンドポイントだが、候補生成は target から構造的に導出しており焼き込みではない（`check_vdp_product_independence` pass が担保）。

## Next step

- SGK-2026-0455 は本タスクの実走行で C1（confirmed>=1）が実証された（0455 経路で confirmed=3・consistent）。0455 の正式クローズ（plan done 化・work_report 作成・ledger 遷移）は 0455 の完了契約に従い実施する。
- commit は検証後の成果物（smart_xss.py・テスト・docs）をステージングし実施、push はユーザー。

## deferred_tasks

```yaml
deferred_tasks:
  - description: SGK-2026-0455 の正式クローズ（C1 実証済み・plan done 化と work_report 作成、ledger 遷移）
    tracking_task_id: SGK-2026-0455
    tracking_doc: docs/shigoku/plans/done/2026-08-20_sgk-2026-0455_dom-xss-confirmation-routing.md
```
