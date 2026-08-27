---
task_id: SGK-2026-0459
doc_type: work_log
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/2026-08-22_sgk-2026-0459_active-save-sink-discovery.md
- docs/shigoku/reports/2026-08-26_sgk-2026-0459_active-save-sink-discovery_work_report.md
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0458_stored-xss-firing-path.md
title: 能動的な保存sink発見（前半4手・安全境界・dispatch結線）実装フェーズ 作業ログ
created_at: '2026-08-26'
updated_at: '2026-08-28'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- discovery
- xss
- stored
- recon
- browser
---

# SGK-2026-0459 作業ログ（実装フェーズ・前半・安全境界・結線）

## 2026-08-26

### フェーズ0（診断）は承認済み・今回は実装

- フェーズ0 診断レポート（A–G）と Claude 独立検証を踏まえ、指示の固定順序どおり **DeepSeek はユニット（T1/T2/T3/T5）まで**、実走行（検問A(T-reach)→T4）は Claude 担当で実施。

### 実装1: 前半（到達・書き込み）を playwright_recon.py に拡張（新規ファイルなし）

- 手(a) `_inventory_surfaces`（textarea/テキスト系 input/[contenteditable] を列挙・`data-shigoku-surface-id` でタグ付け・hidden/disabled 除外）。
- 手(b) `_list_click_candidates`＋`_click_and_diff`（クリック候補をスコア順に1つずつ操作→操作前後の surface sid 集合を差分→新規出現を検知。出なければ Escape/go_back で復元。上限: クリック数・深さ・時間）。
- 手(c) `_try_surface`/`_submit_surface`（面ごとに一意 `sgk{secrets.token_hex(4)}` を投入し、form requestSubmit→包含近接ボタン→Enter の順で送信・submit_attempts 上限・同一マーカー再送スキップ）。
- 手(d) `on_request` 拡張（非GET の `write_requests` 捕捉）＋`_derive_save_endpoints`（本文にマーカーが含まれる書き込みを保存EPとして確定・`save_endpoints` 新キー追加・`methods_by_url` を method別セット保持へ拡張）。
- **未到達は未発見**: 保存EPが確定しなければ finding/dialog_observed は付けない。
- 焼き込み禁止: セレクタは要素種別のみ・route/製品名/ホスト名リテラルなし（許可ホストは settings 既定の 127.0.0.1/localhost）。

### 実装2: 安全境界（ブラウザ経路の GET-only 穴を塞ぐ・最優先）

- `_route_guard_decision`/`_make_route_guard`（crawl の page.route に設定）。GET/HEAD 常時許可・DELETE 常時 abort・その他非GETは能動投稿モードON（get_only False かつ許可ホスト かつ機微パスでない）のみ許可。get_only は settings.sealed_run_get_only から解決。
- `PlaywrightValidator` 側にも `_maybe_install_get_only_route` を注入（既定 off・対象外時は無効）。form 送信系メソッドは get_only 有効時は送信スキップ。
- settings へ additive 追加: `recon_active_post_enabled` / `active_post_allowed_hosts` / `active_post_max_writes` / `active_post_max_writes_per_page` / `active_post_max_reveal_clicks` / `active_post_reveal_depth` / `active_post_reveal_time_budget_ms` / `active_post_submit_attempts` / `active_post_skip_path_tokens`（全て既定 off/練習台のみ）。

### 実装3: dispatch 結線（発見→XSS stored・path名/製品名非依存）

- `discovery/manager.py`: crawl へ `get_only`/`active_post` を透過、summary に `save_endpoints_found` 追加（呼び出し・受け渡しに限定）。
- `injection/manager.py`: `save_endpoints` を `_context` から消費（`current_context["save_endpoints"]`・`discovery_revisit_urls`）。per-URL で `_match_save_endpoint`（urlparse 構造一致）→ 非GET verb なら stored dispatch キー（`vuln_type="xss"`・`resolved_method`=EP verb・`candidate_params`=EP fields・`save_endpoint` メタ供給）。`_same_origin_revisit_candidates` は discovery 在庫を合流（比較ロジック不変）。
- `smart_xss.py`: 起動ゲート verb を `("POST","PUT","PATCH")` へ拡張（追加のみ・検証本体不変）＋`save_endpoint` を META_KEYS へ追加。
- 実走行スレッディング: `pipeline.py` step3b が `save_endpoints` を sidecar へ永続化、`master_conductor.py` `_load_run_save_endpoints` で防御的に読んで `_context["save_endpoints"]` へ供給。

### 実装4: 退行防止・オプトイン

- 能動発見は `recon_active_post_enabled`（既定 off）でオプトイン。既定挙動（反射型/DOM型・他vuln・recon件数・既存 finding）不変。

### 独立検証（DeepSeek 報告は額面で信用しない・Claude がユニット→実走行を照合）

- 実装は2つの fixer レーン（playwright_recon/settings・manager/discovery/validator/pipeline/master_conductor）へ分割委譲し、Orchestrator が**実ファイルを独立に読んで照合**（焼き込み0・route guard は fail-closed・save_endpoints 契約一致）。追加修正: ①surface/click の ID 採番を window カウンタ化（Date.now 衝突で差分検知が壊れるのを防止）②DELETE を route guard で常時 abort＋derive で POST/PUT のみ確定＋form method DELETE/PATCH は投稿スキップ③`smart_xss` META_KEYS に `save_endpoint` 追加。
- ユニット結果: 新規 T1/T3/T5=10 passed・新規 T2=11 passed・既存 stored_revisit/smart_xss/payout_grade=48 passed・validator/pipeline/dynamic_updates=40 passed・playwright_recon=3 passed・network_client -k GetOnly=7 passed。既存6件失敗（proxy/retry・policy_unavailable）は worktree(pristine HEAD) でも同一＝事前既存。
- 製品非依存: `check_vdp_product_independence.py` verdict=pass・total_token_hits=0（token0）。

### 引き渡し（Claude 向け実走行前提）

- 検問A(T-reach): Caido 8081・Juice Shop・`SHIGOKU_RECON_ACTIVE_POST_ENABLED=1`（GET_ONLY 無し・`SHIGOKU_T3_HYBRID_ENABLED=1`）で「一意マーカー入りの非GET書き込みが発生し、保存EP＋項目名を捕捉」を session で確認。許可ホストは既定で localhost/127.0.0.1 が含まれる。通らなければ前半のみ差し戻し。→ T4（発火・確定・confirmed=1）へ。

## 参考ルール

rules/lessons.md（一ファイル断定回避・worktree 回帰比較・snip 置換注意）、rules/codingrules.md（局所変更・エラーハンドリング・シークレット非露出）、rules/task-ledger.md、rules/shigoku-docs.md、rules/python-tests.md、CLAUDE.md §16/§17/§19。
