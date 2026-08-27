---
task_id: SGK-2026-0459
doc_type: work_report
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/2026-08-22_sgk-2026-0459_active-save-sink-discovery.md
- docs/shigoku/worklogs/2026-08-26_sgk-2026-0459_active-save-sink-discovery_work_log.md
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0458_stored-xss-firing-path.md
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0457_stored-xss-confirmation.md
title: 能動的な保存sink発見（前半4手・安全境界・dispatch結線）実装フェーズ 作業完了報告
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
target: src/tools/custom/playwright_recon.py,src/core/config/settings.py,src/core/agents/swarm/injection/manager.py,src/core/agents/swarm/injection/smart_xss.py,src/core/agents/swarm/discovery/manager.py,src/core/engine/master_conductor.py,src/recon/pipeline.py,src/tools/browser/playwright_validator.py,tests/unit/tools/test_playwright_recon_active_save.py,tests/core/agents/swarm/injection/test_save_endpoint_dispatch.py
---

# SGK-2026-0459 作業完了報告 — 能動的な保存 sink 発見（前半・安全境界・結線）実装フェーズ

## What（何をしたか）

フェーズ0（診断）承認後の **実装フェーズ** を実施した。範囲は指示の通り「前半（到達・書き込み）・安全境界・dispatch 結線・0458 verb 拡張」で、**実走行の検問A(T-reach)→T4 は Claude が実施する前提**。DeepSeek はユニット（T1/T2/T3/T5）までを通し、引き渡し状態にした。判断は全て振る舞いと位置関係のみ（特定製品/selector/route の焼き込みなし）。

- **前半4手（能動保存sink発見）**: `src/tools/custom/playwright_recon.py` を拡張（新規ファイルなし）。
  - 手(a) 可視入力面の棚卸し: `textarea`／テキスト系 `input`／`[contenteditable]` を列挙し、一意 `data-shigoku-surface-id` でタグ付け。
  - 手(b) 隠れた入力面を“出す”探索: クリック可能要素（`a[href]`/`button`/`[role=button]`/`[role=tab]`/`[role=menuitem]`/`input[type=submit]`/`[aria-haspopup]`）をスコア順に1つずつ操作し、**操作前後の入力面集合を差分比較**して新規入力面/ダイアログ出現を検知（＝到達合図）。出なければ Escape/go_back で復元。クリック数・深さ(1〜2)・制限時間の上限を課し、少クリックで出た面を優先。
  - 手(c) 一意マーカー投入と送信: 面ごとに `sgk{secrets.token_hex(4)}` の一意マーカーを投入し、構造的に紐づく送信手段（同一 `form` の requestSubmit／包含近接ボタン／Enter）で送信。ボタンは名前でなく包含・近接（祖先コンテナ内の `button`/`input[type=submit]`/`[role=button]`）で選ぶ。
  - 手(d) 書き込み通信の捕捉: `on_request` で非GET/HEAD の `write_requests`（url・method・post_data・content_type）を捕捉し、本文に投入マーカーが含まれるものを `save_endpoints=[{url,method,fields,marker,source_page,revisit_urls}]` として確定（同一文字列一致のみ）。`methods_by_url` は単一上書きから **method別セット保持**（`{url:{GET,PUT}}`）へ拡張。既存キー（urls/endpoints/js_files/errors）は不変で `save_endpoints` を追加。
  - **未到達は未発見の規律**: 手(b)で入力面が出ない／手(d)で書き込み通信が観測できない場合は `save_endpoints` を空とし、finding/dialog_observed を一切付けない。
- **安全境界（ブラウザ経路の GET-only 穴を塞ぐ・最優先）**: `crawl` の context/page 生成直後に `page.route("**/*", _make_route_guard(...))` を設定。**GET/HEAD 常時許可・DELETE 常時 abort**、その他非GETは「能動投稿モードON（= get_only False かつ許可ホスト一致 かつ機微パスでない）」のときのみ continue、それ以外は abort（fail-closed）。許可ホストは settings の明示リスト（既定 127.0.0.1/localhost のみ・製品非依存）。機微パス（/admin /users /profile 等）・危険動詞（DELETE/PATCH）は能動投稿スキップ。`PlaywrightValidator` 側にも `_maybe_install_get_only_route` を注入（既定は settings に従い、対象外時は無効）。
- **dispatch 結線（発見→XSS stored・path名/製品名非依存）**:
  - `discovery/manager.py`: `run_playwright_recon` が crawl へ `get_only`/`active_post` を透過し、summary に `save_endpoints_found` を追加（呼び出し・受け渡しに限定）。
  - `injection/manager.py`: `_context` の `save_endpoints` を消費（`current_context["save_endpoints"]`・`discovery_revisit_urls`）。per-URL ループで保存EP と構造一致（urlparse の scheme+netloc+path・query 無視）かつ非GET verb なら **stored dispatch キー**（`vuln_type="xss"`・`resolved_method`=EP verb・`candidate_params`=EP fields・`save_endpoint` メタ供給）。`_same_origin_revisit_candidates` は discovery 在庫を同一オリジン構造比較で合流（比較ロジック不変）。
  - `smart_xss.py`: **起動ゲートの verb を `method=="POST"` → `("POST","PUT","PATCH")` へ拡張（追加のみ・検証本体不変）**。`save_endpoint` を META_KEYS へ追加（payload 化防止）。
  - 実走行スレッディング: `recon/pipeline.py` step3b が crawl 結果の `save_endpoints` を sidecar（`*_save_endpoints.json`）へ永続化し、`master_conductor.py` が防御的に読み込んで `task_params["_context"]["save_endpoints"]` へ供給（存在時のみ・additive）。
- **退行防止・オプトイン**: 能動発見は `SHIGOKU_RECON_ACTIVE_POST_ENABLED`（settings `recon_active_post_enabled`・既定 off）でオプトイン。既定挙動（反射型/DOM型・他vuln recon/dispatch・recon 件数・既存 finding）は不変。

## Why（なぜ）

0458 実走行で `variant="stored"` finding が 0 件だった真因は「保存 API は実際に投稿した瞬間にしか XHR に現れない」ことであり、受け身の傍受では発見不能。本タスクは「入力面を探して操作し、一意マーカーを書き込み、非GET書き込みと項目名を捕捉する」能動発見を前半として実装し、発見メタ（保存EP・項目名・再訪候補）を挙動ベースで 0458 起動ゲート（verb 拡張後）へ渡す配線を追加する。フェーズ0 で実証された「ブラウザ経路の書き込みが素通し」の穴（GET-only 強制が `AsyncNetworkClient` 内のみ）は本タスクの安全境界で塞ぐ。

## Validation（検証・DeepSeek 実施ユニット）

- **T1（C1a・能動発見）**: `tests/unit/tools/test_playwright_recon_active_save.py`（新規・10 passed）。可視面→一意マーカー→非GET書き込み+項目名捕捉、クリック前後差分で隠れ面出現→面ごと異なるマーカー→2 EP、**到達不可は save_endpoints 空（finding を捏造しない）**回帰。
- **T2（C1b/偽陽性）**: `tests/core/agents/swarm/injection/test_save_endpoint_dispatch.py`（新規・11 passed）。`_match_save_endpoint`（構造一致・query 許容）、`_collect_discovery_revisit_urls`（同一オリジン・bounded・dedup）、`_same_origin_revisit_candidates`（discovery 在庫の合流）、**PUT/PATCH ゲートで stored 発火時のみ `variant="stored"`/`dialog_observed=true`**、GET/候補なしはゲート不発（回帰）、**複数マーカー混在で他マーカーを自マーカーと誤紐付けしない（同一文字列一致のみ）**。
- **T3（C6・安全境界）**: 同ファイル群で `_route_guard_decision` マトリクス（GET/HEAD 常時許可・非許可ホスト abort・get_only abort・機微パス abort・DELETE 常時 abort・POST/PUT/PATCH 許可）＋ハンドラ実装、許可ホスト限定・保存sinkあたり1回・件数上限・危険動詞除外をユニット固定。
- **T5（C2・一般化）**: 2つ目の stub（127.0.0.1:9080・別面名 subject/body・別 route /v2/comments）でも能動発見が機能（Juice Shop 特化でない構造担保）。
- **既存回帰**: `test_smart_xss_stored_revisit.py`＋`test_smart_xss.py`＋`test_payout_grade.py`＝**48 passed**、`test_playwright_unit.py`＋`test_playwright_proxy_availability.py`＋`test_step3b_hybrid_url.py`＋`test_dynamic_updates.py`＝**40 passed**、`test_playwright_recon.py`＋新規2本＝**39 passed**。
- **製品非依存（C2）**: `scripts/check_vdp_product_independence.py`（manifest+denylist+changed-files 8件）**verdict=pass / total_token_hits=0**。
- **network_client GET-only 経路（C6 の片側）**: `tests/unit/infra/test_network_client.py -k GetOnly` **7 passed**。同ファイルの他6件（proxy/retry 系・`policy_unavailable` fail-closed）は **pristine HEAD（git worktree）でも同一の6件失敗**＝事前既存（本変更起因でない）。

## Risks / 未達（正直な開示）

- **検問A(T-reach)・T4 は未実施**（Claude 担当の実走行）。本報告はユニットと結線の「機能する状態」までの引き渡しであり、confirmed=1 はまだ未達。判定は指示の通り、届く証拠（保存EP＋項目名の捕捉）が出てから発火・確定に進む。
- 探索はブラウザ操作に依存するため不安定要因あり（ダイアログ表示のタイミング・SPA レンダリング・クリック対象の動的変化）。上限（クリック数・深さ・時間・件数）で保護済み。
- 反映遅延（モデレーション等）がある練習台ではマーカーが即時反射せず「未発見」扱いになり得る（偽陰性と「保留（未確定）」の区別は T4 実走行時に Claude が session で確認）。
- 認証依存 sink はスコープ外（計画書 NOT in scope）。未認証で保存・表示が成立する練習台を対象とする。
- `validate_frontend_idor` の既存 `page.route` とは Playwright の LIFO 順序で `get_only` ガードが実質効かない可能性（既存ハンドラ改変禁止のため・機微・非回帰）。

## Next step（Claude 向け）

実走行前提は `docs/shigoku/plans/2026-08-22_sgk-2026-0459_active-save-sink-discovery.md` および work_log 参照。
1. ユニット実物照合 → 2. **検問A(T-reach)**: Caido 8081・Juice Shop・`SHIGOKU_RECON_ACTIVE_POST_ENABLED=1`（GET_ONLY 無し）で「一意マーカー入りの非GET書き込みが発生し保存EP＋項目名を捕捉」を session で確認 → 通らなければ前半のみ差し戻し → 3. T4 で `variant="stored"`/`dialog_observed=true` → 0457 経由 confirmed=1 → 4. ledger 遷移（done）。

## 実走行・独立検証記録（2026-08-27〜28・Claude・DeepSeek報告は額面で信用しない）

DeepSeek 実装を実物照合し、実走行と隔離ハーネスで検問A→T4を検証した。過程で複数の真因を引用特定し、修正を反映（各修正は独立検証済み・バー無改変・製品非依存 token0）。

- **根本バグ（最重要・実ブラウザで確定）**: `_try_surface` の記入欄 fill が `page.evaluate(js, sid, marker)` と**2引数**を渡しており、Playwright(Python) の evaluate は1引数のみのため**実行時に常に TypeError**（`except` で握り潰し）。結果、**印が一度も入力されず→書き込み0→保存sink未捕捉**。stub テストは `evaluate` を `*args` で受けるため見逃していた（stub偏重の危険の実例）。修正: `([sid, marker])` の単一引数化＋stub整合＋**実ブラウザ回帰テスト追加**。直接診断で `POST /comment` にマーカー付き書き込み→`save_endpoints` 捕捉を確認。
- **単一URL配線**: 動的偵察（能動発見）が `step3b_hybrid_url_discovery` の `if not live_subs: return` に阻まれ、単一ローカル対象では丸ごとスキップされていた。修正: 単一URL対象では種URL自身（scheme+port 保持）を crawl 種にする（追加のみ・多サブドメイン経路不変）。実走行で `Saved 1 save_endpoints sidecar` を確認（発見側がパイプラインで保存sinkを捕捉）。
- **適応待ち**: クリック後の固定250msでは SPA ダイアログの入力面出現前に見切っていた。修正: `_wait_for_reveal`（`_inventory_surfaces` によるタグ付けポーリングで新面/汎用オーバーレイ出現まで上限つき待機）。汎用ARIA(role=dialog/aria-modal)のみ・製品/Material焼き込みなし。
- **Caido 経路配線**: pipeline の `PlaywrightCrawler()` に proxy 未注入だった箇所を `settings.get_proxy_url()` 注入（他ツールと同一の既存パターン・1行）。ブラウザ書き込みを Caido 経由に是正。

**確定側の実証（成功・目標の核心）**: 隔離ハーネス（`_attempt_stored_revisit_validation` を練習台に直接駆動）で、印を保存EPへ書く→別ページ(GET /)で反射発見→本物ペイロード再保存→**実ブラウザで alert 発火→`variant="stored"`/`dialog_observed=true`/`event=stored_revisit_browser_execution`** を **Caido経由・直結の双方で繰り返し再現**。基準緩和・カーブフィッティングなし。これにより **SHIGOKU の保存型XSS確定能力そのものが本物のブラウザ証拠つきで動く**ことを実証した。

**未達（正直な開示）**: **C1c（フル製品パイプラインでの単一走行 confirmed=1・整合 consistent）は未達**。ブロッカーは SHIGOKU の保存型検出ロジックではなく、**プロジェクト横断の永続状態汚染**（KG無効化後も、共有ワークスペース/スプール/台帳経由で過去の別ターゲット（Juice Shop `localhost:3000`・旧ポート `5001`）のURL/タスクが現在の走行へ注入され、走行が肥大・中断）。フル走行は毎回この汚染で完走に至らず。→ SGK-2026-0460 で隔離を先行する。

**副次の記録**: 練習台フィクスチャの設計で、POST が表示ページへ 303 リダイレクトすると書き込み応答に印が写り込み、stored 判定が「反射型」と誤認する（`_attempt_stored_revisit_validation` の POST応答反射チェックが True 化）。正しい保存型の形（書き込み応答はフォームのみ・印は GET / のみ反射）に修正して解消。これは的の設計であり SHIGOKU 本体のバグではない。

## deferred_tasks

```yaml
deferred_tasks:
  - description: フル製品パイプラインでの単一走行 confirmed=1（variant=stored）・整合 consistent の実証。前提として横断汚染の隔離(SGK-2026-0460)が必要。能動発見(前半4手)・安全境界・結線・確定側(stored発火)は個別に実証済み（根本バグ修正後）。
    tracking_task_id: SGK-2026-0459
    tracking_doc: docs/shigoku/plans/2026-08-22_sgk-2026-0459_active-save-sink-discovery.md
  - description: プロジェクト横断の永続状態汚染の隔離。KG(Neo4j)無効化のみでは不十分で、共有ワークスペース/スプール/run_ledger/adjacency 等の永続ストアが過去の別ターゲットURL・タスクを現在走行へ注入し、単一ターゲットのクリーンな走行と confirmed=1 判定を妨げる。汚染源の特定と、走行単位の状態隔離（クリーンなワークスペース等）を実装する。
    tracking_task_id: SGK-2026-0460
    tracking_doc: docs/shigoku/plans/2026-08-28_sgk-2026-0460_cross-target-state-isolation.md
```

## 参考ルール

rules/lessons.md（一ファイル断定回避・worktree 回帰比較・snip 置換注意）、rules/codingrules.md（局所変更・エラーハンドリング・シークレット非露出）、rules/task-ledger.md、rules/shigoku-docs.md、rules/python-tests.md、CLAUDE.md §16（外部ツール配置＝既存拡張）/§17/§19。
