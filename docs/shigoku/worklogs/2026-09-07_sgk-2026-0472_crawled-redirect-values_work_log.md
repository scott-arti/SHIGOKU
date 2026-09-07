---
task_id: SGK-2026-0472
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-07_sgk-2026-0472_open-redirect-allowlist-enum-and-chains.md
- docs/shigoku/reports/2026-09-07_sgk-2026-0472_crawled-redirect-values_work_report.md
- docs/shigoku/plans/2026-09-07_sgk-2026-0473_open-redirect-value-heuristic-param-crawl-bypass.md
- docs/shigoku/plans/done/2026-09-07_sgk-2026-0471_open-redirect-confirmation.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
created_at: '2026-09-07'
updated_at: '2026-09-07'
tags:
- shigoku
- detection
- open-redirect
- crawled-values
---

# SGK-2026-0472 作業ログ（クロール由来の正規値取得・核スライス）

## 1. 事実確認（実コードで確定・2026-09-07）

- `run_open_redirect_check`（`injection/manager.py`）はクロール済み在庫を
  `OpenRedirectSpecialist` へ渡していない。一方 XSS は `_same_origin_revisit_candidates`
  由来の値を `params["revisit_candidates"]` として渡している（この形を踏襲）。
- `_same_origin_revisit_candidates` は `current_context['url_results']` と
  `discovery_revisit_urls` から同一オリジン URL を urlparse 構造比較のみで抽出。
- エンジン `open_redirect.py` は検査対象 URL 自身のクエリ値（`original_value`）からしか
  正規値を得られない。`_normalize_tool_supplied_params` は `dict(params or {})` で全キーを
  引き継ぐため、params に足した新キーは task.params まで届く。
- `_find_redirect_params` は「パラメータ名が redirect 系 OR 値が http/https/// で始まる」で
  redirect パラメータを判定する（`to` は名前非該当・値ヒューリスティックで拾える）。

## 2. 実装（ユーザー承認スコープ「核だけ」）

- `manager.py`:
  - `REDIRECT_VALUE_NAME_HINTS`（補助・名前ヒント）+ `_crawled_redirect_values(target_url, limit=10)`
    （在庫源は url_results + discovery_revisit_urls・同一オリジンのみ・urlparse 構造比較のみ・
    名前ヒント OR 値が URL 始まりで値を収集・空文字除外・順序保持で重複排除・limit・例外時空）。
  - `run_open_redirect_check` で build_hunter_task 前に（XSS の revisit_candidates と同流儀）:
    `params["allowlisted_redirect_values"]` を加算のみ追加。既存キーは不変・在庫無しは空リスト。
- `open_redirect.py`:
  - `_execute_redirect_internal` が task.params の `allowlisted_redirect_values`（list）を読み、
    `_test_redirect_param(..., crawled_values=...)` へ渡す。
  - `_test_redirect_param` に `crawled_values` 引数を追加。
  - `_build_payloads(original_value, crawled_values=None)`: 素朴テンプレートは不変。
    original_value 非空 → 従来どおり original 優先（0471 挙動）。original_value 空のときだけ
    crawled_values の正規値（先頭最大3件）で同じ3形（`?_ok=` / `#` / path）の回避ペイロードを
    生成。どちらも無し → 素朴のみ。各試行はユニーク verify_host。発火・確定・ホスト一致は無改変。

## 3. テスト（製品非依存 fixture・example.org / evil.com 系のみ）

- `test_manager_crawled_redirect_values.py`（新規）: (a) 同一オリジン url_results /
  discovery_revisit_urls の正規値採掘、(b) 別オリジン除外、(c) 重複排除・limit、(d) 在庫空/非 http/不正
  在庫 → 空。加えて run_open_redirect_check の配線（在庫→params・在庫空→空・既存キー尊重）。
- `test_open_redirect_crawled_values.py`（新規）: engine (a) original 空＋crawled で回避ペイロード発火
  （redirect_to に正規値が部分文字列で載る）、(b) original 非空→従来優先（クロール値は試行されない）、
  (c) 両方無し→素朴のみ（許可リスト風サーバで fail-closed）。
- 既存 injection スイート非回帰: 695 passed（うち open_redirect 既存 18 passed 維持）。

## 4. 検証（実出力）

- `tests/core/agents/swarm/injection/` = 695 passed in 13.59s
- `git diff --name-only HEAD`: 本スライスの変更は manager.py / open_redirect.py と新規テスト2件のみ。
  作業ツリーの他の modified（data/vuln_roi_db.json・learnings.md・本計画書・learned_params.txt）は
  開始前から存在（本スライス非関与）。
- 凍結5ファイルは `git diff --quiet HEAD` 全て exit 0（0471 差分のまま・今回増分 0）。

## 5. Claude 独立検証（完了報告を額面で信用せず実施・2026-09-07）

- 新規16テスト独立実行 → 全緑。injection＋validation = 878 passed / 2 failed（phase_b 環境依存・0471 時と同一・無関係）。
- 凍結5ファイル `git diff --quiet HEAD` 全 exit 0・denylist ヒット0・差分精読で指示準拠と非回帰を確認。
- **完了条件5の実測的決着**: Juice Shop `/redirect?to=` の `to` は名前非該当で「値が URL のとき」だけ検出され、
  検出時点で `original_value` 非空＝0471 経路になり、空/空白/非URL値では検出自体されない。よって 0472 の
  「original 空＋クロール値」分岐は Juice Shop `to` では**構造的に発火不能**と実測確定（Juice Shop の ◎ は 0471 済み）。
  0472 の能力は認可済み許可リスト付き制御対象（名前該当パラメータ `redirect`・値空・クロール供給値
  `https://accounts.example.org/session/return`）でフル判定経路が **CONFIRMED / hybrid_confirmed** に到達することを
  Claude 独立 E2E で実証（ペイロードにクロール正規値が部分文字列で載る→302 攻撃者ホスト外部→
  payout_grade=True/external_redirect→SealedReproductionChecker GET 再送 matched）。ユーザー承認のもと完了条件5を
  この内容へ修正し 0472 を done とした。

## 6. deferred

- 名前非該当パラメータ（値ヒューリスティック検出）でのクロール由来回避 → [[sgk-2026-0473]]（active・非阻害）。
