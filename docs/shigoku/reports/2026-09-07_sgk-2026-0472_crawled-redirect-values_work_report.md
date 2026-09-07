---
task_id: SGK-2026-0472
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-07_sgk-2026-0472_open-redirect-allowlist-enum-and-chains.md
- docs/shigoku/worklogs/2026-09-07_sgk-2026-0472_crawled-redirect-values_work_log.md
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

# SGK-2026-0472 作業報告 — クロール由来の正規値取得（核スライス・完了 / Claude 独立検証済み）

## 何をしたか / なぜ

SGK-2026-0471 は「検査対象 URL 自身が正規の飛び先値を持っている」前提で許可リスト回避を実証した。
本スライスは 0472 計画書の「確定した範囲（核だけ）」= **対象 URL 自身に正規値が無くても、クロールで
既に見つかっている「アプリ自身がその redirect パラメータで実際に使う正規値」を拾って回避ペイロードの
部分文字列に流用できる配線** を実装した。0471 の確定バー（A①/A②）と回避ペイロード形は流用・無改変。

## 事実（実コードで確定）

- `run_open_redirect_check` はクロール済み在庫を OpenRedirectSpecialist へ渡していない
  （XSS は `_same_origin_revisit_candidates` 由来の `revisit_candidates` を渡している）。
- エンジンは検査対象 URL 自身のクエリ値（`original_value`）からしか正規値を得られない。
- `_find_redirect_params` は「名前が redirect 系 OR 値が http/https/// で始まる」で判定。
- `_normalize_tool_supplied_params` は `dict(params or {})` で全キーを引き継ぐ（新キーは task.params まで届く）。

## 実装（変更は非凍結2ファイルのみ）

- **`src/core/agents/swarm/injection/manager.py`**
  - `_crawled_redirect_values(target_url, limit=10)`: 在庫源は `_same_origin_revisit_candidates` と同じ
    （`current_context['url_results']` 各 entry の `url` + `discovery_revisit_urls`）。urlparse 構造比較で
    同一オリジンのみ。クエリ（parse_qs）を走査し「名前ヒント（補助）OR 値が http(s)://・//・/ で始まる」
    のパラメータ値（=アプリの実際の飛び先）を収集。空文字除外・順序保持で重複排除・limit 件・例外時空。
    製品名・特定ホスト・特定パスのリテラル不使用。
  - `run_open_redirect_check`: build_hunter_task の直前に（XSS の revisit_candidates と同流儀・加算のみ）:
    `params = dict(params or {})` → `allowlisted_redirect_values` が未指定なら `_crawled_redirect_values(url)`
    を設定。既存キーは不変・在庫無しは空リスト（既存挙動不変）・共通経路は無改変。
- **`src/core/agents/swarm/injection/open_redirect.py`**
  - `_execute_redirect_internal`: task.params の `allowlisted_redirect_values`（list・文字列のみ）を読み、
    `_test_redirect_param(..., crawled_values=...)` へ伝搬。
  - `_test_redirect_param(..., crawled_values=None)`: `original_value` は従来どおり対象 URL 自身から取得。
    `_build_payloads(original_value, crawled_values)` を呼ぶ。
  - `_build_payloads(original_value, crawled_values=None)`: 素朴テンプレート（既存順）は不変。
    original_value 非空 → 従来どおり original で回避3形を生成（0471 挙動・優先）。original_value 空のとき
    だけ crawled_values の正規値（先頭最大3件）で同一3形（`https://<vh>/?_ok=<legit>` / `/#<legit>` /
    `/<legit>`）を生成。どちらも無し → 素朴のみ（0471 不変）。各試行はユニーク verify_host と対。
  発火判定・確定（Playwright / フォールバックのホスト一致 `_request_host_is`）・result/impact/
  reproduction_steps/injected_host は一切無改変。

## 検証（実出力）

- 新規テスト（製品非依存・example.org/evil.com 系のみ）:
  - manager: (a) 同一オリジン在庫の正規値採掘（url_results + discovery_revisit_urls・`to` は値ヒューリ
    スティックで採掘）、(b) 別オリジン除外、(c) 重複排除・limit、(d) 在庫空/非 http/不正在庫 → 空。
    配線: run_open_redirect_check が在庫を params へ・在庫空は空リスト・明示既存キーは尊重。
  - engine: (a) original 空＋crawled → 回避ペイロード発火（redirect_to に正規値が部分文字列で載り
    injected_host とホスト一致）、(b) original 非空 → 従来優先（クロール値は試行されない＝回帰禁止）、
    (c) 両方無し → 素朴のみ（許可リスト風サーバで fail-closed）。
  - `PYTHONPYCACHEPREFIX=/tmp/sgk0472_pycache .venv/bin/python -m pytest -q tests/core/agents/swarm/injection/`
    = **695 passed in 13.59s**（既存 open_redirect 0471 テスト 18 passed を含む非回帰）。
- 差分スコープ: `git diff --name-only HEAD` で本スライスの変更は manager.py / open_redirect.py と
  新規テスト2件のみ（作業ツリーの他 modified は開始前から存在・本スライス非関与）。
- 凍結5ファイル（payout_grade.py / sealed_reproduction_checker.py / poc_judge.md / task_queue.py /
  finding_validator.py）: `git diff --quiet HEAD` 全て exit 0 = 0471 差分のまま・今回の増分 0。
- 製品非依存 token 0（コード/コメント/テストに juice/dvwa 等のリテラルなし・追加行スキャン済み）。

## Claude 独立検証（額面の完了報告を信用せず実施・2026-09-07）

- 新規テスト16件を独立実行 → 全緑。`tests/core/agents/swarm/injection/ tests/core/validation/` = **878 passed / 2 failed**。
  2 failed は `test_phase_b_readiness.py`（`workspace/projects/juice_shop_demo/...` 成果物の存在チェック＝環境依存・
  本変更は workspace 配下に不関与）。0471 時と同一の既存失敗・無関係。
- 凍結5ファイル（payout_grade.py / sealed_reproduction_checker.py / poc_judge.md / task_queue.py /
  finding_validator.py）: `git diff --quiet HEAD` 全 exit 0（無改変）を独立確認。
- 製品非依存 token 0: denylist 照合で変更コード・テストにヒット 0 を独立確認。
- 差分精読: manager `_crawled_redirect_values`（同一オリジン在庫採掘・例外は型限定・重複排除・上限）と
  engine `_build_payloads`（original 非空→0471 優先／空のときだけ crawled_values 先頭3件／ホスト一致確定不変）が
  指示どおりで、素朴経路・0471 経路の非回帰も確認。

## 完了条件の充足（完了契約・ユーザー承認で条件5を修正・2026-09-07）

- 条件1〜4,6: PASS（上記独立検証）。
- **条件5（許可リスト付き対象でのクロール由来値 ◎）: PASS（修正後）**。当初想定の Juice Shop `/redirect?to=` は
  `to` が名前非該当で「値が URL のとき」だけ検出される＝検出時点で `original_value` 非空＝0471 経路になり、
  空/空白/非URL値では検出自体されないため、0472 の「original 空＋クロール値」分岐は**構造的に発火不能**と実測確定。
  Juice Shop の open redirect ◎ は 0471 で達成済み。0472 の能力は**認可済み許可リスト付き制御対象
  （リダイレクト名パラメータ `redirect`・値空・クロール供給値 `https://accounts.example.org/session/return`）で
  フル判定経路が `CONFIRMED / hybrid_confirmed` に到達**することを Claude が独立 E2E 実測で実証:
  ペイロードにクロール供給の正規値が部分文字列で載り→302 で攻撃者ホスト（shigoku-verify-*.evil.com・外部）→
  `payout_grade=True / external_redirect`→実 SealedReproductionChecker GET 再送 `matched`→CONFIRMED。
- `in_scope_blocker=0`。追跡可能な `deferred_followup`（下記）を残して 0472 を done とする。

## deferred_tasks

```yaml
deferred_tasks:
  - title: 名前非該当リダイレクトパラメータ（値ヒューリスティック検出）でのクロール由来回避
    reason: Juice Shop の `to` 等は名前リスト非該当で値が URL のときだけ検出され、0472 の original 空分岐が構造的に発火しない。名前ヒント受け渡し／非許可値で弾かれた際のクロール値追加試行など検出拡張が必要。
    blocking: false
    tracking_task_id: SGK-2026-0473
```

## 参考にしたルールファイル

- rules/lessons.md / rules/codingrules.md / rules/python-tests.md / rules/task-ledger.md /
  rules/shigoku-docs.md（AGENTS.md §17 動的ロード規律に従いロードして適用）
