---
task_id: SGK-2026-0472
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-07_sgk-2026-0471_open-redirect-confirmation.md
- docs/shigoku/reports/2026-09-07_sgk-2026-0472_crawled-redirect-values_work_report.md
- docs/shigoku/worklogs/2026-09-07_sgk-2026-0472_crawled-redirect-values_work_log.md
- docs/shigoku/plans/2026-09-07_sgk-2026-0473_open-redirect-value-heuristic-param-crawl-bypass.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
created_at: '2026-09-07'
updated_at: '2026-09-08'
tags:
- shigoku
- detection
- open-redirect
- followup
---

# SGK-2026-0472 計画 — オープンリダイレクト検出の賢さ強化（許可リスト値の能動獲得・多段連鎖）

## 目的（何を・なぜ）

[[sgk-2026-0471]] で、飛び先許可リストで守られた実対象（例: Juice Shop `/redirect?to=`）に対し、
**アプリ自身がそのパラメータで使う正規値を runtime に観測できている場合**は、その正規値を部分文字列として
付す許可リスト回避ペイロードで本物確定（◎）に到達できるようになった。

本タスクはその**残り**を扱う: 正規値が未観測のケースや、より堅い許可リスト実装に対しても検出できるよう
検出の賢さを強化する。0471 の確定バー（A①/A②）はそのまま流用し、**エンジン側のペイロード獲得能力**を広げる。

## 確定した範囲（ユーザー承認・2026-09-07「核だけ＋実物◎」）

本タスクは**許可リスト値の能動獲得（クロール由来の正規値取得）という核の1機能**に絞る。
追加バイパス構造・多段連鎖は本タスクでは扱わず後続へ回す（下記 NOT in scope / deferred）。

## 事実（実物観測で確定・2026-09-07）

- **欠落配線**: `run_open_redirect_check`（`injection/manager.py`）は、クロール済み在庫を
  `OpenRedirectSpecialist` へ渡していない（XSS は `_same_origin_revisit_candidates` 由来の
  `revisit_candidates` を渡している）。エンジンは検査対象 URL 自身のクエリ値からしか
  正規値（`original_value`）を得られない（`open_redirect.py:278`）。
- **クロール在庫の実在**: クローラ（`playwright_recon.py`）は `a[href]` を urljoin＋同一オリジン
  フィルタで収集し、在庫（`current_context['url_results']` / `discovery_revisit_urls`）に入る。
- **実対象の実在確認**: 認可対象 Juice Shop のランディング DOM には、クリック不要で
  `./redirect?to=<許可された正規URL>` のアンカーが存在し、urljoin 後に同一オリジン URL
  （`/redirect?to=<正規値>`）としてクロールで拾える。正規値は `_find_redirect_params` と同じ
  「パラメータ名一致 OR 値が http/https/// で始まる」ヒューリスティックで抽出できる
  （`to` は名前非該当だが値ヒューリスティックで該当）。

## 対象（このタスクで触るファイル・いずれも非凍結）

- `src/core/agents/swarm/injection/manager.py`
  - `_same_origin_revisit_candidates` と同じ在庫源（`url_results` ＋ `discovery_revisit_urls`・
    同一オリジンのみ・urlparse 構造比較のみ）から、**redirect 系パラメータの正規値**を抽出する
    小ヘルパーを追加（名前一致 OR 値が URL で始まる、の `_find_redirect_params` と同等基準。
    製品名・特定ホスト・特定パスのリテラル禁止）。重複排除・件数上限つき。
  - `run_open_redirect_check` で、そのヘルパー結果を**加算のみ**の新パラメータ
    （例: `params["allowlisted_redirect_values"]`）として渡す。在庫が無ければ空（既存挙動不変）。
- `src/core/agents/swarm/injection/open_redirect.py`
  - `_execute_redirect_internal` / `_test_redirect_param` / `_build_payloads` が、
    `task.params` 経由のクロール由来正規値を受け取り、**検査対象 URL 自身の `original_value` が
    空のときに**、それらの値を使って許可リスト回避ペイロードを生成する（0471 の回避形
    `https://<attacker>/?_ok=<legit>` / `…/#<legit>` / `…/<legit>` を流用）。
    対象自身の値が非空なら従来どおりそれを優先（0471 挙動不変）。
  - 発火・確定のホスト一致判定（`_request_host_is`）は不変。偽陽性耐性を維持。

## 確定バー（凍結・本タスクでは無改変）

- A①`payout_grade.py` / A②`sealed_reproduction_checker.py` は **0471 のものを byte-identical で流用**
  （`external_redirect` マーカー経路をそのまま使う）。
- 残り3凍結（`poc_judge.md` / `task_queue.py` / `finding_validator.py`）も無改変。

## 完了条件（完了契約）

1. 在庫採掘: `url_results` / `discovery_revisit_urls` に redirect 系パラメータの正規値を持つ URL が
   あるとき、`run_open_redirect_check` がその正規値群をエンジンへ渡す（同一オリジンのみ・重複排除・
   上限・在庫無しは空＝既存挙動不変）。
2. エンジン流用: 検査対象 URL 自身の正規値が空でも、クロール由来の正規値から許可リスト回避ペイロードを
   生成する。対象自身に正規値があるときは従来優先（0471 挙動不変）。ホスト一致確定・偽陽性 fail-closed は不変。
3. 製品非依存 token 0（コード/コメント/テストに juice/github 等のリテラルを入れない。
   テスト fixture は example.org 系の正規値と evil.com 系の攻撃者ホストのみ）。
4. 確定バー無改変: `payout_grade.py` / `sealed_reproduction_checker.py` / `poc_judge.md` /
   `task_queue.py` / `finding_validator.py` が `git diff --quiet HEAD` exit 0。
5. **許可リスト付き対象での ◎（クロール由来値）**: 許可リスト（部分文字列チェック）で守られた対象の
   **リダイレクト名パラメータ**を、**検査対象 URL 自身には正規値を付けず**（空/空白値）、正規値は
   **クロール在庫から供給**してフル判定経路が `CONFIRMED` に到達する E2E を1件実証
   （攻撃者ホストはユニーク・外部・Location に再出現・証拠は合言葉マスク）。
   これにより 0471（対象 URL に正規値が付いている前提）との差分＝「クロール由来取得」が本物だと示す。
   - **実測で判明・完了条件5の当初想定を修正（ユーザー承認・2026-09-07）**: 当初は認可対象 Juice Shop の
     `/redirect?to=` で実証する想定だったが、Juice Shop の `to` は `_find_redirect_params` の名前リスト
     非該当で「値が http/https/// で始まる」ときだけ検出される。すなわち `to` が検出される時点で
     `original_value` は必ず非空＝0471 経路になり、空/空白/非URL値では検出自体されない（実コードで実測確定）。
     よって Juice Shop の `to` では 0472 の「original 空＋クロール値」分岐は**構造的に発火し得ない**。
     Juice Shop の open redirect ◎ は既に 0471 で達成済み。0472 の能力（クロール由来値での回避）は
     **認可済みの許可リスト付き制御対象（リダイレクト名パラメータ `redirect`・値空・クロール供給値
     `https://accounts.example.org/session/return`）で、フル判定経路（実 payout_grade フロア＋
     prize AI スタブ＋実 SealedReproductionChecker の GET 再送）が `CONFIRMED / hybrid_confirmed` に
     到達することを実証**した（Claude 独立検証・攻撃者ホスト shigoku-verify-*.evil.com・外部・
     再現 matched・製品非依存）。
   - 値ヒューリスティックでしか検出されない名前非該当パラメータ（Juice Shop の `to` 等）で 0472 経路を
     発火させる検出拡張は本タスク NOT in scope とし [[sgk-2026-0473]] で追跡する（非阻害）。

## 必須テスト

- `manager` 在庫採掘ヘルパー単体: (a) redirect 正規値を持つ同一オリジン URL を採掘、
  (b) 別オリジンは除外、(c) 重複排除・上限、(d) 在庫無し→空。
- `open_redirect` エンジン単体: (a) 対象自身の値が空＋クロール正規値あり→回避ペイロード生成、
  (b) 対象自身の値が非空→従来優先（クロール値は補助）、(c) クロール値も無い→素朴ペイロードのみ（0471 不変）。
- 統合（疑似サーバ）: クロール正規値経由の回避ペイロードで `validate_finding` が `CONFIRMED`。
- injection スイート全体（`tests/core/agents/swarm/injection/`）＋ validation 非回帰。
- 変更後 `python3 scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py` が 0 エラー。

## NOT in scope（本タスクで扱わない・後続タスクへ）

- 追加のバイパス構造（スキーム相対・二重URL・エンコード差・`@` 記法）の実測選別と拡充。
- 多段リダイレクト連鎖（allowlisted 経由でさらに攻撃者ホストへ）。
- 確定バーの改変・敷居低下。
- 許可リスト値の能動「推測/総当り」（本タスクはクロールで実在が観測された正規値の再利用に限る）。
- 値ヒューリスティックでしか検出されない名前非該当パラメータ（例: `to`）で 0472 経路を発火させる
  検出拡張 → [[sgk-2026-0473]] で追跡（非阻害）。
- オープンリダイレクト以外の種別。

## 備考

- 親能力: 検出能力マップ [[sgk-2026-0465]]。実装は DeepSeek/opencode、Claude 独立検証。
