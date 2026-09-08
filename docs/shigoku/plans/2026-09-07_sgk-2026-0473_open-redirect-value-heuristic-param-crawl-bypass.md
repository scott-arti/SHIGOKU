---
task_id: SGK-2026-0473
doc_type: plan
status: deferred
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-07_sgk-2026-0472_open-redirect-allowlist-enum-and-chains.md
- docs/shigoku/plans/done/2026-09-07_sgk-2026-0471_open-redirect-confirmation.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- open-redirect
- followup
created_at: '2026-09-07'
updated_at: '2026-09-08'
---

# SGK-2026-0473 計画 — 名前非該当リダイレクトパラメータでのクロール由来回避（値ヒューリスティック検出の拡張）

## ステータス: deferred（パーク・2026-09-08・ユーザー承認）

着手時の事実確認で、本タスクは**実利が乏しい**と判明したためパークする。理由:
- 検査スキャナは redirect エンドポイントを**クロールで見つけたURLそのまま**（クエリ値を保持）で検査する
  （`_process_single_url` に渡る `target_url` は prioritize されたクロール由来URL）。
- よって Juice Shop の `/redirect?to=<正規値>` は正規値付きで検査され **0471 経路で既に ◎**。
  `to` を「正規値なし」で検査する自然な場面は存在せず、本タスクを Juice Shop で発火させるには
  `to` に偽の値を注入する人工デモが必要になり curve-fit に当たる。
- 本タスクの価値は「redirect パラメータは見つかるが正規値が別にある」実対象向けのロバスト性のみで、
  現時点の優先度は低い。将来そうした実対象が現れたら active 化して制御対象＋実対象で実証する。

## 目的（何を・なぜ）

[[sgk-2026-0472]] で、クロール在庫から拾った正規値を使い、**リダイレクト名パラメータ**（`redirect`/`url`/
`next` 等）が空値のケースで許可リスト回避 ◎ に到達できるようになった（制御対象でフル判定経路 CONFIRMED を実証）。

だが実測で、認可対象 Juice Shop の `/redirect?to=` の `to` は `_find_redirect_params` の名前リスト非該当で、
「値が http/https/// で始まる」ときだけ検出される。すなわち `to` が検出される時点で `original_value` は必ず
非空＝0471 経路になり、空/空白/非URL値では検出自体されない。よって 0472 の「original 空＋クロール値」分岐は
**名前非該当パラメータでは構造的に発火しない**。本タスクはこのギャップを埋め、`to` のような名前非該当
パラメータでもクロール由来値で回避 ◎ に到達できるようにする。

## 事実（着手時に実コードで再確認する前提メモ・2026-09-07 実測）

- `OpenRedirectSpecialist._find_redirect_params`: 「名前が REDIRECT_PARAM_NAMES のいずれかを含む OR
  値が http/https/// で始まる」で判定。`to` は名前非該当。
- `parse_qs`（既定 keep_blank_values=False）: `?to=` 空値はキーごと落ちる。`?to=%20`（空白）は残るが
  値ヒューリスティック非該当で `to` は検出されない。
- 0472 のエンジン分岐は `original_value` が空のときだけ crawled_values を使う。名前非該当パラメータでは
  この条件に到達できない。

## 想定スコープ（詳細設計は着手時に事実確認から）

以下のいずれか／複数を実測で選別（curve-fit 回避のため単純化しすぎない）:

- **クロールで実在が観測された redirect パラメータ名の受け渡し**: recon/クロールで
  「このエンドポイントは `to` に飛び先を取る」ことが観測できている場合、そのパラメータ名を検出のヒントとして
  エンジンへ渡し、名前非該当でも検査対象に含める（`_find_redirect_params` を壊さず追加経路で）。
- **非許可値で弾かれた（例: 406/402）ときにクロール値を追加試行**: 対象 URL 自身の値が非空でも、その値での
  回避が許可リストで弾かれた場合に限り、クロール由来の正規値でも回避を試す（試行数増を抑える発火条件つき）。
- いずれも確定バー（0471 A①/A②）は無改変で流用。製品名・特定ホスト・特定パスのリテラル禁止（token 0）。

## 完了条件（案・着手時に確定）

- 名前非該当パラメータ（値ヒューリスティックでしか検出されないもの）に対し、検査対象 URL 自身に許可される
  正規値を付けなくても、クロール由来の正規値で許可リスト付き対象の open redirect を ◎ に到達させる E2E を1件
  （可能なら認可対象 Juice Shop の `/redirect?to=` で実証）。
- 確定バー無改変・製品非依存 token 0・偽陽性 fail-closed・既存検出の非回帰。

## NOT in scope

- 確定バーの改変・敷居低下。
- 許可リスト値そのものの能動「推測/総当り」。
- 追加バイパス構造の拡充・多段リダイレクト連鎖（別途）。
- オープンリダイレクト以外の種別。

## 備考

- 親能力: 検出能力マップ [[sgk-2026-0465]]。実装は DeepSeek/opencode、Claude 独立検証。
