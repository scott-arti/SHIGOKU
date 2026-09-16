---
task_id: SGK-2026-0506
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/reports/2026-09-16_sgk-2026-0506_blind-sqli-autonomous-wiring_work_report.md
- docs/shigoku/worklogs/2026-09-16_sgk-2026-0506_blind-sqli-autonomous-wiring_work_log.md
- docs/shigoku/plans/done/2026-09-16_sgk-2026-0504_autonomous-detection-wiring.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- autonomous-integration
- blind-sqli
created_at: '2026-09-16'
updated_at: '2026-09-17'
---

# SGK-2026-0506 計画 — blind_sqli を自律走行へ配線（URL 駆動の汎用自己適応・非カーブフィット）

## 背景・事実（コードで実測）

SGK-2026-0504 で配線土台（`hunter_registry.py`）を整備し pilot=nosql を自走化した。次の1本として
`smart_blind_sqli`（boolean ブラインド SQLi・◎/SGK-2026-0502）を自走へ載せる。

事実確認で、`SmartBlindSQLiHunter` の中核は**汎用で健全**（非カーブフィット）と確認した:
- 真偽オラクルは実応答から特徴行を**自己導出**（`_derive_signature`・`<title>`/自然文を優先採点。
  製品固有文字列のハードコードなし）。
- 恒真 `1=1` / 恒偽 `1=2` の差分が判別不能なら fail-close（`_ORACLE_MAX_RATIO`）。
- 確定は**実データ抽出**が成立して初めて（抽出不能なら fail-close）。

**唯一の自走ギャップ**は入力適応: `_build_url`/`_probe` が `blind_sqli_mode`（既定 `path`）・
`blind_sqli_param`（既定 `id`）・`blind_sqli_base_value`（既定 `1`）を task ヒント頼みで解決するため、
**ヒントの無い任意のクエリパラメータ対象を自走で扱えない**（既定の path/id は SKF ラボ形状に寄っている）。

## カーブフィッティング回避（本タスクの絶対条件）

- ラボ固有のヒント（特定 param 名・mode・成功印・DB 種別）を**与えない／ハードコードしない**。
- 自己適応は**対象 URL と実応答からのみ**導出する（発見される param、その現在値、自己校正オラクル）。
- 真偽オラクルが自己校正できない、または実データ抽出ができない対象は**潔く fail-close**（偽◎を作らない）。
- 完了契約に「特定ラボで確定する」ことを含めない（それ自体がカーブフィット）。実対象での確定は
  target 依存の自走E2Eとして deferred。

## 対象（完了契約）

1. `smart_blind_sqli` に **URL 駆動の自己適応** `_effective_target(task)` を追加し、`_build_url`/`_probe` で使う:
   - `blind_sqli_mode` が明示されていれば従来通り（後方互換）。
   - 明示が無く対象 URL にクエリがある → `mode=query`・`param=先頭クエリ param`・
     `base_value=その param の現在値`（無ければ `1`）を URL から導出。
   - クエリが無ければ従来の `path`/`id`/`1`（挙動不変）。
2. `hunter_registry.NEW_HUNTER_SPECS` に `blind_sqli` を追加（key=`blind_sqli`）。
3. `unknown_hypotheses` に `blind_sqli` 仮説を追加（sqli 面かつ**クエリ param が存在**するときに選択。
   error-based `sqli` と併走＝blind が拾う差分を追加カバー）。
4. 単体テスト（登録→routing→汎用 dispatch 到達／URL 駆動自己適応／後方互換／fail-close）。

## 実装方針（最小差分・追加中心・非カーブフィット）

- `_effective_target` は純粋な URL 解析＋params フォールバックのみ（ネットワーク不要・ラボ固有ゼロ）。
- `_build_url` と `_probe` の `mode/param/base_value` 解決を `_effective_target` に一本化（重複除去）。
- `build_blind_sqli_url`/`build_blind_sqli_value`（封印再現と共有の module 関数）は無変更。
- 確定バー（凍結 `payout_grade`/`sealed_reproduction_checker`）は無変更。
- 既存 `blind_sqli` テスト（明示 `blind_sqli_mode=path`）は挙動不変。

## 完了条件

- CB-1: `blind_sqli` が `hunter_registry` 経由で登録され、sqli×クエリ面で routing 選択→汎用
  `_run_registered_hunter` で起動されることをテストで実証。
- CB-2: URL `…?id=1`（明示 params 無し）に対し `_effective_target`/`_build_url` が **query モードで
  先頭 param `id` に base_value `1` を注入**する URL を構築することをテストで実証（ラボ固有ヒント不使用）。
- CB-3: 後方互換 — クエリ無し URL＋params 無し → `path`/`id`/`1`（不変）、明示 `blind_sqli_mode=path`
  → 従来通り（既存テスト green）。
- CB-4: injection スイート回帰なし（既存の pre-existing 失敗 `test_t3_hybrid_wiring::...` を除く）。
- CB-5: 能力マップ更新＋`sync`→`validate` 0エラー。実コマンドと結果を報告。

## NOT in scope（deferred・honest boundary／非カーブフィット）

- 実対象での自走E2E◎認証（target 依存）。
- 文字列コンテキスト（quote 推定）・複数 DB 抽出（sqlite 以外の version 関数）への一般化＝
  現状は数値文脈・sqlite 抽出既定で、非該当は fail-close（偽◎を出さない honest boundary）。
- 残り13ハンターの配線・第2 dispatch(`vuln_type`)・OOB 受信器統合。

## 参考にしたルール

- `CLAUDE.md` §11〜§19、`rules/codingrules.md`・`rules/python-tests.md`・`rules/lessons.md`
- メモリ [[no-capability-minimization]]（カーブフィット禁止・真の実力に作り込む）、
  [[detection-capability-wiring-map]]、[[current-phase-autonomous-integration]]
