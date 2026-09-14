---
task_id: SGK-2026-0497
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0497_prototype-pollution.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0497_prototype-pollution_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0496_oob-deserialization.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- prototype-pollution
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0497 作業完了報告 — プロトタイプ汚染（サーバサイド Node.js）を実対象で本物確定（◎）

## 何をしたか / なぜ

能力マップのプロトタイプ汚染（ユーザー当初案）を ◎ 化。既存 `prototype_pollution_tester` は未配線
だったため、in-band 差分で確定する新エンジンを新設。応答に汚染が反映される差分＋一意マーカーで
確定した。

実対象（実測）：**SKF `js-prototype-pollution`**（Node/Express・`POST /message` が
`_.merge({}, req.body, {ipAddress})`＝lodash.merge の PP sink）。entrypoint の app.js は不在で実体は
index.js（`node index.js` で起動）。実測で `__proto__.admin` に一意マーカーを送ると、以降 `/create` で作る
**admin を一度も設定しない新ユーザー**の `/login` 応答（loggedin.ejs の Admin 欄）にマーカーが継承・出現
（汚染前は空）。

## 実装（新設1＋承認済み凍結2）

- **smart_prototype_pollution.py（非凍結・新規）**: `SmartPrototypePollutionHunter`。task 由来の sink
  （`__proto__.<prop>={marker}` マージ要求）／setup（新オブジェクト生成・{uniq}）／observe（反映）で駆動。
  ①control（汚染前 setup+observe→マーカー非出現）②pollute（sink 送信）③observe（別 setup+observe→マーカー
  出現）の差分で確定。`self._client` seam・marker 中心スニペット・`prototype_pollution_evidence`／`_replay`／
  差分3ステップ poc。製品固有ハードコードなし。
- **payout_grade.py（凍結・承認）**: `_MARKER_CATEGORIES["prototype_pollution"]=
  "prototype_pollution_confirmed"`＋発火分岐（sink_url／observe_url／pollute_property／marker 非空＋observe
  2xx＋marker が polluted_served_body 実在＋control_served_body 非実在が**全て揃ったときだけ**発火・fail-closed）。
- **sealed_reproduction_checker.py（凍結・承認）**: `_check_pp_replay`（新マーカーで pollute→setup→observe を
  封印スコープ内で順に再送し新オブジェクトへの再出現→matched。json sink は **Content-Type: application/json
  を明示**＝欠落すると express.json() 未解析で汚染不発だった修正込み）。

## 結果（独立検証・Claude が実測）

- **実 SKF PP ラボ**で実 `SmartPrototypePollutionHunter.execute` が差分で自走検出（prop=admin・汚染後の
  新ユーザー login にマーカー・汚染前は空・observe 200）→`payout_grade=True/prototype_pollution_confirmed`→
  **実 `SealedReproductionChecker` が新マーカーで pollute→create→login を再実行し再出現→matched→CONFIRMED**。
- **本物の poc_judge（実 LLM）で 5/5 承認**（is_real=True・has_actual_impact=True・counter=False）。審査理由は
  「一意マーカーが送信ペイロードの `__proto__.admin` 経由でのみ注入され、別リクエスト・別オブジェクト生成の
  POST /login 応答で Admin 値として出現、汚染前は不在＝Object.prototype 汚染の実測」。**完全3ゲート達成＝◎**。
- テスト: 新規19テスト（engine 差分確定・非脆弱で不確定・3ステップ poc・replay 記述子・シナリオ無しで不確定／
  payout_grade fail-closed 各否定側／sealed matched・mismatched(非脆弱)・not_run(client なし/スコープ外/記述子
  不備)）緑。非回帰: 失敗3件は本変更前でも失敗する既存（phase_b×2・t3_hybrid budget）＝**0497 起因の
  回帰ゼロ**（1312 passed）。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）exit 0。承認済凍結2は承認範囲の追加のみ。
  製品非依存 token 0・trailing whitespace 0・秘密値非露出。

## 確度の結論（正直な格付け）

- **プロトタイプ汚染（サーバサイド・privesc/認証バイパス/DoS/RCE ガジェット起点）＝実害あり**で実
  poc_judge も通り **◎（完全3ゲート）**。curve-fit なし（新マーカーは fail-closed・一意マーカー差分・
  シナリオは task 由来でエンジンに製品固有値なし）。**高度化 低(L1)**（lodash.merge sink・SKF 単一・
  クライアント側 PP・特定ガジェット連鎖は別途）。Object.prototype 汚染はグローバル状態変更だが良性
  マーカーのみ（非破壊的確認）。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の実 poc_judge を 5/5 で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（実対象到達の証明・一ファイルの挙動を仕様と
しない）、`rules/codingrules.md`（bare except 禁止・秘密非露出・境界のみ noqa・明示タイムアウト）、
メモリ [[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。

## 非阻害の観測（deferred / 別件）

- クライアント側 PP（DOM）・特定ガジェットチェーン（RCE/DoS 連鎖）・非 lodash マージ実装の網羅・
  パイプライン統合は本タスク対象外（`deferred_followup`）。json sink の Content-Type 明示は封印再現の
  必須要件（教訓として記録）。
