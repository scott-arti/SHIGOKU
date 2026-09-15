---
task_id: SGK-2026-0502
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-16_sgk-2026-0502_boolean-blind-sqli_work_report.md
- docs/shigoku/worklogs/2026-09-16_sgk-2026-0502_boolean-blind-sqli_work_log.md
tags:
- shigoku
- detection
- sqli
- blind
- boolean-based
created_at: '2026-09-16'
updated_at: '2026-09-16'
---

# SGK-2026-0502 計画 — boolean ベース・ブラインド SQLi（データ抽出）

## 背景・事実（偵察で実測）

既存 `smart_sqli` は error-based（`sql_error` マーカー）＋ boolean 差分＋`sqlite_version()` 抽出だが、
真の boolean ブラインド抽出は「target に文字列 `sqli_blind` を含むときだけ time-based を強制発火」
という**ラボ名依存のヒューリスティック**（`_run_time_based_blind_precheck`）で curve-fit 気味。
SQLite は SLEEP を持たず time-based は不安定。

実対象（実測）: **SKF `sqli-blind`**（Flask・:5000・SQLite）。`/home/<pageId>` が
`SELECT pageId,title,content FROM pages WHERE pageId=<pageId>`（数値文脈・引用符なし連結）を実行し、
**行が返れば通常ページ／返らなければ 404 ページ**を返す（status は常に 200）。実測で
`1 AND 1=1`→通常ページ／`1 AND 1=2`→404／`1 AND unicode(substr((SELECT sqlite_version()),1,1))>50`
の真偽で `sqlite_version()`=`3.25.3` を1文字ずつ復元できることを確認＝本物の boolean ブラインド SQLi。

## 対象（完了契約）

1. 新エンジン `smart_blind_sqli`（`SmartBlindSQLiHunter`）: **自己校正した真偽オラクル**
   （恒真 `AND 1=1`→TRUE クラス／恒偽 `AND 1=2`→FALSE クラス・特徴行は実行時自動導出＝製品固有
   文字列ハードコードなし）で注入を確定し、真偽オラクルの二分探索で DB の値（既定は非機微な
   `sqlite_version()`）を1文字ずつ抽出して実害を証明。
2. 確定バー（凍結・承認）: 新 vuln_type `blind_sqli`→新マーカー `blind_sqli_confirmed`（fail-closed）。
   error-based の `sqli`/`sql_error` パスは無改変（成熟パスを触らない）。
3. 封印再現（凍結・承認）: `_check_blind_sqli_replay`（恒真/恒偽 GET でオラクルをその場で再校正し
   先頭文字を再抽出→元抽出値と一致）。
4. 実対象で完全3ゲート＋実 poc_judge。

## poc_judge 対策（[[poc-judge-raw-evidence]]）

- 真偽の識別特徴は「意味のある行（`<title>`・自然文）」を優先選択する（SVG パス断片等を使うと
  「本文切り詰め差と区別できない」と却下される）。差分は同一領域の両側で見せる。
- **抽出は主張でなく raw transcript で見せる**（先頭数文字の等値確認 `=code`→TRUE / `=code+1`→FALSE の
  実 request/response 対を PoC に載せる）。抽出値を自己申告要約で書くだけでは却下される。

## 完了条件

1. エンジンが実 `sqli-blind` で真偽オラクルを自己校正し `sqlite_version()` を抽出。
2. GATE1 payout_grade=True/blind_sqli_confirmed → GATE2 封印再現 matched → GATE3 実 poc_judge
   is_real=True/impact=True（3回安定）。
3. payout_grade fail-closed（抽出値なし／恒真恒偽が真偽に分類されない／条件が SQL 数値比較でない）。
4. 既存 error-based SQLi・他エンジン非回帰。凍結3 exit 0。製品トークン0・秘密値非露出。

## NOT in scope（正直なスコープ）

- time-based ブラインド（SQLite は SLEEP なし・RDBMS 依存）は別途。機微データ抽出は既定で行わない
  （非機微な DB バージョンで能力実証）。query/JSON/POST 注入点の一般化・パイプライン統合は別途。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`、`rules/codingrules.md`、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。
