---
task_id: SGK-2026-0502
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-16_sgk-2026-0502_boolean-blind-sqli.md
- docs/shigoku/worklogs/2026-09-16_sgk-2026-0502_boolean-blind-sqli_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- sqli
- blind
- confirmation-bar
created_at: '2026-09-16'
updated_at: '2026-09-16'
---

# SGK-2026-0502 作業完了報告 — boolean ベース・ブラインド SQLi（データ抽出）を実対象で本物確定（◎）

## 何をしたか / なぜ

既存 `smart_sqli` は error-based が本体で、boolean ブラインド抽出は「target に `sqli_blind` を含む
ときだけ time-based を強制発火」というラボ名依存のヒューリスティックで curve-fit 気味だった。
真の boolean ブラインド抽出能力を、自己校正オラクル＋実データ抽出の新エンジンで ◎ 化。

実対象（実測）: **SKF `sqli-blind`**（Flask・:5000・SQLite。`/home/<pageId>` が
`SELECT ... WHERE pageId=<pageId>` を引用符なし数値連結し、行あり＝通常ページ／行なし＝404）。

## 実装（新設1＋承認済み凍結2）

- **smart_blind_sqli.py（非凍結・新規）**: `SmartBlindSQLiHunter`。恒真 `1 AND 1=1`／恒偽 `1 AND 1=2`
  を送り、**TRUE 応答専用行と FALSE 応答専用行を実行時に自動導出**（`_derive_signature`＝absent 本文に
  部分一致しない・意味の強い行を `<title>`/自然文優先で採点。SVG パス断片等は減点＝poc_judge が
  「切り詰め差と区別不能」と却下するのを回避）。恒真=TRUE・恒偽=FALSE に分類できれば注入確定。
  その真偽オラクルの二分探索で `unicode(substr((SELECT sqlite_version()),i,1))` を評価し
  **DB バージョンを1文字ずつ抽出**（既定は非機微な `sqlite_version()`）。先頭数文字は等値確認
  （`=code`→TRUE / `=code+1`→FALSE）の**実 request/response 対を transcript として PoC に記録**。
  `_client` seam・auth マスク・path/query モード対応。
- **payout_grade.py（凍結・承認）**: 新 vuln_type `blind_sqli`→新マーカー `blind_sqli_confirmed`
  ＋発火分岐（request_url 非空＋恒真恒偽が SQL 数値比較＋オラクルが true/false 分類＋抽出フィールド名
  非空＋抽出値非空＝真偽オラクルだけで DB 内容を実際に復元）。すべて揃うときだけ発火・fail-closed。
  error-based の `sqli`/`sql_error` パスは**無改変**。`finding.py` に `VulnType.BLIND_SQLI`。
- **sealed_reproduction_checker.py（凍結・承認）**: `_check_blind_sqli_replay`（恒真/恒偽 GET で
  オラクルをその場で再校正し、二分探索で先頭文字を再抽出→元抽出値の先頭文字と一致で matched）。

## 結果（独立検証・Claude が実測）

- **実 SKF `sqli-blind`** で実 `SmartBlindSQLiHunter.execute` が真偽オラクルを自己校正
  （true_sig=`<title>SKF Labs</title>`／false_sig=`<title>SKF Labs - 404 Error</title>`）し、
  `sqlite_version()`=**`3.25.3`** を真偽差分だけで抽出→**GATE1 payout_grade=True/blind_sqli_confirmed**。
- **GATE2**: 実 `SealedReproductionChecker` がオラクルを再校正＋先頭文字 `3` を再抽出→**matched**
  （`reproduction_marker_matched:blind_sqli_confirmed`）。
- **GATE3**: 本物の poc_judge（実 LLM）で **is_real=True・has_actual_impact=True・counter_evidence=False・
  needs_human=False を3回連続**（審査理由「同一リクエストで条件のみ `1=1`/`1=2` を変えると応答クラスが
  反転＝SQL 条件として評価・Step3 の transcript `=51 TRUE/=52 FALSE, =46 TRUE/=47 FALSE` で各文字が
  真偽分類され、本文にデータが一切出ないのに `3.25.3` を復元＝ブラインド SQLi のデータ窃取」）。
  **完全3ゲート達成＝◎**。
  - 初回は is_real=False（自動導出シグネチャが SVG パス断片＋抽出が主張のみで却下）→ シグネチャを
    意味のある行優先に改善＋抽出 transcript を raw 提示で is_real=True/impact=True に到達（バー非低下・
    証拠の見せ方の底上げ＝[[poc-judge-raw-evidence]] の SQLi 版）。
- テスト: 新規11テスト（engine 抽出・payout fail-closed×3・transcript 検証・オラクル不成立で非検出／
  sealed matched・mismatched・not_run×2・抽出文字不一致で mismatched）緑。error-based SQLi・LDAP 等
  非回帰。凍結3（poc_judge.md/task_queue.py/finding_validator.py）exit 0（無改変）。製品トークン0・
  秘密値非露出（既定抽出は非機微な DB バージョン）。

## 確度の結論（正直な格付け）

- **boolean ベース・ブラインド SQLi（データ窃取）＝ ◎（完全3ゲート）**。curve-fit なし（オラクルは
  実行時自己校正・抽出は実 transcript で実証・発火は fail-closed）。**高度化 中(L2)**（boolean 抽出
  1形態・SKF 単一・数値文脈・time-based/機微抽出/query・JSON 注入点の一般化は別途）。非破壊
  （読み取りクエリ・良性抽出のみ）。既存 error-based SQLi（◎ L3）とは別 vuln_type で併存。

## 完了条件の充足

計画の完了条件 1〜4 をすべて充足（条件2 の実 poc_judge を3回安定で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（実対象到達の証明・一ファイルの挙動を仕様と
しない）、`rules/codingrules.md`（bare except 禁止・明示タイムアウト・秘密非露出・重複排除＝URL/注入値
構築をモジュール関数化して sealed と共有）、メモリ [[no-capability-minimization]]・
[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・[[skf-labs-ssti-crlf]]。

## 非阻害の観測（deferred / 別件）

- time-based ブラインド（RDBMS 依存）・機微データ抽出・query/JSON/POST 注入点の一般化・パイプライン
  統合・第2対象検証は `deferred_followup`。
