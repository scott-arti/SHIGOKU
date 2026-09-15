---
task_id: SGK-2026-0502
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-16_sgk-2026-0502_boolean-blind-sqli.md
- docs/shigoku/reports/2026-09-16_sgk-2026-0502_boolean-blind-sqli_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- sqli
- blind
created_at: '2026-09-16'
updated_at: '2026-09-16'
---

# SGK-2026-0502 作業ログ（boolean ベース・ブラインド SQLi・◎）

## 1. 偵察(事実優先・実測)
- 既存 smart_sqli の boolean ブラインドは target に "sqli_blind" を含むときだけ time-based を強制する
  ラボ名依存ヒューリスティック（curve-fit 気味）。SQLite は SLEEP なしで time-based 不安定。
- SKF sqli-blind ソース確認（コンテナ内 /home/app/SQLI-blind）: /home/<pageId> が
  `SELECT ... WHERE pageId=<pageId>`（数値・引用符なし連結・SQLite）。行あり=通常ページ/行なし=404。
- 実測: 1 AND 1=1→通常(9783B)/1 AND 1=2→404(9437B)/二分探索で sqlite_version()=3.25.3 抽出成功。

## 2. 台帳・計画・承認
- SGK-2026-0502 採番(registry.yaml・DOC-0572)。boolean ブラインド SQLi の選択=ビルド承認(凍結2 追加)。

## 3. 実装(Claude 直接)
- smart_blind_sqli(新規): 自己校正オラクル(恒真/恒偽→TRUE/FALSE 特徴行を自動導出)+二分探索抽出。
  URL/注入値構築はモジュール関数(build_blind_sqli_url/value)に切り出し sealed と共有(重複排除)。
- payout_grade: VulnType.BLIND_SQLI + _MARKER_CATEGORIES["blind_sqli"]="blind_sqli_confirmed"
  + _SQL_BOOLEAN_PATTERN + fail-closed 発火分岐。error-based(sqli/sql_error)は無改変。
- sealed_reproduction: _check_blind_sqli_replay(オラクル再校正+先頭文字再抽出→元値と一致で matched)。
- finding.py に VulnType.BLIND_SQLI。

## 4. 独立検証(Claude・実出力)
- 実 SKF E2E: 検出→GATE1 payout_grade=True/blind_sqli_confirmed(extracted sqlite_version=3.25.3)。
- GATE2 sealed matched(オラクル再校正+先頭文字 '3' 再抽出)。
- GATE3 poc_judge: 初回 is_real=False(自動導出 true_sig が SVG パス断片で真偽差が判別不能・抽出が
  主張のみで却下)→(a)シグネチャ選定を <title>/自然文優先の採点に改善(SVG/タグ soup 減点)、
  (b)先頭数文字の等値確認(=code TRUE/=code+1 FALSE)を実 request/response 対の transcript として
  PoC に記録、で is_real=True/impact=True/counter=False/needs_human=False を3回連続。
- 新規11テスト緑(engine/payout fail-closed×3/transcript/オラクル不成立非検出、sealed matched/
  mismatched/not_run×2/抽出文字不一致 mismatched)。error-based SQLi・LDAP 非回帰。凍結3 exit0。
- docker lab(skf-sqliblind)後片付け済。製品token0・秘密値非露出。

## 5. 完了
- 完了条件1〜4充足(条件2 実 poc_judge 3回安定)。in_scope_blocker 0 → done。
- 能力マップ: SQLi 行に boolean ブラインド抽出(別 vuln_type blind_sqli・◎)を追記。
- 教訓: (1) ブラインドの真偽オラクルは**識別特徴の意味の強さ**が要る。SVG パス/タグ属性の羅列を
  シグネチャにすると judge が「本文切り詰め差と区別できない」と却下→<title>/自然文を優先採点。
  (2) ブラインド抽出は**主張でなく実 transcript**(等値確認の request/response 対)で見せると impact 通過。
  (3) error-based の成熟パスは触らず別 vuln_type で分離＝回帰を避けつつ能力追加。
  [[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・[[skf-labs-ssti-crlf]]。
- 観測(別件): time-based ブラインド・機微抽出・query/JSON/POST 注入点一般化・パイプライン統合は deferred。
