---
task_id: SGK-2026-0487
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0487_nosql-injection-confirmation.md
- docs/shigoku/reports/2026-09-13_sgk-2026-0487_nosql-injection-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- nosql-injection
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0487 作業ログ（NoSQL 演算子注入・実 crAPI・◎）

## 1. 偵察（事実優先・実測）
- CORS が ○ の理由をユーザーに説明（能力は本物・実ラボが ACAO:* で本物脆弱でない＝偽◎を出さない）。
- NoSQLi へ。既存 `nosql_tester.py` は在るが未配線。実対象探し: Juice Shop track-order は特殊文字を
  サニタイズ（不適）。**crAPI クーポン検証（Mongo・要auth）** が本物: 無効リテラル→500、`{"$ne":null}`/
  `{"$regex":".*"}`→200＋有効クーポン TRAC075（差分明確）。テストアカウント作成→token 取得で実測。

## 2. 確定バーの欠落点（事実）
- specialist 未配線・`_MARKER_CATEGORIES` に nosql なし・既存検出はヒューリスティック。

## 3. 台帳・計画・承認
- SGK-2026-0487 採番（registry.yaml・DOC-0557）。NoSQLi 新設の選択＝ビルド承認（凍結2 追加）。

## 4. 実装（Claude 直接）
- smart_nosql（新規）: 候補 JSON フィールドに①無効リテラル②MongoDB 演算子を送り、①失敗×②成功の
  決定論的差分で確定。`_client` seam・nosql_evidence(op+control)・nosql_replay・2ステップ差分 poc・
  auth は poc マスク/evidence 保持。製品固有ハードコードなし。
- payout_grade: `_NOSQL_OPERATOR_PATTERN`＋`_nosql_body_has_data`＋`_MARKER_CATEGORIES["nosql_injection"]=
  "nosql_operator_injection"`＋発火分岐（request_url／operator に演算子／演算子成功／コントロール失敗＝
  全て揃いで発火・fail-closed）。
- sealed_reproduction: `_check_nosql_replay`（演算子 JSON body を封印内 1 回再送→2xx+データ再観測→matched・
  auth は evidence.request_headers）＋dispatch 分岐＋import。

## 5. 独立検証（Claude・実出力）
- 実 crAPI E2E: execute→field coupon_code・`{"$ne":null}`→200+TRAC075／リテラル→500→payout_grade=True/
  nosql_operator_injection→実再現 matched→CONFIRMED。poc マスク・judge 可視に生トークンなし。
- 実 poc_judge: 初回 2/5（差分の片側=リテラル失敗を poc に含めず judge が「差分不足」と正しく指摘）→
  **2ステップ差分 poc に底上げして 5/5**（Step1 500×Step2 200 の差分を明示評価）。バー非低下・証拠の
  見せ方の強化＝[[poc-judge-raw-evidence]]。
- 新規19テスト緑。非回帰: 失敗3件は HEAD でも失敗する既存（phase_b×2・t3_hybrid budget・本セッションで
  stash 確認済み）＝0487 起因の回帰ゼロ。凍結3 exit 0。製品 token0・whitespace0・秘密値非露出。

## 6. 完了
- 完了条件1〜5 充足（条件3 実 poc_judge 5/5）。in_scope_blocker 0 → done。
- 能力マップ: **NoSQLi 行を新規追加し ◎**（演算子注入の決定論的差分を完全3ゲート）。ギャップ節から NoSQLi 除去。
- 教訓: (1) 差分型脆弱性（NoSQLi/IDOR）は「両側（成功と失敗）の生証拠」を poc に載せないと実 poc_judge が
  通らない（片側だけだと『差分不足』で正しく突き返される）。(2) 認証付き対象は auth を poc マスク＋
  evidence 保持＋judge 入力から除外で秘密を守りつつ再現可能。[[poc-judge-raw-evidence]]・[[no-capability-minimization]]。
- 観測(別件): blind/time-based NoSQLi・破壊的更新は対象外。task_registry 構造ずれ（運用影響なし）。
