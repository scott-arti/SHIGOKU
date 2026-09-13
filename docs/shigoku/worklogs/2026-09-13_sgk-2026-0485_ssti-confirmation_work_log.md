---
task_id: SGK-2026-0485
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0485_ssti-confirmation.md
- docs/shigoku/reports/2026-09-13_sgk-2026-0485_ssti-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- ssti
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0485 作業ログ（SSTI・実 SKF ラボ・◎）

## 1. 偵察（事実優先・実測）
- GET のみで現行4ラボ（DVWA/Juice Shop/crAPI/DVGA）に SSTI/CRLF の実シンク無しを確認
  （CRLF 注入ヘッダはどこにも反映せず・SSTI 描画 param 無し）。
- OWASP SKF `blabla1337/owasp-skf-lab:ssti` を `127.0.0.1:5085` に起動。コンテナ内 SSTI.py を確認し
  **404 ハンドラが `render_template_string(template.format(request.url))`** ＝ URL 自体が注入点と判明。
- 実測: `?q={{7*7}}`→404ページに `?q=49`（Jinja2 評価）。`{{9999*9999}}`→99980001。任意クエリ param で到達。

## 2. 確定バーの欠落点（事実）
- `SmartSSTIHunter` は SSTI 自走検出も evidence.response_status=0・生証拠不足で payout_grade 非到達。
- `_MARKER_CATEGORIES` に `ssti` 無し。再現経路未整備。

## 3. 台帳・計画・承認
- SGK-2026-0485 採番（registry.yaml・DOC-0555）。SSTI を ◎ 化する選択＝ビルド承認（凍結2 は 0482〜0484
  と同種の追加）。SKF イメージ pull＋起動もユーザー選択で承認。

## 4. 実装（Claude 直接・小粒surgical）
- smart_ssti: `_capture_ssti`（`self._client` seam・GET は params で 1 回エンコード＝二重エンコード回避）・
  `_evidence_snippet`（expected 中心スニペット・後方反映を保持）・`_convert_to_findings` を確定グレード化
  （ssti_evidence／ssti_replay／生 poc 対／impact／repro）。`expected`=算術積＋一意マーカー。
- payout_grade: `_MARKER_CATEGORIES["ssti"]="template_evaluated"`＋発火分岐（request_url／status>0／payload／
  expected／served_body に expected 実在で発火・fail-closed）。
- sealed_reproduction: `_check_ssti_replay`（payload を封印内で 1 回再送 GET/POST→expected 再観測→matched）
  ＋dispatch 分岐。

## 5. 独立検証（Claude・実出力）
- 実 SKF E2E: execute→検出→捕捉（status 404・本文に `49<marker>`）→payout_grade=True/template_evaluated
  →実再現 matched→CONFIRMED。
- 実 poc_judge: **5/5 承認**（is_real/impact True・counter False。「反射でなくサーバ側評価・一意マーカーで
  偶然/捏造排除・RCE 隣接」）。初回は DeepSeek DNS 一時失敗で 2/4（ネットワーク flake・判定拒否ではない）→
  回復後 5/5。
- 新規21テスト緑。非回帰: 失敗3件は HEAD でも失敗する既存（phase_b×2・t3_hybrid budget・stash 確認・
  1115 passed）＝0485 起因の回帰ゼロ。凍結3 exit 0。製品 token0・whitespace0。

## 6. 完了
- 完了条件1〜5 充足（条件3 実 poc_judge 5/5）。in_scope_blocker 0 → done。
- 能力マップ: SSTI/CRLF 行を分割し **SSTI を ◎**（SKF・Jinja2 テンプレート評価を完全3ゲート）。CRLF は △ のまま。
- 教訓: (1) 事前エンコード URL を aiohttp に渡すと二重エンコードで壊れる → params で 1 回エンコードさせる。
  (2) 反映が本文後方にある場合、先頭固定切り詰めで証拠が落ちる → 証拠は「マーカーを中心にしたスニペット」で保持。
  (3) SSTI は「算術積＋一意マーカーの再出現」で実 poc_judge を通す（反射・偶然・捏造を排除）。[[poc-judge-raw-evidence]]。
  バー非低下・証拠の実体と見せ方の強化。[[no-capability-minimization]]。
- 観測(別件): CRLF は次タスク（SKF http-response-splitting）。task_registry 構造ずれ（運用影響なし）。
