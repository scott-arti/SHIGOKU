---
task_id: SGK-2026-0486
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0486_xxe-confirmation.md
- docs/shigoku/reports/2026-09-13_sgk-2026-0486_xxe-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- xxe
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0486 作業ログ（XXE・新エンジン新設・実 SKF ラボ・◎）

## 0. 前段（CRLF の決着）
- CRLF は事実確認で「現代ランタイムがヘッダ内 CRLF をサニタイズ＝真のシンク不在」（SKF python/java＝
  本文反映のXSS系・bWAPP/PHP5.5＝header() が CRLF 拒否）と判明。ユーザー判断で**対象外**に決定。
- 次に「エンジンが無いギャップ領域」へ。NoSQLi はテスターが在るが未配線、XXE は完全 greenfield。
  ユーザー選択で **XXE から新設**。

## 1. 偵察（事実優先・実測）
- SKF `blabla1337/owasp-skf-lab:xxe` を `127.0.0.1:5089` に起動。app 確認: `/home` が
  `request.form['xxe']` を `xml.dom.pulldom.parseString`→`<items>` を expandNode→toxml() 反映。
- 実測: `<!ENTITY x SYSTEM "file:///etc/passwd">` を含む XML の form POST で `root:x:0:0:...` が反映＝
  本物 in-band XXE（ファイル読み取り）。

## 2. 確定バーの欠落点（事実）
- XXE のテスター・VulnType・specialist いずれも不在（真の新設）。`_MARKER_CATEGORIES` に xxe なし。

## 3. 台帳・計画・承認
- SGK-2026-0486 採番（registry.yaml・DOC-0556）。XXE 新設の選択＝ビルド承認（凍結2 追加＋SKF pull 承認）。

## 4. 実装（Claude 直接）
- finding: `VulnType.XXE`。
- smart_xxe（新規）: 汎用外部実体ペイロード（passwd）× ラッパ要素（items/data/root/xml/foo）×
  パラメータ（task＋xml/xxe/data/body/content）× モード（raw/form）で試行→passwd 署名反映で確定。
  `self._client` seam・署名中心スニペット・構造化 xxe_evidence/xxe_replay/生 poc 対。製品固有ハードコードなし。
- payout_grade: `_XXE_FILE_PATTERNS`（passwd/PEM）＋`_XXE_ENTITY_PATTERN`＋`_MARKER_CATEGORIES["xxe"]=
  "xxe_file_read"`＋発火分岐（request_url／status>0／payload に外部実体／served_body にファイル署名＝
  全て揃いで発火・fail-closed）。
- sealed_reproduction: `_check_xxe_replay`（外部実体 payload を封印内 1 回再送 form/raw→署名再観測→matched）
  ＋dispatch 分岐。`_send_post_form` を form/raw 両用に流用（新ヘルパ不要）。

## 5. 独立検証（Claude・実出力）
- 実 SKF E2E: execute→form param `xxe`＋要素 `items` を自走発見→passwd 反映→payout_grade=True/
  xxe_file_read→実再現 matched→CONFIRMED。
- 実 poc_judge: **5/5 承認**（is_real/impact True・counter False。「ペイロードは実体宣言のみ・応答に
  passwd 実内容＝本物の XXE」）。
- 新規18テスト緑。非回帰: 失敗3件は HEAD でも失敗する既存（phase_b×2・t3_hybrid budget・本セッション
  で stash 確認済み・1133 passed）＝0486 起因の回帰ゼロ。凍結3 exit 0。製品 token0・whitespace0。

## 6. 完了
- 完了条件1〜5 充足（条件3 実 poc_judge 5/5）。in_scope_blocker 0 → done。
- 能力マップ: **XXE 行を新規追加し ◎**（外部実体ローカルファイル読み取りを完全3ゲート）。CRLF は
  対象外（据え置き・理由明記）。
- 教訓: 「エンジンが無い領域」も、汎用ペイロード（外部実体）＋実対象＋「本来読めないファイル内容の
  反映」という決定的証拠で新設 ◎ に到達できる。証拠は署名中心スニペットで有界化。[[poc-judge-raw-evidence]]。
  バー非低下・実対象で本物確定。[[no-capability-minimization]]。
- 観測(別件): OOB/blind XXE は外部受信基盤が要る別タスク。task_registry 構造ずれ（運用影響なし）。
