---
task_id: SGK-2026-0491
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0491_host-header-injection-confirmation.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0491_host-header-injection-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- host-header-injection
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0491 作業ログ（Host Header Injection・実 SKF ラボ・◎）

## 1. 偵察（事実優先・実測）
- 既存 HostHeaderInjectionTester は reflection ヒューリスティックのみ・確定バー未接続。
- SKF に host-header-authentication-bypass ラボを発見。SSTI/XXE/race と同 posture で 127.0.0.1:5092 に起動。
- race.py ならぬ app 解析: /dashboard は未ログインで Host が localhost/127.0.0.1(is_local_request)なら
  admin panel(給与データ)を返し、非該当ホストは redirect('/')=Hostヘッダを認可判定に使用。実測で
  Host:localhost→200+給与データ、Host:attacker.example→302 を確認。

## 2. 台帳・計画・承認
- SGK-2026-0491 採番（registry.yaml・DOC-0561）。HHI 新設の選択＝ビルド承認（凍結2 追加）。

## 3. 実装（Claude 直接）
- smart_host_header（新規）: 候補ホストヘッダ×バイパス値を注入し control(非バイパス)との差分で確定。
  注入ヘッダが Host 以外なら Host を control 値に固定し原因帰属を厳密化（誤検知防止）。allow_redirects=False。
  署名中心スニペット。_client seam・host_header_evidence(injection+control)・host_header_replay・2ステップ poc。
  製品固有ハードコードなし（署名は task 由来）。
- payout_grade: `_MARKER_CATEGORIES["host_header_injection"]="host_header_auth_bypass"`+発火分岐
  (request_url/header/value/signature 非空+2xx+署名が injected に実在+control に非実在・fail-closed)。
- sealed_reproduction: `_check_host_header_replay`（注入ヘッダ付き GET を封印内1回再送→署名再出現で matched・
  既存 _send_get_jwt の汎用ヘッダ GET 流用）+dispatch。

## 4. 独立検証（Claude・実出力）
- smoke: 発火 positive／署名 control 出現・非反映・非2xx・header/署名欠落 の fail-closed 確認。
- 実 SKF E2E: 初回は署名が offset>1500 で先頭切り詰めにより payout_grade=False→**署名中心スニペット**に
  底上げして検出→payout_grade=True/host_header_auth_bypass→封印再現 matched→CONFIRMED。
- 実 poc_judge: **初回から 5/5**（Host のみ差し替えで拒否→給与データ許可の差分を評価）。
- 新規21テスト緑。非回帰: 失敗3件は HEAD でも失敗する既存（phase_b×2・t3_hybrid budget・0488/0489 で
  stash 確認済み）＝0491 起因の回帰ゼロ（1241 passed）。凍結3 exit 0。製品 token0・whitespace0・秘密値非露出。

## 5. 完了
- 完了条件1〜5 充足（条件3 実 poc_judge 5/5）。in_scope_blocker 0 → done。
- 能力マップ: **Host Header Injection 行を新規追加し ◎**＋高度化 低(L1)。
- 教訓: (1) 差分型で「注入ヘッダ以外」を送るときはベースライン（Host）を control 値に固定して原因帰属を
  厳密化（誤検知防止）。(2) 制限署名は本文後方に来るため**署名中心スニペット**が必須（先頭切り詰めは証拠を
  落とす＝poc_judge が正しく突き返す）。(3) 確定意味論が近い送信は既存封印再現ヘルパ(_send_get_jwt)を汎用
  流用できる。[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・[[no-capability-minimization]]。
- 観測(別件): reflection 型・リセットポイズニング・実運用対象・統合は高度化フェーズで deferred。
