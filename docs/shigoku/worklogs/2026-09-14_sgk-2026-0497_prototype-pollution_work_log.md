---
task_id: SGK-2026-0497
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0497_prototype-pollution.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0497_prototype-pollution_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- prototype-pollution
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0497 作業ログ（プロトタイプ汚染・実 SKF ラボ・◎）

## 1. 偵察(事実優先・実測)
- 既存 prototype_pollution_tester は未配線。SKF js-prototype-pollution(Node/Express・POST /message が
  _.merge({},req.body,...)=lodash PP sink)。entrypoint app.js 不在で実体は index.js(node index.js で起動)。
- 実測: __proto__.admin に一意マーカー→/create の admin無し新ユーザーの/login(Admin欄)に継承出現、汚染前は空。

## 2. 台帳・計画・承認
- SGK-2026-0497 採番(registry.yaml・DOC-0567)。PP 新設の選択=ビルド承認(凍結2 追加)。

## 3. 実装(Claude 直接)
- smart_prototype_pollution(新規): task由来のsink/setup/observeで①control(汚染前)②pollute③observe(汚染後)の
  差分+一意マーカーで確定。_client seam・marker中心スニペット・pp_evidence/pp_replay/3ステップpoc・製品固有なし。
- payout_grade: _MARKER_CATEGORIES["prototype_pollution"]="prototype_pollution_confirmed"+発火分岐
  (sink/observe/property/marker非空+observe2xx+markerがpolluted実在+control非実在・fail-closed)。
- sealed_reproduction: _check_pp_replay(新マーカーでpollute→setup→observe再実行→新オブジェクト再出現でmatched)。

## 4. 独立検証(Claude・実出力)
- smoke: PP positive発火・fail-closed(control出現/非反映/非2xx/空prop)確認。
- 実 SKF E2E: 検出→payout_grade=True/prototype_pollution_confirmed→封印再現 初回mismatched→
  **json sinkにContent-Type:application/json明示の修正**でmatched(欠落するとexpress.json()未解析で汚染不発だった)。
- 実 poc_judge: **5/5**(__proto__.admin経由の一意マーカーが別オブジェクトのlogin応答に出現・汚染前不在を評価)。
- 新規19テスト緑。非回帰: 失敗3件はHEADでも失敗の既存(phase_b×2・t3_hybrid budget)=0497起因の回帰ゼロ
  (1312 passed)。凍結3 exit0。製品token0・whitespace0・秘密値非露出。

## 5. 完了
- 完了条件1〜5充足(条件3 実poc_judge 5/5)。in_scope_blocker 0 → done。
- 能力マップ: プロトタイプ汚染 ◎ 行を追加・高度化 低(L1)。
- 教訓: (1) PP は「汚染後に別オブジェクトへ一意マーカー継承×汚染前不在」の in-band 差分で確定。(2) 封印再現の
  json sink は Content-Type:application/json を明示しないと express.json() が解析せず汚染不発(sync送信ヘルパは
  呼び出し側でヘッダ付与が必要)。(3) シナリオ(sink/setup/observe)を task 由来にすればエンジンは製品非依存。
  [[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・[[skf-labs-ssti-crlf]]。
- 観測(別件): クライアント側PP・特定ガジェット連鎖・非lodash実装網羅・統合は deferred。
