---
task_id: SGK-2026-0499
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0499_ldap-injection.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0499_ldap-injection_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- ldap-injection
created_at: '2026-09-14'
updated_at: '2026-09-15'
---

# SGK-2026-0499 作業ログ（LDAP インジェクション・実 SKF ラボ・◎）

## 1. 偵察(事実優先・実測)
- ldap_tester.py は完全プレースホルダ(_test_payload がリクエスト送らず空結果)=未配線。
- SKF ldap-injection(Flask・:5000・実 LDAP)。POST /login が (&(cn=<u>)(sn=<p>)) を文字列連結し search_s。
  コンテナ内 /home/app/Ldap-injection/ldap-injection.py で確認: len(result)==True(=1件)で "You are now admin user!"。
- 実測: control(nouser123/nopass123)→"Wrong identity provided."、username=*&password=*→"You are now admin user!"。

## 2. 台帳・計画・承認
- SGK-2026-0499 採番(registry.yaml・DOC-0569)。LDAP 新設の選択=ビルド承認(凍結2 追加)。

## 3. 実装(Claude 直接)
- smart_ldap_injection(新規): 負のコントロール(ランダムリテラル×2)×LDAP メタ文字ペイロードの差分で確定。
  成功印は task 由来優先、無ければ2コントロール安定ベースラインに対し注入応答にだけ現れる特徴行を自動導出。
  マーカー中心スニペット+コントロール同一領域切り出し。_client seam・auth マスク/保持・差分2ステップpoc。
- payout_grade: _LDAP_METACHAR_PATTERN + _MARKER_CATEGORIES["ldap_injection"]="ldap_injection_confirmed"
  + 発火分岐(fail-closed)。finding.py に VulnType.LDAP_INJECTION。
- sealed_reproduction: _check_ldap_replay(fresh リテラル control×メタ文字 injection を form 再送→差分再観測)。
  _LDAP_METACHAR_PATTERN を payout_grade から import。

## 4. 独立検証(Claude・実出力)
- 実 SKF E2E: 検出→GATE1 payout_grade=True/ldap_injection_confirmed。
- 初回 marker が offset>1500 で snippet 切り詰め外→marker中心スニペット修正で injected_body に載る。
- GATE2 sealed matched(fresh control×メタ文字 form 再送で差分再観測)。
- GATE3 poc_judge: is_real=True/impact=True/counter=False/needs_human=False(初回一発・両側同領域提示)。
- 新規12テスト緑。非回帰: 失敗3件は HEAD でも失敗の既存(phase_b×2・t3_hybrid budget)=0499起因の回帰ゼロ
  (1382 passed)。凍結3 exit0。製品token0・whitespace0・秘密値非露出。

## 5. 完了
- 完了条件1〜5充足(条件3 実poc_judge 初回一発)。in_scope_blocker 0 → done。
- 能力マップ: LDAP インジェクション ◎ 行を追加・高度化 中(L2)。
- 教訓: (1) 差分型は両側(リテラル失敗×メタ文字成功)を同じ領域で見せると poc_judge 初回一発。
  (2) 成功印は製品固有文字列をハードコードせず「2コントロール安定ベースライン vs 注入応答の特徴行」で
  自動導出できる。(3) マーカーが本文後方(offset>1500)に来るとき先頭切り詰めで証拠が落ちる→マーカー中心
  スニペット必須(SSTI/Host ヘッダと同じ)。[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
  [[skf-labs-ssti-crlf]]。
- 観測(別件): ブラインド(真偽/時間)LDAP・属性開示・AD 固有・GET/JSON 注入点・統合は deferred。
