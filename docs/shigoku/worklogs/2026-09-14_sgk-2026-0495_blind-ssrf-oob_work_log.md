---
task_id: SGK-2026-0495
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0495_blind-ssrf-oob.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0495_blind-ssrf-oob_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- ssrf
- oob
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0495 作業ログ（Blind SSRF・OOB 基盤横展開・実 SKF ラボ・◎）

## 1. 方針
- OOB 基盤(0494)を横展開。SSRF はサーバ側 fetch を OOB コールバックで確定。宛先を変えるだけ＝新エンジンは
  Finding を作るだけ・payout_grade 不変(汎用マーカー再利用)。

## 2. 偵察(事実優先・実測)
- SKF ssrf ラボ(--network host)：POST /check_existence form url を requests.head でサーバ側 fetch(内容非返却
  =実質ブラインド)。URL パラメータに OOB コールバックを入れると標的から HEAD /callback/token が受信器へ到達。

## 3. 台帳・計画・承認
- SGK-2026-0495 採番(registry.yaml・DOC-0565)。OOB 横展開の選択＝ビルド承認(凍結1=sealed に query/json 追加)。

## 4. 実装(Claude 直接)
- smart_blind_ssrf(新規): 候補 URL パラメータ×form/query/json モードに callback を入れて送信→poll で token
  到達確認。_client/_oob seam・oob_evidence(payload=token含む送出値)/oob_replay/生 OOB inbound の poc・製品固有なし。
- payout_grade: 改変なし(汎用 OOB マーカー oob_interaction_received を ssrf で再利用)。
- sealed_reproduction: _check_oob_replay に query(GET)/json(POST) モード追加(従来 form/raw に加え)。

## 5. 独立検証(Claude・実出力)
- smoke: SSRF OOB positive 発火・poc 形式 OK。
- 実 SKF E2E: execute→blind SSRF OOB 検出(HEAD /callback/token 到達)→payout_grade=True/
  oob_interaction_received→封印再現 matched→CONFIRMED。
- 実 poc_judge: **5/5**(標的自身=python-requests から HEAD callback が受信器へ到達＋token 相関を評価)。
- 新規9テスト緑。非回帰: 失敗3件は HEAD でも失敗の既存(phase_b×2・t3_hybrid budget)=0495 起因の回帰ゼロ
  (1302 passed)。凍結3 exit0・payout_grade 不変。製品 token0・whitespace0・秘密値非露出。

## 6. 完了
- 完了条件1〜5 充足(条件3 実 poc_judge 5/5)。in_scope_blocker 0 → done。
- 能力マップ: SSRF 行に blind/OOB SSRF ◎ を追記(in-band 0482＋blind 0495 の2形態)・高度化 中(L2)。
- 教訓: OOB 基盤の横展開は最小コスト(新エンジン＋sealed に query/json モード追加のみ・payout_grade 不変)で
  ◎。汎用 OOB マーカーは vuln_type 横断で再利用でき、OOB SQLi/デシリアライズも同型で追加可能。
  [[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・[[skf-labs-ssti-crlf]]。
- 観測(別件): DNS-only OOB・公開 interactsh・OOB SQLi/デシリアライズ・compose 標的 reachability・統合は deferred。
