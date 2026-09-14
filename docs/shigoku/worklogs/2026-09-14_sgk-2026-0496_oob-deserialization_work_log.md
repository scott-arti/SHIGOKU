---
task_id: SGK-2026-0496
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0496_oob-deserialization.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0496_oob-deserialization_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- deserialization
- oob
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0496 作業ログ（OOB デシリアライズ・RCE級・実 SKF des-pickle・◎）

## 1. 方針
- OOB SQLi は SKF sqli=SQLite でネットワーク関数無し=OOB 不可・実対象無しで据え置き(ユーザー判断)。
  OOB 基盤(0494/0495)を横展開しデシリアライズへ。

## 2. 偵察(事実優先・実測)
- SKF des-pickle(--network host): POST /sync form data_obj=hex(pickle) を pickle.load で逆シリアライズ=RCE。
- __reduce__→os.system(python3 urllib callback) の pickle を hex 送信→標的が逆シリアライズ→token 受信器到達
  =OOB デシリアライズ成立を実測。

## 3. 台帳・計画・承認
- SGK-2026-0496 採番(registry.yaml・DOC-0566)。OOB デシリアライズの選択=ビルド承認(凍結2 追加)。

## 4. 実装(Claude 直接)
- detection/oob_payload_builders(新規): build_oob_payload(kind,cb)->bytes + encode_payload。python_pickle は
  __reduce__→os.system(curl/wget/python3 callback)。エンジンと封印再現(builderパス)で共有。良性コールバックのみ。
- injection/smart_blind_deser(新規): provider から callback 発行→ビルダでガジェット生成→hex→sink へ送信→
  poll で token 到達確認。_client/_oob seam・oob_evidence(payload=token含むcallback記述)/oob_replay(builder/
  encoding)/生OOB inbound の poc・製品固有なし。
- payout_grade: _MARKER_CATEGORIES["deserialization"]="oob_interaction_received" 追加(汎用OOB分岐を発火可能に)。
- sealed_reproduction: _check_oob_replay に builder パス追加(oob_replay.builder があれば fresh callback から
  作り直して再送=バイナリpickle正しく再生成・{OOB}置換の代替)。

## 5. 独立検証(Claude・実出力)
- smoke: deser OOB positive 発火・builder バイト検査。
- 実 SKF E2E: execute→OOB デシリアライズ検出(GET /callback/token 到達)→payout_grade=True/
  oob_interaction_received→封印再現 matched(builderパス)→CONFIRMED。
- 実 poc_judge: **5/5**(pickle ガジェットにのみ埋めた token が標的から受信器へ実リクエストで到達を評価)。
- 新規15テスト緑。非回帰: 失敗3件は HEAD でも失敗の既存(phase_b×2・t3_hybrid budget)=0496 起因の回帰ゼロ
  (1313 passed)。凍結3 exit0。製品 token0・whitespace0・秘密値非露出。テストは生成pickleを一切unpickleしない
  (バイト検査のみ)で実行回避。

## 6. 完了
- 完了条件1〜5 充足(条件3 実 poc_judge 5/5)。in_scope_blocker 0 → done。
- 能力マップ: 安全でないデシリアライズ ◎(OOB)行を追加・高度化 低(L1)。
- 教訓: (1) OOB 基盤は builder パスを足すだけで任意のデシリアライズ言語へ拡張可能(pickleは__reduce__→
  os.system callback)。(2) バイナリペイロードの封印再現は{OOB}置換でなく fresh callback から builder で
  作り直す。(3) デシリアライズ確認のテストは生成物を unpickle せずバイト検査(実行回避)。
  [[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・[[skf-labs-ssti-crlf]]。
- 観測(別件): in-band 確認・Java/PHP ビルダ・DNS-only OOB・公開受信器・統合は deferred。OOB SQLi 据え置き。
