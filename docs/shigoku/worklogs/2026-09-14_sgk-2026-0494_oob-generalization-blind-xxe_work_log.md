---
task_id: SGK-2026-0494
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0494_oob-generalization-blind-xxe.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0494_oob-generalization-blind-xxe_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- oob
- xxe
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0494 作業ログ（OOB 基盤汎化＋blind XXE・実 SKF ラボ・◎）

## 1. 方針（ユーザー質問→指示）
- 「今の OOB 受信は interactsh?独自?」→事実回答（実質は独自 LocalOOBListener・interactsh は BBOT 未導入で
  ガード・oob_correlator は Placeholder）。「今後ベストは?」→自前ホスト interactsh(DNS+HTTP・公開)。ただし
  当面は OOBProvider 抽象化＋LocalOOBListener(HTTP)で進め、後で無改修で差込。「Placeholder は影響なければ削除」。

## 2. 偵察（事実優先・実測）
- Placeholder は oob_correlator.py のみ(本番未使用・consumer は統合テスト1メソッド)。
- SKF xxe ラボで外部実体 http://受信器/callback/token を送るとパーサが受信器を fetch=token 到達(blind XXE)。
  docker→host:13337 は firewall 不通→lab を --network host で起動し 127.0.0.1:13337 を通す(=公開受信器が
  実標的に必要な裏付け)。

## 3. 台帳・計画・承認
- SGK-2026-0494 採番(registry.yaml・DOC-0564)。OOB 汎化+blind XXE の選択=ビルド承認(凍結2 追加)。

## 4. 実装(Claude 直接)
- Placeholder 削除: oob_correlator.py 削除+統合テストの OOB import/1メソッド外科除去。
- detection/oob_provider(新規): OOBProvider Protocol+LocalOOBProvider(LocalOOBListener ラッパ・new_callback/
  poll・callback_base で到達先差替)。
- injection/smart_blind_xxe(新規): 一意コールバック発行→外部実体を form/raw で送信→poll で token 到達確認で
  確定。_client/_oob seam・oob_evidence/oob_replay({OOB}テンプレ)・生 OOB inbound を載せた poc・製品固有なし。
- payout_grade: _match_firing_marker 先頭に汎用 OOB 分岐(token/payload/received/path 全て揃いで
  oob_interaction_received・欠ければ in-band へ fallback=fail-closed・既存不変)。
- sealed_reproduction: oob_provider seam+dispatch+_check_oob_replay(新 token で payload_template 埋め再送→
  受信器再観測→matched・専用スレッド asyncio.run・送信失敗=not_run/非到達=mismatched)。

## 5. 独立検証(Claude・実出力)
- smoke: OOB positive 発火／非到達・token 非 payload・token 非 path・空 token の fail-closed 確認。
- 実 SKF E2E: execute→blind XXE OOB 検出(token 到達)→payout_grade=True/oob_interaction_received→封印再現
  matched→CONFIRMED。
- 実 poc_judge: 初回 0/5(OOB を # コメント要約で書き「独立検証不可」と正しく却下)→**生の OOB inbound
  リクエスト+token 相関を raw 提示して 5/5**=poc-judge-raw-evidence の OOB 版・バー非低下。
- 新規20テスト緑。非回帰: 失敗3件は HEAD でも失敗の既存(phase_b×2・t3_hybrid budget・stash 比較確認)=
  0494 起因の回帰ゼロ(1296 passed)。phase_d は削除後も他テスト維持(3失敗は HEAD 同一の env 依存・OOB無関係)。
  凍結3 exit0。製品 token0・whitespace0・秘密値非露出。

## 6. 完了
- 完了条件1〜6 充足(条件4 実 poc_judge 5/5)。in_scope_blocker 0 → done。
- 能力マップ: blind/OOB XXE ◎＋帯域外(OOB)基盤行を追加。SSRF 注記を更新(HTTP OOB 基盤で blind SSRF も
  同型で ◎ 化可能)。
- 教訓: (1) OOB も poc_judge に受理可能だが「標的が受信器に送ってきた生の inbound リクエスト+token 相関」を
  raw で見せるのが必須(# コメント要約は却下)=poc-judge-raw-evidence の OOB 拡張。(2) OOB マーカーは
  vuln_type 横断の汎用にでき blind SSRF/SQLi/デシリアライズへ再利用可(宛先だけ変える)。(3) ローカルでは
  ラボ→受信器の到達性に工夫(--network host)が要り、実標的には公開受信器(自前 interactsh)が必要=DNS も含め別タスク。
  [[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・[[skf-labs-ssti-crlf]]。
- 観測(別件): DNS-only OOB・公開 interactsh・blind SSRF/SQLi/デシリアライズ適用・統合は deferred。
