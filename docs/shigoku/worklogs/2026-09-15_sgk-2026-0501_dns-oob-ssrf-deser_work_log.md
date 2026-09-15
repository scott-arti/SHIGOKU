---
task_id: SGK-2026-0501
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-15_sgk-2026-0501_dns-oob-ssrf-deser.md
- docs/shigoku/reports/2026-09-15_sgk-2026-0501_dns-oob-ssrf-deser_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- oob
- dns
- ssrf
- deserialization
created_at: '2026-09-15'
updated_at: '2026-09-15'
---

# SGK-2026-0501 作業ログ（DNS-OOB を SSRF/deser へ横展開）

## 1. 偵察(事実優先・実測)
- smart_blind_ssrf/deser とも OOB ブロックを HTTP 形式で固定・`interaction.channel` 未使用・
  `"channel":"http"` を直書き。DNS finding を出すと PoC が HTTP 形式になり judge の channel 整合に反する。
- XXE（0500）は既に channel 対応済み＝これをテンプレとして移植。

## 2. 台帳・計画・承認
- SGK-2026-0501 採番(registry.yaml・DOC-0571)。SSRF/deser の DNS 横展開の選択＝ビルド承認(凍結0)。

## 3. 実装(Claude 直接)
- smart_blind_ssrf: `channel` 変数追加。DNS 分岐で OOB ブロックを「DNS クエリ QNAME＋送信元」で提示・
  HTTP 行を混ぜない。impact/title/description を DNS 用に分岐。oob_evidence.channel に実チャネル反映。
- smart_blind_deser: 同上。DNS では複数 DNS クエリを QNAME 行で列挙・Java は URLClassLoader/ServiceLoader
  由来を明記。凍結(payout_grade/sealed)無改修。

## 4. 独立検証(Claude・実出力)
- 受信器: wcp イメージ(py3.7)で dns_oob_listener を :53 コンテナ起動(oob-dns=172.17.0.8)。
- deser: java-des-yaml を `--dns=172.17.0.8` で起動(172.17.0.10)。DNS-only 真ブラインドで GATE1=True/
  oob_interaction_received→GATE2 matched→GATE3 poc_judge 3回連続 is_real=True/impact=True/counter=False
  /needs_human=False ＝◎。
- ssrf: ssrf ラボを `--dns` で起動(172.17.0.9)。手動 probe で `<token>.oob.test` の解決が受信器着弾を確認。
  GATE1=True→GATE2 matched→GATE3 poc_judge 3回連続 is_real=True/**impact=False**(理由: DNS 解決のみで
  内部到達の実害は未実測=仮定)。honest に一段下げて記録(curve-fit しない)。
- 新規 DNS テスト2件緑。既存 HTTP 経路(SSRF/deser/XXE)非回帰。凍結3 exit0。回帰: 既存3件のみ失敗
  (phase_b×2・t3 budget)＝0501 起因ゼロ(1358 passed)。docker 3コンテナ後片付け済。

## 5. 完了
- 完了条件 1・2・4 充足。条件3(SSRF)は影響格付けを実測に従い honest 記録(実在性は通過)。in_scope_blocker 0 → done。
- 能力マップ: OOB 基盤 DNS 行に「deser=DNS-only ◎／SSRF=DNS プリミティブ確定(実害は DNS 単独で未達)」を追記。
- 教訓: (1) DNS-only OOB は**脆弱性クラスにより実害到達度が異なる**。deser は「ホスト解決＝ガジェット連鎖
  の発火＝コード実行の実測」で impact=True・◎。SSRF は「ホスト解決≠内部到達」で impact=False(判定は正当)。
  DNS 証拠の強さは vuln_type に依存すると認識する。(2) channel 追加(HTTP→DNS)は各 blind エンジンの
  `_build_finding` に channel 分岐を足すだけ＝確定バー無改修で横展開できる。
  [[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・[[skf-labs-ssti-crlf]]。
- 観測(別件): SSRF の DNS リバインドによる内部到達 in-band 実証・自前ホスト interactsh デプロイは deferred。
