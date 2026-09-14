---
task_id: SGK-2026-0500
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0500_dns-oob-receiver_work_report.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0500_dns-oob-receiver_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0494_oob-blind-xxe.md
tags:
- shigoku
- detection
- oob
- dns
- blind
- infrastructure
created_at: '2026-09-14'
updated_at: '2026-09-15'
---

# SGK-2026-0500 計画 — DNS OOB 受信器（真ブラインド拡張）

## 背景・事実（偵察で実測）

OOB 基盤（SGK-2026-0494）は HTTP 受信のみ（`LocalOOBListener` :13337・`LocalOOBProvider` channel="http"）。
真ブラインド（標的が外向き HTTP を出せないが DNS 解決はする／DNS でしか漏れない）や、DNS-only の
コールバックは拾えなかった。メモリ [[detection-capability-wiring-map]] は「将来は自前ホスト interactsh
（DNS+HTTP）を OOBProvider として無改修で差込」を将来像として記載済み。本タスクはその DNS 受信器を作る。

実測（環境制約）: dnspython 未導入・:53 は特権ポート（root 必要）・docker bridge→host の高ポートは
firewall 不通（HTTP ラボが `--network host` を要したのと同根）。→ 受信器は**依存ゼロ**で実装し、ローカル
実証は受信器をコンテナで :53 起動＋標的を `docker --dns <受信器>` で名前解決させる（コンテナ間は非 firewall）。

## 対象（完了契約）

1. 依存ゼロの DNS OOB 受信器（`LocalDNSOOBListener`）＋ `OOBProvider` 実装（`LocalDNSOOBProvider`,
   channel="dns"）を新設。既存 blind エンジンが**プロバイダ差し替えだけ**で DNS-only を確定できること
   （エンジン無改修・[[detection-capability-wiring-map]] の設計を実証）。
2. 実対象で**真ブラインド DNS-OOB を完全3ゲート**で確認（例: blind XXE の外部実体ホスト名を標的が名前解決
   → その DNS クエリが受信器に到達）。汎用マーカー `oob_interaction_received` を DNS でも発火（**payout_grade
   無改修**＝`token in interaction.path` に問い合わせ FQDN を写像）。

## 実装方針（新設2＋非凍結1・凍結0）

1. **`utils/dns_oob_listener.py`（非凍結・新規）**: 標準ライブラリのみで UDP DNS サーバ。受信クエリの
   QNAME を解析し token を含む問い合わせを記録・良性 A 応答（0.0.0.0）を返す。ポート可変（本番 :53）。
2. **`detection/oob_provider.py`（非凍結）**: `LocalDNSOOBProvider`（channel="dns"・new_callback は既存
   エンジン互換の URL `http://<token>.<domain>/`／`hostname_only` でホスト名・poll は問い合わせ FQDN を
   `path` に写像＝汎用マーカーが無改修で発火）を additive 追加。
3. **`agents/swarm/injection/smart_blind_xxe.py`（非凍結）**: PoC 生成を **channel 対応**にする（DNS のときは
   「権威 DNS が受けた DNS クエリ」として提示。HTTP 形式で書かない＝poc_judge の一貫性要件）。

## poc_judge 対策（[[poc-judge-raw-evidence]]）

DNS 証拠は DNS クエリ（QNAME＋送信元）として提示し、HTTP 行を混ぜない（初回は HTTP 形式のまま出して
`received_at:None`・`DNS ... HTTP/1.1` 不整合で却下された→DNS 専用フレーミングに修正）。

## 完了条件

1. `LocalDNSOOBListener` が実 DNS クエリを解析・記録し良性応答を返す（実 UDP・単体テスト）。
2. `LocalDNSOOBProvider` が OOBProvider を満たし、poll が問い合わせ FQDN を `path` に写像。
3. 実対象（SKF `xxe` ラボ・`--dns` で受信器へ名前解決）で blind XXE の外部実体ホスト名を標的が解決→
   DNS クエリが受信器に到達→GATE1 payout_grade=True/oob_interaction_received→GATE2 封印再現 matched
   （新 token で再送→標的再解決→再観測）→GATE3 実 poc_judge True/True。
4. 既存 HTTP blind XXE 経路が非回帰。DNS 受信器/プロバイダの新規単体テスト緑。
5. 凍結3 exit 0（本タスクは**凍結ファイル無改修**）。製品トークン0・秘密値非露出・回帰ゼロ。

## NOT in scope（正直なスコープ）

- インターネット標的での運用は**権威 DNS を自ドメインに委譲し :53 で受ける**デプロイ（自前ホスト
  interactsh 相当）が必要。本タスクは受信器コード＋プロバイダ＋実対象実証まで（デプロイ topology は別）。
- ローカル実 E2E の封印再現は、firewall/:53/no-root のため受信器をコンテナで動かし docker logs 経由で
  ポーリングするシムを用いる（受信器コードは本物・DNS クエリも本物）。本番は `LocalDNSOOBProvider` が
  自プロセス内受信器を直接ポーリング（シム不要）。
- SSRF/deser 等 他 blind エンジンの DNS 対応 PoC フレーミング（XXE と同型で追加可能）は別途。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`、`rules/codingrules.md`、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。
