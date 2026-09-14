---
task_id: SGK-2026-0500
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0500_dns-oob-receiver.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0500_dns-oob-receiver_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- oob
- dns
created_at: '2026-09-14'
updated_at: '2026-09-15'
---

# SGK-2026-0500 作業ログ（DNS OOB 受信器・真ブラインド拡張・◎）

## 1. 偵察・環境制約(事実優先・実測)
- OOB 基盤は HTTP のみ(:13337)。DNS-only 真ブラインド未対応。
- dnspython 未導入・:53 は root 必要・bridge→host 高ポートは firewall 不通(HTTP ラボが --network host を
  要したのと同根)。→ 受信器は依存ゼロで実装、ローカルは受信器をコンテナ :53 起動＋標的 docker --dns。

## 2. 台帳・計画・承認
- SGK-2026-0500 採番(registry.yaml・DOC-0570)。DNS OOB 受信器の選択=ビルド承認(凍結0)。

## 3. 実装(Claude 直接)
- dns_oob_listener(新規・stdlib のみ): UDP DNS サーバ・QNAME 自前解析・token 記録・良性 A 応答・port 可変。
- oob_provider: LocalDNSOOBProvider(channel=dns・new_callback は URL http://<token>.<domain>/ か hostname・
  poll は問い合わせ FQDN を path に写像=汎用マーカー無改修で発火)を additive 追加。
- smart_blind_xxe: PoC を channel 対応(DNS は QNAME+送信元の DNS クエリ行として提示・HTTP 行混在なし)。
- 凍結ファイル(payout_grade/sealed)は無改修=汎用マーカー+プロバイダ seam で DNS 対応が通る設計を実証。

## 4. 独立検証(Claude・実出力)
- プロトコル: 実 UDP で DNS クエリ→受信器が記録・良性応答・provider.poll が path に FQDN 写像を確認。
- 実対象: 受信器をコンテナ :53 で起動→SKF xxe ラボを --dns=<受信器> で起動→blind XXE 外部実体
  http://<token>.oob.test/ を送信→標的が名前解決→受信器が RECV <token>.oob.test from <lab-ip> を記録。
- GATE1 payout_grade=True/oob_interaction_received。GATE2 sealed matched(新 token 再送→標的再解決→再記録)。
- GATE3 poc_judge 初回 False(PoC が HTTP 形式・received_at:None・DNS...HTTP/1.1 不整合)→DNS 専用フレーミング
  修正で連続5回 True/True(is_real/impact・counter False)。
- 新規単体テスト(listener/provider/blind XXE DNS PoC)緑。既存 HTTP blind XXE 非回帰。凍結3 exit0。

## 5. 完了
- 完了条件1〜5充足。in_scope_blocker 0 → done。
- 能力マップ: OOB 基盤に DNS 受信器を追記(真ブラインド拡張・DNS-only ◎)。
- 教訓: (1) OOB 到達不通は標的でなく**受信器の到達性/ルーティング**を先に疑う(bridge→host firewall・:53
  特権)。ローカル DNS は受信器をコンテナ :53 で動かし標的を docker --dns で向ける(コンテナ間は非 firewall)。
  (2) チャネル追加(HTTP→DNS)は汎用マーカー(token in path)+プロバイダ seam で**凍結0改修**で通る=受信器
  差し替え設計が正しい。(3) OOB PoC は**チャネル整合**が必須(DNS を HTTP 形式で書くと judge が不整合として
  却下)。(4) 受信器は依存ゼロ(stdlib の UDP+自前 QNAME 解析)で書ける。
  [[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・[[skf-labs-ssti-crlf]]。
- 観測(別件): 他 blind エンジン(SSRF/deser)の DNS PoC・自前ホスト interactsh デプロイ(:53・委譲ドメイン)・
  DNS 応答での exfil(TXT)は deferred。
