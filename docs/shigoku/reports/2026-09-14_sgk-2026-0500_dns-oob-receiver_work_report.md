---
task_id: SGK-2026-0500
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0500_dns-oob-receiver.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0500_dns-oob-receiver_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
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

# SGK-2026-0500 作業完了報告 — DNS OOB 受信器（真ブラインド拡張）を新設し実対象で DNS-OOB を完全3ゲート確定（◎）

## 何をしたか / なぜ

OOB 基盤（SGK-2026-0494）は HTTP 受信のみで、真ブラインド（標的が外向き HTTP を出せないが DNS 解決は
する／DNS でしか漏れない）を拾えなかった。**依存ゼロの DNS OOB 受信器**と `OOBProvider` 実装を新設し、
既存 blind エンジンが**プロバイダ差し替えだけ**で DNS-only を確定できることを実対象で実証した
（[[detection-capability-wiring-map]] の「受信器は差し替え可能・エンジンは宛先しか見ない」設計の実証）。

## 実装（新設2＋非凍結1・凍結0）

- **utils/dns_oob_listener.py（非凍結・新規）**: 標準ライブラリのみの UDP DNS サーバ。受信クエリの QNAME を
  自前解析し token を含む問い合わせを記録・良性 A 応答（0.0.0.0）を返す（リゾルバのリトライ回避・非破壊）。
  ポート可変（本番 :53）・`generate_hostname()`＝`<token>.<domain>`・`get_interactions()` は部分一致でも走査。
- **detection/oob_provider.py（非凍結）**: `LocalDNSOOBProvider`（channel="dns"・new_callback は既存エンジン
  互換の URL `http://<token>.<domain>/`（`hostname_only` でホスト名）・poll は受信 DNS クエリの **FQDN を
  `path` に写像**）を additive 追加。**payout_grade は無改修**（汎用マーカー `oob_interaction_received` は
  `token in interaction.path` で発火するため DNS でもそのまま通る）。
- **agents/swarm/injection/smart_blind_xxe.py（非凍結）**: PoC 生成を **channel 対応**に（DNS のときは「権威
  DNS が受けた DNS クエリ（QNAME＋送信元）」として提示・HTTP 行を混ぜない）。impact/title/description も DNS 版。
- **凍結ファイルは一切変更なし**（payout_grade.py / sealed_reproduction_checker.py も無改修）。

## 結果（独立検証・Claude が実測）

- **受信器**: 実 UDP で DNS クエリを解析・記録し良性応答を返すことを確認（単体テスト・プロトコルレベル）。
- **実対象 DNS-OOB（真ブラインド）**: SKF `xxe` ラボを `docker --dns <受信器>` で起動し、blind XXE の外部実体
  `SYSTEM "http://<token>.oob.test/"` を送ると、**標的の XML パーサがホスト名を名前解決し、その DNS クエリ
  （token を含む FQDN）が受信器に到達**（in-band は 500・空＝真ブラインド）。実 `SmartBlindXXEHunter`（DNS
  プロバイダ差し替え・エンジン無改修）が finding を生成。
  - **GATE1 `payout_grade=True/oob_interaction_received`**（DNS interaction・token in path）。
  - **GATE2 封印再現 matched**（新 token で再送→標的が再解決→受信器が新 token を再記録＝**DNS 上の実 live
    再現**）。
  - **GATE3 実 poc_judge を 5/5（連続 5 回すべて is_real=True・has_actual_impact=True・counter=False）**。
    初回は PoC を HTTP 形式のまま出して却下（`received_at:None`・`DNS ... HTTP/1.1` 不整合）→**DNS 専用
    フレーミング**（QNAME＋送信元の DNS クエリ行）に修正して安定 True。
- **設計実証**: DNS 対応は**凍結ファイル 0 改修**（汎用 OOB マーカー＋プロバイダ seam）で達成＝受信器差し替え
  だけで新チャネルが通る設計が正しいことを確認。
- テスト: 新規（DNS listener の QNAME 解析/記録/良性応答/ホスト名発行/部分一致・DNS provider のプロトコル
  充足/new_callback/poll の path 写像・blind XXE の DNS チャネル PoC フレーミング）緑。既存 HTTP blind XXE
  経路は非回帰。凍結3 exit 0（無改修）。製品トークン0・秘密値非露出。

## 確度の結論（正直な格付け）

- **DNS OOB（真ブラインド）＝ 実対象で完全3ゲート ◎**（受信器コードは本物・DNS クエリは実標的からの実測・
  live 封印再現も DNS 上で成立・実 poc_judge 5/5）。curve-fit なし（payout_grade/sealed 無改修・汎用マーカー・
  PoC は実 DNS クエリ）。**高度化 中(L2)**。
- **正直な運用スコープ**: インターネット標的での運用は**権威 DNS を自ドメインに委譲し :53 で受ける**デプロイ
  （自前ホスト interactsh 相当）が必要。本タスクは受信器コード＋プロバイダ＋実対象実証まで。ローカル実 E2E の
  封印再現は、host firewall（bridge→host 不通）・:53 特権・no-root のため、受信器を**コンテナで :53 起動**し
  `docker logs` 経由でポーリングするシムを用いた（**受信器コードは本物・DNS クエリも実標的からの実測**・シムは
  ローカル topology のポーリング手段のみ）。本番は `LocalDNSOOBProvider` が自プロセス内受信器を直接ポーリング
  （シム不要）。この topology 制約は能力の限界ではなくローカル検証環境の制約。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（実対象到達の証明・受信器の到達性を先に疑う）、
`rules/codingrules.md`（bare except 禁止・秘密非露出・境界のみ noqa・明示タイムアウト・stdlib のみ）、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。

## 非阻害の観測（deferred / 別件）

- SSRF/deser 等 他 blind エンジンの DNS 対応 PoC フレーミング（XXE と同型で追加可能）・自前ホスト interactsh
  デプロイ（DNS+HTTP・公開・:53・委譲ドメイン）・DNS 応答での data exfil（TXT 等）は `deferred_followup`。
