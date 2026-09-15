---
task_id: SGK-2026-0501
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-15_sgk-2026-0501_dns-oob-ssrf-deser_work_report.md
- docs/shigoku/worklogs/2026-09-15_sgk-2026-0501_dns-oob-ssrf-deser_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0500_dns-oob-receiver.md
tags:
- shigoku
- detection
- oob
- dns
- ssrf
- deserialization
- blind
created_at: '2026-09-15'
updated_at: '2026-09-15'
---

# SGK-2026-0501 計画 — DNS-OOB を SSRF/deser へ横展開

## 背景・事実（偵察で実測）

SGK-2026-0500 で DNS OOB 受信器（`utils/dns_oob_listener`＋`LocalDNSOOBProvider`）を新設し、
blind XXE を DNS-only 真ブラインドで ◎ 化した。そのとき PoC を channel 対応にしたのは
`smart_blind_xxe.py` のみ。`smart_blind_ssrf.py`・`smart_blind_deser.py` は OOB ブロックを
**HTTP 形式で固定**し `interaction.channel` を分岐に使っていない（`channel` を読まず常に
`"channel": "http"` を書く）ため、DNS チャネルの finding を出すと PoC が HTTP 形式になり
poc_judge の channel 整合要件（[[poc-judge-raw-evidence]]）に反する。

## 対象（完了契約）

1. `smart_blind_ssrf.py`・`smart_blind_deser.py` の `_build_finding` を **channel 対応**にする
   （XXE と同型：`interaction.channel == "dns"` のとき DNS クエリ（QNAME＋送信元）として提示し、
   HTTP 行を混ぜない。impact/title/description も DNS 用に分岐。`oob_evidence.channel` に実チャネルを反映）。
2. 実対象で **DNS-only 真ブラインド**を完全3ゲート検証（受信器コンテナ :53＋標的 `docker --dns`）。
   - deser: SKF `java-des-yaml`。SnakeYAML ガジェット内 URL のホスト解決が受信器に到達。
   - ssrf: SKF `ssrf`。form `url` に入れた callback のホスト解決が受信器に到達。
3. 汎用マーカー `oob_interaction_received` が DNS でも発火（**payout_grade・sealed 無改修**）。

## 実装方針（非凍結2・凍結0）

- `smart_blind_ssrf.py`（非凍結）: `channel` 変数を追加し OOB ブロック／impact／title／description を
  DNS 分岐。
- `smart_blind_deser.py`（非凍結）: 同上。DNS では複数 DNS クエリ行を QNAME で列挙。
- 凍結（payout_grade / sealed）は無改修（汎用マーカーが `token in interaction.path` で DNS でも発火）。

## poc_judge 対策（[[poc-judge-raw-evidence]]）

DNS 証拠は DNS クエリ（QNAME＋送信元）として提示し、HTTP 行を混ぜない。

## 完了条件

1. 両エンジンが `channel="dns"` のとき DNS 形式 PoC を出す（HTTP 行を OOB ブロックに混ぜない）。単体テスト緑。
2. deser: 実 `java-des-yaml` を `--dns` で起動→DNS-only 真ブラインドで GATE1/2/3（実 poc_judge）を通す。
3. ssrf: 実 `ssrf` を `--dns` で起動→GATE1/2＋実 poc_judge の実在性を通す。**影響格付けは実測に従う**
   （DNS 解決のみで実害まで実証できない場合は honest に一段下げ、curve-fit しない）。
4. 既存 HTTP 経路（SSRF/deser/XXE）が非回帰。凍結3 exit 0。製品トークン0・秘密値非露出。

## NOT in scope（正直なスコープ）

- SSRF の DNS-only 実害昇格（DNS リバインドで内部 IP へ解決させ内部到達を in-band 実証する等）は別途。
- インターネット標的運用は権威 DNS 委譲（自前ホスト interactsh 相当）が必要＝別途（SGK-2026-0500 と同じ）。
- ローカル封印再現は受信器コンテナを docker logs 経由でポーリングするシムを用いる（受信器コード・DNS
  クエリは本物・SGK-2026-0500 と同じ topology）。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`、`rules/codingrules.md`、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。
