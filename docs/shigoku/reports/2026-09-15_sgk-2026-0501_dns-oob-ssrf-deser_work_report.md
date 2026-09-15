---
task_id: SGK-2026-0501
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-15_sgk-2026-0501_dns-oob-ssrf-deser.md
- docs/shigoku/worklogs/2026-09-15_sgk-2026-0501_dns-oob-ssrf-deser_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0500_dns-oob-receiver.md
tags:
- shigoku
- detection
- oob
- dns
- ssrf
- deserialization
- confirmation-bar
created_at: '2026-09-15'
updated_at: '2026-09-15'
---

# SGK-2026-0501 作業完了報告 — DNS-OOB を SSRF/deser へ横展開（deser=◎・SSRF=プリミティブ確定）

## 何をしたか / なぜ

SGK-2026-0500 で新設した DNS OOB 受信器を、既存 blind エンジンへ**プロバイダ差し替えだけ**で
広げる設計を、SSRF と deserialization で実証。両エンジンの PoC は OOB ブロックを HTTP 形式で
固定していた（`interaction.channel` 未使用）ため、XXE と同型に **channel 対応**へ改修した。

## 実装（非凍結2・凍結0）

- **smart_blind_ssrf.py（非凍結）**: `_build_finding` に `channel` 変数を追加し、`channel=="dns"` のとき
  OOB ブロックを「権威 DNS が受けた DNS クエリ（QNAME＋送信元）」として提示（HTTP 行を混ぜない）。
  impact/title/description も DNS 用に分岐。`oob_evidence.channel` に実チャネルを反映。
- **smart_blind_deser.py（非凍結）**: 同上。DNS では届いた複数 DNS クエリを QNAME 行で列挙し、
  Java の場合はガジェット内 URL のホスト解決が JVM の URLClassLoader/ServiceLoader 由来である旨を明記。
- **凍結（payout_grade / sealed_reproduction_checker）は無改修**。汎用マーカー
  `oob_interaction_received` が `token in interaction.path` で DNS でもそのまま発火する設計を再確認。

## 結果（独立検証・Claude が実測）

受信器を wcp イメージ（py3.7）で :53 にコンテナ起動し、標的を `docker --dns=<受信器>` で名前解決を向けた
（コンテナ間は非 firewall・SGK-2026-0500 と同 topology）。

- **deserialization（DNS-only 真ブラインド）= ◎**: 実 `java-des-yaml` ラボで `SmartOOBDeserHunter`
  （java_snakeyaml・base64・path モード）が DNS プロバイダ差し替え・**エンジン本体無改修**で finding 生成。
  GATE1 `payout_grade=True/oob_interaction_received` → GATE2 封印再現 matched（新 token 再送→標的再解決→
  再記録）→ GATE3 実 poc_judge **3回連続 is_real=True/impact=True/counter=False/needs_human=False**。
  審査理由「ガジェット内 URL のホスト解決＝逆シリアライズとガジェット連鎖の発火そのもの・token は送信
  ペイロードにのみ存在＝RCE 級の実測」。**完全3ゲート＝◎**。
- **SSRF（DNS-only）= プリミティブ確定（◎ 未達・honest）**: 実 `ssrf` ラボ（form `url`）で
  `SmartBlindSSRFHunter` が DNS プロバイダ差し替え・無改修で finding 生成。GATE1=True・GATE2 matched・
  GATE3 実 poc_judge **3回連続 is_real=True だが impact=False**（needs_human=False）。審査理由「サーバ側で
  URL ホスト名の名前解決が行われた実在性は妥当だが、in-band は 200 空でブラインド・示されているのは
  『DNS 解決が発生した』事実のみ。内部到達/データ取得/メタデータ/ポートスキャン等の実害は未実測で仮定に
  留まる」。**curve-fit で覆さず honest に一段下げて記録**（SSRF の完全な実害確定は HTTP コールバックの
  SGK-2026-0495 で既に ◎）。
- テスト: 新規 DNS チャネルテスト2件（ssrf/deser 各 `test_dns_channel_renders_dns_framed_poc`）緑。
  既存 HTTP 経路（SSRF/deser/XXE）非回帰。回帰: 失敗3件は本変更前でも失敗する既存（phase_b×2・
  t3_hybrid budget＝作業成果物欠如）＝**0501 起因の回帰ゼロ**（1358 passed）。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）exit 0（無改変）。凍結（payout_grade/sealed）
  **無改修**。製品非依存トークン0・秘密値非露出。

## 確度の結論（正直な格付け）

- **DNS-only 真ブラインド deserialization（RCE 級）＝ ◎（完全3ゲート）**。curve-fit なし。
- **DNS-only 真ブラインド SSRF ＝ プリミティブ確定（is_real＋封印再現＋機械フロア）だが実害は DNS 単独で
  未実証**（poc_judge impact=False が正当）。DNS 解決は「サーバがホスト名を解決した」ことは示すが
  「内部到達」までは示さない。**この差は本質的**（deser は解決＝コード実行連鎖の発火／SSRF は解決≠内部到達）。
- 設計実証: 新チャネル（DNS）を**エンジン本体・確定バー無改修**で 2 エンジンに横展開＝「受信器差し替えで
  無改修」の設計が正しいことを再確認。

## 完了条件の充足

計画の完了条件 1・2・4 を充足。条件3（SSRF）は「影響格付けは実測に従う」と明記した通り、DNS 単独では
実害未達を honest に記録（実在性は通過）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（実対象到達の証明・一ファイルの挙動を仕様と
しない）、`rules/codingrules.md`（秘密非露出・明示タイムアウト）、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。

## 非阻害の観測（deferred / 別件）

- SSRF の DNS-only 実害昇格（DNS リバインドで内部 IP へ解決させ内部到達を in-band 実証）は
  `deferred_followup`。自前ホスト interactsh デプロイ（:53・委譲ドメイン）も別途（SGK-2026-0500 と同じ）。
