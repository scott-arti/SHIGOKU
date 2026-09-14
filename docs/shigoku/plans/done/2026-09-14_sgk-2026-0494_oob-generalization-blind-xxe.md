---
task_id: SGK-2026-0494
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0494_oob-generalization-blind-xxe_work_report.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0494_oob-generalization-blind-xxe_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0493_subdomain-takeover-detection.md
tags:
- shigoku
- detection
- oob
- xxe
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0494 計画 — OOB(帯域外)検出基盤の汎化＋blind XXE を実対象で本物確定（◎）

## 背景・方針（ユーザー指示）

ブラインド脆弱性（in-band に何も返らない）は「標的が我々の管理する受信器へ外向きコールバックするか」
だけが手がかり。ユーザー指示：受信器は差し替え可能な `OOBProvider` 抽象化にし（宛先を変えるだけ）、
当面は自前ローカル HTTP 受信（`LocalOOBListener`）で進める。将来ベストは自前ホスト interactsh
（DNS＋HTTP・公開）だが無改修で差し込める設計にする。加えて Placeholder は影響なければ削除。

## 事実（偵察で実測）

- 受信器は3つ存在：`utils/oob_listener.py`（`LocalOOBListener`・実 HTTP・:13337・master_conductor/
  smart_sqli/oob_verifier に配線済＝実質メイン）、`tools/oob/interactsh_client.py`（BBOT 経由・公開
  interactsh.com・BBOT 未導入でガード）、`detection/oob_correlator.py`（poll/start_server が **Placeholder**・
  本番未使用・唯一の consumer は統合テスト1メソッド）。
- 実測：SKF xxe ラボに外部実体 `SYSTEM "http://<受信器>/callback/<token>"` を送ると XML パーサが
  我々の受信器を fetch＝一意 token 到達（blind XXE OOB 成立）。ただし docker コンテナ→host:13337 は
  firewall で不通のため、ローカルデモは lab を `--network host` で起動しラボ→`127.0.0.1:13337` を通す
  （＝実インターネット標的には公開受信器が必要という裏付け）。

## 対象（完了契約）

1. Placeholder の `oob_correlator.py` を削除（consumer は統合テスト1メソッドのみ→外科除去）。
2. `OOBProvider` 抽象化＋`LocalOOBProvider`（自前 HTTP 受信）を新規整備（受信器差し替え可能）。
3. **blind XXE** を実 SKF ラボで **機械フロア＋実再現＋実 poc_judge の完全3ゲート**で ◎。確定は
   「我々が生成した一意 token をペイロード（外部実体 URL）に埋めて送り、標的が我々の受信器へその
   token でコールバックした」ことで行う（vuln_type 横断の汎用 OOB マーカー）。非破壊。

## 実装方針（新設＋承認済み凍結2）

1. **`detection/oob_provider.py`（非凍結・新規）**: `OOBProvider` Protocol＋`LocalOOBProvider`
   （`LocalOOBListener` ラッパ・`new_callback()->(url,token)`・`poll(token)->interaction`・`callback_base`
   で到達可能アドレスに差し替え可）。旧 `oob_correlator.py` は削除。
2. **`injection/smart_blind_xxe.py`（非凍結・新規）**: `SmartBlindXXEHunter`。provider から一意
   コールバック発行→外部実体 `SYSTEM "<callback>"` を含む XML を form/raw モードで送信→poll で token
   到達を確認→確定。`self._client`／`self._oob` 注入 seam。`oob_evidence`（token/callback/payload/
   interaction）＋`oob_replay`（{OOB} プレースホルダ入りテンプレ）＋raw な OOB inbound リクエストを
   載せた poc＋`unique_oob_callback_received`。製品固有ハードコードなし。
3. **`payout_grade.py`（凍結・承認）**: `_match_firing_marker` の**先頭に vuln_type 横断の汎用 OOB
   分岐**（token 非空＋token が payload に実在＋interaction_received＋受信 path に token 実在→
   `oob_interaction_received`。1つでも欠ければ通常 in-band 経路へフォールバック＝fail-closed・既存不変）。
4. **`sealed_reproduction_checker.py`（凍結・承認）**: `oob_provider` seam を `__init__` に追加＋
   `oob_interaction_received` dispatch＋`_check_oob_replay`（新 token＋新コールバックで payload_template を
   埋めて 1 回再送→受信器で再観測→matched・async 受信器を専用スレッド内 asyncio.run で回す・GET でなく
   POST・fresh token 隔離）。

## 完了条件

1. `oob_correlator.py` 削除＋統合テスト外科除去で collection/他テスト維持。
2. 実 SKF xxe ラボで実 `SmartBlindXXEHunter.execute` が blind XXE を OOB で自走検出→
   payout_grade=True/oob_interaction_received。
3. 実 `SealedReproductionChecker`（oob_provider 注入）が新 token で再送し受信器再観測→matched→CONFIRMED。
4. 本物の poc_judge（実 LLM）で承認（生の OOB inbound リクエスト＋token 相関を提示）。
5. 製品非依存 fixture の新規テスト緑（provider 実自己コールバック／engine OOB 確定・非到達で不確定／
   payout_grade 汎用 OOB 発火・fail-closed 各否定側／sealed OOB matched・mismatched・not_run）。
6. 凍結3 exit 0。製品トークン 0・秘密値非露出・回帰ゼロ。

## NOT in scope

- DNS-only OOB（DNS 受信器プロバイダ）・自前ホスト interactsh（公開・DNS＋HTTP）の実装＝別タスク
  （抽象化は差し替え可能に設計済み）。blind SSRF/OOB SQLi/デシリアライズへの適用は本基盤で後続。
- パイプライン自動走行への統合。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（実対象到達の証明・一ファイルの挙動を仕様と
しない）、`rules/codingrules.md`（bare except 禁止・秘密非露出・境界のみ noqa・明示タイムアウト）、
メモリ [[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。
