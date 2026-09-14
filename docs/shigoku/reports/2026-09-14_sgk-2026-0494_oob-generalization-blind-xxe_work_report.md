---
task_id: SGK-2026-0494
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0494_oob-generalization-blind-xxe.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0494_oob-generalization-blind-xxe_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0493_subdomain-takeover-detection.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- oob
- xxe
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0494 作業完了報告 — OOB(帯域外)検出基盤の汎化＋blind XXE を実対象で本物確定（◎）

## 何をしたか / なぜ

ブラインド脆弱性（in-band に何も返らない）は「標的が我々の管理する受信器へ外向きコールバックするか」
だけが手がかり。ユーザー指示に沿い、受信器を差し替え可能な `OOBProvider` 抽象化に統一（宛先を変える
だけ・将来は自前ホスト interactsh を無改修で差込）、当面は自前ローカル HTTP 受信で **blind XXE を
完全3ゲートで ◎**。あわせて Placeholder の死んだ scaffolding を削除。

## 事実（偵察で実測）

- 受信器は3つ存在：`LocalOOBListener`（実 HTTP・:13337・master_conductor/smart_sqli/oob_verifier 配線済＝
  実質メイン）、`interactsh_client`（公開 interactsh.com・BBOT 未導入でガード＝実働せず）、
  `oob_correlator.py`（poll/start_server が **Placeholder**・本番未使用・consumer は統合テスト1メソッド）。
- 実測：SKF xxe ラボに外部実体 `SYSTEM "http://<受信器>/callback/<token>"` を送ると XML パーサが
  我々の受信器を fetch＝一意 token 到達（blind XXE OOB 成立）。docker コンテナ→host:13337 は firewall で
  不通のため、ローカルデモは lab を `--network host` で起動しラボ→`127.0.0.1:13337` を通した
  （＝実インターネット標的には公開受信器が必要という戦略的裏付け）。

## 実装（新設2＋承認済み凍結2＋Placeholder 削除）

- **Placeholder 削除**: `detection/oob_correlator.py`（Placeholder・本番未使用）を削除。唯一の consumer
  だった `tests/integration/test_phase_d_implementation.py` の OOB import 1行＋テスト1メソッドを外科除去
  （他 Phase-D テストは維持・collection 正常）。
- **`detection/oob_provider.py`（非凍結・新規）**: `OOBProvider` Protocol＋`LocalOOBProvider`
  （`LocalOOBListener` ラッパ・`new_callback()->(url,token)`・`poll(token)->interaction`・到達可能アドレス
  差し替え用 `callback_base`）。受信器を差し替えれば宛先が変わるだけでエンジン無改修。
- **`injection/smart_blind_xxe.py`（非凍結・新規）**: `SmartBlindXXEHunter`。provider から一意コールバックを
  発行→外部実体 `SYSTEM "<callback>"` を含む XML を form/raw モードで送信→poll で token 到達を確認して
  確定。`self._client`／`self._oob` seam。`oob_evidence`＋`oob_replay`（{OOB} テンプレ）＋**生の OOB
  inbound リクエストを載せた poc**＋`unique_oob_callback_received`。製品固有ハードコードなし・非破壊。
- **`payout_grade.py`（凍結・承認）**: `_match_firing_marker` の**先頭に vuln_type 横断の汎用 OOB 分岐**を
  追加。token 非空＋token が payload に実在（我々が送った証明）＋interaction_received＋受信 interaction.path
  に token 実在（標的からのコールバックが我々の一意 token を運んだ）＝`oob_interaction_received` を発火。
  1つでも欠ければ通常の in-band 経路へフォールバック（fail-closed・既存マーカーは byte 不変）。乱数 token で
  偶然混入・捏造不可。
- **`sealed_reproduction_checker.py`（凍結・承認）**: `__init__` に `oob_provider` seam を追加＋
  `oob_interaction_received` dispatch＋`_check_oob_replay`（新 token＋新コールバックで payload_template を
  埋め封印スコープ内へ 1 回再送→受信器で新 token 再観測→matched。async 受信器を呼び出し元コンテキストに
  依存せず回すため専用スレッド内 `asyncio.run`。送信失敗=not_run／送信成功で非到達=mismatched）。

## 結果（独立検証・Claude が実測）

- **実 SKF xxe ラボ**で実 `SmartBlindXXEHunter.execute` が blind XXE を OOB で自走検出（form モード・
  一意 token が標的から受信器へ到達・in-band は空）→`payout_grade=True/oob_interaction_received`→**実
  `SealedReproductionChecker`（oob_provider 注入）が新 token で再送し受信器で再観測→matched→CONFIRMED**。
- **本物の poc_judge（実 LLM）で 5/5 承認**。（初回は OOB コールバックを `#` コメント要約で書いたため
  「独立検証できない」と正しく 0/5 で却下→**標的が受信器に送ってきた生の inbound リクエスト（method/path/
  source-IP/token）＋token 相関**を raw 提示して 5/5＝poc-judge-raw-evidence の OOB 版・バー非低下。）
  **完全3ゲート達成＝◎**。
- テスト: 新規20テスト緑（provider 実自己コールバック＋protocol／engine OOB 確定・非到達で不確定・poc が
  メソッド/ステータス行開始・生 inbound 掲載／payout_grade 汎用 OOB 発火(xxe/ssrf)・fail-closed 各否定側
  ＝非到達・token 非 payload・token 非 path・空 token／sealed OOB matched・mismatched・not_run(provider なし/
  スコープ外/テンプレ placeholder 無し)）。非回帰: 失敗3件は本変更前でも失敗する既存（phase_b×2・t3_hybrid
  budget・stash 比較で HEAD 同一を確認）＝**0494 起因の回帰ゼロ**（1296 passed）。phase_d は削除後も他テスト
  維持（3失敗は HEAD 同一の env 依存・OOB 無関係）。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）exit 0。承認済凍結2は承認範囲の追加のみ。
  製品非依存 token 0（追加コード・テストは example のみ。SKF/5000/13337 は scratchpad E2E のみ）。
  trailing whitespace 0。

## 確度の結論（正直な格付け）

- **blind XXE（OOB）＝実害あり**で実 poc_judge も通り **◎（完全3ゲート）**。curve-fit なし（汎用 OOB
  マーカーは fail-closed・乱数 token 相関・エンジンは製品固有ハードコードなし）。**OOB は poc_judge に
  受理可能**と実証（生 inbound リクエスト＋token 相関）。**高度化 低(L1)**（HTTP OOB のみ・SKF 単一・
  DNS 受信器と公開受信器＝自前 interactsh は別タスク・未統合）。
- **戦略的意義**: この基盤で **blind SSRF / OOB SQLi / デシリアライズ**も同型（宛先だけ）で ◎ 化可能に
  なった。DNS-only と実インターネット標的は公開受信器（自前 interactsh・DNS＋HTTP）を無改修で差し込む
  設計（別タスク）。

## 完了条件の充足

計画の完了条件 1〜6 をすべて充足（条件4 の実 poc_judge を 5/5 で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（実対象到達の証明・一ファイルの挙動を仕様と
しない）、`rules/codingrules.md`（bare except 禁止・秘密非露出・境界のみ noqa・明示タイムアウト）、
メモリ [[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。

## 非阻害の観測（deferred / 別件）

- DNS-only OOB（DNS 受信器プロバイダ）・自前ホスト interactsh（公開・DNS＋HTTP）・blind SSRF/OOB SQLi/
  デシリアライズへの適用・パイプライン統合は本タスク対象外（`deferred_followup`・抽象化は差し替え可能に
  設計済み）。ローカルではラボ→受信器の到達性に `--network host` 等が要る（実標的は公開受信器が必要）。
