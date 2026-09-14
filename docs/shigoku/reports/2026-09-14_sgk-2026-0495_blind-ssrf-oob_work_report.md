---
task_id: SGK-2026-0495
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0495_blind-ssrf-oob.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0495_blind-ssrf-oob_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0494_oob-generalization-blind-xxe.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- ssrf
- oob
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0495 作業完了報告 — Blind(OOB) SSRF を実対象で本物確定（◎・OOB 基盤の横展開）

## 何をしたか / なぜ

SGK-2026-0494 の OOB 基盤（`OOBProvider`＋`LocalOOBProvider`＋汎用マーカー `oob_interaction_received`＋
`_check_oob_replay`）を横展開し、**blind SSRF を完全3ゲートで ◎**。SSRF は「サーバがリクエスト中の URL を
fetch するが結果を返さない」ため、我々の OOB 受信器を fetch 先に指定し token 到達で確定。宛先を変える
だけ＝新エンジンは Finding を作るだけ・payout_grade は不変（汎用 OOB マーカーが vuln_type=ssrf でそのまま
発火）。

## 事実（偵察で実測）

- **SKF ラボ `ssrf`**（Flask）を `--network host` で起動。`POST /check_existence` form `url` を
  `validators.url` 検証後 `requests.head(url, timeout=2)` でサーバ側 fetch（結果は "found/reacheable" 等の
  文言のみ・内容非返却＝実質ブラインド）。URL パラメータに OOB コールバックを入れると標的サーバが
  `HEAD /callback/<token>` で我々の受信器へ到達＝blind SSRF OOB 成立。

## 実装（新設1＋承認済み凍結1・最小）

- **smart_blind_ssrf.py（非凍結・新規）**: `SmartBlindSSRFHunter`。OOB provider から一意コールバックを
  発行し、候補 URL パラメータ（url/uri/target/webhook/… 汎用）× モード（form/query/json）に callback を
  入れて送信→poll で token 到達を確認して確定。`self._client`／`self._oob` seam。`oob_evidence`（token/
  callback/payload＝token を含む送出値）＋`oob_replay`（mode/param/payload_template="{OOB}"）＋**生の OOB
  inbound リクエストを載せた poc**。製品固有ハードコードなし・非破壊。
- **payout_grade.py：改変なし**（汎用 OOB マーカー `oob_interaction_received` は vuln_type 横断で ssrf も
  既存カテゴリのため発火経路に乗る＝基盤の再利用）。
- **sealed_reproduction_checker.py（凍結・承認）**: `_check_oob_replay` に **query（GET）/ json（POST）
  モードを追加**（従来 form/raw に加え）。SSRF の URL パラメータ再現に対応（SKF は form だが実標的の
  `?url=`／`{url:}` への汎用性のため）。

## 結果（独立検証・Claude が実測）

- **実 SKF ssrf ラボ**で実 `SmartBlindSSRFHunter.execute` が blind SSRF を OOB で自走検出（form/param=url・
  標的サーバから `HEAD /callback/<token>` が受信器へ到達・in-band は空）→`payout_grade=True/
  oob_interaction_received`→**実 `SealedReproductionChecker`（oob_provider 注入）が新 token で再送し受信器で
  再観測→matched→CONFIRMED**。
- **本物の poc_judge（実 LLM）で 5/5 承認**（is_real=True・has_actual_impact=True・counter=False）。審査理由は
  「form field url に指定した一意 token 付き callback URL に対し、標的サーバ自身（User-Agent: python-requests）
  から `HEAD /callback/<token>` が我々の OOB 受信器へ到達＝サーバ側 fetch の実測」。**完全3ゲート達成＝◎**。
- テスト: 新規9テスト（blind SSRF engine 5＝OOB 確定・非到達で不確定・query/json replay 記述子・poc 形式／
  sealed OOB query モード matched を既存 sealed OOB テストに追加）緑。非回帰: 失敗3件は本変更前でも失敗する
  既存（phase_b×2・t3_hybrid budget）＝**0495 起因の回帰ゼロ**（1302 passed）。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）exit 0。**payout_grade も本タスク不変**
  （汎用 OOB マーカー再利用）。承認済凍結1（sealed_reproduction の query/json 追加）は承認範囲の追加のみ。
  製品非依存 token 0・trailing whitespace 0・秘密値非露出。

## 確度の結論（正直な格付け）

- **blind SSRF（OOB）＝実害あり**で実 poc_judge も通り **◎（完全3ゲート）**。curve-fit なし（汎用 OOB
  マーカーは fail-closed・乱数 token 相関・エンジンは製品固有ハードコードなし）。SSRF 全体は in-band（0482）
  ＋blind/OOB（0495）の2形態で **高度化 中(L2)**。
- **戦略的意義**: OOB 基盤の横展開が最小コスト（新エンジン＋query/json モード追加のみ・payout_grade 不変）で
  成功。同型で OOB SQLi / デシリアライズも追加可能。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の実 poc_judge を 5/5 で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（実対象到達の証明）、`rules/codingrules.md`
（bare except 禁止・秘密非露出・境界のみ noqa・明示タイムアウト）、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。

## 非阻害の観測（deferred / 別件）

- DNS-only OOB・自前ホスト interactsh・OOB SQLi/デシリアライズへの適用・compose 標的（crAPI 等）での
  reachability・パイプライン統合は本タスク対象外（`deferred_followup`）。
