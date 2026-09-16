---
task_id: SGK-2026-0507
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-16_sgk-2026-0507_registered-hunter-primary-path-wiring.md
- docs/shigoku/worklogs/2026-09-16_sgk-2026-0507_registered-hunter-primary-path-wiring_work_log.md
- docs/shigoku/plans/done/2026-09-16_sgk-2026-0504_autonomous-detection-wiring.md
- docs/shigoku/plans/done/2026-09-16_sgk-2026-0506_blind-sqli-autonomous-wiring.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- autonomous-integration
- primary-dispatch
created_at: '2026-09-16'
updated_at: '2026-09-17'
---

# SGK-2026-0507 作業完了報告 — 登録ハンターを本流ディスパッチ(vuln_type 経路)へ相乗り配線

## 何をしたか / なぜ

0504/0506 の `nosql`/`blind_sqli` 配線先（`_run_unknown_hypothesis_scans`）は unknown 経路の非既定
サブパスにしか無く**既定の自律走行で未発火**だった（実 session のグラウンドトゥルースで、分類器は
JSON API→`api`・クエリ param→`sqli` を割り当て、`nosql`/`blind_sqli` の vuln_type は出さないと確認）。
分類器を改造せず、新ハンターを**既存 vuln_type 分岐へ相乗り**させて本流で発火させた。

## 実装（最小差分・additive・分類器/凍結バー無変更）

- `HunterSpec.attach_vuln_types` を追加。`nosql→("api",)`・`blind_sqli→("sqli",)`。
- `_process_single_url` の if/elif/else ディスパッチ直後に、`vuln_type` に相乗り宣言した登録ハンターを
  追加起動する汎用ループを追加（primary hunter の後・findings/tested_params 加算・
  `attached:<key>:start` を attempt_trace に記録）。
- 既存9分岐・分類器・unknown 経路（0504/0506）は無変更。

## 結果（独立検証・Claude が実測）

### 単体テスト
- `test_registered_hunter_primary_dispatch.py`（4件）: `_process_single_url(url,"sqli")`→blind_sqli 起動、
  `(url,"api")`→nosql 起動、`(url,"xss")`→非起動、attach メタデータ。**4 passed**。
- injection スイート **961 passed, 1 failed**（唯一の失敗 `test_t3_hybrid_wiring.py::...` は本変更前(HEAD)でも
  再現する既存失敗＝配線非起因）。

### 実自律走行での確定（CB-5・本丸）
- 実対象 **Juice Shop（http://localhost:3000）** に対し **`--mode vulntest --profile bbpt --fast-iterate`** で
  フル MC 走行（preflight PASSED・ガード有効・InjectionSwarm 稼働）。
  - **注**: `localhost` は internal 判定。bugbounty はプログラム用コンパイル済みガードバンドル必須
    （Juice Shop 用は不在→`policy_unavailable`）、ctf は InjectionSwarm 除外。**vulntest がテスト対象の正路**。
- 実走行ログに **`[InjectionManager] Delegating nosql check to SmartNoSQLHunter (registry hunter, quick_mode=False)` ×4** を観測
  ＝登録ハンター `nosql` が**本流の `api` 相乗り経路で実 dispatch**（ガードブロック無し＝実トラフィック成立）。
  → **attach 機構が実自律走行で end-to-end 発火することを確定。**
- `blind_sqli` は同一の汎用 attach ループ（`sqli` 相乗り・単体テスト実証済）。今回の signal-routing が
  api/cors 中心で `sqli` vuln_type タスクが生成されず未出現＝**ルーティング依存であり配線ではない**
  （機構は nosql 実発火で証明済み）。

## 完了条件の充足

- CB-1（sqli→blind_sqli・api→nosql 起動）／CB-2（無関係 vuln_type 非起動）／CB-3（回帰なし・唯一の失敗は既存）／
  CB-4（マップ更新＋validate 0エラー）: 単体テストで充足。
- CB-5（実対象の自律走行で登録ハンターが dispatch）: **nosql の実発火 ×4 で充足**（本流 attach の end-to-end 実証）。

`in_scope_blocker` は0件。完了契約を満たすため本タスクを `done` とする。

## 参考にしたルール

- `CLAUDE.md` §11〜§19、`rules/codingrules.md`・`rules/python-tests.md`・`rules/lessons.md`
- メモリ [[detection-capability-wiring-map]]・[[no-capability-minimization]]・[[current-phase-autonomous-integration]]

## deferred / 別件（非阻害）

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0507-D01
    title: "blind_sqli の実自律走行での dispatch 観測（sqli vuln_type タスクが出る対象で）"
    reason: "機構は単体テスト＋nosql 実発火で実証済。blind_sqli 固有の実走行観測は sqli 分類タスクの生成に依存（今回の routing は api/cors 中心）。"
    impact: low
    tracking_task_id: SGK-2026-0507
    recommended_next_action: "明確な数値クエリ param(?id=)を持つ練習台で走らせ attached:blind_sqli を観測する"
  - deferred_id: SGK-2026-0507-D02
    title: "残り11ハンターの相乗り宣言（自走適応が genuine に可能なものを1本ずつ・非カーブフィット）"
    reason: "多くは狙い撃ち confirmer でヒント必須。genuine に自走適応できるものだけを載せる。"
    impact: medium
    tracking_task_id: SGK-2026-0504
    recommended_next_action: "各ハンターの execute が URL/recon から自走適応できるか精査し、可能なものだけ attach 宣言＋実走行確認する"
```
