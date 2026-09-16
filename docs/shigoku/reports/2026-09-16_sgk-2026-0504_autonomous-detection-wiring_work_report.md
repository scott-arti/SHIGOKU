---
task_id: SGK-2026-0504
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-16_sgk-2026-0504_autonomous-detection-wiring.md
- docs/shigoku/worklogs/2026-09-16_sgk-2026-0504_autonomous-detection-wiring_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- autonomous-integration
- swarm-wiring
- phase-b
created_at: '2026-09-16'
updated_at: '2026-09-16'
---

# SGK-2026-0504 作業完了報告 — 自律走行への配線土台の一般化＋pilot=nosql

## 何をしたか / なぜ

フェーズB「自律走行への統合」の土台タスク。棚卸し（読み取り専用）で、直近◎化した新設15ハンターが
自律走行の入口（`InjectionManagerAgent` の登録・routing・dispatch の3点継ぎ目）に未配線＝単体E2Eのみ
であると確定した（下流ゲート＝`sealed_reproduction_checker`／`payout_grade _MARKER_CATEGORIES` は配線済）。
「単発◎でも自走で出せなければ賞金にならない」ため、まず**3点継ぎ目をレジストリ駆動に一般化**し、
新 vuln クラスを1エントリのデータ追加で載せられるようにした。pilot として in-band・受信器不要・既に◎の
`nosql` を配線し、機構が実ハンターを通せることをテストで実証した。旧9種の bespoke 経路は一切変更せず
（挙動不変・回帰ゼロ）。

## 実装（最小差分・追加中心・凍結5ファイル無改変）

- 新規 `manager_internal/hunter_registry.py`: `HunterSpec`（key／module／class_name／hypotheses／
  vuln_name／severity）＋`NEW_HUNTER_SPECS`（pilot=nosql）＋`HUNTER_SPEC_BY_KEY`／`hypothesis_specialist_pairs()`。
- `manager_internal/specialist_router.py`: `SPECIALIST_MAP` をレジストリから `setdefault` で拡張
  （新規 hypothesis 名のみ・旧9種の routing 不変）。
- `manager_internal/unknown_hypotheses.py`: JSON API 面（`api_json_surface`）で `nosql` 仮説を追加。
- `manager.py`: ①`import importlib`＋registry import ②`_initialize_specialists` 末尾にレジストリ登録ループ
  （旧9種と同じ lazy import・`except (ImportError, AttributeError)`・個別失敗は他を止めない）
  ③汎用 runner `_run_registered_hunter`（`run_lfi_check` と同骨格＝`build_hunter_task`→
  `execute_with_retry`→findings 収集→`normalize_findings_additional_info`→`format_simple_hunter_result`
  を specialist_key でパラメータ化）④`_run_unknown_hypothesis_scans` の dispatch ループに
  `elif specialist in HUNTER_SPEC_BY_KEY` 分岐を追加。
- 新規テスト `tests/core/agents/swarm/injection/test_registry_hunter_wiring.py`（10件）。
- 能力マップ [[sgk-2026-0465]] の NoSQL 行と方針を pilot 配線済みに更新。

## 結果（独立検証・Claude が実測）

- 新機構ユニット/統合テスト: `.venv/bin/pytest tests/core/agents/swarm/injection/test_registry_hunter_wiring.py`
  → **10 passed**。fixture ハンターを新登録キーで dispatch できること（nosql 非固有＝汎用）、
  nosql が `api_json_surface` 仮説で選択・起動されること、未登録時は error dict を返すこと、
  `_run_unknown_hypothesis_scans` が登録キーを汎用経路へ流すことを検証。
- 回帰: `.venv/bin/pytest tests/core/agents/swarm/test_injection_manager.py tests/core/agents/swarm/injection/`
  → **949 passed, 1 failed**。唯一の失敗 `test_t3_hybrid_wiring.py::TestT6BudgetExhaustion::
  test_needs_more_still_no_f5_emit` は本変更を stash した HEAD 状態でも同一に失敗＝**既存の失敗**
  （候補ライフサイクル `NEEDS_MORE` vs `inconclusive_parked` 領域・本配線と無関係）。
- ドキュメント: `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py --repo-root .`
  → `REGISTRY_ISSUES=0` / `BROKEN_LINKS=0` / `DEFERRED_LINK_ISSUES=0`（既存の無関係 FM 1件のみ）。
- `graphify update .` 実行済（exit 0）。

## 完了条件の充足

- CB-1（機構ユニット/統合テスト green）: 満たす。
- CB-2（pilot nosql が `api_json_surface` で選択・起動）: 満たす。
- CB-3（旧9種の回帰なし・挙動不変）: 満たす（949 passed・唯一の失敗は既存）。
- CB-4（能力マップ更新）: 満たす。
- CB-5（sync+validate 0エラー）: 満たす（既存の無関係 FM を除く）。
- 検証は**テストと（graphify を含む）実行の両方**をカバー。実対象の自走E2E認証は計画で NOT in scope。

`in_scope_blocker` は0件。完了契約を全て満たすため本タスクを `done` とする。

## 参考にしたルール

- `rules/codingrules.md`（局所・追加中心・過度な抽象化回避・specific `except`）
- `rules/python-tests.md`（新規挙動テスト・`.venv/bin/pytest`・回帰非破壊・分岐網羅）
- `rules/lessons.md`（一ファイルの局所挙動を仕様と断じない→3点継ぎ目の canonical owner を
  manager.py／unknown_hypotheses.py／specialist_router.py で確認）
- `CLAUDE.md` §11〜§19、メモリ [[detection-capability-wiring-map]]

## deferred / 別件（非阻害・後続タスク）

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0504-D01
    title: "残り14ハンターの自律走行配線（1本ずつ）＋各実対象の自走E2E◎認証"
    reason: "土台の一般化と pilot=nosql までが本タスクのスコープ。個別配線は後続。"
    impact: high
    tracking_task_id: SGK-2026-0504
    recommended_next_action: "hunter_registry.NEW_HUNTER_SPECS に1エントリずつ追加し、対象別に自走E2Eで認証する追跡タスクを active で起票する"
  - deferred_id: SGK-2026-0504-D02
    title: "第2 dispatch(vuln_type 経路・manager.py ~4607) と OOB 受信器の自走統合"
    reason: "本タスクは unknown-hypothesis(primary path)のみ一般化。vuln_type 経路と OOB 受信器起動は別。"
    impact: medium
    tracking_task_id: SGK-2026-0504
    recommended_next_action: "vuln_type 経路の汎用化と OOB 受信器(HTTP/DNS)の自走起動を扱う追跡タスクを起票する"
  - deferred_id: SGK-2026-0504-D03
    title: "pilot nosql の実 crAPI フル自走E2E◎認証"
    reason: "target 依存の強い確認。機構は単体テストで実証済み。"
    impact: medium
    tracking_task_id: SGK-2026-0504
    recommended_next_action: "実 crAPI を起動し自走で nosql finding→確定まで目視確認する追跡タスクを起票する"
```
