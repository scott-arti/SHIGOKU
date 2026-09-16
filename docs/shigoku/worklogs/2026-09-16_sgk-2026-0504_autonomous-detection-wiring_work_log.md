---
task_id: SGK-2026-0504
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-16_sgk-2026-0504_autonomous-detection-wiring.md
- docs/shigoku/reports/2026-09-16_sgk-2026-0504_autonomous-detection-wiring_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- autonomous-integration
- swarm-wiring
created_at: '2026-09-16'
updated_at: '2026-09-16'
---

# SGK-2026-0504 作業ログ（自律走行への配線土台の一般化・pilot=nosql）

## 1. 棚卸し（読み取り専用・事実確認）

- 自律走行の入口＝`InjectionManagerAgent`（`swarm/injection/manager.py`・`master_conductor` から起動）
  の3点継ぎ目を特定: ①`_initialize_specialists` の `self.specialists` 登録 ②`unknown_hypotheses`＋
  `specialist_router` の signal→hypothesis→specialist 選択 ③`_run_unknown_hypothesis_scans` の dispatch。
- 全ハンタークラスの instantiate 箇所を grep → 新設15ハンターは自モジュール以外で instantiate されず
  ＝入口未配線（`finding.py` の2件はコメント）。下流ゲート（`sealed_reproduction_checker`／
  `payout_grade`）は配線済＝欠けは入口だけ、と確定。

## 2. 台帳・計画

- SGK-2026-0504 を採番し計画書を作成・登録（この過程で registry の mid-list 誤ネスト破損を発見し、
  別タスク SGK-2026-0505 で修復）。

## 3. 実装（Claude 直接・最小差分）

- `hunter_registry.py` 新設（`HunterSpec`＋`NEW_HUNTER_SPECS`＝pilot nosql）。
- `specialist_router.py` の `SPECIALIST_MAP` を `setdefault` で拡張（旧9種不変）。
- `unknown_hypotheses.py` に `nosql` 仮説（`api_json_surface`）追加。
- `manager.py`: importlib＋registry import／登録ループ／汎用 runner `_run_registered_hunter`／
  dispatch の `elif specialist in HUNTER_SPEC_BY_KEY` 分岐。
- 旧9種の `run_*_hunter` と bespoke 分岐は無変更。凍結5ファイル無変更。

## 4. 検証（Claude・実出力）

- 新規テスト10件 green（`test_registry_hunter_wiring.py`）。
- injection スイート 949 passed / 1 failed（唯一の失敗は HEAD でも再現する既存の T3 失敗＝配線非起因、
  変更を stash して確認）。
- `sync_shigoku_updated_at.py`→`validate_shigoku_docs.py` 0エラー（既存の無関係 FM 1件除く）。
- `graphify update .` 実行済（exit 0）。

## 5. 完了

- 完了契約 CB-1〜CB-5 を全て満たし `in_scope_blocker` 0件。work_report／work_log を作成し
  計画書を `done/` へ移動、registry status を `done`、台帳を再生成してクローズ。
- 後続（残り14ハンター配線・第2 dispatch(`vuln_type`)・OOB 受信器統合・実 crAPI 自走E2E認証）は
  work_report の `deferred_tasks` に記載。
