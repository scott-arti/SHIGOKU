---
task_id: SGK-2026-0507
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-16_sgk-2026-0507_registered-hunter-primary-path-wiring.md
- docs/shigoku/reports/2026-09-16_sgk-2026-0507_registered-hunter-primary-path-wiring_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- primary-dispatch
created_at: '2026-09-16'
updated_at: '2026-09-17'
---

# SGK-2026-0507 作業ログ（登録ハンターの本流相乗り配線）

## 1. 発見（本流の実測）

- `_process_single_url` の vuln_type 分岐が本流。unknown 経路は既定で分類のみ（0504/0506 配線は未発火）。
- 実 session（session_20260902_014352.json）で分類器は api/sqli/cors/... を割当（nosql/blind_sqli 無し）。

## 2. 実装（Claude 直接）

- `HunterSpec.attach_vuln_types` 追加（nosql→api・blind_sqli→sqli）。
- `_process_single_url` の dispatch 直後に汎用 attach ループ（`_run_registered_hunter` を相乗り実行・
  `attached:<key>:start` を trace 記録）。凍結バー/分類器/既存分岐は無変更。

## 3. 検証

- 単体4件緑（sqli→blind_sqli / api→nosql / xss→非起動 / メタデータ）。injection 961 passed（既存T3失敗のみ）。
- ハーネス（実 _process_single_url × 実 Juice Shop）: `attached:blind_sqli:start` 発火を確認（ただし
  スタンドアロンはガード policy_unavailable で実トラフィックはブロック）。
- 実自律走行: `--mode vulntest`（internal/test 対象の正路）で preflight 通過・InjectionSwarm 稼働。
  ログに `Delegating nosql check to SmartNoSQLHunter (registry hunter)` ×4 ＝本流 attach の end-to-end 実発火を確定。

## 4. 環境知見（次回のため）

- Juice Shop 等 localhost/テスト対象は **`--mode vulntest`** で走らせる（bugbounty はプログラム用ガード
  バンドル必須で未整備なら `policy_unavailable`／ctf は InjectionSwarm 除外）。
- 対象 URL は scheme 明示（`http://localhost:3000`）＝forward probe の SSL 誤判定回避。

## 5. 完了

- CB-1〜CB-5 充足（CB-5 は nosql 実発火で実証）。`in_scope_blocker` 0件。work_report/log 作成・
  計画書を done/ へ移動・registry status=done・台帳再生成してクローズ。blind_sqli 固有の実走行観測と
  残ハンター相乗りは work_report の deferred_tasks に記載。
