---
task_id: SGK-2026-0507
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/reports/2026-09-16_sgk-2026-0507_registered-hunter-primary-path-wiring_work_report.md
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

# SGK-2026-0507 計画 — 登録ハンターを本流ディスパッチ(vuln_type 経路)へ相乗り配線

## 背景・事実（コード＋実 session で実測）

SGK-2026-0504/0506 で `nosql`/`blind_sqli` を配線したが、その配線先
（`_run_unknown_hypothesis_scans` 内の汎用 dispatch）は **unknown 経路の非既定サブパス**
（`unknown_classification_only=False`）にしか無く、**既定の自律走行では発火しない**ことが判明。

本流のハンター実行は `_process_single_url(url, vuln_type, …)` の **vuln_type キー分岐**（manager.py:4628〜）：
- 既知 vuln_type（sqli/xss/lfi/ssti/cors/crlf/redirect/cmd_ssrf/ssrf/csrf/api/admin）→ 各 `run_*_hunter`。
- unknown → 既定で分類のみ（ハンター非実行）。

**実 session の実測（グラウンドトゥルース）**: `workspace/projects/localhost:3000/sessions/
session_20260902_014352.json` の vuln_type 割当は `cors/crlf/api/xss/sqli/csrf/broken_access_control`
で、**`nosql`/`blind_sqli` は無い**。分類器（本タスクでは未変更）は:
- JSON API URL → `vuln_type="api"`（→ `_run_api_minimal_check`。nosql 分岐なし）
- クエリ param → `vuln_type="sqli"`（→ error-based `run_sqli_hunter`。blind_sqli 分岐なし）

## 対象（完了契約）

分類器を改造せず、**新ハンターを既存 vuln_type 分岐へ「相乗り」**させて本流で発火させる:

1. `HunterSpec` に `attach_vuln_types: Tuple[str, ...]` を追加。`blind_sqli → ("sqli",)`・
   `nosql → ("api",)`（それぞれの検出面に一致する既存 vuln_type）。
2. `_process_single_url` の if/elif/else ディスパッチ直後に、`vuln_type` に相乗り宣言した登録ハンターを
   追加実行する汎用ループを置く（primary hunter の後に走り、findings を加算）。
3. 既存の unknown 経路配線（0504/0506）は非回帰で温存（opt-in 時のカバー）。
4. 実対象での自律走行で `nosql`/`blind_sqli` が発火することを実 session で確認（ユーザー実走行）。

## 実装方針（最小差分・additive・分類器非改造）

- `hunter_registry.HunterSpec` に `attach_vuln_types`（既定 `()`）を追加。nosql/blind_sqli に設定。
- `_process_single_url`: if/elif/else の後・`normalize_findings_additional_info` の前に、
  `for spec in NEW_HUNTER_SPECS: if vuln_type in spec.attach_vuln_types and spec.key in specialists:
  await self._run_registered_hunter(...)` を実行し、`findings_count`/`findings_list`/`tested_params` を加算。
- 既存9分岐・分類器・確定バー（凍結）・unknown 経路は無変更。

## 完了条件

- CB-1: `_process_single_url(url, "sqli", …)` が `blind_sqli` を、`_process_single_url(url, "api", …)`
  が `nosql` を、primary hunter の後に追加起動することを単体テストで実証（fixture/mock で確認）。
- CB-2: 相乗り対象外の vuln_type（例 "xss"）では追加起動しないことを確認。
- CB-3: injection スイート回帰なし（既存の pre-existing 失敗を除く）。
- CB-4: 能力マップ更新＋`sync`→`validate` 0エラー。
- CB-5（実対象確認）: ユーザー実走行の session で `nosql`/`blind_sqli` が dispatch されたことを確認
  （attempt_traces もしくは finding で実測）。**これが本タスクの本丸**（単体E2Eでなく本流の実証）。

## NOT in scope（deferred）

- 分類器そのものの拡張（新 vuln_type の発行）— 相乗り方式で不要。
- 残り11ハンターの相乗り宣言（自走適応が genuine に可能なものを1本ずつ・非カーブフィット）。
- OOB 受信器の自走統合・第2の measurement 経路。

## 参考にしたルール

- `CLAUDE.md` §11〜§19、`rules/codingrules.md`・`rules/python-tests.md`・`rules/lessons.md`
- メモリ [[detection-capability-wiring-map]]・[[no-capability-minimization]]・[[current-phase-autonomous-integration]]
