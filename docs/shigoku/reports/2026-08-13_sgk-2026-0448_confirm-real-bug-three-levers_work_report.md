---
task_id: SGK-2026-0448
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-13_sgk-2026-0448_confirm-real-bug-three-levers.md
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0447_real-caido-rerun-and-fake-proxy-guard.md
- docs/shigoku/worklogs/2026-08-13_sgk-2026-0448_confirm-real-bug-three-levers_work_log.md
created_at: '2026-08-13'
updated_at: '2026-08-13'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- confirmation
- sealed-run
deferred_tasks:
- id: SGK-2026-0448-D01
  summary: Phase-2/LLM 生成 finding（SmartSQLiHunter 等）が PoC 対＋firing marker（sql_error）を持つ一方 impact/reproduction_steps 空で missing_impact に落ちる。STEP 3 実測で sqli 候補 b41d9c6e47cd が該当。レバー2 の機械的 impact 埋めパターンを specialist 生成 finding へ拡張する（同一バーのまま対処可能）。
  tracking_task_id: SGK-2026-0442
- id: SGK-2026-0448-D02
  summary: authz_diff 候補は単一封印 GET 再現では再現不能（2アカウント証明が必要・sealed_reproduction_checker 設計 fail-closed）のため確定に到達しない。GET-only エンベロープ内で確定を目指す場合の再現設計の見直しを判断する。
  tracking_task_id: SGK-2026-0442
- id: SGK-2026-0448-D03
  summary: 0447 D-B4-1（mass_assignment discovery 経路の ReadonlyEnforcedError サイレントスキップ・検知欠落）は継続追跡（本タスクで変更なし・送信ゼロで安全）。
  tracking_task_id: SGK-2026-0442
---

# 作業完了報告: SGK-2026-0448 — 本物の対象で「確定1件」を実際に出すための3レバー

（親ロードマップ: SGK-2026-0442。前提 0447=done で攻撃が本物 Juice Shop に到達済み。本タスクは「届いた上で確定=0 のまま」の原因を 3 レバーに切り分けて潰す。）

## 1. 変更要約

### フェーズ0（STEP 1・コード変更なし・設計承認必須ゲート）
- 本物 Caido（127.0.0.1:8081）経由・本物 Juice Shop（localhost:3000）・GET-only・diagnostics ON で封印 run を 1 回実行（`session_20260813_223445`）。preflight PASS（TCP/GraphQL/Forwarding）・consistency consistent。
- 候補単位トレース表（5 候補）で 3 レバーを判定:
  - **レバー1 confirmed**: ログ `Early return (phase1_early_return)` ×3。legacy フラグ経路（`manager.py:3249-3252` の `early_return_enabled` 既定 `not phase1_coverage_mode` = bbpt で True）が発火し、payout-grade 未成立候補（F4 evidence_insufficient）があるのに Phase-2 を打ち切り。`payout_grade_hold` は auto 経路のみをゲート。
  - **レバー2 confirmed**: broken_access_control 2 件が authz_differential の signals 要件を満たし firing marker `authz_diff` 一致するのに `impact=''`/`reproduction_steps=[]` で `missing_impact`（`payout_grade.py:451`）。
  - **レバー3 否定**: T3 pass は早期終了判定より前（`manager.py:3290`）に配線済み・全候補は機械フロアで再現段階に未到達。authz_diff の単一 GET 再現不能は設計 fail-closed。→ スコープ除外。
- 設計案を提示 → **ユーザー承認** → STEP 2 へ。

### STEP 2（承認後・confirmed レバーのみ実装）
- **レバー1**: `manager_internal/execution_policy.py` に `should_early_return_phase2()` を additive 追加（オプトイン `phase1_early_return_require_payout_grade` 既定 False → 既存 run バイト等価。ON + `payout_grade_hold=True` で legacy 早期終了も保留し Phase-2 実行）。`manager.py:3292` の分岐を同関数へ置換。
- **レバー2**: 新規 `manager_internal/authz_fields.py`（`authz_signals_satisfied` / `build_authz_impact_and_reproduction_steps`。signals 充足時のみ、検出済み事実（method/url/認証あり・なしの status）を機械的に言語化。2 分岐: both_ok=未認証アクセス許可 / status_improved_with_auth=認証必須。未達は `(None,None)` fail-closed）。配線: manager.py 3 箇所（unauthenticated_api_access / unauthenticated_discovered_api_access / authenticated_overposting_requires_auth_context・status 役割明示）+ idor.py `_run_unauth_check` のみ。
  - **object_ab_idor_probe は配線しない**: `build_authz_differential` は「test リクエスト成功」を無条件に `unauth_success` と命名するため、両プローブ認証済みの object_ab では述語が誤発火し偽の「未認証アクセス許可」impact を捏造しうる。実測レビューで発見し配線除外（guard コメント付き）。
- **payout_grade.py は diff 0 バイト**（3条件 AND・marker 語彙・impact 定義すべて無変更）。PCR-P1 対象ファイル無変更。

### STEP 3（確定 run・検証）
- `master_conductor.py` の 2 タスク生成箇所（scenario_probe params / signal_task_params）へ一時的に `phase1_early_return_require_payout_grade: True` を追加 → 封印 run 1 回（`session_20260813_232923`）→ **byte-exact 復元**（sha256 `f923709f…` 一致・git diff 0）。
- 結果: funnel `by_reason {task_suppressed_ownership: 2, phase2_skipped_early_return: 1}`（**フェーズ0 の 3 → 1**）。authz 2 件が **payout_grade PASS**（impact+repro 3 件機械埋め・実 URL・200/200）。cors 3 件は Phase-2 実行（早期終了なし）。Phase-2 で新規 sqli 候補 `b41d9c6e47cd` が生成（実 Payload `/rest/products/search?q=' OR '1'='1' --` で 500 実応答・marker sql_error 発火・impact 空で missing_impact）。
- 完了判定: **(a) 確定 0 件**（誤確定ゼロ維持）→ **(b) 候補単位 fail-closed 説明で条件 3 を満たす**（authz 2 件は再現裏取りが設計 fail-closed（2アカウント証明）・cors 3 件は marker 語彙外（NOT in scope）・sqli 1 件は impact 欠落の正当な保留）。いずれも「バーを下げれば確定する」類ではない。
- Haddix 初期リリースゲート: **fail**（`confirmed_below_minimum` / `candidate_above_maximum` / `unexpected_missing_scenarios` 4 件＝phase-0 と同一セット）。ゲートは fail-closed 設計であり本タスク契約 (b) と整合（ゲートポリシー変更はスコープ外・fail-closed として正しい）。

## 2. 検証（証拠付き）

| 項目 | 結果 |
|---|---|
| 確定 run | `session_20260813_232923`・preflight PASS・consistency **consistent**（exit 0） |
| funnel 変化 | `phase2_skipped_early_return` 3 → **1**（レバー1）・authz missing_impact 2 → **payout_grade PASS 2**（レバー2） |
| 必須テスト | `.venv/bin/pytest tests/core/agents/swarm/injection/ -q` → **555 passed**（対象スライス 64 passed 含む） |
| バー無改変 | `git diff src/core/agents/swarm/injection/payout_grade.py` = **0 バイト** |
| 製品独立 | `.venv/bin/python scripts/check_vdp_product_independence.py --manifest config/diagnostics/product_independence_manifest_v1.json --denylist config/diagnostics/sealed_product_denylist.txt` → **pass / exit 0**（6/6・total_token_hits 0） |
| PCR-P1 | 対象テストファイル変更なし（git diff 0） |
| GET-only | evidence の request_method は **GET のみ**・OPTIONS 17 件が B4 境界でブロック（両 run とも） |
| secret | 生値 0（mask-and-restore 維持） |
| commit | なし（HEAD `1e1744c` のまま） |
| 一時パッチ復元 | `master_conductor.py` sha256 一致・git diff 0 |
| run 副作用 | `data/vuln_roi_db.json` / `wordlists/custom/learned_params.txt` 変更（報告のみ・commit 対象外） |

## 3. 完了契約（計画書 §完了条件）との対照

| 条件 | 判定 |
|---|---|
| 1. フェーズ0トレース表 + 各レバー confirmed/否定更新 | ✅（計画書「フェーズ0結果」節） |
| 2. confirmed レバー修正 + payout_grade.py 無改変 | ✅（STEP 2・diff 0） |
| 3. 封印 run で (a) 確定1件以上 または (b) 候補単位 fail-closed 説明 | ✅ (b) |
| 4. 必須テスト全 pass | ✅ 555 passed |
| 5. 安全境界（vdp 独立 exit 0 / PCR-P1 diff 0 / secret 0 / 非 GET 0） | ✅ |
| 6. docs 整合（sync → validate 0 エラー） | ✅ |

## 4. 変更ファイル

- `src/core/agents/swarm/injection/manager_internal/execution_policy.py`（+31: `should_early_return_phase2`）
- `src/core/agents/swarm/injection/manager_internal/authz_fields.py`（新規: signals 述語 + 機械的 impact/repro 生成）
- `src/core/agents/swarm/injection/manager.py`（+50: import・早期終了分岐置換・authz 3 箇所配線・object_ab 配線除外 guard コメント）
- `src/core/agents/swarm/logic/idor.py`（+16/-1: `_run_unauth_check` 配線のみ）
- `tests/core/agents/swarm/injection/test_execution_policy.py`（+76: `should_early_return_phase2` 5 件）
- `tests/core/agents/swarm/injection/manager_internal/test_authz_fields.py`（新規: helper 2 分岐・未達系・idor 配線・object_ab guard 記録）
- docs: 計画書（フェーズ0/STEP2/STEP3 追記 → `done/` へ移動）・本報告書・作業ログ・registry/ledger 更新

## 5. 最終監査分類（§19）

### in_scope_blocker: 0 件

### deferred_followup
- **SGK-2026-0448-D01**: Phase-2/LLM 生成 finding の impact 欠落（実測: sqli `b41d9c6e47cd`）。レバー2 の機械的埋め拡張を追跡タスクで設計判断。
- **SGK-2026-0448-D02**: authz_diff の単一封印 GET 再現不能（設計境界）→ 確定に届かない構造。GET-only エンベロープ内での再現設計見直しを追跡。
- **SGK-2026-0448-D03**: 0447 D-B4-1 継続（mass_assignment discovery のサイレントスキップ）。

### non_blocking_observation
- **O1**: `candidate_ledger.json` は cross-run 成果物（前 run の状態を持ち越す。例: cors `b7aa7f57bce4` が run3 由来 refuted 表示）。run 単位の真実は funnel/session を使用。
- **O2**: F0 `task_suppressed_ownership` で 2 候補が F2 前に抑制（両 run 共通・既存動作・本タスクスコープ外）。
- **O3**: Haddix 初期リリースゲート fail は `confirmed_below_minimum` / `candidate_above_maximum` / `unexpected_missing_scenarios`（phase-0 と同一セット）による fail-closed 設計どおりの結果。ゲートポリシー変更はスコープ外。
- **O4**: run 副作用 `data/vuln_roi_db.json` / `wordlists/custom/learned_params.txt`（commit 対象外・ユーザー判断）。

## 6. 参考ルール
`rules/lessons.md`（2026-08: 1ファイル断定禁止・pii_masker 正・sealed-run 実到達証明）、`rules/report-session-consistency.md`、`rules/cli-ops-routing.md`、`rules/python-tests.md`、`rules/shigoku-docs.md`、`rules/task-ledger.md`、AGENTS.md §8/§19
