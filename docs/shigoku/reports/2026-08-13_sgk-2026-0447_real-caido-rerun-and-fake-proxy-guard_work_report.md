---
task_id: SGK-2026-0447
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0447_real-caido-rerun-and-fake-proxy-guard.md
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0445_wire-hybrid-judge-into-swarm-live.md
created_at: '2026-08-13'
updated_at: '2026-08-13'
tags:
- shigoku
- vdp
- security-sensitive
- preflight
- sealed-run
---

# 作業完了報告: SGK-2026-0447 — 本物 Caido 経由の正しい再実行 ＋ 偽プロキシ検知ガード

（親ロードマップ: SGK-2026-0442。T3=0445 の封印 run が偽 Caido スタブに全通信を吸われていた問題の是正。）

## 1. 変更要約

### Part A: 偽プロキシ検知ガード（コード）
- **`src/core/preflight/caido_check.py`**（+184・既存メソッド無改変）: `check_forwarding()` を additive 追加。run の in-scope target へ GET 3 本（root + nonce 2 本）を `use_proxy=True`（run と同一プロキシ経路）で送り、全応答の status==200 かつ byte-identical かつ ≤512B → `PROXY_NOT_FORWARDING`（FAIL closed）・例外 → `PROXY_FORWARD_CHECK_FAILED`（fail-closed）・パス依存 → PASS。200 identical >512B は PASS + WARNING（false-negative 可視化）。body 非ログ（status/len/sha256 先頭 12 桁のみ）・target は host:port のみ。
- **`src/core/preflight/entry_gate.py`**（+42）: `_run_caido_check` に `target=context.target` を渡し、TCP→HTTP(identity)→forwarding の順で実行。`snapshot.caido_forward_ok` 追加。
- **`src/core/preflight/models.py`**（+2）: `PreflightSnapshot.caido_forward_ok: bool = False`。
- **`src/core/infra/network_client.py`**（+67）:
  - `skip_guard: bool = False`（additive・preflight 内部プローブ専用・docstring に攻撃コードからの利用禁止明記）— 転送プローブが compiled guard（bugbounty モード・policy 未ロード時の fail-closed block）に呑まれないための唯一の呼び出し箇所（`caido_check.py:_probe_urls` 1 か所のみ・grep 検証済み）。
  - **B4: `ReadonlyEnforcedError(NetworkClientError)`**（reason_code=`READONLY_GET_ONLY_ENFORCED`）+ `sealed_run_get_only` フラグ ON かつ **`use_proxy=True`** かつ GET/HEAD 以外 → 送信前にブロック。use_proxy=False は Caido コントロールプレーン専用（preflight identity / caido_auth / caido_sitemap）として対象外。
- **`src/core/config/settings.py`**（+6）: `sealed_run_get_only: bool = False`（既定 off → 既存 run byte-identical・env `SHIGOKU_SEALED_RUN_GET_ONLY`）。
- **`src/core/agents/swarm/injection/manager.py`**（+220）: mass_assignment 経路で `ReadonlyEnforcedError` を捕捉 → finding を **needs_human**（`LifecycleState.NEEDS_HUMAN` / `hybrid_needs_human`）に写像・candidate_ledger に直接 put（judge 非依存・confirmed に絶対しない・重複防止）。
- テスト: `test_caido_check.py`（+276・mock + 実 fixture サーバー経由）・`test_entry_gate.py`（+91）・`tests/fixtures/proxy_fakes.py`（新規・stdlib のみ・製品非依存）・`test_network_client.py`（+87・B4 7 件）・`test_mass_assignment_readonly.py`（新規 2 件）。

### Part B: 正しい再実行（クリーン run = session_20260813_011154・封印 1 回）
- 設定: `scan.proxy="http://127.0.0.1:8081"` 一時設定（byte-exact 復元 `d8f0f81d…887d` 一致）・env `SHIGOKU_CAIDO__URL=8081`（YAML より優先）・`SHIGOKU_MODE=vulntest`（run6 と同一・compiled guard 非活性）・`SHIGOKU_T3_HYBRID_ENABLED=1`（T3 配線）・`SHIGOKU_DIAGNOSTICS__ENABLED=true`（funnel 記録）・`SHIGOKU_SEALED_RUN_GET_ONLY=1`（B4 ガード）。
- エントリゲート **ON**（`SHIGOKU_SKIP_ENTRY_GATE` 不使用）: `CaidoCheck TCP 8081 reachable` → `GraphQL introspection succeeded` → `Forward: identical 200 body 75002B (>512) → PASS+WARNING` → `Preflight PASSED`。
- 実行: `.venv/bin/python -m src.main --target http://localhost:3000 --mode vulntest --profile bbpt --recon-start-step 1`（1 回）。

## 2. 実測結果（クリーン run = session_20260813_011154）

| 指標 | 結果 |
|---|---|
| 応答が本物 | ✅ finding evidence に実 Juice Shop JSON（Score Board / 商品データ・status 200・実ヘッダ）・75002B HTML・canned 署名ゼロ |
| **funnel（B3 解決）** | ✅ F0:5 / F1:5 / F2:2 / F3:5 / F4:5 / **F5:1** / F6:0（by_reason: phase2_skipped_early_return 3 / task_suppressed_ownership 2） |
| **GET-only（B4 解決）** | ✅ evidence の request_method は **GET のみ 6 件・PATCH/POST/PUT/DELETE 0 件**（run1 は PATCH 13 件 → 0 に）・**OPTIONS 17 件がネットワーク境界でブロック**（mass_assignment discovery の allow-method 探索） |
| confirmed/parked/needs_human | ✅ ledger 16 候補: refuted 1 / inconclusive_parked 8 / needs_more 7 / **confirmed 0 = 誤確定ゼロ** |
| T3 配線 | ✅ poc_judge 1 call・ledger 保存 |
| consistency | ✅ `verify_report_session_consistency.py` exit 0（consistent） |
| config 復元 | ✅ byte-exact（`d8f0f81d…887d` 一致） |
| 秘密 | ✅ canned 署名なし・PII マスク 0 新規・ledger `[PII:` 14 |

### 比較（run1 = session_20260812_234723 → run3 = session_20260813_011154）
- run1（B4 実装前）: **PATCH 13 件が実送信**されていた（mass_assignment recheck・run6 では偽的のため発動せず「GET-only 20/20」に見えていた = 偽の的の数字の別側面を実測で確定）。
- run3（B4 実装後）: PATCH/POST/PUT/DELETE **0 件**・OPTIONS 17 件が境界でブロック → **GET-only 契約をネットワーク境界で強制達成**。

## 3. 検証（§5 完了条件との対照）

| 完了条件 | 判定 | 証拠 |
|---|---|---|
| 1. ガード self-checking (a) ダミー→FAIL (b) 転送→PASS (c) 到達不能→fail-closed (d) 302/404→PASS | **PASS** | 183 passed（mock + 実 fixture サーバー・evaluate_at_layer patch なし = 本番挙動そのまま） |
| 2. GET-only 境界ガード self-checking (a) PATCH/POST/PUT ブロック (b) OFF byte-identical (c) needs_human 写像 | **PASS** | B4 テスト 7 件 + 実測（run3: PATCH 0・OPTIONS 17 ブロック） |
| 3. 正しい再実行・応答が本物・funnel before/after・誤確定 0 | **PASS** | run3 実測（上記 §2） |
| 4. preflight exit 0・PCR-P1 diff 0・consistent・GET-only・実行 1 回・validator 0・秘密漏洩 0 | **PASS** | 183 passed / task_queue 等 diff 0 / consistent / GET-only 実測 / 実行 1 回 / validator 0 / 秘密 0 |

- `skip_guard=True` 呼び出し箇所が転送プローブ 1 か所のみ（grep・ユーザー独立検証対応）✅
- `check_vdp_product_independence.py` → **verdict: pass**（6/6・token hits 0）✅
- 既存 identity/TCP チェック無改変（diff 0）✅

## 4. 最終監査分類（§19）

### in_scope_blocker: 0 件

### deferred_followup
- **SGK-2026-0447-D01**（= レビュー D-B4-1）: mass_assignment discovery ループ（manager.py L2017-2028・L2043-2050）の `except Exception: continue` が `ReadonlyEnforcedError` をサイレントに飲むため、write method が Allow に出ないターゲットでは「状態変更が必要」の検知・needs_human 写像が欠落する（送信はゼロで安全・検知のみ欠落）。実測: run3 で OPTIONS 17 件ブロック（写像なし）。**対応**: 追跡タスク SGK-2026-0442 系で discovery 経路のブロック検知・写像の設計判断。
- **SGK-2026-0447-D02**: run1（session_20260812_234723）は B4 実装前のため PATCH 13 件を実送信した（誤確定ゼロ・confirmed 0 は維持）。run3 で解消済み。run1 の session は証跡として温存。

### non_blocking_observation
- O-B4-1: guard 評価が GET-only ブロックより前 — bugbounty + policy=None では `policy_unavailable` が優先（送信ゼロで安全・vulntest 封印 run では非問題）。
- O-B4-2: RotatingSession（httpx・recon 系）等は AsyncNetworkClient 境界外（計画書スコープ定義どおり・封印 run の完全性は「攻撃送信が全て AsyncNetworkClient 経由」に依存）。
- O1〜O7（前回レビュー指摘・今回の diff で不変）。

## 5. 変更ファイル
- `src/core/preflight/caido_check.py`（+184）・`src/core/preflight/entry_gate.py`（+42）・`src/core/preflight/models.py`（+2）・`src/core/infra/network_client.py`（+67）・`src/core/config/settings.py`（+6）・`src/core/agents/swarm/injection/manager.py`（+220/-2）
- テスト: `tests/unit/preflight/test_caido_check.py`（+276）・`test_entry_gate.py`（+91）・`tests/unit/infra/test_network_client.py`（+87）・`tests/unit/core/agents/swarm/injection/test_mass_assignment_readonly.py`（新規）・`tests/fixtures/proxy_fakes.py`（新規）
- docs: `docs/shigoku/plans/…/2026-08-12_sgk-2026-0447_…md`（done/ へ移動・B3/B4 追記）

## 6. 参考ルール
- `rules/lessons.md`（SGK-2026-0445 canned 応答教訓・マスク原則・ネットワークガードの fail-safe 維持）、`rules/codingrules.md`（additive・fail-closed・エラーハンドリング）、`rules/shigoku-docs.md`（docs 規約）、`rules/task-ledger.md`（完了契約・§19）、AGENTS.md §8（consistency ゲート・§19 分類）
