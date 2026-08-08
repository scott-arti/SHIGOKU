---
task_id: SGK-2026-0433
doc_type: work_report
status: active
parent_task_id: SGK-2026-0432
related_docs:
- docs/shigoku/plans/done/2026-08-08_sgk-2026-0433_m3a-gap-closure-capability_plan.md
- docs/shigoku/worklogs/2026-08-08_sgk-2026-0433_m3a-gap-closure-auth-setup_work_log.md
title: m3a gap-closure auth-setup 実装報告（sealed Juice Shop A/B provisioning）
created_at: '2026-08-08'
updated_at: '2026-08-08'
tags:
- shigoku
target: tests/fixtures/vdp_juiceshop_sealed
deferred_tasks:
  - deferred_id: SGK-2026-0433-D01
    title: "authz 比較 follow-up の結合検証と封印実測（B 認証 GET で A resource 比較 → S10 独立証拠）"
    reason: "本ターンは auth-setup（pre-run provisioning）実装まで。比較 follow-up は engine 側の既存 comparison lane との結合検証と、封印コンテナでのライブ実測が必要（plan 完了条件2・3・6 の残 scope）"
    impact: high
    tracking_task_id: SGK-2026-0433
    recommended_next_action: "0433 plan の残 scope として、認証済み比較 follow-up の検証と sealed live run 実測を実施"
  - deferred_id: SGK-2026-0433-D02
    title: "timing 基盤（insufficient_timing_validation gap-closure）"
    reason: "repeat/timing control による timing 差 marker の取得は本ターン対象外（plan 完了条件4 の残 scope）"
    impact: medium
    tracking_task_id: SGK-2026-0433
    recommended_next_action: "0433 plan の残 scope として実装"
---

# 作業完了報告: SGK-2026-0433（auth-setup 実装 slice）

## 0. 対象と方法

0433 plan（m3a gap-closure 能力拡張）のうち、**認可エンベロープ承認済みの auth-setup 能力**（テスト用アカウント A/B の register/login provisioning）を実装。
**src/ 配下は一切変更なし**（engine は既存 comparison lane のまま）。変更は全て sealed fixture + テスト + harness スクリプト。

## 1. 変更内容（ファイル）

| ファイル | 変更 | 内容 |
|---|---|---|
| `tests/fixtures/vdp_juiceshop_sealed/auth_setup_config.json` | 新規 | 製品固有 provisioning config（register POST `<opaque register endpoint>`・login POST `<opaque login endpoint>`・token path `<opaque json_path>`・bearer・id_factory）。tests/fixtures は preflight token scan 対象外（src/ には製品パス無し。具体パスは fixture 内のみ） |
| `tests/fixtures/vdp_juiceshop_sealed/auth_setup.py` | 新規 | stdlib-only provisioning モジュール。`AuthSetupGuard`（fail-closed allowlist: A/B register/login のみ、注入可能 transport）、provisioning フロー、0600 session env 書き出し、redaction（sha256 digest のみ出力） |
| `tests/fixtures/vdp_juiceshop_sealed/run_m5_audit.sh` | 編集 | docstring/env 契約更新・**phase 6d（auth-setup, pre-run）**追加（main runner と同一の docker run パターン: `--network container:$TARGET_CONTAINER` + proxy env + NO_PROXY、失敗時 die＝fail-closed）・main runner に `--env-file $M5_OUT/session_env.txt` 追記（不在時 WARN のみ） |
| `tests/unit/engine/test_vdp_auth_setup_guard.py` | 新規 | guard fail-closed・provisioning・redaction/0600・config schema・CLI fail-closed の 30 テスト（fake transport のみ・実通信なし） |

## 2. 安全不変条件の実証

- **guard fail-closed**: allowlist は config のみから構築（register A/B・login A/B）。method/path/body が 1 つでも逸脱すれば `AuthSetupRejected` が **transport 呼び出し前に** 発生（テストで fake transport の calls == 0 を assert）。
- **m3a は GET-only 維持**: auth-setup は pre-run provisioning phase（phase 6d）のみ。run 本体（phase 7）の挙動は不変。
- **secret 境界**: 値の write 先は 0600 session env ファイルのみ（atomic replace 書き出し）。stdout/stderr は sha256 digest のみ（captured output に値が無いことをテストで assert）。エラーは **status + 固定ラベル**のみで response body を含めない（フォローアップで redact/truncate 方式から strict 化）。
- **実ターゲット非接触**: テストは全て fake transport。実コンテナへの auth-setup 実行は行っていない（封印 harness 実測は D01 で追跡）。
- **PCR-P1 / src/ 無改変**: `git status` で src/ 配下の変更ゼロ。

## 3. 検証（実測コマンドと結果）

```text
.venv/bin/pytest tests/unit/engine/test_vdp_auth_setup_guard.py -q
  → 30 passed in 0.12s
.venv/bin/pytest tests/unit/reporting/test_vdp_juiceshop_sealed_cases.py -q
  → 56 passed, 1 skipped in 0.24s（既存 sealed case テスト無回帰）
bash -n tests/fixtures/vdp_juiceshop_sealed/run_m5_audit.sh
  → SYNTAX OK
git diff --check
  → clean
docs: sync_shigoku_updated_at.py → validate_shigoku_docs.py（後述・0 issue）
```

## 4. 完了条件判定（plan 契約との対応）

plan 必須テスト 1（auth-setup が A/B register/login POST のみ・他は fail-closed）: **PASS**（38 テスト）。
plan 必須テスト 6（封印 harness 実測とテストの両方）: テスト側は PASS、**封印実測は未実施**（実コンテナ必須のため本ターン対象外 → D01）。

**in_scope_blocker 0件**。deferred_followup: D01（比較 follow-up 結合検証 + sealed live 実測）・D02（timing 基盤）。non_blocking_observation なし。
本 slice は完了（plan は active のまま、残 scope は 0433 plan で追跡）。

## 5. レビュー・フォローアップ適用（2026-08-08 追記）

独立レビューの 6 指摘を全て適用（挙動・既存テストは維持、新テスト 8 件追加 → 計 38 件）:

1. **redirect 非追従（fail-closed 強化）**: `_urllib_transport` を `_NoRedirectHandler`（`redirect_request()` が任意 3xx で `AuthSetupError` を送出）付き opener に変更。307/308 が POST body（credential）を未検証 Location へ再送する経路を遮断。加えて応答 `geturl()` が要求 URL と一致しない場合も `AuthSetupError`（belt and braces）。
2. **harness fail-open 解消**: run_m5_audit.sh で `session_env.txt` 不在時の WARN→run 継続を `die`（abort）に変更。
3. **partial credential fail-closed**: id/secret の片方のみ提供時は `AuthSetupError`（暗黙の生成にフォールバックしない）。4 組み合わせをテスト。
4. **error message の body 完全除去**: 旧 redact/truncate 方式（prefix 断片漏洩リスク）を廃止し、status + 固定ラベル `(response body omitted)` のみ。`_safe_body_summary`/`REDACT_MARK` 削除。
5. **session env 書き出しの atomic 化**: 同ディレクトリの temp ファイルへ書いて chmod 0600 → `os.replace()`。中間状態・読取可能な残骸なし（テストで temp 残骸ゼロを assert）。
6. **timeout 余裕**: harness phase 6d の `timeout 120` → `timeout 180`。

検証: `.venv/bin/pytest tests/unit/engine/test_vdp_auth_setup_guard.py -q` → 38 passed / sealed cases 56 passed, 1 skipped / bash -n OK / `git diff --check`（本タスク変更分スコープ）clean。src/ 無改変は維持（src/core/engine/vdp_follow_up_executor.py は他エージェントの並行変更のため diff 全体チェックは一時的に不可）。
