---
task_id: SGK-2026-0461
doc_type: work_report
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/2026-08-29_sgk-2026-0461_browser-evidence-confirm-enforce.md
- docs/shigoku/worklogs/2026-08-29_sgk-2026-0461_option-b-confirm-enforce_work_log.md
title: Option B（凍結バー自身の確認で保存型XSSを formal confirmed に）実装 作業完了報告
created_at: '2026-08-29'
updated_at: '2026-09-01'
tags:
- shigoku
- vdp
- xss
- stored
- t3-hybrid
- confirmation
- gate
---

# SGK-2026-0461 作業完了報告 — Option B（browser_evidence スコープの確認フロー起動 + 封印再現配線 + poc_judge 頑健化）

## What（何をしたか）

計画書（B）で確定した真因（`_t3_apply_hybrid_verdict` が `settings.t3_hybrid_enabled`（既定 False）でゲートされ、実走行で確認フローが一度も起動しない → `hybrid_final_state=None` → canonical 候補）に対し、**確定バー5ファイル無改変**のまま以下を実装した。

### 1. 確認フローの起動（browser_evidence スコープ・自動検知）

- `src/core/config/settings.py`（+5行・`t3_hybrid_enabled` 直後）: `t3_hybrid_browser_evidence_auto: bool = True` を追加（kill-switch。既定 True で browser_evidence 実在時のみ確認フローをスコープ起動）。
- `src/core/agents/swarm/injection/manager.py`:
  - `_t3_browser_evidence_auto_active(findings)`（+20行）: 明示 override（`hybrid_enabled=...`）優先（fail-closed）→ kill-switch → `_t3_browser_evidence_trigger` が非空の finding が 1 件でも実在するか。
  - `_t3_run_hybrid_pass` ゲート変更（-2/+22行）: `explicit_active or auto_active`。**自動起動時は判定対象を browser_evidence を持つ finding に限定**（通常走行を過負荷にしない。明示 `t3_hybrid_enabled` 時は従来どおり全 finding 判定）。browser_evidence 無しの走行は従来どおり OFF（byte-identical）。

### 2. 封印再現（stored 分岐）の full pipeline 配線

- `manager.py` の `SealedReproductionChecker` 構築に `masker=get_pii_masker()` を追加（0439 token_map 復元。マスク済 URL を `masked_url_unresolvable` の not_run に落とさない）。network_client / scope_definition / time_budget_seconds=600 は SGK-2026-0452（承認E）済みの既存配線を維持。checker 本体（stored/dom browser re-execution・`_check_dom_via_browser`）はバー無改変。

### 3. poc_judge のロバスト化（バー無改変・判定緩め禁止）

- **新規** `src/core/agents/swarm/injection/poc_judge_robust.py`（193行）:
  - `_BoundedLLMClient`: LLM generate 1 回の timeout を 90s に強制（11分ループ防止）。応答 content に `_salvage_json_object` を適用（best-effort・ここでは raise しない）。
  - `_salvage_json_object`: 全体 json.loads → コードフェンス除去 → 先頭 `{...}` のバランス走査 → 抽出 JSON のパース検証。捏造なし・失敗は None。
  - `RobustPoCJudge`: `PoCJudge(client=_BoundedLLMClient(LLMClient(role="poc_judge")))` を遅延構築。`max_attempts=2` のリトライは **ValueError（JSON パース不能）のみ**。正当な却下（パース成功・payout_grade=false）は raise しないため決して再試行しない。全試行失敗は ValueError → 既存 wiring が ai_judge=None → needs_more（fail-closed）。
- `manager.py` の既定 judge を `RobustPoCJudge()` に変更し、明示予算 `PoCJudgeBudget(max_calls=6, max_seconds=480)` を設定（11分ループ防止・超過時 JudgeBudgetExhausted → needs_more。決して confirmed を偽装しない）。注入済み judge は従来どおり優先。

## Validation（実コマンド出力・そのまま）

- `$ .venv/bin/pytest tests/core/agents/swarm/injection/test_t3_hybrid_wiring.py tests/core/agents/swarm/injection/test_poc_judge_robust.py tests/core/validation/test_sealed_reproduction_checker.py -q`
  - 出力: `105 passed in 1.90s`（うち新規18件: `TestT3BrowserEvidenceAuto` 7件 + `TestRobustPoCJudge` 11件）
- `$ .venv/bin/pytest tests/core/agents/swarm/injection/ tests/core/validation/ -q`
  - 出力: `791 passed, 2 failed in 13.05s`。失敗2件は `test_phase_b_readiness.py`（`juice_shop_demo/tagged_urls`・`admin_test_results.json` の実体ファイル存在検査）。当該プロジェクトディレクトリは本環境に存在せず、テストファイルは本変更と無関係（HEAD で同じ経緯の既知環境依存）。**本変更起因の失敗ゼロ**。
- `$ git diff --quiet HEAD -- src/core/agents/swarm/injection/payout_grade.py src/prompts/roles/poc_judge.md src/core/engine/task_queue.py src/core/validation/finding_validator.py src/core/validation/sealed_reproduction_checker.py && echo BAR_UNCHANGED`
  - 出力: `BAR_UNCHANGED`（確定バー5ファイル無改変）
- `$ python3 scripts/check_initial_release_gate.py --report workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md`
  - 出力: `status: fail` / `reason_codes: ["candidate_above_maximum"]` — **変更前と完全同一**。5候補の reason code 不変（`payload_request_mismatch,untested_no_second_account` / `authz_impact_not_proven` / `untested_no_second_account` / `public_data_cross_origin_read` / `state_change_not_verified`）。DVWA 既知安全保留は confirmed に昇格していない（browser_evidence 無・機械フロア非充足のため確認フローは起動しない）。
- `$ python3 scripts/verify_report_session_consistency.py --report workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md`
  - 出力: `status: consistent` / `rerun_required: false`
- `$ python3 scripts/check_vdp_product_independence.py --manifest config/diagnostics/product_independence_manifest_v1.json --denylist config/diagnostics/sealed_product_denylist.txt`
  - 出力: `verdict: pass` / `total_token_hits: 0`（checks 6/6 ok・changed_files_input=4（新規2ファイル含む）・closure 31）

## 完了契約との対応（SGK-2026-0461 計画書・B 改訂）

- CB2（確定バー5ファイル無改変）: **PASS**（BAR_UNCHANGED）。finding 側の PoC 証拠運搬配線は既存（SGK-2026-0458/0459 の stored_revisit スキーマ・0455 の browser_execution 可視化）を活用。
- CB4（製品非依存 token0・新規/変更ユニット緑）: **PASS**（verdict pass / token_hits 0・対象ユニット 105 passed・広域 791 passed で本変更起因失敗ゼロ）。
- CB3（実運用に乗る: 判定の安定性・所要時間）: **ユニットレベル PASS**（per-call 90s タイムアウト・バウンド付きリトライ・6コール/480s 明示予算で 11分ループを構造的に防止。正当な却下の再ロールなし）。実走行での所要時間は下記 deferred（Claude 実走行で最終確認）。
- CB1（保存型XSSが凍結バー自身の確認を通り `hybrid_final_state="confirmed"` → canonical formal confirmed=1）: **実装は到達可能な状態。実走行での最終確認は未実施**（下記 deferred・ユーザー実走行で検証）。凍結バーの3条件ANDのうち:
  1. 機械フロア `evaluate_payout_grade` → フェーズ0ハーネスで payout_grade=True 実証済み。
  2. poc_judge（LLM）→ 本実装でパース/リトライ/タイムアウトを頑健化。**ただし判定自体はバーに委ねており、過去実データでは保存型XSS finding（id=0d6bd9d501b3）に `ai_no_prize_grade`（パース成功・payout_grade=false）を返した記録が candidate_ledger.json に残っている**。判定緩め・再ロールは禁止のため、Claude の実走行で judge が false を返した場合は confirmed は正当に不成立（fail-closed）となり、その場合の次手（証拠表現の改善等）は本スコープ外（`_build_user_payload` は凍結）の追跡タスクとなる。
  3. 封印再現（stored 分岐・browser re-execution）→ 実 target live 時のみ実行。network_client/scope/masker/time_budget は配線済み。target 停止中は browser 再ロード不可のため not_run（fail-closed）。

## Risks / 未達（正直な開示）

- **実走行未実施（本ターンは環境要因で不可）**: 練習台（127.0.0.1:5008）・Caido（127.0.0.1:8081）・Juice Shop（localhost:3000）は全て停止中（`ss -tln` で非リスニング確認済み）。練習台アプリの起動方法はリポジトリ内に無く（`Practice Feedback` Flask アプリのソースはプロジェクト外）、本ターンでは実走行を実施できなかった。下記コマンドでユーザー（Claude）が実走行検証する前提。
- **judge の past verdict**: 上記 CB1-2 のとおり、実 judge（deepseek-v4-flash・poc_judge role）は過去実データで保存型XSSに payout_grade=false を返した実績がある。本実装は「判定への到達の頑健化」であり「判定結果の変更」ではない。confirmed=1 は judge の正当受理が前提。
- **自動起動の範囲**: browser_evidence を持つ finding が 1 件でもあれば確認フローは起動するが、判定対象は browser_evidence のみに限定（過負荷防止）。それ以外の finding は従来どおり 0441 ゲートの候補（不変）。

## deferred_tasks

```yaml
deferred_tasks:
  - description: "CB1 実走行最終確認（ユーザー担当）: クリーン練習台 127.0.0.1:5008（最新1件保持・latest-only）でフル走行（`.venv/bin/python -m src.main --target http://127.0.0.1:5008 --mode vulntest`、Caido=127.0.0.1:8081 起動状態・SHIGOKU_T3_HYBRID_ENABLED は不要＝browser_evidence 自動起動）し、保存型XSS（variant=stored・dialog_observed=True）が hybrid_final_state=confirmed → canonical formal confirmed=1・混入0・正常完了（ウォッチドッグ内）を確認。あわせて candidate_ledger.json で当該 finding の state=confirmed を確認。"
    tracking_task_id: SGK-2026-0461
    tracking_doc: docs/shigoku/plans/2026-08-29_sgk-2026-0461_browser-evidence-confirm-enforce.md
  - description: "実走行で poc_judge が保存型XSSに payout_grade=false を返した場合の対応（本スコープ外）: `_build_user_payload`（凍結 finding_validator.py）は poc_request/poc_response しか judge に渡せず、stored の「再訪レンダーで発火した実測」は browser_execution の事実サブフィールドのみ。もし judge が false を返し続けるなら、証拠表現の改善（例: 再訪レスポンスボディの写像追加）を別タスクとして起票する（判定緩め・プロンプト改変は禁止）。"
    tracking_task_id: SGK-2026-0461
    tracking_doc: docs/shigoku/plans/2026-08-29_sgk-2026-0461_browser-evidence-confirm-enforce.md
```

## Next step

1. ユーザー（Claude）の実走行検証（上記 deferred-1 のコマンド）で CB1 を最終確認。
2. CB1 確認後、SGK-2026-0461 を done 化（plan を done/ へ移動・台帳更新）。

## 参考ルール

rules/lessons.md（バー無改変・fail-closed・一ファイル断定回避・sealed run の REAL target 到達検証）、rules/codingrules.md（局所変更・エラーハンドリング・秘密境界）、rules/task-ledger.md、rules/shigoku-docs.md、rules/python-tests.md、rules/report-session-consistency.md、CLAUDE.md §17/§19。
