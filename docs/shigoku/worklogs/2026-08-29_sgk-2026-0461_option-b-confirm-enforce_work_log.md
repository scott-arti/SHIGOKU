---
task_id: SGK-2026-0461
doc_type: work_log
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/2026-08-29_sgk-2026-0461_browser-evidence-confirm-enforce.md
- docs/shigoku/reports/2026-08-29_sgk-2026-0461_option-b-confirm-enforce_work_report.md
title: Option B（browser_evidence スコープ確認フロー起動 + poc_judge 頑健化）実装 作業ログ
created_at: '2026-08-29'
updated_at: '2026-09-01'
tags:
- shigoku
- vdp
- xss
- stored
- t3-hybrid
- confirmation
---

# SGK-2026-0461 作業ログ（実装フェーズ・独立検証）

## 2026-08-29

### 実装（確定バー5ファイル無改変・製品非依存・後方互換）

計画書（B・改訂）のフェーズ0結論（真因 = `_t3_hybrid_active()` の settings ゲートで確認フローが実走行で一度も起動しない）に対し、以下を実装した。

1. **`src/core/config/settings.py`**（+5行）
   - `t3_hybrid_browser_evidence_auto: bool = True` を追加（browser_evidence 自動起動の kill-switch）。

2. **`src/core/agents/swarm/injection/manager.py`**（+44/-7行）
   - `_t3_browser_evidence_auto_active(findings)` を追加（override 優先 → kill-switch → browser_evidence trigger の存在）。
   - `_t3_run_hybrid_pass`: ゲートを `explicit_active or auto_active` に変更。自動起動時は判定対象を browser_evidence finding に限定。browser_evidence 無し走行は従来 OFF（byte-identical）。
   - 既定 judge を `RobustPoCJudge()` に変更 + `PoCJudgeBudget(max_calls=6, max_seconds=480)` の明示予算。
   - `SealedReproductionChecker` 構築に `masker=get_pii_masker()` を追加（0439 token_map 復元）。

3. **`src/core/agents/swarm/injection/poc_judge_robust.py`**（新規・193行）
   - `_salvage_json_object`（全体パース → フェンス除去 → 先頭 `{...}` バランス走査 → 検証。捏造なし）。
   - `_BoundedLLMClient`（per-call timeout 90s clamp + 救済適用。best-effort・raise しない）。
   - `RobustPoCJudge`（ValueError のみ max 2 試行。正当な却下は再試行しない。全試行失敗は ValueError → needs_more）。

4. **テスト（18件追加）**
   - `tests/core/agents/swarm/injection/test_t3_hybrid_wiring.py` + `TestT3BrowserEvidenceAuto` 7件（OFF 維持 / 自動起動 confirmed / スコープ限定 / kill-switch / override 優先 / masker 配線 / RobustPoCJudge+予算構築）。
   - `tests/core/agents/swarm/injection/test_poc_judge_robust.py`（新規）`TestRobustPoCJudge` 11件（クリーンパース / 前後散文 / フェンス / 複数オブジェクト先頭 / リトライ / fail-closed / 正当却下の再試行なし / timeout clamp / 予算連動 / マスク）。

### 独立検証（実コマンド出力・そのまま）

- 対象ユニット: `105 passed in 1.90s`（t3_hybrid_wiring 46 + poc_judge_robust 11 + sealed_reproduction 48）。
- 広域（injection/ + validation/ ディレクトリ）: `791 passed, 2 failed in 13.05s`。失敗2件は `test_phase_b_readiness.py` の環境依存（`juice_shop_demo` 実体ファイル不存在）で本変更起因ではない。
- 確定バー: `BAR_UNCHANGED`（5ファイル diff 0）。
- DVWA ベースライン: gate `fail / candidate_above_maximum`（5候補・reason code 不変）・`consistent / rerun_required=false`。
- 製品非依存: `verdict: pass / total_token_hits: 0`。
- 実走行: 本ターンは環境要因（練習台 127.0.0.1:5008・Caido 127.0.0.1:8081 停止中）で未実施。ユーザー（Claude）が実走行で CB1 を最終確認する。

### 実データ診断（本実装の前提確認）

- `workspace/projects/127.0.0.1:5008/sessions/session_20260829_005742.json`（run 95a2ff0f）: 保存型XSS finding（id=0d6bd9d501b3・variant=stored・dialog_observed=True・test_url=http://127.0.0.1:5008/）に `hybrid_final_state: None` — 確認フロー未起動（真因どおり）。
- `candidate_ledger.json`: 同 finding の record は `state=needs_more / reason=ai_no_prize_grade / budget_used=1` — フェーズ0の T3 有効走行で judge が**パース成功のまま payout_grade=false** を返した実績。判定緩め・再ロールは禁止のため、実走行の confirmed=1 は judge の正当受理が前提（work_report Risks に記載）。

## 参考ルール

rules/lessons.md、rules/codingrules.md、rules/task-ledger.md、rules/shigoku-docs.md、rules/python-tests.md、rules/report-session-consistency.md。
