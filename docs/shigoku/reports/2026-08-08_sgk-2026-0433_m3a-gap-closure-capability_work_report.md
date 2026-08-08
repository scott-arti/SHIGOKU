---
task_id: SGK-2026-0433
doc_type: work_report
status: done
parent_task_id: SGK-2026-0432
related_docs:
- docs/shigoku/plans/done/2026-08-08_sgk-2026-0433_m3a-gap-closure-capability_plan.md
- docs/shigoku/reports/2026-08-08_sgk-2026-0433_m3a-gap-closure-auth-setup_work_report.md
- docs/shigoku/worklogs/2026-08-08_sgk-2026-0433_m3a-gap-closure-auth-setup_work_log.md
- docs/shigoku/worklogs/2026-08-08_sgk-2026-0433_m3a-gap-closure-capability_work_log.md
- docs/shigoku/plans/2026-08-08_sgk-2026-0436_timing-live-acquisition-and-harness-ownership_plan.md
title: m3a gap-closure 能力拡張（第2アカウント authz 比較・タイミング基盤）完了報告
created_at: '2026-08-08'
updated_at: '2026-08-08'
tags:
- shigoku
target: workspace/projects/localhost:3000
deferred_tasks:
  - deferred_id: SGK-2026-0433-D01
    title: timing ライブ取得（封印 run で timing_measurement 証拠の生成）
    reason: queue の exact-replay skip（param 付き観測）で follow-up 未投入となりライブ未実行。基盤はユニット実証済み（19 tests）だが、実測での取得には queue 判定の見直しが必要
    impact: low
    tracking_task_id: SGK-2026-0436
    recommended_next_action: "0436 で param 付き観測の timing 系 gap 実行可否を見直し、封印 run で honest な marker を取得"
  - deferred_id: SGK-2026-0433-D02
    title: 封印harness成果物の所有権改善（runner --user / chown）
    reason: docker runner（root）生成の report/session が root 所有となり、bbb から読めず §8 consistency gate が blocked。chown で復旧済みだが恒久対策が必要
    impact: low
    tracking_task_id: SGK-2026-0436
    recommended_next_action: "0436 で main runner に --user $(id -u):$(id -g) を付与"
---

# 作業完了報告: SGK-2026-0433（m3a gap-closure 能力拡張）

## 0. 成果物サマリ

- **Lane A（auth-setup）**: 封印harnessに A/B アカウント provisioning を追加。
  `AuthSetupGuard` が config 由来の register/login POST 4種のみを許可し、それ以外は
  送信前に fail-closed（リダイレクト追従も禁止・atomic write・body 完全非開示）。
  run_m5_audit.sh に phase 6d を追加、セッショントークンは 0600 ファイル経由で注入。
- **Lane B（timing 基盤）**: `insufficient_timing_validation` を m3a 実行可能に。
  baseline/positive/negative control の GET 制御列で latency を測定し
  `timing_measurement` evidence と `timing_difference_observed` marker を honest に記録
  （真の差分が無ければ "false"＋reason＝正しい hold）。
- **独立レビュー**: oracle の指摘 6 件（リダイレクト追従・WARN→die・request_count
  二重計上・部分資格情報・body 漏洩・atomicity）を全て修正、レビュー再確認済み。
- **封印実測**: 1 回のライブ run を実施（session_20260807_174454.json）。

## 1. 実測結果（session_20260807_174454.json・consistent）

### authz 比較 lane（計画 §完了条件 2・3）
- `auth_a_id`/`auth_b_id` が follow-up spec に注入され、**認証 GET 比較が実行された**。
- evidence **ev-87cbedb909e33a28**（execution_result）: `account_a_status=200` /
  `account_b_status=200` / `second_account_compared=true` /
  `cross_account_compared=True` / `owner_record_accessible_to_non_owner=False` /
  `sensitive_fields_shared_with_non_owner=False` / `request_count=2`。
- `authz_impact_proven` は**記録されず**＝B は A のリソースに 200 だが owner 特権情報の
  共有なし → **真の境界越えなし → 正しく hold**（成功条件 3(b) 充足。
  **confirmed 件数は指標にしない**＝比較が実行され独立証拠が記録されたことが成功）。
- Evidence Validator・閾値・marker 語彙は一切変更していない（PASS 条件は既存のまま）。

### timing lane（計画 §完了条件 4）
- 実測では `timing_measurement` evidence **0 件**。原因は queue の exact-replay skip
  （対象 candidate の観測に param あり→follow-up 未投入。payload_request_mismatch と
  同一機構の安全設計）。
- 基盤自体はユニット実証済み（19 tests: 差分なし→"false" hold、模擬差分→"true"＋
  Validator 満足、予算・guard・transport エラー分類）。
- **能力不足の明示**: ライブ取得は D01（SGK-2026-0436）として追跡。

### 評価（opaque・6 cases）
- S05 ineligible（m3a readonly で状態変更不可）: OPAQUE-AUTH-01 / IDOR-01 / PRIV-01。
- first_failure @ S12: OPAQUE-XSS-01 / DATA-01 / AUTH-02（S10/S11 は到達:
  evidence_built + status=candidate）。confirmed 0・candidate hold 2。

## 2. 不変条件の実証

- **PCR-P1**: task_queue.py diff 0 行（無改変）。
- **preflight**: `check_vdp_product_independence.py` → **verdict pass / exit 0**
  （変更 src/ 1 ファイル走査・token hit 0・import closure OK）。
- **secret redaction**: VDP_ACCOUNT_A/B_SECRET（トークン値）は全 artifact（run_stdout /
  auth_setup_stdout / target_access / proxy_access / session / report）で **0 件**。
  アカウント ID のみ designed な `auth_a_id`/`auth_b_id` spec フィールドに出現
  （＝エンジンが資格情報を解決するための設計チャネル。secret ではない）。
  session_env.txt は 0600・4 変数のみ。
- **状態変更0**: 実測中の m3a run は GET のみ。auth-setup POST（register/login）は
  phase 6d のガード内でのみ実行・それ以外は fail-closed。
- **§8 consistency gate**: `verify_report_session_consistency.py` →
  **consistent**（reason_codes 空。S10/S11 到達・fail-open なし）。
- **docs validator**: 0 issues。

## 3. 本タスク中のハーネス修正（phase 9 SIGPIPE）

実測で発見・修正: `find | head -1` が `set -euo pipefail` 下で SIGPIPE により
evaluator 実行前に harness を abort（engine が中間+最終の session を2つ書くため）。
`find -printf '%T@ %p' | sort -n | tail -1 | cut` に置換（最も新しい session を
決定的に選択・pipe 早期 close なし）。再現テスト＋実 artifact での phase-9 リプレイ
（evaluate_m5.py rc=0・出力再生成）で検証済み。fix-3 は中間 session を誤選択しない。

## 4. 完了条件判定（計画書対比）

| 完了条件 | 判定 | 根拠 |
|---|---|---|
| 1. auth-setup が A/B register/login のみ・他は fail-closed | PASS | 38 tests＋oracle PASS＋実測で許可外 POST 0 |
| 2. B の認証 GET 比較→独立証拠 | PASS | ev-87cbedb909e33a28（second_account_compared=true） |
| 3. 境界越えあれば confirmed／なければ hold | PASS(hold) | 越えなし→正しく hold（成功 3(b)） |
| 4. timing marker 取得 or 能力不足を明示 | PASS | 基盤実装＋19 tests＋能力不足を D01/0436 で明示 |
| 5. 安全0／PCR-P1 無改変／preflight exit 0 | PASS | §2 参照 |
| 6. 封印実測＋テスト両方 | PASS | ライブ run 1 回＋全テスト |

**in_scope_blocker 0件**。deferred_followup: D01/D02（両方 SGK-2026-0436 に実ID紐付け）。
non_blocking_observation: なし。本タスクを **done** とする。
