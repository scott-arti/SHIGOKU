---
task_id: SGK-2026-0450
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-14_sgk-2026-0450_deterministic-error-based-sqli-detection.md
- docs/shigoku/plans/2026-08-15_sgk-2026-0451_smart-sqli-firing-path-fix.md
- docs/shigoku/worklogs/2026-08-15_sgk-2026-0450_ai-hunter-toolcalling-dedup_work_log.md
created_at: '2026-08-15'
updated_at: '2026-08-15'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- reliability
deferred_tasks:
- id: SGK-2026-0450-D01
  summary: SmartSQLiHunter が発火 payload を一度も送らない（0450 STEP 3 の 3 run すべてで probe_sent=0）第4根本原因。発見パラメータへ error-based プローブを汎用的に確実送信し sql_error 候補を生成する発火経路修正。0450 の完了条件3（F5>0×3run）を carve-out して所有する。
  tracking_task_id: SGK-2026-0451
- id: SGK-2026-0450-D02
  summary: live confirmed=1 に必要な「実害の安全な実証（GET-only データ抽出）」能力。error-based SQLi は実害未証明だと poc_judge が正しく却下するため、候補生成（0451）とは別に必要。審査員は緩めない。
  tracking_task_id: SGK-2026-0442
---

# 作業完了報告: SGK-2026-0450 — AI ハンターの信頼化（tool-calling 移行 ＋ 重複排除ガード）

（親ロードマップ: SGK-2026-0442。0449 で「候補さえ出れば確定できる」機構は実証済みだが実 run は confirmed=0＝検出が非決定的。step-1 根本原因調査で 3 因を特定し、(1) は flash 化で対処済み（commit 8040cf2）、本タスクで (2) tool-calling 移行・(3) 重複排除ガードを実装した。）

## 1. 変更要約

### A) tool-calling 移行（根本原因2＝自由テキスト ReAct の脆いパースの対処）
- `src/core/models/llm.py`（+28/-6）: `tool_loop: bool=True` を追加。既定 True で既存呼び出しはバイト等価、False で `tool_calls` を含む生応答をそのまま返す（キャッシュスキップ）。
- `src/core/agents/swarm/base_manager.py`（+243）: `_build_tool_schemas()`（`inspect.signature` から機械生成）・think loop の tool-calling 経路（オプトイン時のみ）・`_handle_tool_calls`（fail-closed・`role: tool` 履歴復帰）。
- `src/core/agents/swarm/injection/smart_sqli.py`（+111）: `_build_specialist_tool_schema()`（`request(payload: str)`/`finish(summary: str)` — payload は自由文字列＝能力不変）・`decide()` の tool-calling 分岐（既定 OFF は regex パス維持）。
- `src/core/config/settings.py`（+4）: `tool_calling_enabled` / `dedup_guard_enabled`（既定 OFF・env オプトイン）。

### B) 重複排除／前進ガード（根本原因3＝マネージャに重複排除が無いの対処）
- `base_manager.py`: `_normalize_target_url` / `_action_fingerprint` / 重複排除ガードを think loop の `_execute_tool` 実行前に追加。キー `(action, 正規化URL, params fingerprint)`。params 違いは別手として許可（適応幅不変）。空引数の同一 URL 再実行のみ抑止。

### 保護境界（無改変）
- `payout_grade.py` / `sealed_reproduction_checker.py` / `injection_evidence_fields.py` **diff 0**。poc_judge 無改変。PCR-P1（main-thread assertion）無改変。

## 2. なぜ（背景）

0449 の実 run では同じコードで発火/不発が分かれる**検出の非決定性**で confirmed=0 だった。step-1 で (1) LLM 判定が遅い（対処済み）、(2) 自由テキスト ReAct の ast/regex パースが散文・空引数で手を無駄にする、(3) 重複排除ガードが無く脆弱でない EP に繰り返し委譲、を特定。本タスクは (2)(3) を tool-calling ＋ガードで潰した。

## 3. 検証（実施したこと・観測結果）

### 単体・回帰テスト（.venv）
- 新規 3 本 20 件 passed（`test_llm_tool_loop.py` / `test_smart_sqli_tool_calling.py` / `test_base_manager_tool_calling.py`）: tool_calls 実行・fail-closed・重複排除ガード・URL 正規化・既定バイト等価。
- injection 回帰スライス 567 passed。DeepSeek 報告の広域スライスは 587 passed。

### 実 run（連続3回・本物 Caido 8081・本物 Juice Shop・GET-only・オプトイン ON）
- session_20260815_083119 / 084844 / 090008。tool-calling で**空引数 Action は消滅・繰り返しは低減**（根本原因2/3 の解消を funnel/ログで確認）。

### 独立検証（Claude・実データ）
- 保護3ファイル diff 0（`git diff --stat` exit 0）。
- `check_vdp_product_independence.py` **verdict=pass・token hits 0**（changed_files=4）。
- 既定 OFF＝byte-equal（`tool_calling_enabled=False`/`dedup_guard_enabled=False`、`tool_loop` 既定 True）。
- GET-only 維持・consistency consistent。secret 生値 0。run 副作用は `data/vuln_roi_db.json` のみ（報告のみ）。

## 4. 完了契約との対照（§19）

- 完了条件1（フェーズ0確定・A/B 設計承認）: **PASS**。
- 完了条件2（tool-calling 動作・ガード・保護無改変）: **PASS**（単体テスト＋実 run で構造化ツール呼び出し・fail-closed・ガード動作を確認、保護3ファイル diff 0）。
- 完了条件3（連続3run で発火送信＋sql_error 候補生成）: **未達 → SGK-2026-0451 へ carve-out（ユーザー承認・2026-08-15）**。STEP 3 独立検証で `probe_sent=True` が全 sqli url_result（各18件）で 0＝発火経路が実プローブを出していない**第4の根本原因**が判明。step-1 が特定した根本原因2/3 とは別の上流欠陥のため A+B では直らない。silent-done は §19 違反として却下し、ユーザー明示承認を得て契約を変更・条件3を 0451 へ移管。
- 完了条件4（能力を狭めていない）: **PASS**（payload 自由文字列・適応ループ維持・params 違いは別手許可）。
- 完了条件5（テスト・product-independence・GET-only・secret）: **PASS**。
- 完了条件6（docs 整合）: **PASS**（sync→validate 0 エラー）。

**判定**: 固定済み完了条件のうち条件3をユーザー承認のうえ 0451 へ carve-out し、残る条件（A+B＝根本原因2/3 の解消）はすべて PASS、`in_scope_blocker` 0 件。よって 0450 は A+B の範囲で **done**。能力ギャップ（発火経路・実害実証）は破棄せず追跡タスクが所有する。

## 5. リスク

- 発火経路未修正のうちは検出は非決定的なまま（0451 で対処）。0450 の A+B は既定 OFF のオプトインで、既定 run はバイト等価のため回帰リスクは隔離。

## 6. 次の一手

- **SGK-2026-0451**（発火経路の汎用修正）: フェーズ0 で probe_sent=0 の真因を実データで特定 → 承認 → 汎用修正（`q` 決め打ち禁止）→ 連続3run で F5>0。
- 実害の安全な実証（データ抽出）は別途 SGK-2026-0442 配下で追跡（poc_judge は緩めない）。
