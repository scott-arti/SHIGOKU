---
task_id: SGK-2026-0451
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-14_sgk-2026-0450_deterministic-error-based-sqli-detection.md
- docs/shigoku/plans/done/2026-08-15_sgk-2026-0451_smart-sqli-firing-path-fix.md
- docs/shigoku/worklogs/2026-08-15_sgk-2026-0451_smart-sqli-firing-path-fix_work_log.md
created_at: '2026-08-15'
updated_at: '2026-08-15'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- reliability
deferred_tasks:
- id: SGK-2026-0451-D01
  summary: live confirmed=1 に必要な「実害の安全な実証（GET-only データ抽出）」能力。error-based SQLi はエラーマーカーのみでは poc_judge が正しく確定させない（needs_more）ため、発火・候補生成（本タスクで達成）の先に実害実証が必要。審査員は緩めない・impact 捏造禁止。
  tracking_task_id: SGK-2026-0442
- id: SGK-2026-0451-D02
  summary: リクエスト衛生の cleanup。発火リクエストが payload_params 全体を baseline として送るため、内部メタ `method` と socket.io ノイズ `EIO/transport/t` が URL に baseline 値として残る（注入対象からは除外済みだが送信リクエストには載る）。検出・誤確定・GET-only には影響しないが、送信リクエストからも内部メタ/ノイズを落とす整理。オーケストレータ独立検証で発見（非blocking）。
  tracking_task_id: SGK-2026-0442
---

# 作業完了報告: SGK-2026-0451 — SmartSQLiHunter 発火経路の修正（発見パラメータへ error-based プローブを確実に送る）

（親ロードマップ: SGK-2026-0442。0450 で tool-calling＋重複排除により根本原因2/3 は解消したが、第4根本原因＝**SmartSQLiHunter が発火 payload を一度も送らない**（3 run 全 sqli url_result で probe_sent=0）を本タスクで汎用的に修正。完了条件: 連続3run で発見パラメータへの error-based 発火（probe_sent=True・poc_request 非空）と sql_error 候補生成（funnel F5>0）。）

## 1. 変更要約（STEP 1 → STEP 2 → STEP 3 の流れ）

### STEP 1（フェーズ0・実装前調査・承認済み）
真因を実データで特定（計画書「フェーズ0結果」節に追記）:

- **(b) 主因・構造確定**: recon の `discovered_params` ヒント（socket.io の `EIO`/`transport`/`t` が先頭）と内部メタキー（`url_evidence`/`detection_mode` が META_KEYS に無く payload_params へ漏れる）が `MAX_PARAMS_TO_TEST=5` 枠を占有し、**実パラメータ q/query は候補から完全に除外**（実コード再現で candidate_params=`['url_evidence','detection_mode','EIO','transport','t']` を確認）。3 run × 3 URL の sanitize 後 tested_params が全同一パターンなのも整合。
- **(a) 増幅**: sqli_specialist は 21 calls/15 ループ（≈1.4/param＝即 finish）。対照的に xss_specialist は 75-77 calls（ループ機構は正常）。
- **(d) 副次・要修正**: `run_sqli_hunter`/`_process_single_url` が sqli 経路で `probe_sent`/`probe_request_raw` を返さず None/"" のまま（記録経路欠落）。
- **(c) 非該当**: 送信自体ゼロのため payload 長問題は観測されない。

### STEP 2（実装・汎用のみ・オプトイン）
- `settings.py`: `sqli_firing_path_enabled`（既定 False・env `SHIGOKU_SQLI_FIRING_PATH_ENABLED`）。OFF 時バイト等価。
- `smart_sqli.py`（フラグ ON 時のみ）: ①META_KEYS 拡張＋`NOISE_PARAM_NAMES={"eio","transport"}`＋URL 実在クエリ優先の汎用順序（`keep_blank_values` 対応・名前決め打ちなし）②`_fire_error_based_probe`（既存 `_send_request` 再利用・シングルクォート系 basic プローブ・`probe_sent`/`used_payloads`/`_last_poc_*` 記録）＋`_record_sql_observation`（act() と共通化・バイト同一）③LLM ループ前に決定的発火・観測を `decide()` プロンプトへ反映（適応ループ・payload 幅不変）④`execute()` で `sql_error_observed ∧ poc_request 非空` 時に finding 生成（fail-closed）⑤戻り値に `probe_sent`/`probe_request_raw`/`probe_response_raw`（フラグ ON 時のみ）。
- `manager.py`（記録配線・数行）: `run_sqli_hunter` → `_process_single_url` で sqli 経路の probe 記録を url_result へ反映（フラグ ON 時のみ）。dispatch ロジック無改変。

### 保護境界（無改変・確認済み）
- `payout_grade.py` / `sealed_reproduction_checker.py` / `injection_evidence_fields.py` **diff 0**（`git diff --quiet HEAD`）。poc_judge・marker 語彙無改変。PCR-P1（main-thread assertion）diff 0。

## 2. なぜ（背景・真因）

0450 STEP 3 独立検証で「発火経路が実 HTTP プローブを出していない」上流欠陥が判明。ハンターは LLM ループを内部メタ＋socket.io ノイズに対してのみ実行しており、実パラメータへの error-based プローブは構造的に不可能だった。本タスクは「発見した実パラメータ全般へ汎用的に発火を保証」する経路をオプトインで追加した（能力縮小なし・製品固有焼き込みなし）。

## 3. 検証（実施したこと・観測結果）

### 単体・回帰テスト（.venv）
- 新規 13 件（`tests/unit/test_smart_sqli_firing_path.py`）: メタ/ノイズ除外・URL 実在優先（空値 `?q=` 含む）・発火送信と probe_sent/poc_request/poc_response 記録・sql_error 観測時の候補 finding 生成（フラグ ON）・既定 OFF の非生成（バイト等価）・decide への probe observation 反映・manager 記録配線（フラグ ON/OFF）。
- 回帰: `tests/unit/test_smart_sqli_firing_path.py tests/unit/test_smart_sqli_tool_calling.py tests/core/agents/swarm/injection/ tests/unit/agents/swarm/test_base_manager_tool_calling.py` → **596 passed**（既存失敗 1 件 `test_smart_sqli_hunter_post_json_support` は 022aa05 時点から存在する事前失敗・本変更と無関係）。

### 実 run（封印 run 連続 3 回・本物 Caido 8081・本物 Juice Shop・GET-only・オプトイン全 ON）
- session_20260815_121901 / 123531 / 125303（report: haddix_report_20260815_121902 / 123532 / 125305）。
- **3 run とも**: 発火した sqli url_result で `probe_sent=True`・`poc_request` 非空。`/rest/products/search?q=` で error-based 発火（`q=1"` 等）→ `sql_error_observed=True`（error_type=syntax）→ **sql_error 候補 finding 1 件生成**（finding は param `q`。注入対象の選定からノイズ/メタは除外され root cause (b) は解消）。**funnel F5>0**（各 run 4 エントリ F5 到達）。誤検出・誤確定 0（sqli 候補は poc_judge が `needs_more`（ai_no_prize_grade / ai_counter_evidence）で正しく確定させず＝審査員は緩めていない）。
  - **正直な補足（オーケストレータ独立検証）**: 発火リクエストの実体は `GET /rest/products/search?method=GET&EIO=1&transport=1&t=1&name=1&q=1'&query=...`。**注入対象**からはノイズ（EIO/transport）・内部メタは除外されているが、**発火時の HTTP リクエストは payload_params 全体を baseline として送る**ため、内部メタ `method` と socket.io ノイズ `EIO/transport/t` が URL に baseline 値として残る（Juice Shop はこれらを無視し sql_error は `q=1'` 由来＝検出は正当）。「tested_params=`['q']`・実パラメータのみ」は finding 対象の話であり、送信リクエストは junk baseline 込み。これは誤確定・製品依存・GET-only 違反いずれにも該当しないが、リクエスト衛生の cleanup を deferred に記録（下記 D02）。
- **決定性**: 3 run 完全同一パターン（probe_sent True×3・finding 1・F5>0・sqli candidate needs_more）。

### 独立検証
- 保護4対象 diff 0・PCR-P1 diff 0（`git diff --quiet` exit 0）。
- `check_vdp_product_independence.py` **verdict=pass・total_token_hits 0**（changed_files=4: settings.py / smart_sqli.py / manager.py / test ファイル）。
- session evidence `request_method` は 3 run とも **GET のみ 28 件・非 GET 0**。poc 先頭メソッド GET のみ。secret 生値ヒット 0。
- `verify_report_session_consistency.py` 3 ペアとも **status=consistent**（reason_codes 空）。
- 既定 OFF＝バイト等価（フラグ OFF で新キーなし・候補順序不変・sql_error 単独では finding 非生成・prompt 不変 — 単体テストで確認）。
- docs: `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` **0 エラー**。

## 4. 完了契約との対照（§19）

- 完了条件1（フェーズ0で真因特定・汎用最小差分設計承認）: **PASS**（計画書「フェーズ0結果」節・ユーザー承認済み）。
- 完了条件2（連続3run で発火送信＋sql_error 候補生成 F5>0・誤検出/誤確定 0）: **PASS**（上記 3 run 証拠）。
- 完了条件3（能力を狭めていない・特定パラメータ決め打ちなし）: **PASS**（payload 自由文字列・適応ループ・ペイロード幅不変。URL 実在優先は汎用ルールで名前決め打ちなし。product-independence verdict=pass）。
- 完了条件4（保護3ファイル無改変・poc_judge 無改変・PCR-P1 無改変）: **PASS**（diff 0 確認）。
- 完了条件5（必須テスト全 pass・product-independence pass・secret 0・GET-only）: **PASS**。
- 完了条件6（docs 整合）: **PASS**（sync→validate 0 エラー）。

**判定**: `in_scope_blocker` 0 件。追跡可能な `deferred_followup`（実害実証）のみ残るため、固定完了契約（計画書）に基づき **done**。

## 5. リスク

- 発火経路はオプトイン（既定 OFF＝バイト等価）のため既定 run への回帰リスクは隔離。フラグ ON 時の新挙動は GET-only・fail-closed 内。
- sqli 候補は poc_judge により needs_more のまま（誤確定なし）— live confirmed には実害実証（別タスク）が必要。審査員・marker 語彙は無改変のため、確認された脆弱性の検出品質は不変。

## 6. 次の一手

- **SGK-2026-0442 配下**: 実害の安全な実証（GET-only データ抽出）で live confirmed へ。poc_judge は緩めない。
- オーケストレータが検証後にコミット（本タスクでは commit/push しない）。
