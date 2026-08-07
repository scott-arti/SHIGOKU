---
task_id: SGK-2026-0427
doc_type: work_report
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/subtasks/2026-08-06_sgk-2026-0427_m5-sealed-audit-active-rerun_subtask_plan.md
- docs/shigoku/subtasks/done/2026-08-05_sgk-2026-0425_vdp-causal-attack-funnel-diagnosis_subtask_plan.md
- docs/shigoku/reports/2026-08-06_sgk-2026-0425_vdp-causal-attack-funnel-diagnosis_work_report.md
- docs/shigoku/subtasks/2026-08-05_sgk-2026-0426_vdp-product-independent-improvement-and-hidden-reevaluation_subtask_plan.md
- docs/shigoku/worklogs/2026-08-06_sgk-2026-0427_m5-sealed-audit-active-rerun_work_log.md
title: M5 sealed audit active rerun 完了報告（instrumented session・opaque case別first-failure実測）
created_at: '2026-08-06'
updated_at: '2026-08-07'
tags:
- shigoku
target: tests/fixtures/vdp_juiceshop_sealed,src/reporting,config/diagnostics,workspace/projects/localhost:3000
deferred_tasks: []
---

# 作業完了報告: SGK-2026-0427（M5 sealed audit active rerun）

## 0. 位置づけと実施内容

SGK-2026-0425 の deferred **D01「M5 sealed audit active rerun」** を実施。ユーザー最終GO（m3a read-only・egress allowlist・kill switch 3層・1回実行）のもと、ローカル使い捨て対象コンテナ（http://localhost:3000）へ計装実行（`diagnostics.enabled=true` + `required=true`、VDP `readonly_enforce`/`m3a`）を1回実施し、sealed 6 opaque case の first-failure（S00〜S12 or S05 ineligible）を実測した。

## 1. 実行の実績（attempt記録 — 成功扱いは本番runのみ）

| attempt | 結果 | 対象への通信 |
|---|---|---|
| 1 | Caido entry gate FAIL（preflight abort・session無し） | 0 |
| 2 | Caido entry gate FAIL（`SHIGOKU_SKIP_ENTRY_GATE=1`導入前） | 0 |
| 3 | 内部セッションgate FAIL（Caido必須のためabort・session無し） | recon開始のみ（naabu/katana、session未作成） |
| **4（本番）** | **exit 0・instrumented session産出** | **1回の計装実行として記録** |

本番runは 2026-08-06 10:52〜10:56（JST 19:52〜19:56）。session: `workspace/projects/localhost:3000/sessions/session_20260806_105634.json`（run_id 9908371a）。

## 2. run設定（固定・承認済み）

- アプリmode `vulntest`（bugbountyはguard policy必須のため。bundle捏造なし。`network_client.py:344` がbugbountyのみguard評価）
- VDP `readonly_enforce` + stage `m3a` + `capability_rules: {follow_up_probe: allowed}`（unknown→prohibited）
- diagnostics enabled/required true（bounds既定）
- budget engine既定（max_requests 1000 / follow_ups 50 / retries 3 / concurrency 10 / runtime 3600s）＋harness timeout 3900s
- egress: 内部network（sgk-m5-net）＋allowlist proxy（api.deepseek.com:443, api.openai.com:443 のみ）＋DNS gate。Caido readinessは公式 `SHIGOKU_SKIP_ENTRY_GATE=1` とharness identity stub（トラフィック非経由）
- 実行1回（run_markerで二重実行防止）・config snapshot(sha256)→run後byte-identical復元

## 3. instrumented funnel（session `vdp_diagnostics_v1`、5 events）

| stage | outcome | producer |
|---|---|---|
| S00 | reached | master_conductor（実行契約準備） |
| S01 | reached | vdp_observation_adapter（raw producer artifact） |
| S02 | reached | vdp_observation_adapter（typed observation） |
| S03 | reached | vdp_hypothesis_generator（**6 hypotheses生成**） |
| S05 | **failed** | master_conductor（follow-up queue注入例外） |

canonical: hypotheses 6 / attempts 0 / evidence 0 / verdicts 6 / next_actions 6 / vdp_active True。

## 4. opaque case別 first-failure（evaluator post-binding 実測）

`config/diagnostics/first_failure_juiceshop_v1.json`（eval v1・analyzer v1・run_mode m3a-readonly）

| opaque_case_id | capability family | verdict | first-failure stage | cause_candidates | confidence |
|---|---|---|---|---|---|
| OPAQUE-XSS-01 | client_side_injection | first_failure | **S05** | （analyzer: 空※） | supported |
| OPAQUE-DATA-01 | sensitive_data_exposure | first_failure | **S05** | （analyzer: 空※） | supported |
| OPAQUE-AUTH-02 | token_trust_boundary | first_failure | **S05** | （analyzer: 空※） | supported |
| OPAQUE-AUTH-01 | auth_bypass_injection | **ineligible** | S05 | — | not_applicable |
| OPAQUE-IDOR-01 | object_level_authz | **ineligible** | S05 | — | not_applicable |
| OPAQUE-PRIV-01 | access_control_escalation | **ineligible** | S05 | — | not_applicable |

trace_coverage 6/6（ineligible 3件は母数・理由 `state_changing_not_allowed_m3a_readonly` 付きで記録。計画書§3.1の正当capability拒否であり検出不良ではない）。

※**S05 failure eventがreason_codes空でemitted**（`master_conductor.py:11702` は `source_refs=['follow_up_enqueue_failed']` のみ）。analyzerは空reason_codesからcause_candidates=[]を返す（telemetry gap・C13相当の計測改善候補として§8へ記録）。**ログ由来の原因候補**: `run_stdout.log:240` の例外文言 `PCR-P1: task_queue mutation must be on main thread` により **C10（infrastructure/thread-confinement）**、mechanism `queue_backpressure` 相当。confidence: **supported**（S05 failed event＋例外ログが同一lineageで一致）。

## 5. 診断結果の解釈（一次診断）

- **S00〜S03は全て到達**：reconのsignal bundle→observation→6仮説生成までVDPパイプラインは正常動作。対象面の取得・正規化・仮説生成に失敗はない。
- **S05（admission/queue注入）で全read-only caseがcut**：`_queue_vdp_follow_ups` の `self._add_tasks()` が task_queue のスレッド閉込規約（PCR-P1: main thread限定）に違反して例外 → S05 failed event。**実エンジン統合での初回実測された真のfirst-failure**（0425のfixture harnessはqueue注入をmain threadで模擬しており発見不可だった — D02の予言どおり）。
- 後段（S06〜S12）は `downstream_not_reached`（二重計上なし）。
- POST系3件はm3aでは実行不可のためineligible（承認済み）。m3b実測は別フェーズ（本物のprogression記録を実runで獲得後）。

## 6. 安全・整合の実証（全て実artifact）

| 項目 | 結果 | 証拠 |
|---|---|---|
| report/session consistency | **consistent**（reason_codes []） | `shigoku-ops report consistency`（haddix_report_20260806_110200.md）+ `verify_report_session_consistency.py` 両方 |
| secret 0 | session/report/log/proxy/evaluator出力すべて0件（bearer/cookie/JWT/API key/credential pattern） | 正規表現scan実測 |
| scope逸脱 0 | recon結果URL全件 `localhost:3000` のみ・VDP S08未到達（送信0） | tagged_urls 20260806_*・session events |
| 未承認state変更 0 | VDP送信0（S05でcut）。reconはGET/TCP scanのみ | session attempts=0・targetログ |
| 二重送信 0 | VDP送信0件（送信自体なし） | session events |
| 予算超過 0 | budget消費0（S05でcut） | session budget_snapshot |
| egress | 許可外**成功0**。proxy log: allowlist成功1（api.deepseek.com）、外部試行11件（nuclei等のtelemetry/update: api.pdtm.sh×6, storage.googleapis.com, registry.npmmirror.com, raw.githubusercontent.com, playwright.azureedge.net）は**全件proxy DENY・データ送出0**＋example.com deny検証1件。DNS gate（外部名解決不能）をbring-upで実証 | proxy_access.log・bring-up 6a/6c |
| 実行回数 | 本番run 1回（run_marker）。attempt 1-3はsession未産出のbring-up失敗として記録（成功扱いしない） | run_marker・run_stdout.log |
| preflight | 実行前・全コード変更後ともに **exit 0**（token hit 0） | check_vdp_product_independence.py |
| config復帰 | `mode: bugbounty`/`vdp.mode: off`/`diagnostics.enabled: false` へ**byte-identical復元**（sha256一致・runtime surface hash一致） | config.sha256 vs after・hashes.start/end |
| runtime無変更 | src/config/prompts の実行前後hash完全一致（reporting埋め込みは実行後に実装し、実artifactは再生成経路で適用） | hashes.start/end |

## 7. 実装した成果物（通信0部分）

- `tests/fixtures/vdp_juiceshop_sealed/labels/expected_path_cases_v1.json`（sealed 6ケース・製品token 0・DAG検証済み）
- `tests/fixtures/vdp_juiceshop_sealed/evaluate_m5.py`（post-binding driver・opaque出力）
- `tests/fixtures/vdp_juiceshop_sealed/run_m5_audit.sh`（隔離run harness・単一run guard・config snapshot/復元）
- `tests/fixtures/vdp_juiceshop_sealed/proxy/`（allowlist proxy・Dockerfile）
- `tests/fixtures/vdp_juiceshop_sealed/caido_stub.py`（readiness identity probe応答のみ・トラフィック非経由）
- `tests/unit/reporting/test_vdp_juiceshop_sealed_cases.py`（56 passed, 1 skip）
- **D04解消**: `haddix_formatter.py` / `haddix_submission_internal_formatter.py` / `main.py` に `vdp_diagnostic_index_v1` additive埋め込み（`embed_vdp_diagnostic_index`、canonical summary有無と独立。section無しはno-opでlegacy bit-identical）。`test_vdp_formatter_projection.py` に4テスト追加
- 成果物: `config/diagnostics/first_failure_juiceshop_v1.json`・`config/diagnostics/external_audit_v2.json`（opaque case/stage/reason/confidenceのみ・製品情報なし）

## 8. 検証コマンドと実結果

```text
.venv/bin/pytest tests/unit/reporting/test_vdp_juiceshop_sealed_cases.py tests/unit/reporting/test_vdp_diagnostic.py -q
  → 116 passed, 1 skipped
.venv/bin/pytest tests/unit/reporting/ tests/unit/main/test_main_report_haddix_vdp_gate.py -q
  → 1037 passed, 1 skipped（reporting広域回帰）
.venv/bin/pytest tests/unit/reporting/test_vdp_formatter_projection.py tests/unit/reporting/test_vdp_report_projection.py tests/unit/reporting/test_report_session_consistency.py tests/unit/reporting/test_vdp_diagnostic_index.py tests/unit/reporting/test_vdp_consistency_index.py -q
  → 79 passed（D04埋め込み）
check_vdp_product_independence.py（clean-diagnostic）→ verdict pass / exit 0（前・後）
shigoku-ops report consistency → consistent / reason_codes []
verify_report_session_consistency.py → consistent / reason_codes []
python3 scripts/sync_shigoku_updated_at.py → UPDATED=0
python3 scripts/validate_shigoku_docs.py → 全category 0
git diff --check → clean
graphify update . → 完了
```

## 9. SGK-2026-0426への引き継ぎ（proven化候補）

- **C10/task_queue thread-confinement（PCR-P1）**: `_queue_vdp_follow_ups` のqueue注入がmain thread外で実行され例外→S05 cut。実装変更の反証実験（§4の単一変数条件）を0426で実施する価値が最も高い候補。対応改善は「VDP follow-up queue注入をmain thread/イベントループ上で実行（またはtask_queue側の許可）」。
- **C13 telemetry gap**: `master_conductor.py:11702` のS05 failed emissionがreason_codes空。funnel診断の因果候補をanalyzerに載せるため、follow_up_enqueue_failed時はmechanism code（例 `queue_backpressure`）を付与する計測改善を0426へ。
- POST系3件（AUTH-01/IDOR-01/PRIV-01）の実測は、m0〜m3aを実runで正当に通した本物のprogression記録獲得後の別フェーズ（本タスク外・別起票）。

## 10. 完了条件判定

計画書§5の完了条件（m3a版）に対して: ①trace_coverage 6/6（ineligible3件は母数・理由記録）✓ ②read-only 3件がvdp_diagnostics_v1からS00〜S12算出、S12はcanonical+consistencyで判定 ✓ ③consistency consistent・safety 0・実行1回・preflight前後exit 0・config既定bit復帰・docs validator 0 ✓ ④産出 `first_failure_juiceshop_v1.json`＋`external_audit_v2.json`（opaqueのみ）✓ ⑤VDP経路で拾えなかった事象は一次診断として記録（S05 cutは診断結果そのもの）✓ ⑥未実行・FAIL/UNKNOWNを成功扱いせず（attempt 1-3は失敗として記録）✓

**in_scope_blocker 0件**。deferred_followup: 上記§9の2件（0426へ追跡、実ID紐付け済み）。本タスクを `done` とする。
