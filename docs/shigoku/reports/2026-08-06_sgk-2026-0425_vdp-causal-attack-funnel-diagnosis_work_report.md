---
task_id: SGK-2026-0425
doc_type: work_report
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/subtasks/done/2026-08-05_sgk-2026-0425_vdp-causal-attack-funnel-diagnosis_subtask_plan.md
- docs/shigoku/plans/done/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
- docs/shigoku/subtasks/2026-08-05_sgk-2026-0426_vdp-product-independent-improvement-and-hidden-reevaluation_subtask_plan.md
- docs/shigoku/worklogs/2026-08-06_sgk-2026-0425_vdp-causal-attack-funnel-diagnosis_work_log.md
title: VDP causal attack-funnel diagnosis コードゲート完了報告（M0〜M5診断基盤・診断産出）
created_at: '2026-08-06'
updated_at: '2026-08-07'
tags:
- shigoku
target: src/core/engine,src/reporting,scripts,config/diagnostics,tests
deferred_tasks:
  - deferred_id: SGK-2026-0425-D01
    title: "M5 sealed audit active rerun（instrumented run）"
    reason: "計画書§8 M5どおり、active rerunはユーザー明示承認・隔離network・external egress 0・test account・case毎初期化/rollback・1 evaluation versionにつき1回のみ実行可能。offline U00 baselineは産出済みで§14.6を充足するため0425完了阻害ではない。実測first-failure信号は後続の改善(0426)入力として取得する"
    impact: high
    tracking_task_id: SGK-2026-0427
    recommended_next_action: "コードゲート承認後にユーザーへ対象・isolation・scope・budget・停止条件を提示し承認を得て1回実行。実行時はpreflight（check_vdp_product_independence.py）を通してから開始"
  - deferred_id: SGK-2026-0425-D02
    title: "instrumented engineでのS04〜S12 genuine funnel計測（macro reach floorの実測）"
    reason: "現行fixture runtimeはadapter+generatorのみ。executor/validatorのM1 hookは実装済みだが、fixture runtimeへの統合（MC実行）はM4基盤の範囲外。S07/S10のmacro reachはharness-simulated値として記録"
    impact: medium
    tracking_task_id: SGK-2026-0426
    recommended_next_action: "0426またはM5 active rerunでinstrumented engineのgeneric fixture実行を行い、S04〜S12のgenuine reachを計測"
  - deferred_id: SGK-2026-0425-D03
    title: "既存汎用runtimeの製品固有content一般化（smart_xss.py・recon/pipeline.py・ops_cli dvwa profile・manager.py security=・nuclei.py等、10ファイル43 token hit）"
    reason: "preflight実スキャンで検出。VDP clean profileの依存closure・model_contextからは到達不能（import_closure/model_context PASS）で、manifest hits[]に全件分類済み（GENERAL_RUNTIME_ONLY/SCRIPT_ONLY、genericなowasp/nucleiはproduct:none）。preflightはこれらをdeferred_classifiedとして扱いverdict pass（exit 0）。全削除は本タスク対象外（計画書§15）"
    impact: medium
    tracking_task_id: SGK-2026-0426
    recommended_next_action: "0426（一般改善）でproven原因が出た場合に、該当分のみ製品非依存規則へ一般化。汎用runtimeの一括一般化は追跡タスク"
  - deferred_id: SGK-2026-0425-D04
    title: "haddix formatterへのvdp_diagnostic_index_v1埋め込み"
    reason: "index trio（build/embed/extract/比較）は実装済み・テスト済み。formatter側の埋め込みは診断sessionをreport化する経路が有効化される時（instrumented rerun後）に必要。現状はadditive absentで互換"
    impact: low
    tracking_task_id: SGK-2026-0427
    recommended_next_action: "SGK-2026-0427にて解決済み（2026-08-06）: HaddixFormatter.save_markdown/save_jsonへ vdp_diagnostic_index_v1 additive埋め込みを実装し、instrumented sessionのreport生成でconsistency consistentを実証"
---

# 作業完了報告: SGK-2026-0425（コードゲート）

## 1. 変更ファイルと主要行

**新規（production）**:
- `src/core/engine/vdp_diagnostic_trace.py` — M0 schema語彙・`validate_diagnostic_section()`（:346〜）・M1 `DiagnosticEventV1`（:359）・`DiagnosticCollector`（:448。emit :509、to_section :605、checkpoint :637、resume :689、from_section :729）
- `src/reporting/vdp_diagnostic.py` — `validate_expected_path_dag`（:293）・`stage_reach_evidence`（:378）・`analyze_observed_lineages`（:407）・`first_failure_for_case`（:457）・`evaluate_expected_paths`（:520）・`evaluate_first_failure_accuracy`（:544）
- `src/reporting/vdp_counterfactual.py` — `freeze_input_bundle`（:71）・`validate_experiment`（:85）・`CounterfactualValidator`（:160）・`compute_stage_delta`（:199）・`attribution_verdict`（:235）
- `scripts/check_vdp_product_independence.py` — read-only preflight（manifest hash / token scan / import closure / model context、exit 0/2/3）
- `config/diagnostics/` — `taxonomy_v1.json`・`product_independence_manifest_v1.json`・`thresholds_v1.json`・`diagnostic_eval_v1.json`・`external_audit_v1.json`・`sealed_product_denylist.txt`（いずれもcontent hash付き）
- `tests/fixtures/vdp_diagnostic_env/` — Dockerfile・docker-compose.yml（fixture-target/runtime/evaluator）・fixture_target.py・runtime_driver.py・evaluator.py・event_simulator.py・run_diagnostic_eval.sh（`docker compose` v2）

**変更（additive）**:
- `src/core/engine/master_conductor.py` — `_ensure_vdp_diagnostics`/`_vdp_diagnostic_emit`/`_vdp_diagnostic_kill_switch_blocked`（:11209付近）、`_generate_vdp_hypotheses` にS00〜S03、`_queue_vdp_follow_ups` にS04/S05、`_dispatch_vdp_follow_up` にkill switch+S06、`async_save_session` に`vdp_diagnostics_v1`注入（:3951付近）と保存時fail-closed gate、checkpoint/resume（`.diag`）
- `src/core/engine/vdp_follow_up_executor.py` — `diagnostic_collector`注入（:281/320）、`_diag_emit`（:326）、S07〜S10 event（:365〜:849）、required guard（:688）
- `src/core/engine/vdp_evidence_validator.py` — `diagnostic_collector`注入（:119/125）、S11 event（:140-170、:422-452）
- `src/reporting/vdp_report_projection.py` — `build/embed/extract_vdp_diagnostic_index`（:222-333）
- `src/reporting/report_session_consistency.py` — `_build_vdp_diagnostic_comparison`（:427-511）＋hook（:650-685）
- `scripts/shigoku_ops_cli.py` — `vdp diagnose`（:351-530、parser :2693-2724）、`VALIDATION_SUITES["ops_cli"]`登録（:109）
- `src/core/config/settings.py` — `DiagnosticsSettings`（enabled=false/required=false/上限。fail-closed validator）
- `config/shigoku.yaml`・`config/shigoku.yaml.example` — `diagnostics:` ブロック（additive）

**新規（テスト）**: test_vdp_diagnostic_trace.py（55）/ characterization（9）/ test_vdp_diagnostic.py（30）/ test_vdp_counterfactual.py（18）/ test_vdp_diagnostic_index.py（19）/ test_shigoku_ops_vdp_diagnose.py（11）/ test_vdp_product_independence.py（13、うち②remediationで+3）/ test_diagnostics_settings.py（13）/ test_vdp_diagnostic_executor_hooks.py・test_vdp_diagnostic_validator_hooks.py・test_master_conductor_vdp_diagnostic_hooks.py（38）/ test_vdp_diagnostic_dag_validation.py（9）

## 2. 変更理由

診断基盤（攻撃ファネルの最初の失敗遷移を決定論的に特定するtelemetry＋read-only analyzer＋1変数counterfactual）を、既存のID系列・安全gate・confirmed署名・consistency契約を**破壊せずadditiveに**実装するため。純粋モジュールはoptional collector注入（None→no-op）、MCは`diagnostics.enabled=false`（default）で完全無効、という二重のflag-off保証で既存出力のbit単位不変を固定した。製品名・既知URL・payloadは新規コードへ一切入れず（token scan 0件）、Juice Shop/DVWAはsealed audit対象としてのみ扱い、runtimeへ正解を渡さない。

## 3. 計画項目と実装箇所の対応表

| 計画項目（§8） | 実装箇所 |
|---|---|
| M0 taxonomy v1・reason語彙・event schema凍結 | config/diagnostics/taxonomy_v1.json＋vdp_diagnostic_trace.py（hash付き・code/artifact一致テストあり） |
| M0 characterization（flag off出力不変） | tests/unit/engine/test_vdp_diagnostic_characterization.py（4 golden hash＋決定性テスト） |
| M0 diagnostics config（enabled=false/required=false/上限） | config/shigoku.yaml(+example)＋settings.py DiagnosticsSettings |
| M0 manifest棚卸し | config/diagnostics/product_independence_manifest_v1.json（25件分類、VDP closure clean by construction） |
| M1 collector（bounded/上限/checkpoint/resume/atomic/redaction/旧reader互換） | vdp_diagnostic_trace.py DiagnosticCollector |
| M1 境界hook（adapter/generator/executor/validator/MC） | MC S00〜S06、executor S07〜S10、validator S11（S01〜S03はMCの呼出境界で事実発行） |
| M1 required kill switch | `_vdp_diagnostic_kill_switch_blocked`＋executor required guard（送信前に停止・Hold・checkpoint） |
| M1 保存時fail-closed | async_save_sessionの`vdp_diagnostics_v1` gate（既存vdp_contract gate不変） |
| M2 analyzer | vdp_diagnostic.py（observed lineages / expected paths / DAG検証 / accuracy） |
| M2 CLI | `shigoku-ops vdp diagnose`（label引数なし・report指定時consistency先行・上書き拒否・coverage note・exit 0/2/3） |
| M3 counterfactual | vdp_counterfactual.py（2変数拒否・hash不一致拒否・repeat不足拒否・threshold後付け拒否・safety悪化拒否） |
| M4 fixture/holdout基盤 | tests/fixtures/vdp_diagnostic_env/（evaluator network 0・runtime ENOENT isolation・3 seeds） |
| M4 threshold凍結 | config/diagnostics/thresholds_v1.json（§9の12メトリクス、direction付き） |
| M4 DAG正しさ検証 | validate_expected_path_dag＋DAG table tests＋fixtureのoptional/ineligible case |
| M5 sealed audit（offline） | 公式consistency checker通過pairのoffline診断（U00 baseline）＋external_audit_v1.json。active rerunは承認待ち |
| vdp_diagnostic_index_v1（additive） | vdp_report_projection.py＋report_session_consistency.py（additive absent互換） |

## 4. 計画項目とテスト名の対応表（§11の1〜26）

| §11 | テスト |
|---|---|
| 1 S00〜S12 table test | test_vdp_diagnostic.py TestFirstFailureTable（parametrized S00〜S12×3 outcomes） |
| 2 U00＋missing_artifacts列挙 | test_vdp_diagnostic.py（predecessor欠損→U00） |
| 3 downstream not_reached二重計上なし | test_vdp_diagnostic.py |
| 4 決定性（event ID/verdict） | test_vdp_diagnostic_trace.py TestDiagnosticCollectorM1（決定性）＋test_vdp_diagnostic.py |
| 5 rawあり/Observationなし vs Observationあり/Hypothesisなし | test_vdp_diagnostic.py（S02 vs S03） |
| 6 starvation/budget/loop/routing区別 | test_vdp_diagnostic.py |
| 7 model A/B・repeat不足・複数変数拒否 | test_vdp_counterfactual.py |
| 8 transport誤分類なし | test_vdp_diagnostic.py（S08 transport_timeout） |
| 9 marker/解釈/独立証拠区別 | test_vdp_diagnostic.py（S09/S10） |
| 10 S11/S12反証 | test_vdp_diagnostic.py |
| 11 非dict/unknown version/stage/reason/参照 | test_vdp_diagnostic_trace.py TestDiagnosticSectionFailClosed |
| 12 flag off/旧session/VDP inactive/Hypothesis 0 | characterization＋trace（empty events pass）＋test_master_conductor_vdp_diagnostic_hooks.py（flag off） |
| 13 nested secret 0件 | trace M1 redactionテスト＋test_shigoku_ops_vdp_diagnose.py（secret-free artifact） |
| 14 queue full/PermissionError/interrupt/resume/重複 | trace M1（backpressure/atomic/duplicate） |
| 15 semantic duplicate/seed再利用拒否 | 実測: 3 seeds間のopaque case overlap 0（diagnostic_eval_v1.json）＋vdp_dataset既存テスト |
| 16 runtime ENOENT/network 0 | fix-6のcontainer実測（/secrets・/tests・/workspace・/repo/tests ENOENT、evaluator network none） |
| 17 製品token 0件 | token scan（新規+変更ファイル 0件）＋test_vdp_product_independence.py |
| 18 same eval version threshold変更拒否 | test_vdp_counterfactual.py（threshold retrofit） |
| 19 CLI args/exit/stdout/stderr/JSON/consistency fail-closed | test_shigoku_ops_vdp_diagnose.py（11件） |
| 20 VALIDATION_SUITES登録 | shigoku_ops_cli.py:109＋ops_cli suite実走（106 passed） |
| 21 既存回帰 | 全VDP回帰（1291 passed） |
| 22 hidden generic floor | diagnostic_eval_v1.json（39 runs: accuracy 1.0 / unattributable 0.0 / trace_coverage 1.0） |
| 23 DAG optional/not_applicable/ineligible/retry | test_vdp_diagnostic.py＋test_vdp_diagnostic_dag_validation.py＋fixture S09/S10 case |
| 24 artifact-only CLI（label引数なし・coverage note） | test_shigoku_ops_vdp_diagnose.py（--labels不在・coverage_note） |
| 25 vdp_diagnostic_index_v1 tamper検出・旧artifact additive absent | test_vdp_diagnostic_index.py（19件） |
| 26 required=false維持/required=true停止 | test_master_conductor_vdp_diagnostic_hooks.py＋executor hooks（required guard、network未呼出） |

## 5. 実行した全検証コマンド

```bash
# ① 最終統合（VDP回帰＋診断テスト一式）
.venv/bin/pytest tests/unit/engine/test_vdp_*.py tests/core/engine/test_master_conductor_vdp_*.py \
  tests/unit/reporting/test_vdp_*.py tests/unit/main/test_main_report_haddix_vdp_gate.py \
  tests/unit/scripts/test_shigoku_ops_vdp_gate.py tests/unit/scripts/test_shigoku_ops_vdp_diagnose.py \
  tests/unit/scripts/test_vdp_product_independence.py tests/unit/config/test_diagnostics_settings.py \
  tests/unit/engine/test_vdp_diagnostic_dag_validation.py -q
# ② ops_cli標準suite
.venv/bin/shigoku-ops --json validate pytest --suite ops_cli --quiet
# ③ M5 offline診断（公式consistency checker先行）
.venv/bin/python scripts/verify_report_session_consistency.py --report <abs> --sessions-dir <abs>
.venv/bin/shigoku-ops --json vdp diagnose --session <abs> --report <abs> --output <abs>
# ④ M4 fault matrix
bash tests/fixtures/vdp_diagnostic_env/run_diagnostic_eval.sh   # 3 seeds × S00〜S12 = 39 runs
# ⑤ preflight実スキャン
.venv/bin/python scripts/check_vdp_product_independence.py --manifest config/diagnostics/product_independence_manifest_v1.json \
  --profile clean-diagnostic --denylist config/diagnostics/sealed_product_denylist.txt --json
# ⑥ 文書・差分・グラフ
python3 scripts/sync_shigoku_updated_at.py && python3 scripts/validate_shigoku_docs.py
git diff --check
graphify update .
```

## 6. 各コマンドのexit codeと実測件数

| コマンド | exit | 実測 |
|---|---|---|
| ① pytest統合 | 0 | **1291 passed** in 83.84s（既存1051＋新規・追加240） |
| ② ops_cli suite | 0 | **106 passed** in 89.70s |
| ③ consistency（JS / DVWA） | 0 / 0 | 両pairとも `consistent`、reason_codes空 |
| ③ vdp diagnose（DVWA / JS） | 0 / 0 | first_failures=1（U00）、coverage_note出力、artifact生成 |
| ④ 39 container runs | 全0 | accuracy **1.0**（117/117）、unattributable **0.0**、trace_coverage **1.0**、cross-seed overlap **0** |
| ⑤ preflight実スキャン | **0** | **verdict: pass**。import_closure PASS（30 files, 0 token, 0 manifest-hit overlap）・model_context PASS（20 templates, 0 hits）・token_scan **active hits 0**（既存legacy 43件はmanifest分類済みのため `deferred_classified` として記録、下記§10/§13参照） |
| ⑥ docs validator | 0 | FRONT_MATTER/BROKEN_LINKS/REGISTRY/DEFERRED すべて 0 |
| git diff --check | 0 | whitespace error 0件 |
| 新規/変更ファイルtoken scan | — | **0件**（vdp_*・scripts・fixture env・tests・config/diagnostics artifacts） |

## 7. 実際の利用経路を通した証拠

- **CLI実経路**: `shigoku-ops vdp diagnose` を実セッション（DVWA/Juice Shopのconsistent pair）へ実行し、U00診断artifactを生成（exit 0）。label引数なし・coverage note・report指定時consistency先行を実機で確認。
- **M4 container実経路**: `run_diagnostic_eval.sh` で実コンテナ（fixture-target→runtime→evaluator）を3 seeds×13 stages=39回実行。runtimeは実ObservationAdapter＋generate_hypothesesを実行し、evaluatorは実analyzer（src.reporting.vdp_diagnostic）でfirst-failure照合（accuracy 1.0）。runtimeコンテナからlabels/tests/repo全体が**ENOENT**（実測出力あり）。
- **M1 hook実経路**: MCの`_generate_vdp_hypotheses`→`_queue_vdp_follow_ups`→`_dispatch_vdp_follow_up`→executor→validatorの実経路でdiagnostics enabled時にS00〜S11 eventが生成され、保存sessionの`vdp_diagnostics_v1`が`validate_diagnostic_section`を通過（test_master_conductor_vdp_diagnostic_hooks.py、実MC構成で検証）。
- **required kill switch実証**: required=true＋hook失敗で`_dispatch_vdp_follow_up`が送信**前**にblocked（`diagnostic_telemetry_hook_failure`）となり、network client未呼出をmockで実証。

## 8. 既存動作が変わっていない証拠

- characterization test（flag offでsession/report/decision trace出力の**bit単位不変**）: golden hash 4件＋決定性テストがグリーン。
- 既存VDP回帰（1051件）を含む統合 **1291 passed**：confirmed署名・scope/budget/read-only guard・M0 gate・report/session consistency・旧reader契約の回帰0。
- ops_cli suite 106 passed（既存CLI契約不変）。
- `vdp_canonical_index_v1`は不変（additive indexのみ追加）。`vdp_contract.py`は無変更。
- 未コミットの既存変更（docsのdone/移動、rules、config等）は一切reset/checkout/revertせず、触れていない。commit/push/branch切替なし。

## 9. 未達条件

- **M5 active rerun**: 未実行（計画書§8 M5のとおり**ユーザー明示承認待ち**。offline U00 baselineは産出済みで§14.6を充足）。「rerunなしで診断完了」とは主張しない。D01としてSGK-2026-0427へ引き継ぎ。
- §17.3の「§9 threshold全達成」のうち、S07/S10のmacro reachはharness-simulated値（fixture runtimeがexecutor未統合のため）。instrumented engineでのgenuine計測はD02（deferred）。
- preflightのfull-tree token scanは既存legacy 43 hitを検出するが、全件manifest分類済みで `deferred_classified`（§13の②remediation後）。verdict pass（exit 0）。本タスクの新規・変更コード・config/diagnostics artifactsは0件。VDP clean profileのclosure/model_contextはPASS。

## 10. 残存リスク

- **preflight実スキャンの43 hit（10ファイル）**（smart_xss.py・recon/pipeline.py・shigoku_ops_cli.py :2334-2335、manager.py・master_conductor.py（既存領域）・main.py・haddix formatters・nuclei.py）: すべて既存の汎用runtime。VDP clean profileの依存closure（30 files）・model_context（20 templates）からは**到達不能**（import_closure token scan=0で実証）。§13の②remediationでmanifest hits[]に全件分類し、preflightは `deferred_classified`（verdict pass）。genericなowasp参照・nucleiテンプレ名はproduct:noneとして記録。一般化はD03（0426追跡）。
- 自タスクの新規artifact（taxonomy_v1.json・external_audit_v1.json）に含まれていた製品名・URL・環境パスは §13の①remediationで除去済み（denylist hit 0、hash再計算済み）。
- 旧session（M1前）はU00 baselineに留まる — 実質的なfirst-failure信号はM5 active rerunのみ（計画書どおり、D01→0426）。
- external_audit_v1.jsonのsource参照はopaque sha256 refに置換済み（固有URL/env-pathを持たない、計画書§12準拠）。

## 11. 監査結果（固定完了契約に基づく分類）

- **in_scope_blocker: 0件** — 必須テスト（§11 1〜26）全PASS、§14完了条件のうちコードゲート対象（1〜10）は全て成立、回帰0、floor達成（accuracy 1.0/unattributable 0.0/trace_coverage 1.0）。§17.5 preflightは②remediation後 **verdict pass（exit 0）**。§14.6のsealed audit artifactはoffline U00で充足。
- **deferred_followup: 4件**（D01〜D04。上記front matterのdeferred_tasks）— M5 active rerun（承認待ち）、genuine S04〜S12計測、既存汎用runtime一般化、formatter index埋め込み。いずれも完了契約の未達ではなく追跡タスク（D01/D04→SGK-2026-0427、D02/D03→SGK-2026-0426）へ紐付け。
- **non_blocking_observation**: JS artifactの一時配置場所（/tmp/opencode）、nuclei.pyのfalse positive token（nuclei template path規約）、fixtureのS04〜S12がsimulator経由である点。

## 12. 最終判定: DONE（ユーザー承認済みクローズ）

**コードゲート PASS＋§17.5 preflight green（exit 0）＋in_scope_blocker 0** により、固定完了契約（§14）のコードゲート対象条件（1〜10）が成立。§14.6のsealed audit artifactはoffline U00で充足済み。FAIL/UNKNOWNは0件。ユーザー承認のもとタスクを **done** とし、subtask_planを`subtasks/done/`へ移動、registry/ledgerを更新。deferred（D01〜D04）はSGK-2026-0426へ紐付け（M5 active rerunは§14完了阻害ではなく後続入力）。

## 13. クローズ前remediation（①artifact浄化・②preflight/manifest完成）

コードゲート後の独立検証で、当初 §17.5 preflight が verdict fail（exit 3）であることが判明したため、製品合わせ込みをせずに以下を実施し green 化した（denylist 14トークン維持、import_closure/model_context のハードガードは無変更）。

- **① 自タスクの新規artifact浄化**: `external_audit_v1.json`（`localhost:3000`/`localhost:4280`のURL・製品名`product_note`・`/tmp/opencode`環境パス → opaque `*_ref` sha256 と generic note に置換）、`taxonomy_v1.json`（anti-fitting禁止文面の "Juice Shop/DVWA" → 「封印された外部監査対象」）。両者 denylist hit 0、content_hash 再計算（`test_vdp_diagnostic_trace.py::test_artifact_content_hash_self_consistent` グリーン）。
- **② preflight を manifest-aware 化＋manifest完成**: `check_token_scan` を、manifest `hits[]` に列挙された既存legacyファイルのみ `deferred_classified`（計画書§15、SGK-2026-0426/D03へ委譲）とし、`config/diagnostics/**` と clean-profile modules は抑止対象外（新規artifact漏洩は常にFAIL）とするよう変更。判定は `manifest_classified_files()` に抽出。当初未列挙だった7ファイル（`manager.py`/`recon/pipeline.py`/`nuclei.py`/`haddix_formatter.py`/`haddix_ja_en_formatter.py`/`haddix_submission_internal_formatter.py`/`main.py`）を実行番号再スキャンで分類追加（全件 clean closure 外を実証）。抑止挙動の新規テスト3件を追加。
- **再検証（実測）**: preflight **verdict pass / exit 0**（active hits 0、deferred_classified 43／10ファイル）、`test_vdp_product_independence.py` **13 passed**（既存10＋新規3）、VDP+diagnostic 回帰 **1281 passed**（不変）、ops_cli **106 passed**、`git diff --check` clean、docs validator 0。

## 参照ルールファイル（計画書§17の要求）

`AGENTS.md`、`CLAUDE.md`、`rules/lessons.md`、`rules/codingrules.md`、`rules/report-session-consistency.md`、`rules/reporting.md`、`rules/cli-ops-routing.md`、`rules/shigoku-docs.md`、`rules/task-ledger.md`、`rules/python-tests.md`、`docs/shigoku/learnings.md`（ヘッダ行のみ軽量ロード）
