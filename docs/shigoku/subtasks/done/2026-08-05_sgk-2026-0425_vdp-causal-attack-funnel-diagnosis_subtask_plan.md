---
task_id: SGK-2026-0425
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/plans/done/2026-07-31_session-evidence-summary-labeling-and-juice-shop-vdp-readiness-assessment_plan.md
- docs/shigoku/plans/done/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0423_vdp-hidden-holdout-evaluation-shadow-rollout-and-recovery_subtask_plan.md
- docs/shigoku/subtasks/2026-08-05_sgk-2026-0424_vdp-m3a-readonly-pilot_subtask_plan.md
- docs/shigoku/subtasks/2026-08-05_sgk-2026-0426_vdp-product-independent-improvement-and-hidden-reevaluation_subtask_plan.md
title: VDP causal attack-funnel diagnosis and first-failure identification foundation
created_at: '2026-08-05'
updated_at: '2026-08-07'
tags:
- shigoku
target: VDP observation-to-report causal diagnosis, counterfactual evaluation, and
  product-independent improvement gates
---

# 実装計画書：VDP causal attack-funnel diagnosis and first-failure identification foundation

## 0. スコープ凍結（M0–M5、改善ループは SGK-2026-0426 へ分割）

本タスクの完了契約は **M0（契約凍結）〜M5（sealed external audit の診断結果産出）** までとする。すなわち「攻撃ファネルのどこで・なぜ落ちたかを再現可能に診断する基盤」と「その診断artifact（first-failure、proven原因、外部監査のstage診断）の産出」までが本タスクの範囲である。

`proven` 原因に基づく**実際の一般改善（M6）と、新規hidden holdoutでの再評価・readiness引き渡し（M7）は SGK-2026-0426 へ分離**する。理由は、診断基盤の正しさ（本タスク）と、hidden holdout floorを満たすまで完了できない open-ended な改善ループ（0426）を1契約に束ねると、`rules/lessons.md [2026-08] CRITICAL` が警告する moving target 化に陥るためである。本タスクは基盤の正しさと診断産出だけで `done` を判定できる。

M4 の generic benchmark / hidden holdout は本タスクで**基盤とbaselineを構築**する（診断自体の first-failure-accuracy 等を測る）。それを使った**改善前後の合否判定は 0426** が行う。

## 1. 達成したいゴール

- [ ] SHIGOKUが期待した脆弱性へ到達できなかったとき、単なる「証拠不足」ではなく、攻撃経路の**最初に失敗した遷移**を1つに特定できる。
- [ ] 「LLMの知能」「担当specialist」「試行回数」「scanner範囲」「parser」「証拠判定」などの原因候補を、失敗地点とは別軸で管理し、1変数だけを変えた反証実験を通過した原因だけを改善対象にできる。
- [ ] Juice ShopとDVWAは、既知URL・payload・challenge・正解一覧をruntimeへ渡さない**封印された外部監査対象**としてのみ使い、両製品で成績が上がるような合わせ込みを禁止する。
- [ ] 改善の合否基準（対象非依存hidden holdout、事前固定threshold、Juice Shop/DVWA検出件数を完了条件・release gateにしない禁止契約）を本タスクで凍結・実装する。実際の改善前後判定は SGK-2026-0426 が同じ基準で行う。
- [ ] 既存のSGK-2026-0419〜0423が作った observation_id → hypothesis_id → attempt_id → evidence_id → verdict_id → next_action_id の系列を再利用し、足りない境界telemetryだけをadditiveに追加する。
- [ ] 本タスク（診断基盤・診断産出）と SGK-2026-0426（一般改善・hidden再評価・readiness引き渡し）が完了するまで、SGK-2026-0424の実VDPパイロットを開始しない。`diagnostic_readiness=go|hold` の最終発行は 0426 が行う。

本タスクの目的は「Juice Shop/DVWAで何件見つけるか」ではない。正解へ至る一般的な経路のどこでSHIGOKUが脱落したかを再現可能に判定し、その原因を製品非依存fixtureで再現できる状態にするまでの診断基盤を作ることである。実際の一般改善は 0426 が担う。

## 2. 現状と最小の追加範囲

SGK-2026-0418では、観測、仮説、試行、証拠、判定、次の行動、reportを同じID系列で保存し、hidden holdoutと安全gateを実装した。しかし、現在のファネル集計は「各段階に何件あったか」を示すものであり、次を因果的には区別できない。

- scannerが対象面を観測しなかった。
- raw観測はあったがadapterが捨てた、または同一視した。
- 正規化観測はあったが仮説が生成されなかった。
- 仮説はあったがpriority、budget、stop条件で選ばれなかった。
- 選択されたが、specialist、tool、recipe、actor、controlの割当が不適切だった。
- requestは送られたがtransportまたは依存が失敗した。
- 応答に差があったが解釈できなかった。
- 脆弱性らしさは示したが、独立証拠を取得できなかった。
- 証拠は十分だったがvalidatorまたはreportで脱落した。

したがって、既存契約を作り直さず、次の最小追加を行う。

1. 各境界の到達・脱落・理由を、秘密値を持たないversion付きdiagnostic eventとして記録する。
2. 既存canonical recordsとdiagnostic eventsを読み、最初の失敗地点を決定論的に判定するread-only analyzerを追加する。
3. 原因を断定する前に、1変数だけを変えるcounterfactual（反証）runnerを追加する。
4. 改善は一般化fixtureで再現し、新しいhidden holdoutでのみ合否を決める。

既存のEvidenceRecord、EvidenceVerdict、confirmed署名、scope、budget、read-only guard、report/session consistencyの意味は変更しない。

## 3. 診断分類 v1

### 3.1 主分類: 最初に失敗した遷移

主分類は相互排他的とし、期待ケースごとに最も早い失敗地点を1つだけ採用する。後段は `not_reached_due_to=<first_failure_id>` として残し、二重に根本原因へ数えない。

S00〜S12はstageの**種類**であり、全ケースへ同じ直線順序を強制しない。`ExpectedPathCaseV1`は必要stageと依存edgeを持つDAG（分岐可能な経路）として定義し、first failureは「前提edgeが到達済みなのに満たされなかった最初のcut」とする。不要stageは`not_applicable`、許可上実行不能なstageは`ineligible`として母数と理由を残す。follow-up/retryはiteration IDとparent NextActionを持つ同stageの反復として扱い、後のretry成功で最初の失敗記録を上書きしない。

| ID | 遷移 | 到達とみなす事実 | この地点での失敗例 |
|---|---|---|---|
| S00 | 実行契約準備 | 対象面取得を始めるための許可、scope、target identity、初期budgetが評価可能 | 対象の許可・scope・識別が不明で、安全に探索を開始できない |
| S01 | 対象面取得 | 期待ケースに対応するraw producer artifactが存在 | crawl、proxy、schema、browser等の探索範囲に入らない |
| S02 | 観測正規化 | raw artifactからtyped Observationが生成 | parser skip、正規化衝突、情報欠落、鮮度誤判定 |
| S03 | 仮説生成 | capability/actor/trust boundaryが一致するHypothesisRecordが存在 | 観測を脆弱性仮説へ変換できない、誤った能力へ分類 |
| S04 | 優先順位付け | 仮説が予算内の実行候補として選択 | diversity、ranking、探索枠、stop方針で正しい仮説が飢餓化 |
| S05 | admission | scope/capability/budget/HITL gateが期待どおり許可または理由付き拒否 | 安全上正当でないblock、必要前提を無視した許可、budget部分消費 |
| S06 | routing | 適合specialist/tool/recipeと必要依存へ割り当て | 誤specialist、能力不足tool、recipe不一致、必要依存unavailable |
| S07 | 試行設計 | actor、owner、method、入力位置、baseline、attack、inverse、falsificationが整合するAttemptSpecを構成 | payload位置違い、比較actor違い、control不足、success条件不整合 |
| S08 | 実行・transport | 許可されたrequestが一度だけ送信され、応答または明示的失敗を記録 | 未送信、timeout、proxy/browser/OOB停止、二重送信防止block |
| S09 | 応答解釈 | 応答差、marker、状態差、timing等を構造化markerへ変換 | 実レスポンスに信号があるのにAI/parserが意味を取れない |
| S10 | 証拠完成 | required_evidenceと独立controlがすべて同一lineageに揃う | 第2actor、read-back、再訪問、相関OOB、統計反復が不足 |
| S11 | 判定 | Evidence Validatorがcandidate/confirmed/refuted/untestedを根拠付きで出力 | 十分な証拠を誤って保留・反証、理由不明confirmed |
| S12 | report投影 | canonical verdictと証拠参照がreportへ欠落なく投影されconsistent | sessionでは成立したがreport/gateで欠落・誤集計 |
| U00 | 判定不能 | 必要telemetryの欠損を具体的に記録 | 古いsessionにraw producer履歴が無く、S01かS02か断定不能 |

判定規則は次のとおりとする。

- predecessorの到達証拠とsuccessorの欠落証拠がそろった地点だけをfirst failureにする。
- 前提条件は必要になるstageで評価する。第2actorやOOB許可を一律S00へ繰り上げ、より早いsurface/observation失敗を隠してはならない。
- telemetryが足りない場合は推測せずU00とし、`missing_artifacts`へ必要なfield/sourceを列挙する。
- scope・capability・安全gateによる正当な拒否を「検出能力の不具合」と数えない。S00またはS05に記録し、改善対象は前提条件またはpolicyの誤りが反証された場合だけとする。
- record件数の比率だけでstage到達を決めない。opaqueな期待ケースIDごとにID系列とeventを照合する。
- report backfill、scenario coverage、LLMの説明文をraw到達証拠として使用しない。
- labelを持たないartifact-only診断は、観測済みlineageの脱落だけを判定する。存在自体を観測できなかった脆弱性をS01へ分類できるのは、隔離evaluatorがsealed expected pathと照合する場合だけである。

### 3.2 副分類: 原因ファミリー

主分類が「どこで止まったか」、副分類が「なぜ止まったか」を表す。同じ原因は複数stageで発生し得るため、stage IDへ混ぜない。

| ID | 原因ファミリー | 例 |
|---|---|---|
| C01 | prerequisite/contract | actor、認証、許可、scope、状態初期化、OOB経路が不足 |
| C02 | producer coverage | scanner/crawler/proxy/schema/browserの取得範囲・深さ不足 |
| C03 | normalization/schema | parser、adapter、dedup、opaque正規化、型変換の欠陥 |
| C04 | deterministic reasoning rule | capability分類、control、success/falsification規則の不足 |
| C05 | model reasoning/context | 同一入力でもLLM role/model差で正しい仮説・解釈へ到達しない |
| C06 | priority/orchestration | ranking、探索枠、stop条件、再計画、loop構造の不適合 |
| C07 | agent/tool/recipe routing | specialist割当、tool能力、recipe選択、依存接続の不適合 |
| C08 | attempt strategy | actor/owner、入力位置、比較control、最小PoC設計の不適合 |
| C09 | budget/termination | request、follow-up、retry、時間、loop回数不足または無駄遣い |
| C10 | infrastructure/dependency | network、proxy、browser、OOB、queue、key、disk、process障害 |
| C11 | safety/policy | admission、read-only、HITL、scope再検証、rate limitのblock |
| C12 | evidence/verdict/report | marker、Evidence Validator、proof、canonical extractor、formatter/gate |
| C13 | telemetry insufficient | 原因を区別する記録がなく、反証実験も構成不能 |

「AIが弱い」「loopが足りない」「担当agentが悪い」は初期仮説であって原因確定ではない。§4の反証条件を満たした場合だけC05、C06、C07、C09を付与する。

各causeにはfree textだけでなく `mechanism_code` を必須とする。最低限、次の語彙をversion管理し、空文字や`unknown`だけで終了しない。

- C02 producer coverage: `source_not_connected`、`asset_not_in_inventory`、`route_depth_exhausted`、`required_state_not_reached`、`protocol_not_supported`、`producer_failed`、`producer_budget_cutoff`。
- C03 normalization/schema: `parse_rejected`、`field_dropped`、`normalization_collision`、`wrong_dedup`、`stale_discarded`、`type_contract_mismatch`。
- C04 deterministic rule: `capability_misclassified`、`actor_owner_not_inferred`、`control_template_missing`、`success_falsification_mismatch`。
- C05 model: `schema_noncompliance`、`semantic_misinterpretation`、`unstable_reasoning`。raw input/context不足はmodel原因にせずC02/C03/C06へ戻す。
- C06/C09 orchestration: `priority_starvation`、`exploration_slot_missing`、`replan_not_triggered`、`premature_stop_with_pending_action`、`budget_spent_on_duplicates`、`iteration_cap_binding`。
- C07 routing: `specialist_capability_mismatch`、`tool_capability_mismatch`、`recipe_contract_mismatch`、`dependency_not_routed`。
- C08 attempt: `wrong_actor_owner_pair`、`wrong_input_location`、`missing_baseline`、`missing_inverse`、`missing_falsification`、`request_fingerprint_mismatch`。
- C10/C11 operational: `dependency_unavailable`、`transport_timeout`、`queue_backpressure`、`scope_block_expected`、`scope_block_incorrect`、`hitl_missing`、`rate_limit_stop`。
- C12 evidence/report: `marker_not_extracted`、`independent_evidence_missing`、`validator_misclassification`、`proof_unverifiable`、`canonical_projection_missing`、`consistency_mismatch`。
- C13 telemetry: `producer_trace_missing`、`stage_event_missing`、`lineage_broken`、`counterfactual_not_constructible`。

未分類の新mechanismはfail-openで既存語彙へ丸めず、taxonomy versionを上げるまでC13としてHoldにする。

### 3.3 原因確度

| level | 条件 | 改善への利用 |
|---|---|---|
| proven | 同一の凍結入力で1変数だけを変更し、再現可能にstage到達が改善 | 実装変更の根拠にできる |
| supported | 直接artifactが原因と整合するが、介入比較が未実施 | generic fixtureで反証実験を先に作る |
| suspected | 説明可能だが競合仮説を排除できない | 改善しない |
| unattributable | telemetry不足または複数変数が同時に変化 | C13/U00として記録し、計測だけ改善 |

## 4. 反証実験の固定規則

counterfactual runnerは、入力bundle、code/config/prompt/taxonomy version、変更した変数、budget、出力hashを保存する。2つ以上の変数を同時に変えたrunは原因確定へ使わない。

| 原因候補 | 固定するもの | 変えるもの | provenの最低条件 |
|---|---|---|---|
| scanner範囲 C02 | scope、auth、target state、予算、後段pipeline | producerまたは探索戦略1つ | 期待surfaceがraw artifactへ現れ、後段へ渡る |
| parser C03 | 同じraw artifact | adapter/parser version1つ | Observation生成または誤衝突が解消 |
| reasoning rule C04 | 同じObservation | 決定論的規則1つ | 正しいcapability/controlsの仮説が再現生成 |
| LLM C05 | 同じ正規化入力、system prompt、context、tool権限、budget、停止条件 | `config/shigoku.yaml`のrole/profile 1つ | 各条件5回以上でstage到達差が再現し、安全違反・false promotionが増えない |
| priority/loop C06/C09 | 同じ仮説集合・routing・model | ranking、探索枠、上限のいずれか1つ | stop時に高情報量NextActionが存在し、上限変更だけで未見generic caseの到達が改善 |
| routing C07 | 同じHypothesis/Attempt契約・model・budget | specialist/tool/recipe 1つ | 適合routingだけが正しいAttempt/Evidenceへ到達 |
| attempt strategy C08 | 同じ仮説、actor資材、transport | actor/control/入力位置のいずれか1つ | success/falsification契約と実request fingerprintが一致 |
| interpretation C05/C12 | 同じ保存済みresponse | interpreter/model/rule 1つ | 既存responseから正しい構造化markerを再現抽出 |
| evidence C12 | 同じAttemptとresponse | 不足していた独立証拠1つ | required_evidence集合が満たされ、正規Validator経路だけで判定が変化 |
| report C12 | 同じcanonical session | formatter/gate 1つ | consistencyを壊さず欠落投影が解消 |

LLM比較は `LLMClient(role="...")` と `config/shigoku.yaml` のrole定義だけを使用し、`model=`直指定やprovider固有分岐を追加しない。外部LLM通信を伴う比較は、対象非依存fixture、明示予算、ユーザー承認を得た評価ターンに限定する。

## 5. 正本アーキテクチャ

```text
                    runtime（正解ラベルを一切見ない）
  raw producers ──> Observation ──> Hypothesis ──> Admission/Route
       │                 │              │                 │
       └──────────── diagnostic events（hash/ID/reasonのみ）│
                                                          v
  Report <── Verdict <── Evidence <── Response markers <── Attempt/Execution
      │
      └── canonical index + report/session consistency

                    evaluator（runtimeから隔離）
  sealed expected-path labels + runtime artifacts + frozen taxonomy/thresholds
                              │
                              v
                  first-failure verdict per opaque case
                              │
                              v
                 one-variable counterfactual experiment
                              │
                              v
        generic fix ──> 新規の対象非依存hidden holdoutでのみ合否
```

### 5.1 additive diagnostic契約

新規のdiagnostic schemaは、confirmed権限を持たないread-only telemetryとする。

- `DiagnosticEventV1`: event_id、run_id、stage_id、outcome（reached/skipped/blocked/failed）、reason_codes、predecessor_ids、successor_ids、opaque_asset_fingerprint、producer/agent/tool/recipe ID、budget/stop snapshot hash、source_refs、schema/taxonomy version。
- `ExpectedPathCaseV1`（evaluator専用）: opaque_case_id、capability family、stage DAG、必要actor/control/evidence、許可action class。固有endpoint/payload/製品名はevaluator境界の外へ出さない。
- `FirstFailureVerdictV1`: opaque_case_id、first_failure_stage、cause candidates、confidence、evidence refs、missing artifacts、downstream_not_reached、analyzer version。
- `CounterfactualRunV1`: frozen input hash、changed_variable、control/treatment config hashes、repeat count、stage delta、safety delta、attribution verdict。
- `DiagnosticEvaluationV1`: stage reach、first-failure分布、原因確度、未知率、safety、leakage、threshold fingerprint、artifact hash、Go/Hold。

sessionへはadditiveな `vdp_diagnostics_v1` sectionとして保存する。`diagnostic_active=false`では出力しない。`diagnostic_active=true`ではHypothesis 0件でもS00〜S03のeventを保存できるようにし、既存の `vdp_active=false + vdp_contract data` 拒否契約は緩和しない。M0はdiagnostic sectionの型、version、event ID、reason code、参照整合を別にfail-closed検証する。

DiagnosticEventにはraw body、Cookie、Authorization、token、credential、既知payloadを保存しない。URL/parameterは既存正規化後のfingerprintとsource referenceだけを保存し、最下層のsession writerで再度deep redactionする。event buffer、artifact size、repeat数は既存ExecutionBudgetの上限内に置く。

### 5.2 既存実装の再利用

- `src/core/models/vdp_contract.py`: 既存recordを変更せず参照する。diagnostic modelを置く場合もconfirmed APIへ接続しない。
- `src/core/engine/vdp_observation_adapter.py`: adapted/skipped/collisionの境界eventを発行する。
- `src/core/engine/vdp_hypothesis_generator.py`: generated/suppressed/unavailableとpriority traceをeventへ接続する。
- `src/core/engine/master_conductor.py`: admission、routing、stop、queue、dispatchの既存境界へhookを置く。既存attack task動作はfeature flag offで不変にする。
- `src/core/engine/vdp_follow_up_executor.py`: Attempt設計、scope再検証、送信、応答、marker生成の事実eventを発行する。
- `src/core/engine/vdp_evidence_validator.py`: evidence completenessとverdict出力の事実だけをeventへ記録し、署名境界は変更しない。
- `src/core/engine/master_conductor_session_service.py` / `vdp_m0_gate.py`: additive sectionのredaction、保存、strict validation、旧session互換を実装する。
- `src/reporting/vdp_canonical.py`: 既存canonical summaryを正本入力として再利用する。
- `src/reporting/vdp_report_projection.py` / `src/reporting/report_session_consistency.py`: 既存 `vdp_canonical_index_v1` は変更せず、diagnostic event hash、case別stage集合、summary digestだけを持つadditiveな `vdp_diagnostic_index_v1` を比較する。labels、固有URL、payloadはreport indexへ入れない。
- `src/reporting/vdp_dataset.py` / `vdp_holdout_runner.py`: split、manifest hash、label隔離、threshold freeze、leakage検査を再利用する。
- `scripts/shigoku_ops_cli.py`: read-onlyなartifact-only `vdp diagnose` を追加し、report指定時は公式consistency checkerを必ず先に通す。runtime CLIへ`--labels`やground-truth path引数を追加しない。

### 5.3 新規ファイルの最小案

- `src/core/engine/vdp_diagnostic_trace.py`: bounded event collector、deterministic event ID、reason vocabulary、redaction-safe serialization。
- `src/reporting/vdp_diagnostic.py`: canonical records + eventsからfirst failureを判定するpure analyzer。
- `src/reporting/vdp_counterfactual.py`: frozen replay bundleと1変数比較のvalidation/集計。実通信は行わない。
- `scripts/check_vdp_product_independence.py`: evaluator側の依存closure、変更file、model-facing context、execution traceをmanifest/denylistと照合するread-only preflight。
- `tests/fixtures/vdp_diagnostic_env/`: 製品名・既知route・payloadを持たない生成fixtureとevaluator。runtimeとlabelsを別mountにする。
- `tests/unit/engine/test_vdp_diagnostic_trace.py`、`tests/unit/reporting/test_vdp_diagnostic.py`、`tests/unit/reporting/test_vdp_counterfactual.py`、`tests/unit/scripts/test_shigoku_ops_vdp_diagnose.py`、`tests/unit/scripts/test_vdp_product_independence.py`: 必須反証テスト。

新しい外部dependencyは追加しない。標準libraryと既存VDP helperで実装する。

## 6. カーブフィッティング禁止契約

### 6.1 データ区分

| 区分 | 用途 | 実装者/runtimeがlabelを見られるか | 合格根拠に使えるか |
|---|---|---|---|
| development generic | TDD、fault injection、個別原因の再現 | 見られる | 単体品質のみ |
| validation generic | 閾値候補と回帰確認。developmentとはseed/grammar instanceを分離 | 評価時に見られる | 最終合格には使わない |
| hidden generic holdout | 新しい乱数seed、opaque route/field/state、対象非依存capability grammar | evaluatorのみ | 本タスクの改善gate正本 |
| Juice Shop/DVWA sealed audit | 現実的な複合経路でfirst failureを外部監査 | evaluatorのみ。runtimeへ正解を渡さない | 診断材料のみ。release passには使わない |
| 実VDP | SGK-2026-0424以降 | 正解labelなし | 本タスクでは通信しない |

### 6.2 禁止事項

- 本タスクの新規・変更コード、config、prompt、recipe、runtime driverへ製品名、既知URL、既知parameter、challenge名、payload、expected finding countを入れない。
- 既存repositoryに残る製品固有のprompt例、expected-detection matrix、target判定、scanner分岐、metricsをclean diagnostic profileの依存closure・model-facing context・実行traceへ入れない。製品固有branchが到達可能または実行されたrunは汚染済みとして評価を無効化する。
- Juice Shop/DVWAの結果を見て、同じeval versionのthreshold、prompt、recipe、priority、budget、capability mappingを変更して合格を主張しない。
- 特定製品でconfirmed件数が増えたことを、本タスクの成功・VDP準備完了・model優位の根拠にしない。
- 同じ対象へ変更と再実行を反復する最適化loopを作らない。
- evaluator label、ground truth、product probe tokenをsession/report/log/checkpoint/exceptionへ出さない。
- target固有条件分岐を名前の難読化、hash、regex、fixture名変更で隠さない。構造scanで同義の分岐もレビューする。

現在のrepositoryには、`src/reporting/expected_detection_matrix.py`、`src/core/agents/swarm/injection/smart_xss.py`、`src/core/validation/`、一部prompt等に製品固有のlegacy/regression用途が存在する。これらの全削除は本タスクの目的ではないが、次の隔離はin scopeとする。

- `product_independence_manifest_v1` に全hit、用途、runtime到達可能性、clean profileでの状態、根拠testを列挙する。
- evaluator-only regression fixtureはruntime import closureから外す。
- 一般runtime pathにある製品固有branchは、製品非依存規則へ一般化してgeneric testを付けるか、clean diagnostic/VDP modeでfail-closed無効化する。
- 実際にLLMへ渡したsystem/user/tool contextをredacted hashとdenylist scan結果で検証し、repository上の未使用文字列だけでなく**modelが見た入力**に漏洩がないことを証明する。
- clean profileの依存closureまたはexecution traceに未分類hitが1件でもあればM5/M6を開始しない。

### 6.3 Juice Shop/DVWAの正しい使い方

1. 先にtaxonomy、評価式、threshold、code/config/prompt hashを凍結する。
2. 既存のconsistentなreport/sessionを最初にoffline解析し、欠損telemetryはU00として記録する。古いartifactから事実を捏造しない。
3. active rerunが必要な場合だけ、対象version、設定、test account、初期state、scope、予算、許可を固定し、外部egressのない隔離networkでユーザー承認後に1 evaluation versionにつき1回実行する。
4. evaluatorだけが既知の正解pathを保持し、runtime artifactへopaque case IDを後結合する。出力はstage/capability/reasonだけで、固有route/payloadを改善担当へ渡さない。
5. supported/provenになった原因は、製品情報を含まないgenerated fixtureで再現できた場合だけ修正する。
6. 修正後の合否は、新しいseedのhidden generic holdoutで決める。同じJuice Shop/DVWAの再実行は参考回帰であり、合格証拠にはしない。
7. 外部監査後に新しい問題が見つかっても、同一タスク内で無限に条件を追加しない。固定済み完了契約外なら追跡タスクへ送る。

## 7. 対象非依存capability grammar

生成fixtureは製品や既知CVEでなく、次の一般構造の組合せからcaseを作る。

- surface: link、form、API schema、GraphQL shape、browser/proxy observation、async/realtime entry。
- actor: anonymous、actor A、actor B、owner、non-owner、role差。
- trust boundary: client/server、tenant、role、session/token、external fetch、stored/revisit、state transition。
- action: read、compare、replay、read-back、browser revisit、OOB（許可時のみ）、state change（隔離fixture + HITL時のみ）。
- evidence: baseline、attack、inverse、falsification、owner/permission/sensitive-field差、independent read-back、unique correlation、repeated timing control。

route、field名、object ID、response順、不要field、遅延、errorはrunごとに生成し、16進opaque pathの正規化衝突など既存adapter仕様を踏まえてcaseが偶然同一視されないmanifest検証を行う。各capability familyは複数caseを持ち、macro平均で一部familyの大量caseによる水増しを防ぐ。

## 8. 実装と実行の段階

### M0: 契約凍結・characterization（通信0）

- [ ] taxonomy v1、reason vocabulary、event schema、case-based metrics、threshold floor、anti-fitting禁止事項をversion/hash付きartifactとして固定する。
- [ ] writer/reader/formatter/gate/CLIの境界表を作り、既存recordだけで判定できるstageと追加eventが必要なstageを確定する。
- [ ] 現行session/report/decision traceのcharacterization testを先に作り、feature flag offで出力が変わらないことを固定する。
- [ ] `config/shigoku.yaml` に既存VDP設定規約へ従う `diagnostics.enabled=false`（default）、`diagnostics.required=false`（通常run）、event/artifact上限をadditiveに定義し、rollbackをflag offで一意にする。
- [ ] 既存の製品固有code/prompt/config/metric/evaluatorを全件棚卸しし、`product_independence_manifest_v1` へ分類する。clean profileから到達可能なhitを0にする設計を先に固定する。

### M1: diagnostic telemetry（通信0、既存動作不変）

- [ ] `DiagnosticEventV1` collectorをTDDで実装し、各境界へadditive hookを接続する。
- [ ] `diagnostics.required=false`の通常runではhook失敗を既存decision traceへ記録して既存経路を維持する。`required=true`の評価runでは次の通信前にkill switchを作動させ、checkpointを保存してHoldにし、telemetryなしで能動実行を継続しない。未知の例外を握り潰さない。
- [ ] bounded queue、artifact上限、checkpoint/resume、atomic save、deep redaction、旧session reader互換を実装する。
- [ ] diagnostic section不正、version不明、非dict event、参照不整合をM0でfail-closedにする。

### M2: first-failure analyzerとCLI（通信0）

- [ ] `analyze_observed_lineages()` はlabelsなしで観測済み系列だけを診断し、未観測caseのcoverageを推測しない。
- [ ] evaluator専用 `evaluate_expected_paths()` はsealed stage DAGとartifactを後結合し、S00〜S12またはU00を1件だけ返す。engine/runtimeからimportしない。
- [ ] `shigoku-ops vdp diagnose --session ... [--report ...] --output ...` を追加する。report指定時はsession明示の有無に関係なくconsistency checkerを通し、label入力を受け付けない。
- [ ] stdoutは人間向け要約、JSON artifactは完全なmachine-readable結果、stderrは実行不能理由に分け、exit codeはpass/hold/input error/runtime errorを区別する。
- [ ] 既存output pathが別hashのartifactを指す場合は上書きを拒否し、同一hashだけをidempotent成功にする。

### M3: counterfactual harness（外部target通信0）

- [ ] raw/Observation/Hypothesis/Attempt/Response/Canonical Sessionの各replay bundleをhash固定する。
- [ ] scanner、parser、rule、model、priority、routing、attempt、interpretation、evidence、reportのfault injectionを1変数ずつ実行できるようにする。
- [ ] 2変数変更、入力hash不一致、threshold後付け、repeat不足、safety差悪化をattribution不成立として拒否する。

### M4: generic benchmarkとhidden holdout（隔離fixtureのみ）

- [ ] development/validation/hiddenをmanifest、seed、semantic duplicate検査で分離する。
- [ ] runtime containerへlabels、tests、evaluator、repo全体をmountせず、evaluatorはnetworkなしにする。
- [ ] 各stageの意図的failure fixtureでfirst-failure正解率と原因誤帰属率を測る。
- [ ] baselineを保存し、thresholdをhidden閲覧前に凍結して1回評価する。
- [ ] hiddenは各capability family 5ケース以上、3つ以上の独立seedを持ち、stage fault injectionは各stage 3変種以上とする。case数と除外理由をmanifestへ固定する。
- [ ] **`ExpectedPathCaseV1` のstage DAG自体の正しさを検証する**。DAG作成は「意図した攻撃経路」という知識のencodingであり、DAGが誤ればfirst-failure・cause・counterfactualが連鎖的にずれる。(a) 各DAGをpeer review対象とし、(b) 正しく最後まで到達すべき合成pass caseでanalyzerが誤ってfirst-failureを立てないこと、(c) 意図的fault caseで想定stageだけがcutされることをtable testで確認する。DAG検証が未達のcaseはfirst-failure判定の母数から除外し理由を残す。

### M5: Juice Shop/DVWA sealed audit（ユーザー承認まで通信0）

- [ ] 既存artifactは公式consistency checkerを通った同一report/sessionだけをoffline診断する。**既存sessionはM1のdiagnostic telemetry導入前に生成されているため、producer/observation traceが無く、first-failureの大半はU00（`producer_trace_missing`）に落ちる見込みである**。既存artifactのoffline passはU00 baselineの確認が主目的であり、実質的なfirst-failure信号はM1導入後のinstrumented active rerun（次項、ユーザー承認必須）でしか得られない。「rerunなしで診断完了」と主張しない。
- [ ] 新規実行が必要なら、実行前にユーザーへ対象、local isolation、scope、method/action、予算、初期化/rollback、停止条件を提示し、明示承認を得る。
- [ ] active auditは意図的脆弱性検証用のlocal ephemeral containerだけを対象にし、internal network、外部egress 0、host secret mount 0、test account/dataのみ、case/runごとの初期化とrollback、対象外宛先fail-closedを実アクセスログで証明する。
- [ ] runtimeへlabelを渡さず、evaluator側でopaque case IDへ結合してfirst failureを出す。
- [ ] 実行前preflightでproduct independence manifest、import closure、実際のmodel-facing context、予定recipe/specialist traceを検査し、製品固有hitが到達可能ならrunを開始しない。
- [ ] audit outcomeはGo/Failでなく、stage分布、U00、supported/proven原因、必要telemetryを示す診断結果とする。

### M6 / M7: SGK-2026-0426 へ分割（本タスク対象外）

一般改善（proven原因ベースのgeneric reproduction test → 最小修正）と、新規hidden holdoutでの改善再評価、SGK-2026-0424への `diagnostic_readiness=go|hold` 引き渡しは、本タスクではなく **SGK-2026-0426** の実装・完了契約とする。本タスクは M0–M5 の診断基盤と診断artifact産出までで `done` を判定する。0426は本タスクが凍結したtaxonomy・threshold・hidden holdout基盤・sealed audit診断結果を入力として再利用する。

## 9. 指標と事前固定threshold

単一の総合点は作らない。case単位、capability family単位、stage単位で分ける。

- `trace_coverage`: evaluatorの全期待ケースがS00〜S12またはU00を持つ割合。必須100%。
- `first_failure_accuracy`: 意図的fault injectionの正解stage一致。hidden genericで95%以上。
- `cause_attribution_precision`: provenとした原因が単一変数再実験で再現する割合。90%以上。
- `unattributable_rate`: 必要telemetryを備えたgeneric caseでU00/C13になる割合。10%以下。
- `surface_reach_macro`: eligible capability familyごとのS01到達macro平均。80%以上。
- `hypothesis_reach_macro`: S03到達macro平均。70%以上。
- `valid_attempt_reach_macro`: S07到達macro平均。60%以上。
- `evidence_completeness_macro`: S10到達macro平均。50%以上。
- `false_promotion_rate`: ground truth不一致confirmed。0%。
- `safety_violation_count`: scope逸脱、未承認状態変更、secret漏洩、二重送信、予算超過。0件。
- `product_leakage_count`: runtime/source/prompt/config/report/sessionへのsealed labelまたは製品固有probe漏洩。0件。
- `regression`: feature flag offの既存session/report、旧reader、gate、attack task出力差分。0件。

上記は最低floorであり、`ThresholdArtifact`はdirectionを明記する。minimum=0やmaximum=1など全runが自明合格する値を禁止する。threshold変更はeval versionを更新し、過去resultを再利用しない。scope外・禁止actionはeligible denominatorから除外するが、除外caseと理由を必ず保存して母数を隠さない。

Juice Shop/DVWAにはpass thresholdを置かない。そこでのmetricはfirst-failureの外部監査であり、本タスクの合否を決めない。

## 10. failure modeと回復

| failure | 動作 | 回復/証拠 |
|---|---|---|
| diagnostic hook例外 | 通常runは既存decision traceへdegradedを記録。`required=true`評価runは次の通信前に停止してHold | checkpoint保存後、event境界を修正してreplay。黙って欠落・継続しない |
| queue/artifact上限 | 新規eventを無言破棄せずbackpressure reasonを保存 | checkpointから再開、上限超過をU00に偽装しない |
| session途中書込 | temp + atomic replace、PermissionError等を伝播 | 最後の有効checkpointから再開 |
| label/runtime境界違反 | 即No-Go、当該eval versionを無効化 | 新しい隔離環境・eval versionでやり直す |
| report/session不一致 | 診断・比較を停止 | reason codeを保存し、同一組を修復するまで推測しない |
| LLM/API障害 | model能力不足と判定せずC10 | 同一bundleの再実行またはHold |
| budget枯渇 | refutedにせずC09 + untested | pending NextActionとstop snapshotを保存 |
| 複数原因同時変更 | provenを拒否 | 1変数ずつ実験を分割 |
| hidden threshold未達 | タスクをdoneにしない | generic原因を再診断。Juice/DVWAへ合わせない |
| 外部監査だけ改善 | release改善と認めない | 新規hidden genericで再現できなければ棄却 |
| real first-failureがgeneric grammarで再現不能 | 製品合わせ込みへフォールバックしない。まずgeneric grammar（§7）へ製品情報を含まない新しい抽象capability caseを追加して再現を試みる | 追加caseで再現できれば通常のproven経路。追加してもなお再現不能なら `C13/telemetry_or_grammar_gap` として記録し計測改善のみ行い、当該原因の改善はHold。grammar拡張が製品リークでないことをmanifest/denylist scanで証明する |

## 11. 必須テスト

```text
generic producer -> adapter -> hypothesis -> priority/admission -> routing -> attempt
       |              |           |                |                 |         |
     S01 test       S02 test     S03 test         S04/S05 test     S06 test   S07 test
                                                                              |
                                report <- verdict <- evidence <- response <- execution
                                  |         |           |           |           |
                                S12 test   S11 test    S10 test    S09 test    S08 test

sealed labels --(evaluator only)--> first failure --> counterfactual --> holdout gate
       |                                  |                 |             |
   isolation/leak test             exact stage test   one-variable test  no-fit test
```

必須テストは次を含む。

1. S00〜S12を1つずつ意図的に失敗させ、最も早いstageだけがfirst failureになるtable test。
2. predecessor evidence欠損時は推測せずU00になり、必要artifact名が列挙されるtest。
3. downstream failureが `not_reached_due_to` になり、root cause集計へ二重計上されないtest。
4. 同じ入力順、時刻、UUID、response順の差でevent IDとverdictが変わらない決定性test。
5. raw artifactあり/Observationなし、Observationあり/Hypothesisなしを区別するtest。
6. priority starvation、budget stop、loop stop、routing mismatchを区別するtest。
7. model A/Bは同じprompt/context/budgetでのみ比較可能で、repeat不足・複数変数変更を拒否するtest。
8. transport errorをmodel/脆弱性反証へ誤分類しないtest。
9. response markerあり/解釈なしと、解釈あり/独立証拠なしを区別するtest。
10. 十分なEvidenceRecordがあるのにcandidateのまま、session confirmedなのにreport欠落、のS11/S12反証test。
11. DiagnosticEventの非dict、unknown version、unknown stage/reason、broken ID referenceをM0が拒否するtest。
12. feature flag off、旧session、VDP inactive、Hypothesis 0件の互換test。
13. nested dict/list/source_refs/exceptionにsecretを入れ、event/session/report/CLI JSONで0件になるtest。
14. event queue full、disk full、PermissionError、interrupt/resume、重複eventでsilent loss/二重状態変更がないtest。
15. development/validation/hidden間のsemantic duplicateとseed再利用をmanifest検証が拒否するtest。
16. runtime containerからlabel path、tests、repo全体がENOENTで、evaluatorがnetworkなしで動くtest。
17. 本タスクの新規・変更code/prompt/config/recipe/runtime driverに製品名、既知route、probe tokenが0件で、clean profileのimport closure・model-facing context・execution traceに既存製品固有hitが0件の構造/実行test。
18. same eval versionのthreshold変更、code/config/prompt/taxonomy hash不一致を拒否するtest。
19. `shigoku-ops vdp diagnose` のargs、exit code、stdout/stderr、JSON schema、report consistency fail-closed test。
20. CLIテストを `VALIDATION_SUITES["ops_cli"]` へ登録し、標準validationで実行されるtest。
21. canonical extractor、Evidence Validator、separated manifest、report/session consistency、rollout gateの既存回帰。
22. 新規hidden genericで§9のfloorを満たし、false promotion/safety/product leakageが0のintegration評価。
23. stage DAGのoptional branch、not_applicable、ineligible、retry/follow-up loopでfirst failureが安定し、後続成功が初回失敗を上書きしないtest。
24. artifact-only CLIにlabel引数が存在せず、未観測caseのrecall/S01を推測せず `coverage_not_measurable_without_sealed_labels` を出すtest。
25. `vdp_diagnostic_index_v1` のevent hash、stage集合、summary digest改変をconsistency checkerが検出し、旧report/sessionではadditive absentとして互換動作するtest。
26. diagnostic hook失敗時、`required=false`は既存通常経路を維持し、`required=true`は次のnetwork client呼出し前に停止・checkpoint・Holdとなるtest。

## 12. 成果物

- `taxonomy_v1.json`: stage、cause、reason、判定規則、hash。
- `product_independence_manifest_v1.json`: 既存/新規product-specific hit、用途、到達可能性、clean profile隔離証拠、hash。
- `diagnostic_events_v1`を含むsession/checkpoint（redacted、bounded、atomic）。
- `first_failure_<run_id>.json`: case別first failure、confidence、evidence refs、missing artifacts。
- `counterfactual_<experiment_id>.json`: frozen input、単一変更、control/treatment結果、attribution。
- `thresholds_<eval_version>.json`: direction付き事前固定thresholdとfingerprint。
- `diagnostic_eval_<eval_version>.json`: hidden genericのmetrics、leakage、artifact hash、Go/Hold。
- `external_audit_<eval_version>.json`: Juice Shop/DVWAのopaque case別stage診断。固有URL/payloadは含めない。
- Haddix separated report + manifest、公式report/session consistency結果、`shigoku-ops vdp diagnose`出力。
- work report / work log: 改善ごとの因果証拠、検証コマンド、実結果、in_scope blocker/deferred/non-blocking分類。

既存artifactは上書きせず、run/eval version別pathへatomic保存する。中断時のpartial artifactは正式成果物として扱わず、manifest/hashがそろったbundleだけを評価する。

artifact-only CLI出力は `coverage_not_measurable_without_sealed_labels` を明記し、S01の見逃し率や全体recallを表示しない。expected-case recallとS00/S01の脱落は隔離evaluator artifactだけが出力する。

## 13. SGK-2026-0424 / SGK-2026-0426との関係

- 本タスク（0425）は診断基盤と診断artifactの産出までを担い、実際の一般改善と `diagnostic_readiness=go|hold` の最終発行は **SGK-2026-0426** が担う。依存順は 0425 → 0426 → 0424。
- SGK-2026-0424はactiveのまま維持するが、0425がdoneになり、続いて0426がdoneになって `diagnostic_readiness` artifactが生成されるまで**実行不可**とする。
- 0426のreadinessがHoldなら、0424は通信せずHold理由を受け取る。0425が `proven` 原因を1件も出さなかった場合、0426はreadinessを `hold`（`no_proven_cause`）として引き渡す。
- readinessがGoでも、0424固有のユーザー許可、VDP scope、ProgramCapabilityMatrix、予算、kill switchを別途固定する。
- 本タスクは実VDPへ通信せず、M3b/M3c/M4を有効化しない。

## 14. 完了条件（固定契約）

1. taxonomy v1がversion/hash付きで固定され、全期待ケースがS00〜S12またはU00の1つだけに分類される。
2. S00〜S12の境界eventが実runtime経路から生成され、旧session・feature flag off・通常session保存を壊さない。
3. raw producer不在、adapter脱落、仮説欠落、priority starvation、routing、attempt設計、transport、解釈、証拠、verdict、reportを反証testで区別できる。
4. model、agent/tool routing、loop/budgetの原因は§4の単一変数条件を満たさない限りprovenにならない。
5. development/validation/hidden/external auditがアクセス境界とmanifestで分離され、runtimeからsealed labelsが読めない。
6. version/config/scopeを固定したJuice ShopとDVWAそれぞれのsealed external audit artifactが存在し、全期待ケースがfirst failureまたはU00を持つ。本タスクの新規・変更コードに製品固有情報が0件で、clean diagnostic profileの依存closure、model-facing context、execution trace、runtime artifactに既存製品固有logic/tokenが0件であり、両製品の検出件数をpass条件にしていない。
7. diagnostic自体が意図的fault injectionのhidden genericで §9 の `first_failure_accuracy`／`cause_attribution_precision`／`unattributable_rate` floorを満たし、stage DAGの正しさ検証（§8 M4）を通す。実際のproduct-code改善は本タスクの完了条件にしない（SGK-2026-0426）。
8. false promotion、scope逸脱、未承認状態変更、secret/product-label漏洩、二重送信、予算超過が0件である。
9. diagnostic CLI、session、report、evaluation artifactが同一ID/hash系列で追跡でき、report/session consistencyがconsistentである。
10. targeted test、VDP関連回帰、docs validator、git diff checkがすべて成功し、失敗を除外して成功宣言していない。
11. 本タスクは実VDPへ通信せず、`first_failure_*`／`counterfactual_*`／`external_audit_*`／`taxonomy_v1`／`thresholds_*` の診断artifactをhash整合込みで産出し、SGK-2026-0426が入力として利用できる状態で引き渡す。`diagnostic_readiness=go|hold` の最終発行は0426が行う。
12. work reportが各診断caseを `first failure -> cause candidate -> confidence -> (該当する場合はproven counterfactual)` の順に説明する。code改善の因果説明はSGK-2026-0426のwork reportが担う。

固定済み完了条件がすべてPASSし、`in_scope_blocker=0`ならdoneにする。外部監査で新たに見つかった計画外hardeningや実改善は追跡タスク（主にSGK-2026-0426）へ送り、本タスクの完了条件へ暗黙追加しない。一方、diagnostic自体のhidden generic threshold未達、label漏洩、誤confirmed、通常経路回帰はin_scope blockerである。

## 15. NOT in scope

- Juice Shop/DVWAの既知脆弱性一覧、固有URL、payload、challenge、flagをruntimeへ組み込むこと。
- Juice Shop/DVWAのconfirmed件数を増やすこと自体、または両製品だけに対するpass判定。
- 実VDPへの通信、実ユーザーデータ取得、scope外探索、第三者OOB、未承認状態変更。
- M3b、M3c、M4の有効化、実VDP rollout判断。
- すべてのscanner/LLM/specialistを一度に交換する大規模rewrite。
- 原因がsuspectedのままprompt、model、loop、threshold、agent routingを変更すること。
- 新しい外部scanner、外部dependency、学習済みmodel、教師データ収集基盤の追加。
- repository全体に残るlegacy製品別regression fixture、過去report、manual、テスト名を一括削除すること。clean profileから到達可能な製品固有branchの一般化または無効化はin scopeとする。
- 製品監査後に同じ対象へ変更と再実行を繰り返す最適化loop。
- labelを持たない通常session/CLIから、未観測脆弱性のrecallやS01見逃しを推測すること。
- 実装責任者、要員配置、工数見積り。

## 16. 実装順序と分割方針

実装と実行を分け、次の順序を崩さない。

1. M0契約・characterization。
2. M1 telemetry。
3. M2 analyzer/CLI。
4. M3 counterfactual harness。
5. M4 generic benchmark/hidden holdout（基盤・baseline構築とDAG検証）。
6. M5 sealed external audit（明示承認後のみ）＝本タスクの終点。

M6（generic fix/new hidden evaluation）とM7（readiness/closeout）は SGK-2026-0426 の実装順序で実施する。

並列化する場合も、contractが固定された後に限り、(A) telemetry、(B) pure analyzer/counterfactual、(C) fixture/evaluatorの3laneへ分ける。同じ `vdp_contract.py`、`master_conductor.py`、`scripts/shigoku_ops_cli.py` を複数fixerが同時編集しない。統合順はA→B→C→CLI/report→external auditとする。

## 17. 検証コマンドと合格条件

実装時は対象を狭く検証してから広げる。予定コマンドは、実装で確定した実ファイル名に合わせて計画書を明示更新してから実行する。

### 17.1 targeted TDD

```bash
.venv/bin/pytest \
  tests/unit/engine/test_vdp_diagnostic_trace.py \
  tests/unit/reporting/test_vdp_diagnostic.py \
  tests/unit/reporting/test_vdp_counterfactual.py \
  tests/unit/scripts/test_shigoku_ops_vdp_diagnose.py \
  tests/unit/scripts/test_vdp_product_independence.py \
  -q
```

合格条件は全pass、skip/xfailed 0、S00〜S12/U00、DAG、単一変数拒否、secret/label境界、CLI fail-closedの各testが実行済みであること。

### 17.2 既存境界回帰

```bash
.venv/bin/pytest \
  tests/unit/engine/test_vdp_*.py \
  tests/core/engine/test_master_conductor_vdp_*.py \
  tests/unit/reporting/test_vdp_*.py \
  tests/unit/main/test_main_report_haddix_vdp_gate.py \
  tests/unit/scripts/test_shigoku_ops_vdp_gate.py \
  tests/unit/scripts/test_shigoku_ops_vdp_diagnose.py \
  -q

.venv/bin/shigoku-ops --json validate pytest --suite ops_cli --quiet
```

合格条件は当該変更起因failure 0、既存confirmed/proof/scope/budget/rollback/old-reader契約の回帰0、追加CLI testが標準suiteで実行されること。

### 17.3 隔離fixtureとhidden評価

```bash
bash tests/fixtures/vdp_diagnostic_env/run_diagnostic_eval.sh
```

合格条件はruntimeからlabels/tests/repo全体が読めず、evaluator network 0、3 independent seeds、§9 threshold全達成、false promotion/safety/product leakage 0、manifest/hash一致であること。Dockerが利用不能な環境では完了扱いにせず、阻害要因として報告する。

### 17.4 実artifact

```bash
.venv/bin/shigoku-ops --json vdp diagnose \
  --session <absolute-session-path> \
  --report <absolute-report-path> \
  --output <versioned-output-path>

.venv/bin/shigoku-ops --json report consistency \
  --report <absolute-report-path> \
  --vdp-key-registry <absolute-public-key-registry-path>
```

合格条件は `consistent`、reason_codes空、diagnostic/canonical digest一致、artifact-only出力にcoverage推測なし、separated manifest/hash一致であること。Juice Shop/DVWAのactive rerunはこのコマンド群へ自動的に含めず、M5の明示承認後にのみ行う。

### 17.5 source・文書・差分

```bash
rg -n -i -f <sealed-product-denylist-path> <changed-production-files>
.venv/bin/python scripts/check_vdp_product_independence.py \
  --manifest <product-independence-manifest> \
  --profile clean-diagnostic \
  --denylist <sealed-product-denylist-path>
python3 scripts/sync_shigoku_updated_at.py
python3 scripts/validate_shigoku_docs.py
git diff --check
graphify update .
```

合格条件は変更production fileのproduct token 0件、clean profileの到達可能/実行/model-context hit 0件、未分類legacy hit 0件、docs validator全category 0、whitespace error 0、graphify artifact更新と主要symbol登録確認である。denylist自体はevaluatorだけが読み、runtime image/mountへ渡さない。
