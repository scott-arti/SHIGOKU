---
task_id: SGK-2026-0421
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/plans/done/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0419_vdp-evidence-schema-safety-budget-and-recovery-foundation_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0420_vdp-capability-driven-hypothesis-generation-shadow-workflow_subtask_plan.md
- docs/shigoku/reports/2026-08-03_sgk-2026-0421_vdp-evidence-gap-driven-verification-and-safe-follow-up_work_report.md
- docs/shigoku/worklogs/2026-08-03_sgk-2026-0421_vdp-evidence-gap-driven-verification-and-safe-follow-up_work_log.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0422_vdp-canonical-evidence-reporting-and-separated-quality-gates_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0423_vdp-hidden-holdout-evaluation-shadow-rollout-and-recovery_subtask_plan.md
title: VDP evidence gap driven verification and safe follow-up
created_at: '2026-07-31'
updated_at: '2026-08-07'
tags:
- shigoku
target: src/core/engine,src/core/agents/swarm
---

# 実装計画書：VDP evidence gap driven verification and safe follow-up

## 1. ゴール

- [x] candidateの不足証拠をreason codeから特定し、最小の追加検証で証拠を揃え、Attempt/Evidence/candidate verdictを保存する（confirmedの生成・validation_proof発行はSGK-2026-0422のcanonical Evidence Validatorが唯一実施する。0421では証拠が十分でもconfirmedを生成せず、0422へ渡せる形で保存する）。
- [x] refutedは明示的な反証証拠が成立した場合だけ設定する。timeout、WAF、auth loss、dependency停止、scope block、budget枯渇はrefutedへ変換せず、candidateまたはuntestedとして理由コードを保存する。
- [x] 同じ追加スキャンを繰り返さず、actor、resource、状態、browser、OOBなど不足した証拠だけを取得する。
- [x] shadowから開始し、安全な読取系だけを限定enforceした後に段階拡大する。
- [x] queue失敗、依存停止、中断時にも候補とpending actionを失わない。

## 2. 依存と対象

SGK-2026-0419とSGK-2026-0420の完了後に開始する。

- src/core/engine/master_conductor.py: evidence gapからNextActionを選び、admission後にqueueへ追加。
- src/core/engine/vdp_observation_adapter.py: SGK-2026-0420で未接続の観測源を既存ObservationSourceKindへ接続し、取得不能時は理由付きunavailable traceを維持する。formは既存 `_signal_bundle._endpoint_signals[*].params[*].location == "form"` から取得する（VDPフックはtask生成より先に実行されるため、task `_context` や `forms_by_url` は使用しない）。crawler、JavaScript、API schema、GraphQL、browser traffic、proxy historyは受動artifactのproducerを確認できたものだけ接続し、producerを確認できないsourceは理由付きunavailableのまま維持する。既存artifactを変換するための新しいcrawlや通信は起動しない。
- src/core/engine/recipe_contracts.py: fixed reason/action vocabulary、allowlist、stop condition。
- src/core/engine/budget_policy.py: follow-up requestとretry予算。
- src/core/agents/swarm/injection/: auth matrix、object comparison、XSS、SQLi、SSRF/OOBなど既存検査。
- src/reporting/haddix_evidence_quality.py: reason codeと必要証拠の正本。
- tests/core/agents/swarm、tests/core/engine、tests/unit/reporting: class別証拠とfailure path。

## 3. Evidence gapからNextActionへの契約

全既知reason codeを集合A〜Eに分類し、各コードを決定論的に一意のNextActionまたはmanual reviewへ写像する（coverage 100%）。

- 集合A（follow-up対象）: evidence gap reason code。表3-1のとおり。
- 集合B（生成系）: recipe_contractsのVDP_REASON_CODES生成系コード。表3-2のとおりfollow-up対象外。
- 集合C（admission系）: AdmissionReasonCode（vdp_contract.py）。表3-2のとおり。
- 集合D（budget/circuit系）: BudgetReasonCodeV1（vdp_contract.py）。表3-2のとおり。
- 集合E（infra系・0421新規）: follow_up_enqueue_failed、evidence_channel_lost、dependency_unavailable、unknown_reason_code。表3-2のとおり。

### 3-1 集合A: evidence gap → NextAction 対応表

| reason code（正確な文字列） | NextAction | 分類 | risk_class | 必要前提 | 成功証拠 | M3aでの扱い |
|---|---|---|---|---|---|---|
| payload_request_mismatch | exact replay | follow_up | read_only（元requestが状態変更ならstate_changing） | scope、budget | 実requestとHypothesis payloadのmethod/URL/body/header位置一致 | 元requestが状態変更なら拒否→manual_review |
| untested_no_second_account | cross-account matrix | follow_up | read_only | authA/authBと各所有資産 | actor/owner交差による越権差分 | 実行可（read_only） |
| authz_impact_not_proven | semantic field comparison | follow_up | read_only | protected resource | owner、permission、sensitive field差分 | 実行可（read_only） |
| semantic_diff_owner_permission_sensitive_field | semantic field comparison | follow_up | read_only | protected resource | 同左 | 実行可（read_only） |
| state_change_not_verified | before/mutation/read-back | follow_up（M3b gate内のみ） | state_changing | 状態変更許可・HITL承認 | 独立再取得で状態差 | 拒否→manual_review |
| state_change_readback | read-back検証 | follow_up（M3b gate内のみ） | state_changing | 状態変更許可・HITL承認 | 同左 | 拒否→manual_review |
| browser_execution_missing | browser context verification | follow_up | read_only（非状態変更browser操作のみ） | browser可、auth continuity | execution token、DOM変化、再訪問 | 状態変更操作を伴うなら拒否 |
| stored_revisit_missing | browser revisit verification | follow_up | read_only（非状態変更browser操作のみ） | browser可 | stored revisit再現 | 同左 |
| insufficient_timing_validation | repeated controls | follow_up | read_only（元request意味で判定） | request budget | baseline/attack/inverseの統計差 | 元requestが状態変更なら拒否→manual_review |
| command_execution_not_verified | safe output/timing proof | follow_up | read_only（元request意味で判定） | action許可 | 安全markerまたは統計的timing | 不明/状態変更は拒否→manual_review |
| ssrf_proof_missing | unique OOB correlation | follow_up | out_of_band | OOB許可・受信先許可 | attempt固有token callback | OOB明示許可時のみ |
| unique_oob_callback | OOB correlation | follow_up | out_of_band | OOB許可・受信先許可 | 同左 | OOB明示許可時のみ |
| insufficient_response_difference | repeated controls / semantic comparison | follow_up | read_only（元request意味で判定） | budget | 正規化後差分 | 元request意味で判定 |
| weak_session_not_statistically_verified | repeated controls | follow_up | read_only（元request意味で判定） | budget | 統計差 | 同左 |
| file_upload_impact_not_proven | semantic comparison | follow_up（M3b gate内のみ） | state_changing | 状態変更許可・HITL承認 | transform/publish差分 | 拒否→manual_review |
| public_documentation_not_authorization_impact | manual review | manual_review | — | — | — | manual_review |
| session_takeover_not_verified | manual review | manual_review | — | — | — | manual_review |
| redirect_target_not_external | manual review | manual_review | — | — | — | manual_review |
| synthetic_response_evidence | manual review（証拠完全性問題） | manual_review | — | — | — | manual_review |
| evidence_channel_lost | dependency recovery / manual | re_evaluate→manual_review | — | health回復 | 同じattempt lineageの証拠 | manual_review（再開条件付き） |
| scope_revalidation_blocked | manual scope review | manual_review | — | scope明示 | 新しいscope verdict | manual_review |

### 3-2 集合B〜Eの決定論的分類

| 集合 | reason code（正確な文字列） | 分類 | 備考 |
|---|---|---|---|
| B（生成系） | label_leakage_detected | terminal | rejection理由として保存（監査可能） |
| B | scope_revalidation_blocked（生成時） | manual_review | 集合Aの同コードへ写像（manual scope review） |
| B | duplicate_dedup_key / diversity_budget_exceeded | terminal | suppression理由として保存 |
| B | no_observations / generator_exception | terminal | degraded理由として保存 |
| B | budget_estimate_missing | manual_review | 予算根拠の欠落 |
| B | generated_candidate | follow_up または manual_review | 生成元のrequired_evidence先頭gapの写像先に従う |
| C（admission系） | scope_revalidation_blocked | manual_review | manual scope review |
| C | out_of_scope / redirect_out_of_scope | terminal | untested相当・理由コード保存 |
| C | hitl_required | manual_review | HITL承認待ち（M3b gateで再評価） |
| C | capability_prohibited / capability_unavailable | terminal | untested相当・理由コード保存 |
| C | budget_exhausted | terminal | untested_budget_exhausted相当 |
| D（budget/circuit系） | requests_exhausted / follow_ups_exhausted / retries_exhausted / concurrency_exceeded / runtime_exceeded / artifact_bytes_exceeded / asset_budget_exhausted / actor_budget_exhausted / hypothesis_budget_exhausted | terminal | untested_budget_exhausted・理由コード保存 |
| D | circuit_open_429 / circuit_open_5xx / circuit_open_timeout / circuit_open_latency | re_evaluate | 冷却後に再評価可（同一attemptは自動再送しない） |
| E（infra系） | follow_up_enqueue_failed | re_evaluate | NextAction喪失なし・degraded |
| E | evidence_channel_lost / dependency_unavailable | re_evaluate→manual_review | health回復後（refutedへ変換しない） |
| E | unknown_reason_code | manual_review | reason付きで停止 |

mapping不能なreason codeはgeneric scanへ送らずmanual reviewに止める。各コードの写像は単体テストで全集合（A〜E）のcoverage 100%を検証する。

## 4. 検証品質仕様

1. Hypothesis payload、実request、保存PoCのmethod、URL、body、header位置を照合する。
2. baseline/attack/inverseをA/B/Aまたは複数回実行し、cacheと時間揺らぎを測る。
3. 認可はauthA所有資産とauthB所有資産を主体と交差させ、read/write/deleteを区別する。
4. 更新系はbefore、mutation response、independent read-backの三点を保存する。
5. browser検証は実行token、DOM変化、stored revisit、実行時actorを結び付ける。
6. OOBはattempt固有token、送信時刻、受信時刻、protocol、negative controlを保存する。
7. response差分は動的nonce等を正規化し、owner、permission、state、sensitive fieldを保持する。
8. 可能な場合はHTTP差分とread-backなど独立した二種類の証拠を要求する。
9. chainは各段階のEvidenceVerdictと相関IDが揃った場合だけ端から端を再現する。
10. timeout、WAF、auth loss、dependency failureをrefutedへ変換しない。
11. required evidence取得、反証成立、scope block、budget枯渇、再現失敗上限をstop conditionにする。
12. 所有するtest data、安全marker、可逆操作だけで影響を証明する。

## 5. 段階導入

- M2 Shadow: NextActionを保存するだけでqueueへ投入しない。
- M3a Read-only enforce: GET相当、許可済みOOB、非状態変更browser検証だけを許可する。
- M3b Controlled state change: ProgramCapabilityMatrix=allowedかつHITL承認済みのtest dataだけを操作する。
- M3c Chain validation: 単体段階がconfirmedで、安全予算内の場合だけ実行する。
- 各段階でfeature flag、kill switch、旧follow-upへのrollbackを用意する。
- shadow/enforce差分と追加request数を保存する。

## 6. 障害と回復

- queue投入失敗はfollow_up_enqueue_failedとしてsessionへ保存し、pending NextActionを残す。
- dependency health check失敗はevidence_channel_lostとし、候補を維持する。
- circuit breaker open時は新規follow-upを止め、既存attemptをcheckpointする。
- 中断再開時はidempotency keyとattempt statusを確認し、状態変更を再送しない。
- unexpected exceptionをwarningだけで握り潰さず、partial/degraded終了へ反映する。
- budget未設定、scope不明、actor不明はfail-closedとする。

## 7. 実装順序

1. reason code -> NextAction mappingとtyped validatorを追加する。
2. shadow decision traceとpending action artifactを実装する。
3. exact replay、controls、auth/owner、read-backの共通executor契約を追加する。
4. crawler、form、JavaScript、API schema、GraphQL、browser traffic、proxy historyをObservationAdapterへ接続し、source別freshnessとunavailable理由を正規化する。
5. browser/OOB/timing evidence adapterを既存detectorへ接続する。
6. M3a read-only enforceをbudget/scope admission経由で有効化する。
7. failure injectionと中断再開を検証する。
8. M3b/M3cは前段gate合格後にのみ有効化する。

## 8. 必須テスト

- 全既知reason code（集合A〜E、reporting側のreason code含む）が一意のNextActionまたはmanual reviewへ写像される。
- mapping不能時にgeneric scanを起動しない。
- shadowでtask queue/network clientが呼ばれない。
- M3aで状態変更methodが拒否される。
- HITLなしのconfirmation_required actionが拒否される。
- cross-account、read-back、browser、OOB、timingの証拠不足でconfirmedにならない。
- queue投入失敗がdegradedとpending actionへ残る。
- dependency停止がrefutedにならない。
- timeout/circuit/budget枯渇で再試行上限を越えない。
- 中断後に同じstate-changing attemptを二重送信しない。
- exact replayとPoC不一致を検出する。
- negative control失敗時にcandidateへ戻る。
- 各未接続観測源が既存typed Observationへ変換され、取得不能時はsource別の理由付きunavailable traceが残る。
- formは既存 `_signal_bundle._endpoint_signals[*].params[*].location == "form"` からObservationSourceKind=formのObservationが生成される。form paramが0件の場合と信号bundle自体が取得不能の場合（producer不在）が理由付きで区別される。

## 9. 完了条件

- M2とM3aが全安全・障害テストを通過。
- reason code coverage 100%、理由不明follow-up 0件。
- silent queue loss、scope逸脱、budget超過、二重状態変更、証拠なしconfirmedが0件。
- M3b/M3cは明示gateなしに有効化されない。
- SGK-2026-0422が集計できるAttempt/Evidence/Verdict/NextActionが保存される。
- SGK-2026-0420で未接続だった観測源が同じObservation契約で消費可能になり、取得不能と観測0件を区別できる（formは既存signal bundleの`location=="form"`から取得し、task `_context`/`forms_by_url`は使わない）。

## 10. NOT in scope

- 新しいscanner追加。
- VDP固有payloadや既知endpoint。
- report formatterからのtask起動。
- hidden holdoutの最終Go判定。
- confirmedの生成、validation_proofの発行・検証、署名境界（SGK-2026-0422のcanonical Evidence Validatorが唯一実施）。0421は証拠が揃ってもconfirmedを生成せず、Attempt/Evidence/candidate verdictの保存までとする。
