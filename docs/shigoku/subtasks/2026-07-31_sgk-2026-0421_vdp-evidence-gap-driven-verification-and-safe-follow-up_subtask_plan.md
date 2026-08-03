---
task_id: SGK-2026-0421
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/plans/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0419_vdp-evidence-schema-safety-budget-and-recovery-foundation_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0420_vdp-capability-driven-hypothesis-generation-shadow-workflow_subtask_plan.md
title: VDP evidence gap driven verification and safe follow-up
created_at: '2026-07-31'
updated_at: '2026-08-03'
tags:
- shigoku
target: src/core/engine,src/core/agents/swarm
---

# 実装計画書：VDP evidence gap driven verification and safe follow-up

## 1. ゴール

- [ ] candidateの不足証拠をreason codeから特定し、最小の追加検証でconfirmed、refuted、untestedへ進める。
- [ ] 同じ追加スキャンを繰り返さず、actor、resource、状態、browser、OOBなど不足した証拠だけを取得する。
- [ ] shadowから開始し、安全な読取系だけを限定enforceした後に段階拡大する。
- [ ] queue失敗、依存停止、中断時にも候補とpending actionを失わない。

## 2. 依存と対象

SGK-2026-0419とSGK-2026-0420の完了後に開始する。

- src/core/engine/master_conductor.py: evidence gapからNextActionを選び、admission後にqueueへ追加。
- src/core/engine/vdp_observation_adapter.py: SGK-2026-0420で未接続のcrawler、form、JavaScript、API schema、GraphQL、browser traffic、proxy historyを既存ObservationSourceKindへ接続し、取得不能時は理由付きunavailable traceを維持する。
- src/core/engine/recipe_contracts.py: fixed reason/action vocabulary、allowlist、stop condition。
- src/core/engine/budget_policy.py: follow-up requestとretry予算。
- src/core/agents/swarm/injection/: auth matrix、object comparison、XSS、SQLi、SSRF/OOBなど既存検査。
- src/reporting/haddix_evidence_quality.py: reason codeと必要証拠の正本。
- tests/core/agents/swarm、tests/core/engine、tests/unit/reporting: class別証拠とfailure path。

## 3. Evidence gapからNextActionへの契約

例として次を決定論的に対応づける。

| Evidence gap | NextAction | 必要前提 | 成功証拠 |
|---|---|---|---|
| payload_request_mismatch | exact replay | scope、budget | 実requestとHypothesis payloadの一致 |
| untested_no_second_account | cross-account matrix | authA/authBと所有資産 | actor/owner交差による越権差分 |
| authz_impact_not_proven | semantic field comparison | protected resource | owner、permission、sensitive field差分 |
| state_change_not_verified | before/mutation/read-back | 状態変更許可 | 独立再取得で状態差 |
| browser_execution_missing | browser context verification | browser可、auth continuity | execution token、DOM変化、再訪問 |
| insufficient_timing_validation | repeated controls | request budget | baseline/attack/inverseの統計差 |
| command_execution_not_verified | safe output/timing proof | action許可 | 安全markerまたは統計的timing |
| SSRF proof missing | unique OOB correlation | OOB許可 | attempt固有token callback |
| evidence_channel_lost | dependency recovery/manual | health回復 | 同じattempt lineageの証拠 |
| scope_revalidation_blocked | manual scope review | scope明示 | 新しいscope verdict |

mapping不能なreason codeはgeneric scanへ送らずmanual reviewに止める。

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

- 全既知reason codeが一意のNextActionまたはmanual reviewへ写像される。
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

## 9. 完了条件

- M2とM3aが全安全・障害テストを通過。
- reason code coverage 100%、理由不明follow-up 0件。
- silent queue loss、scope逸脱、budget超過、二重状態変更、証拠なしconfirmedが0件。
- M3b/M3cは明示gateなしに有効化されない。
- SGK-2026-0422が集計できるAttempt/Evidence/Verdict/NextActionが保存される。
- SGK-2026-0420で未接続だった観測源が同じObservation契約で消費可能になり、取得不能と観測0件を区別できる。

## 10. NOT in scope

- 新しいscanner追加。
- VDP固有payloadや既知endpoint。
- report formatterからのtask起動。
- hidden holdoutの最終Go判定。
