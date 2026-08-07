---
task_id: SGK-2026-0418
doc_type: plan
status: done
parent_task_id: SGK-2026-0416
related_docs:
- docs/shigoku/plans/done/2026-07-31_session-evidence-summary-labeling-and-juice-shop-vdp-readiness-assessment_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0419_vdp-evidence-schema-safety-budget-and-recovery-foundation_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0420_vdp-capability-driven-hypothesis-generation-shadow-workflow_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0421_vdp-evidence-gap-driven-verification-and-safe-follow-up_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0422_vdp-canonical-evidence-reporting-and-separated-quality-gates_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0423_vdp-hidden-holdout-evaluation-shadow-rollout-and-recovery_subtask_plan.md
- docs/shigoku/subtasks/2026-08-05_sgk-2026-0424_vdp-m3a-readonly-pilot_subtask_plan.md
- docs/shigoku/subtasks/done/2026-08-05_sgk-2026-0425_vdp-causal-attack-funnel-diagnosis_subtask_plan.md
- docs/shigoku/reports/2026-08-05_sgk-2026-0418_vdp-capability-benchmark-and-evidence-contract_work_report.md
- docs/shigoku/worklogs/2026-08-05_sgk-2026-0418_vdp-capability-benchmark-and-evidence-contract_work_log.md
title: VDP capability benchmark and staged evidence system
created_at: '2026-07-31'
updated_at: '2026-08-07'
tags:
- shigoku
target: src/core/engine,src/core/agents/swarm,src/reporting,tests
---

# 実装計画書：VDP capability benchmark and staged evidence system

## 1. 達成したいゴール

- [x] 特定製品の既知脆弱性や固有URLを正解として使わず、未知のVDP対象でも探索の広さ、検証の深さ、証拠の完全性を測定できる。
- [x] 発見、仮説、実送信、追加検証、確定、反証、未検証を同じID系列で追跡できる。
- [x] 候補は脆弱性クラス固有の証拠がそろうまで確定へ昇格せず、インフラ障害や前提不足を陰性結果へ混ぜない。
- [x] 実VDPへの影響を抑えるため、record-only、shadow、限定enforce、全面enforceの順で段階導入できる。
- [x] 中断、依存停止、保存失敗、旧session読取時にも、誤判定や二重送信を起こさず回復できる。

## 2. 設計原則

1. 実VDPの確定件数を成功ノルマにしない。脆弱性が存在しない対象でも、許可された仮説を十分に検証し未検証理由を説明できれば実行品質は成立する。
2. runtimeへ訓練用正解、既知URL、製品名、フラグ、固有payloadを渡さない。
3. detectorは観測とcandidate生成までを担当し、確定判定は正本Evidence Validatorだけが行う。
4. reportingは読み取り専用projectionとし、report formatterからtask queueを直接操作しない。
5. VDPポリシー、scope、実行予算、HITL条件は通信直前に再検証し、判定不能はfail-closedとする。
6. schema変更は追加式とし、既存フィールドの削除、改名、意味変更を行わない。
7. 新しい外部スキャナや依存ライブラリを先に増やさず、既存signal、recipe、follow-up、validator、reportingを接続する。

## 3. 正本アーキテクチャ

    VDP policy / ProgramCapabilityMatrix
                    |
                    v
       Observation -> HypothesisRecord
                    |
                    v
       scope / safety / ExecutionBudget gate
                    |
                    v
      AttemptRecord -> EvidenceRecord
                    |
                    v
       EvidenceVerdict（唯一の確定権限）
                    |
            +-------+-------+
            |               |
            v               v
      NextActionRecord   Report projection
            |
            v
      MasterConductor task queue

### 3.1 正本データ契約

SGK-2026-0419で次のversion付き契約を定義する。

- HypothesisRecord v1: observations、capability、trust_boundary、actors、preconditions、controls、success_condition、falsification_condition、required_evidence、priority_trace。
- AttemptRecord v1: hypothesis_id、attempt_id、actor、request fingerprint、budget snapshot、scope verdict、開始/終了時刻、実行結果。
- EvidenceRecord v1: evidence_id、attempt_id、evidence_type、raw hash、redacted excerpt、normalization rule version、auth context version、取得時刻。
- EvidenceVerdict v1: candidate/confirmed/refuted/untested、reason codes、evaluated evidence IDs、validator version。
- NextActionRecord v1: evidence gap、必要前提、action class、risk class、expected information gain、stop condition。
- ProgramCapabilityMatrix v1: allowed/confirmation_required/prohibited/unavailable。
- ExecutionBudget v1: asset/actor/hypothesis単位のrequest、follow-up、retry、concurrency、runtime、artifact上限。

ID系列は observation_id -> hypothesis_id -> attempt_id -> evidence_id -> verdict_id -> next_action_id とする。

## 4. 実装分割と依存順序

| 順序 | タスク | 目的 | 能動通信 | 依存 | 完了条件 |
|---|---|---|---|---|---|
| 1 | SGK-2026-0419 | schema、安全予算、scope再検証、保存、回復の共通基盤 | 追加しない | なし | 旧session互換、予算枯渇、scope block、保存失敗、再開をテスト可能 |
| 2 | SGK-2026-0420 | 能力ベースの仮説生成と優先順位 | record-only | 0419 | 固有URLなしで仮説生成、無効仮説は実行されず監査可能 |
| 3 | SGK-2026-0421 | 証拠不足駆動の追加検証 | shadowから限定enforce | 0419, 0420 | 不足証拠に対応した最小follow-up、二重送信なし、確定/反証/未検証を分離 |
| 4 | SGK-2026-0422 | canonical evidence reportと訓練/実VDP gate分離 | なし | 0419、統合時に0421 | report/session整合、旧reader互換、reportingからengineへの逆依存なし |
| 5 | SGK-2026-0423 | hidden holdout、shadow rollout、rollback | gate通過後のみ | 0419-0422 | holdout漏洩なし、品質閾値達成、kill switchとrollback検証済み |

0420と0422の実装は0419完了後に並行可能。ただし0422の統合テストは0421完了後に行う。0421は能動通信を含むため、0419と0420の完了前に開始しない。

## 5. 実行予算と安全境界

- VDP規定とローカル設定のうち厳しい値を採用する。
- asset、actor、hypothesisごとに最大request数、follow-up数、retry数、並列数、総実行時間を持つ。
- 429率、5xx率、timeout率、応答時間悪化を監視し、circuit breakerで対象単位に停止する。
- 予算枯渇は untested_budget_exhausted、依存停止は evidence_channel_lost、scope不明は scope_revalidation_blocked として保存する。
- リダイレクト、派生URL、ブラウザ遷移、OOB送信先の各通信直前にscopeを再検証する。
- 状態変更、第三者データ、危険操作はProgramCapabilityMatrixに従い、confirmation_requiredはHITL承認なしに送信しない。
- 自動停止後の再開では、送信済みだが保存未完了の状態変更を自動再送しない。

## 6. 保存、秘匿、障害回復

- secret redactionは最下層の書込APIで再帰的に実施し、Cookie、token、credentialの生値をsession、report、ログへ残さない。
- EvidenceRecordはredacted excerptとraw hashを保存し、大容量本文は上限、切詰め理由、元サイズを記録する。
- AsyncWriterは有界queueとし、backpressure時は証拠を黙って破棄せずrunをdegradedへ遷移させる。
- hypothesis/attempt単位でcheckpointを作り、原子的保存とidempotent IDで中断再開を保証する。
- 終了状態は succeeded、partial、degraded、safety_blocked、failedを区別する。
- browser、OOB、proxyなどの依存停止は脆弱性反証に使わず、回復可能なpending evidence gapとして残す。

## 7. 判定とレポートの境界

- detectorのconfidence、task成功数、長時間応答、status=completedだけではconfirmedにしない。
- Evidence Validatorがpayload送信一致、実応答、脆弱性クラス固有証拠、反証条件を評価する。
- scenario backfill、LLM推論、heuristicは実観測と別区分で表示し、確定根拠にしない。
- reportは発見、仮説、実送信、応答、追加検証、確定、反証、未検証のファネルを同じIDで表示する。
- 実VDP gateは確定件数をノルマにせず、scope到達、未検証率、証拠欠落、infra failure、safety blockを評価する。
- 訓練gateだけが既知ラベルに対するrecall、false promotion、evidence completenessを評価する。

## 8. 段階導入とrollback

| 段階 | 動作 | 進級条件 | rollback条件 |
|---|---|---|---|
| M0 Contract | schemaと互換readerのみ | schema/secret/reader tests合格 | 旧session読取失敗 |
| M1 Record-only | 仮説を保存するが送信しない | scope/予算/重複/決定traceが完全 | scope逸脱候補、非決定的出力 |
| M2 Shadow | follow-upを提案するがqueue投入しない | 人手一致率と誤昇格率が固定閾値内 | unsafe action提案、理由不明候補 |
| M3 Limited enforce | 安全な読取系・許可済み検証だけ実行 | budget、circuit breaker、回復試験合格 | 429/5xx急増、二重送信、証拠欠落 |
| M4 Enforce | 許可範囲で全面有効 | hidden holdoutと実artifact gate合格 | 品質回帰、互換破壊、secret漏洩 |

各段階はfeature flagで即時無効化でき、旧処理へ戻せること。enforce移行後もshadow差分を一定期間記録する。

## 9. 評価指標

単一総合点は作らず、次を別々に判定する。閾値はhidden holdoutを見る前に固定する。

- 検知recall、false promotion rate、evidence completeness。
- hypothesis生成率、実送信率、追加検証到達率、反証率、未検証率。
- scope block正確性、budget超過件数、429/5xx/timeout率。
- 一仮説当たりrequest数、follow-up数、artifact量、再開成功率。
- report/session整合率、旧reader互換率、secret leakage件数。
- shadowとenforceの判定差分、理由コード安定率。

実VDPでは真のrecallを測れないため、確定件数や推測recallを品質指標にしない。

## 10. 必須テストと検証

    Program config
         |
         v
    hypothesis -> admission -> probe/follow-up -> evidence -> verdict -> report
         |           |              |               |         |        |
       schema      scope/budget    timeout/HITL    recovery  quality  consistency

- unit: schema validation、state transition、redaction、budget、scope、dedup、reason code mapping。
- integration: record-only、shadow、限定enforce、queue失敗、依存停止、中断再開、旧session読取。
- reporting: canonical extractor、reader compatibility、Haddix evidence quality、initial gate、report/session consistency。
- evaluation: training/validation/hidden holdout分離、manifest hash、label漏洩検査。
- real artifact: consistentなsession/reportだけで評価し、backfillをraw evidenceとして扱わない。

## 11. 主要な失敗モード

| 失敗 | fail-safe動作 |
|---|---|
| 仮説無限生成 | diversity/budget上限で停止し、抑制理由を保存 |
| follow-up queue投入失敗 | degradedとpending NextActionを保存 |
| OOB/browser停止 | candidateを維持しevidence_channel_lost |
| artifact backpressure | 新規能動通信を停止しcheckpoint |
| session部分書込 | 最後の完全checkpointから復元 |
| LLM不正出力 | schema/action/scope検証で拒否し通信しない |
| 旧session未知field | additive readerで無視し既定値生成 |
| scope不明 | safety_blocked、手動確認なしに再開しない |

## 12. NOT in scope

- 特定アプリの既知脆弱性、固有URL、フラグ、固有payloadのruntime組込み。
- 確定件数を増やすための閾値緩和、候補削除、severity引上げ。
- 許可のない破壊的操作、第三者データ取得、永続的状態変更、スコープ外OOB。
- 新しい外部スキャナや依存ライブラリの追加。
- 実装責任者、要員配置、工数見積り。

## 13. 親計画の完了条件

- 0419-0423がすべてdoneで、各work reportとwork logが台帳に登録されている。
- M0-M3を通過し、M4のGo/Hold判定根拠がartifactとして保存されている。
- 対象非依存fixtureとhidden holdoutで、事前固定した品質閾値を満たす。
- real artifactでreport/session consistencyがconsistentとなる。
- secret漏洩、scope逸脱、二重状態変更、理由不明confirmedが0件。
- rollback、kill switch、中断再開が検証済み。
