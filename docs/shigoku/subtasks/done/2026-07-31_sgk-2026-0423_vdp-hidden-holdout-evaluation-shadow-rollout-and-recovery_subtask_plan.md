---
task_id: SGK-2026-0423
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/plans/done/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0419_vdp-evidence-schema-safety-budget-and-recovery-foundation_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0420_vdp-capability-driven-hypothesis-generation-shadow-workflow_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0421_vdp-evidence-gap-driven-verification-and-safe-follow-up_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0422_vdp-canonical-evidence-reporting-and-separated-quality-gates_subtask_plan.md
- docs/shigoku/reports/2026-08-04_sgk-2026-0423_vdp-hidden-holdout-evaluation-shadow-rollout-and-recovery_work_report.md
- docs/shigoku/worklogs/2026-08-04_sgk-2026-0423_vdp-hidden-holdout-evaluation-shadow-rollout-and-recovery_work_log.md
title: VDP hidden holdout evaluation shadow rollout and recovery
created_at: '2026-07-31'
updated_at: '2026-08-07'
tags:
- shigoku
target: tests,src/core/models,src/core/engine,src/reporting,config
---

# 実装計画書：VDP hidden holdout evaluation shadow rollout and recovery

## 1. 達成したいゴール

- [x] 特定製品へ合わせ込まず、未使用の隠し評価データで探索の広さ、検証の深さ、証拠の完全性を判定する。
- [x] record-only、shadow、限定enforce、全面enforceを明確な進級条件で段階導入する。
- [x] scope逸脱、過負荷、二重状態変更、secret漏洩、証拠保存失敗を検出したら直ちに停止・復旧できる。
- [x] 成績が良く見えるまで閾値を調整する運用を防ぎ、実VDP移行判断を監査可能にする。
- [x] 旧処理へのrollback、中断再開、依存停止からの回復を実artifactで確認する。
- [x] confirmed検証鍵の配布、権限、ローテーション、失効、復旧を本番相当の運用境界で検証する。

## 2. 評価データの分離

### 2.1 データ区分

- development fixtures: 実装中の単体・結合試験に使用する。
- validation set: 閾値、予算、優先順位の調整に使用する。
- hidden holdout: 最終判定時だけ評価runnerが使用する。開発中のruntimeから読めない場所または権限境界に置く。
- real VDP artifacts: 正解ラベルなし。安全性、実行品質、証拠完全性だけを評価する。

各集合はmanifest、hash、schema version、生成元、分割規則を保存する。対象名だけを変えた同一fixture、同じendpoint構造、同じpayload familyが複数集合へ漏れないよう、意味的重複も検査する。

### 2.2 漏洩防止

- hidden label、既知URL、製品名、challenge名、flag、期待payloadをruntime config、prompt、recipe、ログへ渡さない。
- 閾値と評価式はhidden holdout実行前にversion付きartifactとして固定する。
- holdout結果を見た後の変更は新しい評価versionとして扱い、同じholdoutで最終合格を主張しない。
- 評価runnerはruntimeのHypothesisRecord、AttemptRecord、EvidenceRecord、EvidenceVerdictだけを入力にする。
- fixture固有分岐、対象名分岐、既知パス照合を静的検索とnegative testで拒否する。

## 3. 段階導入

| 段階 | 有効機能 | 能動通信 | 進級条件 | 即時停止条件 |
|---|---|---|---|---|
| M0 Contract | schema、reader、redaction、budget | 追加なし | 旧session互換、保存・復旧試験合格 | secret漏洩、旧reader破壊 |
| M1 Record-only | 仮説生成とpriority trace保存 | 追加なし | scope/重複/決定理由が完全 | scope外仮説、非決定的暴走 |
| M2 Shadow | follow-up提案と予想差分 | 追加なし | 人手一致、unsafe提案率、誤昇格率が固定閾値内 | HITL回避提案、理由不明confirmed |
| M3a Read-only | 許可済み低影響follow-up | あり | budget/circuit breaker/証拠保存/再開合格 | 429/5xx急増、queue飽和、scope不明 |
| M3b HITL state-change | 承認済み最小状態変更 | 承認時のみ | readback/cleanup/二重送信防止合格 | 無承認送信、cleanup不能、第三者影響 |
| M3c Chain | 許可済み複数段検証 | 制限あり | chain全段のscope再検証と停止条件合格 | trust boundary逸脱、予算超過 |
| M4 Enforce | ProgramCapabilityMatrix内の全面運用 | 制限あり | hidden holdoutと実artifactのGo判定 | 品質回帰、安全違反、互換破壊 |

各段階は独立feature flagで無効化できること。M3以降もshadow判定を並走させ、旧処理との差分を保存する。

### 3.1 confirmed鍵の本番ライフサイクル

- SGK-2026-0422で固定するproof schemaと検証境界を前提とし、このタスクでは鍵の生成、配布、保管、読取権限、ローテーション、失効、監査、災害復旧を扱う。
- enforce環境では暗黙のhome directory fallbackを禁止し、設定済みsecret storeまたは明示的な鍵providerだけを使用する。鍵未設定、形式不正、所有者不一致、過剰権限はfail-closedにする。
- 署名側だけがprivate/secret keyへアクセスし、reporter、reader、gateは検証鍵だけを受け取る。鍵の生値をsession、report、log、checkpoint、例外へ出力しない。
- proofのkey IDと鍵状態（active、verify-only、revoked）をversion付きregistryで管理する。ローテーション中は旧artifact検証用のverify-only鍵を期限付きで保持し、新規署名はactive鍵だけで行う。
- revoked鍵で作られた新規proof、未知key ID、期限切れverify-only鍵は拒否する。過去artifactの扱いは削除せず、理由コード付きHold/No-Goとして監査可能にする。
- 鍵喪失時はconfirmed生成と次段階への進級を停止する。候補・未検証の保存は継続可能にし、鍵復旧後も同じattemptを自動再送しない。
- dev/test用鍵と本番鍵を分離し、固定test keyが本番設定へ入らないnegative testと起動時検査を設ける。

## 4. Go / Hold / No-Go判定

### 4.1 No-Go

次のいずれかが1件でもあれば実VDPの次段階へ進めない。

- scope外、禁止action、HITL未承認の状態変更。
- secretの平文保存またはreport出力。
- idempotency不備による状態変更の二重送信。
- EvidenceVerdictなし、または理由不明のconfirmed。
- report/session不一致、旧session互換破壊、回復不能な部分保存。
- hidden labelまたは対象固有の正解情報がruntimeへ流入。
- kill switch、circuit breaker、budget gateが停止させるべき通信を通過。
- confirmed鍵の未設定、権限不正、失効、未知key IDを無視して署名・検証・進級を継続。
- private/secret keyのsession、report、log、checkpoint、例外への露出。

### 4.2 Hold

安全違反はないが、品質や運用証拠が不足している場合はHoldとする。

- hidden holdoutの対象クラス、actor、trust boundaryが不足。
- browser/OOB/proxy等の依存が不安定で、陰性と未検証を区別できない。
- evidence completeness、false promotion、未検証理由のいずれかが事前閾値未達。
- shadowとenforceの差分原因を説明できない。
- 実artifactの件数または実行時間が少なく、予算・回復・backpressureを評価できない。

### 4.3 Go

- M0から対象段階までの必須testとfailure drillがすべて合格。
- hidden holdoutが事前固定閾値を満たし、漏洩検査が0件。
- real artifactでscope、budget、証拠、report consistency、終了状態を説明できる。
- rollbackとkill switchが規定時間内に通信を停止し、再開時に二重送信しない。
- 未達項目がdeferredではなく明示的なHold/No-Goとして残る。

## 5. failure drill

最低限、次を自動試験または隔離環境の演習で注入する。

- 429、5xx、timeout、応答遅延の急増。
- browser crash、OOB listener停止、proxy切断、認証失効。
- AsyncWriter queue上限、disk full相当、部分書込、hash不一致。
- process interrupt、graceful shutdown失敗、checkpointからの再開。
- リダイレクト先、派生URL、DNS解決結果、OOB宛先のscope変化。
- LLMの不正JSON、禁止action、無限仮説、重複follow-up。
- 状態変更送信後かつ保存前の停止。
- 旧sessionの欠損field、未知field、古いreason code。
- report生成失敗、formatter間の件数不一致、backfill混入。
- feature flag切替中のin-flight taskとrollback。
- confirmed鍵の未設定、形式不正、permission不正、secret store停止、active鍵切替、旧鍵失効、鍵喪失からの復旧。

各drillは注入点、期待停止位置、保存されるreason code、再開可否、再送可否をfixture化する。

## 6. 評価指標と閾値固定

単一の総合点で安全違反を相殺しない。指標を別々に保存する。

- class/actor/trust boundary別のhypothesis coverageとrecall。
- false promotion rate、evidence completeness、refutation quality。
- observation -> hypothesis -> attempt -> follow-up -> verdictの各到達率。
- untested率とbudget/infra/scope/prerequisite別理由分布。
- request、follow-up、retry、artifact量、並列数、実行時間の予算遵守率。
- 429/5xx/timeout率、circuit breaker発火、依存停止検出時間。
- checkpoint復旧率、重複送信件数、report/session整合率。
- shadow/enforce差分率、理由コード安定率、secret leakage件数。

閾値artifactには指標名、値、計算式、対象集合、決定日時、評価versionを含める。閾値未達を候補削除やconfirmed昇格で埋めない。

## 7. 実装ステップ

1. development/validation/hidden/real artifactのmanifest schemaと分割検査を実装する。
2. confirmed鍵provider、権限検査、key registry、ローテーション、失効、secret store障害時のfail-closed動作を実装する。
3. M0-M4のfeature flag、進級判定、kill switch、旧処理rollback経路を構成する。
4. shadow runnerで旧処理と新処理の仮説、NextAction、verdict差分を通信なしで記録する。
5. failure injection fixtureと回復oracleを追加し、鍵ライフサイクルを含めM0から順にdrillを実行する。
6. 事前固定した閾値でhidden holdoutを一度評価し、hash付き結果artifactを保存する。
7. 許可済み隔離環境でM3a、必要時のみM3b/M3cを検証し、real artifact gateを実行する。
8. Go/Hold/No-Go、未達指標、鍵状態、rollback結果、次段階の許可範囲をwork reportへ記録する。

## 8. 必須テスト

- dataset: split重複、意味的重複、label漏洩、manifest/hash改変検出。
- rollout: feature flag組合せ、段階飛越し拒否、設定欠損時fail-closed。
- safety: scope drift、HITL、budget、circuit breaker、kill switch、secret redaction。
- recovery: interrupt、queue failure、部分保存、再開、idempotency、状態変更非再送。
- quality: 固定閾値、集計再現性、class別指標、false promotion、evidence completeness。
- compatibility: 旧session、旧config、旧report reader、旧処理rollback。
- reporting: shadow/enforce差分とGo/Hold/No-Go理由がsessionから再現可能。
- key lifecycle: 初回配布、別process再起動、active鍵切替、旧鍵verify-only、失効、権限不正、provider停止、秘密値非出力。

## 9. artifact

- dataset manifestと分割監査結果。
- 事前固定したthreshold artifact。
- M0-M4ごとのtest/failure drill結果。
- shadow comparisonと差分理由。
- hidden holdout評価結果。
- real artifactのreport/session consistencyとrun-quality gate結果。
- rollback、kill switch、中断再開の証跡。
- key registry、権限検査、ローテーション、失効、復旧drillの証跡（鍵の生値は含めない）。

artifactにはschema version、code/config version、feature flags、入力hash、開始/終了時刻、終了状態を含める。secretと第三者データは保存しない。

## 10. 完了条件

- 隠し評価データとruntimeの間に技術的なアクセス境界があり、漏洩検査が0件である。
- すべての閾値がholdout閲覧前に固定され、同一結果への後付け調整がない。
- M0-M3の必須testとfailure drillが合格し、M4のGo/Hold/No-Go根拠が保存される。
- scope逸脱、secret漏洩、二重状態変更、理由不明confirmedが0件である。
- kill switch、rollback、中断再開が期待どおり動き、旧artifact互換が維持される。
- 特定製品、既知URL、既知payload、既知challengeを使わず評価に合格する。
- 本番相当providerからの鍵配布、最小権限、再起動後検証、ローテーション、失効、provider障害時のfail-closedが実artifactで確認できる。
- private/secret keyのartifact・log露出と、未知・失効鍵によるconfirmed受理が0件である。

## 11. NOT in scope

- hidden holdoutの内容を使った実装、prompt、recipe、閾値の調整。
- Juice Shopその他の単一製品に対する正解表や固有payloadの組込み。
- gate未通過状態での実VDPへの全面enforce。
- 確定件数を増やす目的の安全条件・証拠条件の緩和。
- 実装責任者、要員配置、工数見積り。
- proof payloadの正規化やEvidenceRecord内容結合そのもの（SGK-2026-0422で固定する）。
