---
task_id: SGK-2026-0419
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/plans/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
title: VDP evidence schema safety budget and recovery foundation
created_at: '2026-07-31'
updated_at: '2026-08-03'
tags:
- shigoku
target: src/core/engine,src/core/infra,src/reporting
---

# 実装計画書：VDP evidence schema safety budget and recovery foundation

## 1. ゴール

- [x] 後続タスクが共通利用するversion付きデータ契約を追加し、旧sessionを壊さない。
- [x] scope、VDP許可、実行予算、HITLを通信直前に判定する安全機構（admission gate、scope再検証、ProgramCapabilityMatrix、ExecutionBudget、M0ゲート）を提供する。実通信境界への接続はSGK-2026-0421（follow-up検証）とSGK-2026-0423（shadow rollout）で行う。
- [x] 証拠保存の容量、secret redaction、backpressure、中断再開をfail-safeにする。
- [x] このタスクでは新しい攻撃通信や自動follow-upを有効化しない。

## 2. 対象と再利用

- src/core/engine/budget_policy.py: 既存budget判定をasset/actor/hypothesis単位へ拡張。
- src/core/domain/scope/scope_manager.py: 派生URL、redirect、browser、OOBを含む通信直前scope判定。
- src/core/engine/master_conductor_session_service.py: schema version、checkpoint、旧reader互換。
- src/core/engine/run_ledger_redactor.py と既存redactor: 最下層書込境界で再帰redaction。
- src/core/infra/async_writer.py: 有界queue、backpressure、回復可能な書込失敗。
- src/reporting/haddix_evidence_quality.py: EvidenceRecord/EvidenceVerdictの既存概念を正本契約へ接続。
- tests/unit/engine、tests/core/engine、tests/unit/reporting: 契約と互換性の回帰試験。

## 3. 正本データ契約

追加式schemaとして以下を定義し、各recordにschema_versionを必須化する。

- HypothesisRecord v1。
- AttemptRecord v1。
- EvidenceRecord v1。
- EvidenceVerdict v1。
- NextActionRecord v1。
- ProgramCapabilityMatrix v1。
- ExecutionBudget v1。
- RunHealthRecord v1。

状態遷移は次に限定する。

    observed -> hypothesized -> admitted -> attempted
       -> candidate | confirmed | refuted | untested
       -> next_action_pending | terminal

confirmedはEvidence Validatorだけが設定する。保存失敗、scope block、budget枯渇、依存停止はconfirmed/refutedに遷移させない。

## 4. 安全・予算仕様

- VDP規定とローカル設定のうち厳しい値をeffective budgetとする。
- max requests、max follow-ups、max retries、max concurrency、max runtime、max artifact bytesをasset/actor/hypothesisごとに計算する。
- 429、5xx、timeout、latency悪化のrolling windowとcircuit breakerを定義する。
- redirect、派生URL、browser navigation、OOB destinationの通信直前にscopeを再評価する。
- ProgramCapabilityMatrixはallowed、confirmation_required、prohibited、unavailableの4値とする。
- confirmation_requiredは承認ticket IDなしにadmittedへ進めない。
- budget枯渇、scope block、circuit openを理由コード付きuntestedとして保存する。
- cache keyはcredential値の安全なhash、actor、auth context version、scopeを含む。確定検証はcacheを無効化する。

## 5. 証拠保存と回復

- secret redactionはsession、report、log、recovery fileへ書く最下層APIで再帰的に行う。
- 生Cookie、token、password、credentialを保存しない。
- raw responseはhash、redacted excerpt、元サイズ、切詰め理由、normalization rule versionを保存する。
- AsyncWriter queueへmaxsizeを設定し、満杯時は新規能動通信を止めてdegradedにする。
- hypothesis/attempt単位でcheckpointし、temp fileからatomic replaceする。
- 再開時は最後の完全checkpointを読み、送信済み状態変更を自動再送しない。
- idempotency keyで同じattempt/evidenceの二重保存を防止する。
- 終了状態をsucceeded、partial、degraded、safety_blocked、failedに分離する。

## 6. 実装順序

1. TypedDict/dataclassまたは既存project標準modelでschemaとenumを追加する。
2. readerを先に追加し、旧sessionと新sessionの両方を読めるようにする。
3. ProgramCapabilityMatrix、ExecutionBudget、scope admissionをrecord-onlyで接続する。
4. redaction、artifact size、bounded queue、checkpointを実装する。
5. failure injectionでqueue満杯、保存失敗、中断、旧session読取を検証する。
6. M0 Contract gateを通過させ、後続タスクへschema versionを固定する。

## 7. 必須テスト

- schema必須項目、未知enum、無効状態遷移を拒否する。
- 旧sessionに新fieldがなくても既存結果を維持する。
- 新sessionの未知fieldを旧互換readerが安全に無視する。
- scope不明、redirect scope外、OOB scope外で通信関数が呼ばれない。
- budget枯渇、429 circuit、timeout circuitが理由コードを残す。
- nested dict/list/source refsの深さ2以上にあるsecretをredactする。
- queue満杯で証拠を黙って捨てずdegradedになる。
- checkpoint中断後に状態変更を二重送信しない。
- credential変更後にauth cacheを再利用しない。
- artifact切詰め後もhashと元サイズが残る。

## 8. 完了条件

- M0 Contract gateの全テストが成功。
- 旧session reader compatibilityが維持される。
- secret leakage、scope逸脱、silent evidence loss、二重状態変更が0件。
- 後続0420-0423が参照するschemaとreason codeが固定されている。
- 新しい攻撃通信はまだ有効化されていない。

## 9. NOT in scope

- 仮説生成ロジック。
- 自動follow-up実行。
- report表示やgate policy変更。
- hidden holdout評価。
- 新しい外部依存の追加。
