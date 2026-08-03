---
task_id: SGK-2026-0419
doc_type: work_report
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0419_vdp-evidence-schema-safety-budget-and-recovery-foundation_subtask_plan.md
- docs/shigoku/plans/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
title: VDP evidence schema safety budget and recovery foundation 作業完了報告
created_at: '2026-08-01'
updated_at: '2026-08-03'
tags:
- shigoku
target: src/core/models,src/core/engine,tests/unit/engine
---

# 作業完了報告書：SGK-2026-0419 VDP evidence schema safety budget and recovery foundation

## 1. 成果概要

SGK-2026-0419の全チェック項目を実装し、新規VDPテスト219件+既存回帰テスト64件=283件が全件成功した。後続タスク(SGK-2026-0420～0423)が利用する共通基盤（version付きデータ契約、安全/予算判定、証拠保存、障害回復）を提供した。

新しい能動通信は追加していない（M0 Contract段階）。

## 2. 実装内容

### 2.1 正本データ契約 (`src/core/models/vdp_contract.py`)
- `HypothesisRecord` v1：observation_idから始まる追跡可能ID系列、状態遷移制御
- `AttemptRecord` v1：request fingerprint、scope verdict、budget snapshot
- `EvidenceRecordV1` v1：evidence_type、raw hash、redacted excerpt、truncation
- `EvidenceVerdictV1` v1：candidate/confirmed/refuted/untested、structured reason codes
- `NextActionRecord` v1：evidence gap、action class、risk class
- `ProgramCapabilityMatrix` v1：allowed/confirmation_required/prohibited/unavailable
- `ExecutionBudgetV1` v1：asset/actor/hypothesis単位の上限
- `RunHealthRecord` v1：succeeded/partial/degraded/safety_blocked/failed終了状態
- `ScopeRevalidationResult`：scope再検証結果（fail-closed）
- `redact_secrets_deep()`：再帰的secret redaction（深さ2以上）
- `truncate_evidence_body()`：大容量証拠の上限/切詰め/hash保存
- `VdpCheckpoint`、`atomic_write_checkpoint()`、`read_checkpoint()`：原子的保存
- `IdempotencyGuard`、`StateChangeGuard`：重複防止・二重送信防止
- `check_admission()`：capabilityレベルに基づくadmission判定
- 全recordに`schema_version`必須化。追加式schema変更のみ。

### 2.2 実行予算 (`src/core/engine/vdp_budget.py`)
- `VdpExecutionBudget`：asset/actor/hypothesis単位の予算管理
- burst + cooldown window方式
- circuit breaker（429、5xx、timeout、latency）
- `from_model()`：ExecutionBudgetV1からの構築
- `snapshot()`：checkpoint用の予算状態出力
- 全チェックはfail-closed

### 2.3 安全・admissionゲート (`src/core/engine/vdp_admission.py`)
- `VdpAdmissionGate`：scope → budget → capabilityの3段階評価
- scope不明時はfail-closed
- リダイレクト先scope変化の検出
- confirmation_requiredはHITL ticket必須
- prohibited/unavailableは常に拒否

### 2.4 証拠保存と回復 (`src/core/engine/vdp_session_reader.py`)
- `BoundedEvidenceQueue`：有界queue、満杯時に例外（黙って捨てない）
- `EvidenceWriter`：degraded mode遷移
- `read_session_compat()`：旧session互換reader（欠損fieldに既定値、未知field無視）
- `inject_vdp_fields()`：vdp_contract_version注入
- `redact_and_write_session()`：書込境界での秘密情報redaction

## 3. 検証結果

### 新規VDPテスト（7ファイル・219件）
| テストファイル | 件数 | 結果 |
|---|---|---|
| test_vdp_contract.py | 45 | PASS |
| test_vdp_budget.py | 30 | PASS |
| test_vdp_admission.py | 29 | PASS |
| test_vdp_infrastructure.py | 44 | PASS |
| test_vdp_resilience.py | 18 | PASS |
| test_vdp_auth_cache.py | 9 | PASS |
| test_vdp_real_integration.py | 44 | PASS |
| **新規合計** | **219** | **ALL PASS** |

### 既存回帰テスト（5ファイル・64件）
| テストファイル | 件数 | 結果 |
|---|---|---|
| test_budget_policy.py | 10 | PASS |
| test_scope_manager.py | 2 | PASS |
| test_master_conductor_session_service.py | 26 | PASS |
| test_run_ledger_redactor.py | 22 | PASS |
| test_master_conductor_failure_reason_codes.py | 4 | PASS |
| **回帰合計** | **64** | **ALL PASS** |

### 全テスト合計: 283件 ALL PASS

### 完了条件監査
| 条件 | 状態 | 根拠 |
|---|---|---|
| M0 Contract gate全テスト成功 | PASS | 283件全pass（新規219+回帰64） |
| 旧session reader互換性 | PASS | test_old_session_missing_vdp_fields_is_readable |
| secret漏洩0件 | PASS | test_redact_and_write_session_redacts_secrets, test_source_refs_secret_redacted |
| scope逸脱0件 | PASS | test_scope_indeterminate_fails_closed, test_scope_out_of_scope_fails_closed |
| silent evidence loss 0件 | PASS | test_queue_full_transitions_to_degraded |
| 二重状態変更0件 | PASS | test_double_state_change_prevention |
| 後続0420-0423が参照するschema固定 | PASS | VDP_CONTRACT_SCHEMA_VERSION = 1、全recordにschema_version必須 |
| 新しい攻撃通信未追加 | PASS | test_vdp_contract_has_no_network_calls |

## 4. 親タスクとの関係
- SGK-2026-0418（親タスク）はactiveのまま維持
- SGK-2026-0419はM0 Contract基盤として、後続0420-0423に共通データ契約・安全機構・保存回復プリミティブを提供
- 次のステップ：SGK-2026-0420（能力ベース仮説生成shadow workflow）

## 5. 未完了事項
なし。全チェック項目を実装完了。

## 6. 残存リスク
- 既存のtask_ledger.csvにtrailing whitespace（pre-existing、本タスクとは無関係）
- 既存validator issue（task_243、task_268）はpre-existing、本タスクとは無関係
- circuit breakerのcooldown時間はtestで短縮設定。本番では設定ファイルから適切な値を指定する必要がある

## 7. deferred_tasks

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0419-D01
    title: "HMAC proofの正規化・証拠内容結合・署名境界強化"
    reason: "confirmed検証のHMAC proofは実装済みだが、proofの正規化方式、証拠本文とproofの結合、署名境界の強化（非対称署名化など）は正本Evidence Validatorの接続と合わせて実施する"
    impact: high
    tracking_task_id: SGK-2026-0422
    recommended_next_action: "SGK-2026-0422で正本Evidence Validatorとproof正規化を接続する"
  - deferred_id: SGK-2026-0419-D02
    title: "確認鍵の本番運用（鍵管理・ローテーション・シークレットストア）"
    reason: "SHIGOKU_VDP_CONFIRMATION_KEY環境変数/鍵ファイルの解決は実装済みだが、本番での鍵配布・ローテーション・秘密管理機構への移行はshadow rollout後の運用課題"
    impact: medium
    tracking_task_id: SGK-2026-0423
    recommended_next_action: "SGK-2026-0423で鍵の本番運用とローテーションを整備する"
```
