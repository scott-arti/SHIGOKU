---
task_id: SGK-2026-0163
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Tier 2 Phase 1: Intelligence Integration Spec

## 1. 概要

SHIGOKU の「自律的判断」を強化するため、既存の Intelligence モジュール群 (`RiskPredictor`, `PriorityBooster`, `SelfReflection`) を `MasterConductor` のメインループへ本格的に統合します。

## 2. 目的

- **リスクベースの実行抑制**: `RiskPredictor` により、WAF検知やアカウントロックのリスクが高いアクションを事前に検知し、遅延の挿入や実行の中止を行う。
- **動的優先度制御**: `PriorityBooster` により、重要な資産（admin等）や脆弱性の兆候（エラー漏洩等）を発見した際、関連タスクの優先度をリアルタイムで引き上げる。
- **自己省察と学習**: `SelfReflection` により、各タスクの結果を分析し、成功率の高い手法を優先するフィードバックループを構築する。

## 3. 変更範囲

### 3.1. MasterConductor (`src/core/engine/master_conductor.py`)

- **Planning 段階**: `PriorityBooster` を使用してタスクキューをリソート。
- **Execution 前段階**: `RiskPredictor` を呼び出し、`risk_score` に基づく `recommended_delay` の適用、または `should_proceed` が False の場合に実行をスキップするロジックの追加。
- **Execution 後段階**: `SelfReflection.record` を呼び出し、実行結果（成功/失敗、レスポンスコード等）を記録。
- **Re-planning 段階**: `SelfReflection.reflect` から得られた洞察を次回のタスク生成や優先度決定に反映。

### 3.2. 学習リポジトリ連携

- `SelfReflection` の結果を `LearningRepository` ( `src/core/learning/repository.py` ) に永続化し、セッションを跨いだ学習を可能にする下地を作る。

## 4. 挙動詳細

### Risk-Aware Execution

1. タスク実行直前に `RiskPredictor.assess` を実行。
2. `recommended_delay` 分の `asyncio.sleep` を挿入。
3. `RiskLevel.CRITICAL` の場合はタスクを `TaskState.BLOCKED` に遷移させ、ログを記録。

### Dynamic Priority Boosting

1. エージェントが Finding または新しい URL を発見した際、`PriorityBooster.auto_detect_boost` を実行。
2. ブーストが発生した場合、キュー内の関連タスクの優先度を更新。

### Learning Feedback Loop

1. タスク完了時、`ExecutionRecord` を作成し `SelfReflection` に渡す。
2. 定期的に（あるいは重要な節目で）`SelfReflection.reflect` を行い、プランニングプロンプトに反映。

## 5. 成功の定義

- 高リスクな操作（多数の 403/429 レスポンスを誘発する操作）が自動的にスロットリングされること。
- 重要なパス（admin等）に関連するタスクが、通常タスクよりも先に実行されること。
- 過去の失敗パターン（特定のペイロードでの 500 エラー等）が記録され、後の意思決定で考慮されること。
