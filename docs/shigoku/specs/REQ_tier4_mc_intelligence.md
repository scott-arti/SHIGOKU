---
name: REQ_tier4_mc_intelligence
description: Tier 4 - Master Conductor 知能の完全化機能の仕様定義
task_id: SGK-2026-0096
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Feature Specification: Tier 4 - Master Conductor 知能の完全化

## 1. 概要

SHIGOKU 統一ロードマップ 2026-03-01 に基づく「Tier 4: MC 知能の完全化」を実装する。
本仕様は以下の2つの機能から構成される。

1. **Swarm Manager 適応的判断ロジック**: 致命的脆弱性の早期検知による後続スキャンのスキップと即時エスカレーション。
2. **Agentic RAG フィードバックループ**: 取得したコンテキストの Confidence（信頼度）を自律的に評価し、閾値未満であれば再検索を行う能動的ループ。

## 2. 変更範囲 と 影響を受けるファイル

### Swarm Manager 適応的判断ロジック

- `src/core/agents/swarm/base.py` (`SwarmManager.dispatch` メソッド)
- 既存のすべての SwarmManager 派生クラス（影響はベースクラスで吸収予定）

### Agentic RAG フィードバックループ

- `src/core/intelligence/agentic_rag.py` (新規作成)
- `src/core/engine/master_conductor.py` (インテグレーション)
- トークンサイズや検索クエリを調整するインターフェースの拡張

## 3. 具体的な挙動 (Input/Output)

### 3.1 Swarm Manager 適応的判断ロジック

**Input:** `Specialist.run_with_timeout(task)` から返却される `List[Finding]`
**Behavior:**

1. 各 Specialist からの結果（Findings）を順次チェックする。
2. 発見された脆弱性の中に、`Severity.CRITICAL` に分類されるものがあるか判定する。
3. 該当する脆弱性が検出された場合、以下の処理を実行する。
   - **スキップ**: 未実行の後続 Specialist の実行をキャンセル（`Skipped due to critical finding` としてログに記録）。
   - **即時返却**: 早期リターンにより、結果を直ちに `MasterConductor` へ返す。
   - （可能であれば）発見したタイミングで `EventBus` へアラート（`VULN_FOUND`）を直ちに Publish する（すでにMC側でSubscribeされているため連携が速くなる）

**Output:** スキップされたログが含まれた `SwarmResult`。処理時間が大幅に短縮される。

### 3.2 Agentic RAG フィードバックループ

**Input:** ユーザからのクエリやターゲットURL、過去のRAG検索結果のリスト
**Behavior:**

1. **初期検索**: 初期クエリで Vector DB (Ingester) 等から知識・過去ペイロードを引き出す。
2. **Confidence 評価**: LLMに対して「この検索結果のセットは、現在のタスク（例: SQLiのペイロード作成）に対して十分なContextを持っているか」を `0.0 ~ 1.0` のスコアで評価させる（プロンプトを活用）。
3. **フィードバックループ実行**: - **Confidence >= 0.7 (閾値)**: 検索結果をよしとして、後続処理（Payload生成やアクション決定）へ進む。- **Confidence < 0.7**: LLMが「情報不足」と判定した場合、どこが不足しているか（不足キーワードや観点）を抽出させ、検索クエリを動的に修正して再検索を行う。- 無限ループを防ぐため、最大リトライ回数（例: 3回）を設定する。
   **Output:** 十分な信頼性を担保された Knowledge/Context の抽出リスト。

## 4. 制約と既存アーキテクチャとの整合性

- **アーキテクチャ制約**: 既存の `rag_feedback.py` は「人間のフィードバックによる False Positive の学習」を目的とするモジュールであるのに対して、今回の `AgenticRAGFeedbackLoop` は「タスク実行中のコンテキスト精度向上」を目的として分離する。
- **パフォーマンス**: SwarmManager の適応的判断は、同期的なループ内で行うため軽量な判定とする。また、Agentic RAGの評価用LLMコールは、安価・高速なモデル（mini系など）を利用することを推奨。
- **後方互換**: 全てのSwarmタスクが早期スキップされると困るケース（例: 網羅的スキャンモード "full_scan"）を想定し、タスクのプロパティまたはコンフィグで「`adaptive_skip_enabled=True/False`」を切り替え可能にする。デフォルトは True。
