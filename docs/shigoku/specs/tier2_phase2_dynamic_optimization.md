---
task_id: SGK-2026-0164
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Spec: Tier 2 Phase 2 - 学習データに基づく動的スキャン最適化

## 1. 概要

Tier 2 Phase 1 で構築した `SelfReflection` のフィードバックループを活用し、`AttackPlanner`（LLMプランナー）が過去の実行結果（成功・失敗）を考慮して次の一手を決定できるように最適化します。

## 2. 目的

- **成功パターンの強化**: 類似ターゲットで成功した手法を優先的に選択する。
- **無駄な試行の削減**: 既に失敗した、あるいはWAFでブロックされたパターンを LLM に伝え、不必要な再試行を回避する。
- **適応的プランニング**: ターゲットの反応（レスポンスコード、エラー傾向）に基づき、攻撃の「深さ」や「激しさ」を動的に調整する。

## 3. 変更範囲

### 3.1 AttackPlanner (`src/core/intelligence/attack_planner.py`)

- `plan` メソッドに `ReflectionInsight` を注入する仕組みを追加。
- プロンプトテンプレートを更新し、「過去の知見（Insights）」セクションを新設。

### 3.2 MasterConductor (`src/core/engine/master_conductor.py`)

- `plan` 実行時に `self.self_reflection.reflect()` を呼び出し、得られた洞察を `AttackPlanner` に渡す。

### 3.3 Prompt Engineering

- 成功した ActionType/Agent の組み合わせを推奨する指示の追加。
- ブロックされたペイロードや特定のエラー（504 Gateway Timeout等）を考慮した代替案提示。

## 4. 挙動詳細

### インプットの拡充

LLM へのプロンプトに以下の項目を動的に追加します：

- **Success Patterns**: "過去3回のスキャンでは 'idor' エージェントが有効でした。"
- **Failure Patterns**: "URL 'admin/\*' は 403 Forbidden が返るため、ブラインド攻撃は避けてください。"
- **WAF Sensitivity**: "ターゲットは XSS ペイロードに対して敏感です。難読化を検討してください。"

## 5. 制約事項

- LLM のトークン制限を考慮し、直近の重要な Insight のみにフィルタリングする。
- 個人情報（PII）や機密ペイロードは `PIIMasker` を通して匿名化してから LLM に送る。

## 6. 検証計画

- **Unit Test**: `AttackPlanner` にモックの Insight を渡し、生成されるプランがそれに応じて変化することを確認。
- **Scenario Test**: 意図的に失敗させた後に再プランニングさせ、同じ失敗を繰り返さないプラン（例: ペイロードの変更）が生成されるか確認。
