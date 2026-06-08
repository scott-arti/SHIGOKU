---
task_id: SGK-2026-0136
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Spec: BizLogicHunter Migration to Master Conductor Architecture

## 1. 概要
`BizLogicHunter` はビジネスロジックの脆弱性（IDOR、認可不備、隠しパラメータ、特権操作など）を専門とするエージェントです。
現在の実装は単一の巨大なファイルにロジックが詰め込まれており、新しい Master Conductor アーキテクチャ（Tool-Centric & Context-Aware）に適合していません。
本タスクでは、`BizLogicHunter` をリファクタリングし、拡張性と保守性を高めます。

## 2. 変更範囲
- `src/core/agents/swarm/biz_logic_hunter.py`: エージェント本体のリファクタリング（ロジックの削除とToolの呼び出しへの置換）
- `src/tools/custom/biz_logic_tools.py`: (新設) HTTPリクエストを伴う具体的な検証ロジックをToolとして抽出
- `src/core/factory.py`: エージェント登録の確認（必要に応じて）

## 3. 具体的な挙動
### 3.1 エージェントとしての役割
- **召喚条件**: `MasterConductor` が `logic`, `auth`, `priv_esc`, `idor` などのタグを含むタスクを発行した際。
- **入力**: `SharedWorkspace` に保存されたクロール済みエンドポイント、パラメータ情報。
- **出力**: 検証結果としての `Finding` オブジェクト、および `KnowledgeGraph` への更新。

### 3.2 Tool への分割
以下の機能を Tool として切り出します。
1. `IdorValidator`: 異なるセッションやユーザーIDを使用して認可不備を確認。
2. `HiddenParamHunter`: 動的にパラメータを挿入し、サーバーの反応から隠しパラメータを推測。
3. `PrivilegeEscalationTester`: 一般ユーザー特有のエンドポイントに対し、管理者権限での操作を試行（またはその逆）。
4. `LogicFlowIntegrityCheck`: 多段階の決済や登録フローにおいて、ステップのスキップやパラメータ改ざんを確認。

## 4. 制約と安全性
- **EthicsGuard**: すべての Tool は `ethics_guard.check_scope()` を呼び出す必要があります。
- **Rate Limiting**: `AdaptiveRateLimiter` を尊重し、過剰な負荷をかけないこと。
- **Network**: `AsyncNetworkClient` を使用し、Proxy 設定などを一貫させること。
- **Type Hinting**: すべての関数に型ヒントを付与し、Google Style の Docstring を記述すること。

## 5. 実装フェーズ
1. **Phase 1: Tool の作成**: `src/tools/custom/biz_logic_tools.py` にコアロジックを実装。
2. **Phase 2: Agent のリファクタリング**: `BizLogicHunter` を `BaseAgent` の規約（`__init__`, `run`）に従って再構成。
3. **Phase 3: テストと検証**: `pytest` を用いた単体テストと、Dry-run による起動確認。
