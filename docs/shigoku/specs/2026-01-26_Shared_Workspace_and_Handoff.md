---
task_id: SGK-2026-0074
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-01-26'
updated_at: '2026-07-02'
---

# 仕様書: Phase 2 Shared Workspace & Handoff Mechanism Integration

**目標**: エージェント間の情報共有を「共有ワークスペース」を通じて正規化し、発見した脆弱性情報に基づく動的なエージェント切り替え（Handoff）を実現する。

## 1. 概要

現在、エージェントはそれぞれ独立しており、発見した情報を共有する手段が統一されていません。また、あるエージェント（例: `BizLogicHunter`）が専門的な脆弱性の兆候（例: JWT）を見つけた場合、スムーズに専門エージェント（`AuthNinja`）に交代する仕組みが必要です。

本フェーズでは以下の2点を実装します：

1. **Shared Workspace Integration**: 全エージェントが標準でファイルベースの共有ワークスペースにアクセス可能にする。
2. **Handoff Mechanism**: エージェントが次のエージェントを指名して交代できる仕組みを `MasterConductor` レベルでサポートする。

## 2. 変更対象

### 2.1 Shared Workspace Integration

- **`src/core/agents/base.py`**
  - `SharedWorkspace` をインポート。
  - `__init__` で `self.workspace` を初期化（パスは設定または引数から）。
  - ヘルパーメソッド `save_finding`, `save_intel` を追加し、全エージェントから簡単に呼び出せるようにする。
- **`src/core/agents/swarm/auth_ninja.py`**
  - 重複している `_init_workspace` ロジックを削除し、基底クラスのものを利用するようリファクタリング。

### 2.2 Handoff Mechanism

- **`src/core/agents/base.py`**
  - `HandoffTool` をデフォルトツールとして登録（Configで無効化可能に）。
- **`src/core/engine/master_conductor.py`**
  - エージェント実行結果 (`result`) を解析し、`HandoffResult` (またはそれに相当する辞書) が含まれている場合、次のタスクを動的に生成してキューの先頭に割り込むロジックを追加。
  - "Context-Aware" なので、前のエージェントが収集した `context` (トークン、パラメータ等) を次のエージェントの入力にマージする。

## 3. 実装詳細ルール

### 3.1 Shared Workspace

- ワークスペースのルートパスは `settings.WORKSPACE_ROOT` または実行時の引数で決定。
- ディレクトリ構造は `SharedWorkspace` クラスの定義に従う (`findings/`, `intel/`, `artifacts/`, `context/`)。

### 3.2 Handoffフロー

1. Agent A が実行中に `HandoffTool` を通じて「Agent Bに交代」を提案 (または終了時のResultで指定)。
2. `MasterConductor` がこれを受け取る。
3. `MasterConductor` は現在のタスクを完了とし、即座に Agent B 用の新しいタスクを作成。
4. 新しいタスクの `params` には、Agent A が出力した `handoff_context` を含める。

## 4. 検証計画 (Verification)

### 4.1 ユニットテスト

- **`tests/unit/core/agents/test_shared_workspace_integration.py`**
  - `BaseAgent` を継承したダミーエージェントを作成。
  - `save_finding` を呼び出し、実際にファイルが生成されるか確認。
- **`tests/unit/core/engine/test_handoff_mechanism.py`**
  - `MasterConductor` とモックエージェントを使用。
  - Handoff要求を含む結果を返し、次のタスクがスケジュールされるか確認。

### 4.2 統合動作確認

- `BizLogicHunter` でわざと JWT トークン検知をシミュレートさせ、`AuthNinja` (JWTInspector) にハンドオフされるか確認。
