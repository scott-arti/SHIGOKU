---
task_id: SGK-2026-0015
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# ADR-002: エージェントインターフェースの統一

## ステータス

承認済み (2026-01-05)

## コンテキスト

現在、エージェントには複数の実行メソッドが混在している:

### パターン 1: Swarm 系エージェント

```python
# auth_ninja.py, biz_logic_hunter.py など
def execute(self, target: str, params: dict) -> HandoffContext:
    ...
```

### パターン 2: BaseAgent 系

```python
# CodeAgent, CommandAgent など
async def process(self, input_message: str) -> str:
    ...
```

### 問題点

`MasterConductor._dispatch()` メソッド内で、エージェントの型に応じた分岐が発生している：

```python
# 現状のコード (master_conductor.py Line 1158-1204)
if hasattr(agent, 'execute'):
    result = agent.execute(target, params)
elif hasattr(agent, 'process'):
    result_text = await agent.process(input_message)
```

これにより:

- 新しいエージェントタイプを追加するたびに Conductor を修正する必要がある
- 戻り値の型が統一されておらず、呼び出し側で変換処理が必要
- `hasattr` による型チェックは IDE 補完やリファクタリングツールが効かない

## 決定

1. **`AgentProtocol`** を定義し、全エージェントに統一インターフェースを実装させる
2. 統一メソッドは **`async run(task: dict) -> dict`** とする
3. 既存の `execute()` / `process()` は内部で `run()` から呼び出す形でラップ
4. 戻り値は常に `dict` 形式とし、`HandoffContext` は `to_dict()` で変換

## 詳細設計

### AgentProtocol

```python
from typing import Protocol, Any, runtime_checkable

@runtime_checkable
class AgentProtocol(Protocol):
    @property
    def name(self) -> str: ...

    async def run(self, task: dict[str, Any]) -> dict[str, Any]:
        """統一された実行メソッド

        Args:
            task: {"target": str, "action": str, "params": dict}

        Returns:
            {"success": bool, "data": Any, "error": str | None}
        """
        ...
```

### 既存エージェントへの適用

```python
# Swarm系エージェント
async def run(self, task: dict) -> dict:
    result = self.execute(task["target"], task.get("params", {}))
    return result.to_dict() if hasattr(result, "to_dict") else {"data": result}

# BaseAgent系
async def run(self, task: dict) -> dict:
    output = await self.process(json.dumps(task))
    return {"success": True, "data": {"output": output}}
```

## 結果

### メリット

- `MasterConductor._dispatch()` から `hasattr` チェックが消える
- 新規エージェント追加時のインターフェースが明確
- 型ヒントが効き、IDE 補完が使える
- テストが書きやすくなる

### デメリット

- 全エージェント（約 10 クラス）に `run()` メソッドを追加する作業が必要
- 移行期間中は `run()` と `execute()`/`process()` が併存

## 参考

- 技術的負債検証レポート (2026-01-05)
- Phase 1 実装計画
