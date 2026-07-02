---
task_id: SGK-2026-0156
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Specification: Recipe Execution Engine Optimization

## 1. 目的

SHIGOKUのレシピ実行エンジンを、従来の逐次実行から、依存関係を考慮した非同期並列実行（DAGベース）へとアップグレードする。これにより、診断時間の短縮とリソース利用の効率化を図る。

## 2. 実装詳細

### 2.1 データモデルの変更

`src/core/engine/recipe_loader.py` 内の `RecipeStep` を以下のように拡張する：

```python
@dataclass
class RecipeStep:
    id: str  # 一意なID
    name: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)  # 依存するステップのID
```

### 2.2 グラフ解析ロジック

`networkx.DiGraph` を使用する。

1. 各 `RecipeStep` をノードとして追加。
2. `dependencies` に基づいてエッジを追加。
3. `networkx.is_directed_acyclic_graph()` で循環参照がないかチェック。
4. `networkx.topological_sort()` または `lexicographical_topological_sort` でトポロジカル順序を取得。

### 2.3 並列実行アルゴリズム

`asyncio.Semaphore(max_workers)` を使用して同時実行数を制御しつつ、準備ができたタスク（依存関係が解消されたタスク）から順次実行を開始する。

### 2.4 キャッシュ機構

- 実行中の `Runner` インスタンス内に `_tool_cache` を保持。
- キー: `f"{action}:{hash(json.dumps(params))}"`
- 同一セッション内でのみ有効とする。

## 3. 制約事項

- `EthicsGuard` によるスコープチェックは、各ステップの実行直前に必ず行うこと。
- レート制限 (`AdaptiveRateLimiter`) を遵守すること。
