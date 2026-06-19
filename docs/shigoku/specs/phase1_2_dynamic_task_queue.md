---
task_id: SGK-2026-0143
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Phase 1.2: Dynamic Task Queue 仕様書

## 概要

**機能名**: `DynamicTaskQueue`

**目的**: 現在のMCは「タスクキューに積む→順次実行」だが、実行中のタスクが発見した情報（新しいエンドポイント、認証トークン等）を**キュー内の未実行タスク**に動的に反映する機構を実装する。

**背景**:

- 現在の `task_queue` は単純なリスト（`list[Task]`）
- `_add_tasks()` で優先度ソートは行うが、既存タスクへのコンテキスト注入なし
- JWTトークン発見時にAuthSwarmタスクに渡せない
- Admin panel発見時に優先度ブーストできない（関連タスクのみ）

---

## 変更範囲

| ファイル                                       | 変更内容                               |
| ---------------------------------------------- | -------------------------------------- |
| `src/core/engine/task_queue.py`                | 🆕 新規作成 - 動的タスクキュー         |
| `src/core/engine/context_propagator.py`        | 🆕 新規作成 - コンテキスト伝播ロジック |
| `src/core/engine/master_conductor.py`          | 📝 修正 - DynamicTaskQueue 統合        |
| `tests/unit/engine/test_task_queue.py`         | 🆕 新規作成 - ユニットテスト           |
| `tests/unit/engine/test_context_propagator.py` | 🆕 新規作成 - ユニットテスト           |

---

## 挙動

### Input

タスク実行結果から抽出した `TaskContext`:

```python
@dataclass
class TaskContext:
    """タスク実行中に発見したコンテキスト"""
    discovered_endpoints: List[str] = field(default_factory=list)  # 発見したURL
    auth_tokens: Dict[str, str] = field(default_factory=dict)      # JWT, Session等
    discovered_params: List[str] = field(default_factory=list)     # 新規パラメータ
    tech_stack: List[str] = field(default_factory=list)            # 検出技術
    waf_info: Dict[str, Any] = field(default_factory=dict)         # WAF情報
    critical_findings: List[str] = field(default_factory=list)     # 重要発見（admin等）
```

### Output

キュー内の未実行タスクにコンテキストが反映される:

```python
# Before: AuthSwarm タスク
task.params = {"target": "https://api.example.com"}

# After: JWT発見によりコンテキスト注入
task.params = {
    "target": "https://api.example.com",
    "discovered_tokens": {"jwt": "eyJ..."},  # ← 注入された
}

# Before: 優先度 50
task.priority = 50

# After: Admin panel発見により優先度ブースト
task.priority = 999  # ← ブーストされた
```

### 処理フロー

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        MasterConductor.run()                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  while not task_queue.is_empty():                                       │
│      ┌───────────────────────────────────────────────────────────────┐  │
│      │ 1. task = task_queue.pop()                                    │  │
│      │    └─ 優先度最高のタスクを取得                                 │  │
│      └───────────────────────────────────────────────────────────────┘  │
│                              ↓                                          │
│      ┌───────────────────────────────────────────────────────────────┐  │
│      │ 2. task.params.update(current_context)                        │  │
│      │    └─ 現在の累積コンテキストをタスクに注入                     │  │
│      └───────────────────────────────────────────────────────────────┘  │
│                              ↓                                          │
│      ┌───────────────────────────────────────────────────────────────┐  │
│      │ 3. result = await self._execute_task(task)                    │  │
│      │    └─ Specialistが実行、Finding/新情報を返す                   │  │
│      └───────────────────────────────────────────────────────────────┘  │
│                              ↓                                          │
│      ┌───────────────────────────────────────────────────────────────┐  │
│      │ 4. new_context = context_propagator.extract(result)           │  │
│      │    └─ 結果からJWT、Admin、新エンドポイント等を抽出             │  │
│      └───────────────────────────────────────────────────────────────┘  │
│                              ↓                                          │
│      ┌───────────────────────────────────────────────────────────────┐  │
│      │ 5. current_context.merge(new_context)                         │  │
│      │    └─ 累積コンテキストに追加                                   │  │
│      └───────────────────────────────────────────────────────────────┘  │
│                              ↓                                          │
│      ┌───────────────────────────────────────────────────────────────┐  │
│      │ 6. task_queue.inject_context(new_context)                     │  │
│      │    └─ キュー内タスクにコンテキスト反映 + 優先度調整            │  │
│      └───────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 制約

### 既存アーキテクチャとの整合性

- `MasterConductor` の既存メソッド（`_add_tasks`, `_boost_related_tasks`）は維持
- `DynamicTaskQueue` は既存の `list[Task]` を内部で使用（ラッパー）
- 既存の `task.params` 構造を破壊しない（追加キーのみ）

### パフォーマンス考慮

- `inject_context()` はO(n)でキュー全体を走査するが、通常キューサイズは小さい（<100）
- 優先度変更時はヒープ再構築（O(n log n)）

### EthicsGuard との整合性

- 認証トークンは `PIIMasker` でマスク済みのものを保存
- 外部送信前にはマスク解除が必要

---

## API 設計

### DynamicTaskQueue

```python
class DynamicTaskQueue:
    """動的コンテキスト反映可能なタスクキュー"""

    def __init__(self):
        self._queue: List[Task] = []
        self._task_index: Dict[str, Task] = {}  # ID→Task高速参照
        self._context: TaskContext = TaskContext()

    def add(self, task: Task) -> None:
        """タスクを優先度付きで追加"""
        pass

    def add_batch(self, tasks: List[Task], source: str = "unknown") -> int:
        """複数タスクを一括追加（_add_tasks互換）"""
        pass

    def pop(self) -> Optional[Task]:
        """優先度最高のタスクを取り出し"""
        pass

    def peek(self) -> Optional[Task]:
        """優先度最高のタスクを参照（取り出さない）"""
        pass

    def is_empty(self) -> bool:
        """キューが空か判定"""
        pass

    def inject_context(self, context: TaskContext) -> int:
        """
        キュー内タスクにコンテキストを反映

        Returns:
            影響を受けたタスク数
        """
        pass

    def boost_priority(self, condition: Callable[[Task], bool], new_priority: int) -> int:
        """条件にマッチするタスクの優先度を変更"""
        pass

    def get_all(self) -> List[Task]:
        """全タスクを取得（デバッグ用）"""
        pass
```

### ContextPropagator

```python
class ContextPropagator:
    """タスク実行結果からコンテキストを抽出"""

    # トークン検出パターン
    TOKEN_PATTERNS = {
        "jwt": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*",
        "bearer": r"Bearer\s+[A-Za-z0-9-_.]+",
        "api_key": r"[A-Za-z0-9]{32,}",
    }

    # 重要パス検出パターン
    CRITICAL_PATHS = [
        r"/admin",
        r"/dashboard",
        r"/api/v[0-9]+",
        r"/graphql",
    ]

    def extract(self, result: Dict[str, Any]) -> TaskContext:
        """実行結果からコンテキストを抽出"""
        pass

    def extract_from_finding(self, finding: Finding) -> TaskContext:
        """Findingからコンテキストを抽出"""
        pass
```

### コンテキスト注入ルール

```python
# 注入ルール定義
INJECTION_RULES = [
    # JWT発見 → AuthSwarmタスクに注入
    InjectionRule(
        trigger=lambda ctx: bool(ctx.auth_tokens.get("jwt")),
        target_filter=lambda task: "auth" in task.tags or task.agent_type == "auth",
        inject=lambda task, ctx: task.params.update({"discovered_tokens": ctx.auth_tokens}),
    ),

    # Admin発見 → 関連タスク優先度ブースト
    InjectionRule(
        trigger=lambda ctx: any("admin" in e for e in ctx.critical_findings),
        target_filter=lambda task: "auth" in task.tags or "admin" in task.name.lower(),
        boost_priority=999,
    ),

    # 新エンドポイント発見 → Fuzzing タスクに追加
    InjectionRule(
        trigger=lambda ctx: bool(ctx.discovered_endpoints),
        target_filter=lambda task: task.agent_type in ["injection", "fuzzing"],
        inject=lambda task, ctx: task.params.setdefault("extra_targets", []).extend(ctx.discovered_endpoints),
    ),
]
```

---

## MasterConductor 統合

### 修正箇所

```diff
class MasterConductor:
    def __init__(self, ...):
-       self.task_queue: list[Task] = []
+       from src.core.engine.task_queue import DynamicTaskQueue
+       self.task_queue = DynamicTaskQueue()
+       self.context_propagator = ContextPropagator()
+       self.accumulated_context = TaskContext()

    async def execute_with_replan(self, max_tasks: int = 50):
        for i in range(max_tasks):
-           if not self.task_queue:
+           if self.task_queue.is_empty():
                break

-           task = self.task_queue.pop(0)
+           task = self.task_queue.pop()
+
+           # コンテキスト注入
+           task.params.update(self.accumulated_context.to_dict())

            result = await self._execute_task(task)

+           # コンテキスト抽出・蓄積
+           new_context = self.context_propagator.extract(result)
+           self.accumulated_context.merge(new_context)
+
+           # キュー内タスクにコンテキスト反映
+           self.task_queue.inject_context(new_context)
```

---

## テスト計画

### ユニットテスト

1. **test_task_queue.py**
   - `test_add_and_pop`: 追加・取り出しの基本動作
   - `test_priority_ordering`: 優先度順の取り出し
   - `test_inject_context_jwt`: JWT発見時の注入
   - `test_boost_priority_admin`: Admin発見時の優先度ブースト
   - `test_batch_add`: 一括追加

2. **test_context_propagator.py**
   - `test_extract_jwt_from_response`: JWT抽出
   - `test_extract_admin_path`: Admin パス検出
   - `test_extract_new_endpoints`: 新エンドポイント抽出

### 統合テスト

```python
async def test_context_flows_through_queue():
    """コンテキストがキュー内タスクに伝播することを確認"""
    mc = MasterConductor()

    # タスク追加
    mc.task_queue.add(Task(id="1", name="Recon", agent_type="recon"))
    mc.task_queue.add(Task(id="2", name="Auth Check", agent_type="auth", tags=["auth"]))

    # Recon結果にJWT発見をシミュレート
    result = {"tokens": {"jwt": "eyJ..."}}
    new_context = mc.context_propagator.extract(result)
    mc.task_queue.inject_context(new_context)

    # Auth Checkタスクにコンテキストが注入されているか確認
    auth_task = [t for t in mc.task_queue.get_all() if t.id == "2"][0]
    assert "discovered_tokens" in auth_task.params
```

---

## 工数見積もり

| タスク                       | 工数                  |
| ---------------------------- | --------------------- |
| `task_queue.py` 実装         | 3時間                 |
| `context_propagator.py` 実装 | 3時間                 |
| `master_conductor.py` 修正   | 2時間                 |
| テスト作成                   | 3時間                 |
| E2E 検証                     | 1時間                 |
| **合計**                     | **12時間（約2.5日）** |

---

## 実装順序

1. `src/core/engine/task_queue.py` - 新規、依存なし
2. `src/core/engine/context_propagator.py` - 新規、依存なし
3. テスト作成・実行（task_queue, context_propagator）
4. `src/core/engine/master_conductor.py` - 統合
5. 統合テスト・E2E 検証
