"""
Dynamic Task Queue - 動的コンテキスト反映可能なタスクキュー

タスク実行中に発見したコンテキスト（JWT、Admin panel等）を
キュー内の未実行タスクに動的反映する。

用途:
- JWT発見時にAuthSwarmタスクに自動注入
- Admin panel発見時に優先度ブースト
- 新エンドポイント発見時にFuzzingタスクに追加
"""

import logging
import heapq
import sqlite3
import pickle
import time
import uuid
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Callable, Iterator, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class TaskContext:
    """タスク実行中に発見したコンテキスト"""
    
    # 発見したエンドポイント
    discovered_endpoints: List[str] = field(default_factory=list)
    
    # 認証トークン {"jwt": "eyJ...", "bearer": "...", "session": "..."}
    auth_tokens: Dict[str, str] = field(default_factory=dict)
    
    # 発見したパラメータ
    discovered_params: List[str] = field(default_factory=list)
    
    # 検出した技術スタック
    tech_stack: List[str] = field(default_factory=list)
    
    # WAF情報
    waf_info: Dict[str, Any] = field(default_factory=dict)
    
    # 重要発見 ["admin_panel", "graphql", "debug_endpoint"]
    critical_findings: List[str] = field(default_factory=list)
    
    def merge(self, other: "TaskContext") -> None:
        """
        他の TaskContext をマージ（重複排除）
        
        Args:
            other: マージするコンテキスト
        """
        # リスト系: dict.fromkeys() で順序保持 + 重複排除
        self.discovered_endpoints = list(dict.fromkeys(
            self.discovered_endpoints + other.discovered_endpoints
        ))
        
        self.discovered_params = list(dict.fromkeys(
            self.discovered_params + other.discovered_params
        ))
        
        self.tech_stack = list(dict.fromkeys(
            self.tech_stack + other.tech_stack
        ))
        
        self.critical_findings = list(dict.fromkeys(
            self.critical_findings + other.critical_findings
        ))
        
        # 辞書系: 更新（上書き）
        self.auth_tokens.update(other.auth_tokens)
        self.waf_info.update(other.waf_info)
    
    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return asdict(self)
    
    def is_empty(self) -> bool:
        """コンテキストが空か判定"""
        return (
            not self.discovered_endpoints and
            not self.auth_tokens and
            not self.discovered_params and
            not self.tech_stack and
            not self.waf_info and
            not self.critical_findings
        )
    
    def has_auth_tokens(self) -> bool:
        """認証トークンがあるか"""
        return bool(self.auth_tokens)
    
    def has_critical_findings(self) -> bool:
        """重要発見があるか"""
        return bool(self.critical_findings)


@dataclass
class InjectionRule:
    """
    コンテキスト注入ルール
    
    trigger: コンテキストがこの条件を満たしたらルール発動
    target_filter: キュー内のどのタスクに適用するか
    inject: タスクにコンテキストを注入する関数
    boost_priority: 優先度を変更する場合の新しい優先度
    """
    name: str
    trigger: Callable[[TaskContext], bool]
    target_filter: Callable[[Any], bool]  # Task を受け取る
    inject: Optional[Callable[[Any, TaskContext], None]] = None
    boost_priority: Optional[int] = None
    
    def applies_to(self, task: Any, context: TaskContext) -> bool:
        """このルールがタスクに適用されるか"""
        return self.trigger(context) and self.target_filter(task)
    
    def apply(self, task: Any, context: TaskContext) -> bool:
        """
        ルールを適用
        
        Returns:
            適用されたか
        """
        if not self.applies_to(task, context):
            return False
        
        # コンテキスト注入
        if self.inject:
            self.inject(task, context)
        
        # 優先度変更
        if self.boost_priority is not None:
            task.priority = self.boost_priority
        
        return True


@dataclass
class TaskPriority:
    """ヒープに格納する軽量エントリ"""
    priority: int
    timestamp: float
    task_id: str
    in_memory: bool = True  # False ならディスク上にある


def _default_injection_rules() -> List[InjectionRule]:
    """デフォルトの注入ルール"""
    
    def is_auth_task(task: Any) -> bool:
        """認証関連タスクか判定"""
        if hasattr(task, 'agent_type'):
            if 'auth' in task.agent_type.lower():
                return True
        if hasattr(task, 'name'):
            name_lower = task.name.lower()
            if any(kw in name_lower for kw in ['auth', 'jwt', 'oauth', 'session']):
                return True
        return False
    
    def is_fuzzing_task(task: Any) -> bool:
        """Fuzzingタスクか判定"""
        if hasattr(task, 'agent_type'):
            agent_type = task.agent_type.lower()
            if any(kw in agent_type for kw in ['fuzz', 'injection', 'scan']):
                return True
        return False
    
    def inject_auth_tokens(task: Any, context: TaskContext) -> None:
        """認証トークンをタスクに注入"""
        if hasattr(task, 'params') and isinstance(task.params, dict):
            task.params['discovered_tokens'] = context.auth_tokens.copy()
    
    def inject_endpoints(task: Any, context: TaskContext) -> None:
        """エンドポイントをタスクに注入"""
        if hasattr(task, 'params') and isinstance(task.params, dict):
            existing = task.params.get('extra_targets', [])
            # 重複排除のために set を使うが、順序保持したい場合は dict.fromkeys 等の利用を検討
            # ここでは既存ロジックを踏襲しつつ効率化
            
            # 既存リスト + 新規リスト から重複を除去
            new_targets = [ep for ep in context.discovered_endpoints if ep not in existing]
            existing.extend(new_targets)
            
            task.params['extra_targets'] = existing
    
    return [
        # JWT/認証トークン発見 → Authタスクに注入
        InjectionRule(
            name="auth_token_injection",
            trigger=lambda ctx: ctx.has_auth_tokens(),
            target_filter=is_auth_task,
            inject=inject_auth_tokens,
        ),
        
        # Admin panel発見 → 認証タスク優先度ブースト
        InjectionRule(
            name="admin_priority_boost",
            trigger=lambda ctx: 'admin_panel' in ctx.critical_findings,
            target_filter=is_auth_task,
            boost_priority=999,
        ),
        
        # 新エンドポイント発見 → Fuzzingタスクに追加
        InjectionRule(
            name="endpoint_injection",
            trigger=lambda ctx: bool(ctx.discovered_endpoints),
            target_filter=is_fuzzing_task,
            inject=inject_endpoints,
        ),
        
        # GraphQL発見 → GraphQL関連タスク優先度ブースト
        InjectionRule(
            name="graphql_priority_boost",
            trigger=lambda ctx: 'graphql' in ctx.critical_findings,
            target_filter=lambda t: hasattr(t, 'name') and 'graphql' in t.name.lower(),
            boost_priority=800,
        ),
    ]


class DynamicTaskQueue:
    """
    動的コンテキスト反映可能なタスクキュー (Heapq版)
    
    既存の list[Task] をラップし、コンテキスト注入機能を追加。
    MasterConductor の task_queue を置き換える。
    
    Performance:
    - add/pop: O(log n)
    - boost_priority: O(n log n) with lazy removal
    """
    
    def __init__(
        self,
        injection_rules: Optional[List[InjectionRule]] = None,
        max_memory_size: int = 5000,
        disk_db_path: Optional[str] = None
    ):
        """
        Args:
            injection_rules: カスタム注入ルール（省略時はデフォルト）
            max_memory_size: メモリに保持する最大タスク数
            disk_db_path: ディスク退避用のSQLiteファイルパス
        """
        self._heap: List[Tuple[int, int, TaskPriority]] = []
        self._seq: int = 0          # 挿入順序
        self._task_index: Dict[str, Any] = {}  # id → Task (メモリ内)
        self._injection_rules = injection_rules or _default_injection_rules()
        self._removed_seqs: Set[int] = set()    # Lazy removal 用
        
        # ストレージエンジン設定 (将来的に Redis 等に切り替え可能にするためのフラグ)
        self.storage_mode = "sqlite" # or "redis"
        
        self.max_memory_size = max_memory_size
        self._disk_db_path = disk_db_path or "./workspace/.task_overflow.db"
        self._init_disk_storage()
        
        # メトリクス
        self._spill_count = 0
        self._load_count = 0

    def _init_disk_storage(self) -> None:
        """SQLite ディスクストレージを初期化"""
        db_path = Path(self._disk_db_path)
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
            with sqlite3.connect(self._disk_db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS tasks (
                        task_id TEXT PRIMARY KEY,
                        task_data BLOB NOT NULL,
                        spilled_at REAL NOT NULL
                    )
                """)
                # 検索用インデックス
                conn.execute("CREATE INDEX IF NOT EXISTS idx_task_id ON tasks(task_id)")
                conn.commit()
            
            # パーミッション設定（オーナー読み書きのみ）
            if db_path.exists():
                db_path.chmod(0o600)
        except Exception as e:
            logger.error(f"Failed to initialize disk storage for task queue: {e}")

    def _spill_lowest_priority_task(self) -> None:
        """最も優先度が低いタスクをディスクに退避"""
        if not self._task_store_keys_list():
            return

        # メモリ内のタスクから最低優先度を探す
        # 注意: _task_index はメモリ内の実体のみを持つように調整
        try:
            # 優先度が低い順にソートして先頭を取得
            lowest_task_id = min(
                self._task_index.keys(),
                key=lambda tid: getattr(self._task_index[tid], 'priority', 0)
            )
            
            task = self._task_index.pop(lowest_task_id)
            
            # SQLite に保存
            with sqlite3.connect(self._disk_db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO tasks (task_id, task_data, spilled_at) VALUES (?, ?, ?)",
                    (task.id, pickle.dumps(task), time.time())
                )
                conn.commit()
            
            # ヒープ内のエントリのフラグを更新
            for entry in self._heap:
                _, _, priority_obj = entry
                if priority_obj.task_id == lowest_task_id:
                    priority_obj.in_memory = False
            
            self._spill_count += 1
            logger.debug(f"Spilled task {lowest_task_id} to disk (total: {self._spill_count})")
        except Exception as e:
            logger.error(f"Error spilling task to disk: {e}")

    def _task_store_keys_list(self) -> List[str]:
        return list(self._task_index.keys())

    def _load_from_disk(self, task_id: str) -> Optional[Any]:
        """ディスクからタスクを読み込み"""
        try:
            with sqlite3.connect(self._disk_db_path) as conn:
                cursor = conn.execute(
                    "SELECT task_data FROM tasks WHERE task_id = ?",
                    (task_id,)
                )
                row = cursor.fetchone()
                if row:
                    task = pickle.loads(row[0])
                    # ディスクから削除
                    conn.execute("DELETE FROM tasks WHERE task_id = ?", (task_id,))
                    conn.commit()
                    return task
        except Exception as e:
            logger.error(f"Error loading task {task_id} from disk: {e}")
        return None
    
    def add(self, task: Any) -> None:
        """
        タスクを優先度付きで追加 (O(log n))
        
        Args:
            task: 追加するタスク
        """
        # メモリ制限チェック
        if len(self._task_index) >= self.max_memory_size:
            self._spill_lowest_priority_task()

        priority = getattr(task, 'priority', 0)
        task_id = getattr(task, 'id', str(uuid.uuid4()))
        
        # 軽量エントリを使用
        priority_entry = TaskPriority(
            priority=priority,
            timestamp=time.time(),
            task_id=task_id,
            in_memory=True
        )
        
        # Pythonのheapqは最小ヒープなので、優先度を負の値にする
        entry = (-priority, self._seq, priority_entry)
        heapq.heappush(self._heap, entry)
        self._seq += 1
        
        # プリエンプティブ制御: 超高優先度タスクの場合、既存の並列処理に割り込むフラグを立てる等の拡張が可能
        if priority >= 900:
            logger.info(f"Critical task detected: {task_id} (Priority: {priority})")
        
        self._task_index[task_id] = task
    
    def push(self, task: Any) -> None:
        """add() のエイリアス (互換性用)"""
        self.add(task)
    
    def add_batch(self, tasks: List[Any], source: str = "unknown") -> int:
        """
        複数タスクを一括追加 (O(k log n))
        
        Args:
            tasks: 追加するタスクのリスト
            source: 追加元（ログ用）
        
        Returns:
            追加されたタスク数
        """
        if not tasks:
            return 0
        
        for task in tasks:
            self.add(task)
        
        # 実体のヒープサイズは遅延削除分を含む可能性があるため、有効なタスク数を概算
        effective_size = len(self._task_index)
        logger.debug("Added %d tasks from %s, effective queue size: %d", len(tasks), source, effective_size)
        return len(tasks)
    
    def pop(self) -> Optional[Any]:
        """
        優先度最高のタスクを取り出し (O(log n))
        
        Returns:
            タスク（キューが空なら None）
        """
        while self._heap:
            neg_pri, seq, priority_entry = heapq.heappop(self._heap)
            
            # Lazy removal by seq
            if seq in self._removed_seqs:
                self._removed_seqs.discard(seq)
                continue
            
            task_id = priority_entry.task_id
            
            # メモリにあるかディスクにあるかで分岐
            if priority_entry.in_memory:
                # 優先度変更があった場合、古いエントリはここで弾くことができる
                if task_id not in self._task_index:
                    continue
                
                task = self._task_index.pop(task_id)
                current_priority = getattr(task, 'priority', 0)
                if -neg_pri != current_priority:
                    # 優先度が不一致（古いエントリ）
                    # 新しい優先度のものは別途ヒープにあるはずなので、これは捨てる
                    continue
                
                return task
            else:
                # ディスクから読み込み
                task = self._load_from_disk(task_id)
                if task:
                    self._load_count += 1
                    return task
                # ロードに失敗した、または既にpop済みの場合はスキップ
            
        return None
    
    def peek(self) -> Optional[Any]:
        """
        優先度最高のタスクを参照（取り出さない）
        ただし、Lazy removal のゴミが先頭にある場合は掃除する。
        
        Returns:
            タスク（キューが空なら None）
        """
        while self._heap:
            # 先頭を参照
            neg_pri, seq, priority_entry = self._heap[0]
            
            if seq in self._removed_seqs:
                heapq.heappop(self._heap)
                self._removed_seqs.discard(seq)
                continue
            
            task_id = priority_entry.task_id
            
            if priority_entry.in_memory:
                if task_id not in self._task_index:
                    heapq.heappop(self._heap)
                    continue
                
                task = self._task_index[task_id]
                current_priority = getattr(task, 'priority', 0)
                if -neg_pri != current_priority:
                    heapq.heappop(self._heap)
                    continue
                
                return task
            else:
                # ディスクにある場合は参照不可（または低速なロードが必要になるため、Noneを返さないための工夫が必要）
                # ここでは peek は「次に実行されるもの」の型ヒント等のため、
                # 必要ならロードしてメモリに戻す
                task = self._load_from_disk(task_id)
                if task:
                    # メモリに戻して、ヒープのフラグも更新したいが peek なので一旦メモリに入れるだけにする
                    self._task_index[task_id] = task
                    priority_entry.in_memory = True
                    return task
                else:
                    heapq.heappop(self._heap)
                    continue

            return task
        return None
    
    def is_empty(self) -> bool:
        """キューが空か判定（有効なタスクがない場合も空とみなす）"""
        return self.peek() is None

    def empty(self) -> bool:
        """キューが空か判定（is_empty と同じ - Python 標準 Queue との互換性）"""
        return self.is_empty()

    def inject_context(self, context: TaskContext) -> int:
        """
        キュー内タスクにコンテキストを反映
        """
        if context.is_empty():
            return 0
        
        affected_count = 0
        to_readd = []
        
        # メモリ内のタスクのみに適用
        for task_id, task in list(self._task_index.items()):
            old_priority = getattr(task, 'priority', 0)
            rule_applied = False
            
            for rule in self._injection_rules:
                if rule.apply(task, context):
                    rule_applied = True
                    logger.debug(
                        "Applied rule '%s' to task: %s",
                        rule.name,
                        getattr(task, 'name', 'unknown')
                    )
            
            if rule_applied:
                affected_count += 1
                new_priority = getattr(task, 'priority', 0)
                
                if new_priority != old_priority:
                    # ヒープ上の古いエントリを無効化
                    for entry in self._heap:
                        _, seq, p_entry = entry
                        if p_entry.task_id == task_id:
                            self._removed_seqs.add(seq)
                    to_readd.append(task)
        
        for task in to_readd:
            self.add(task)
            
        return affected_count
    
    def boost_priority(
        self,
        condition: Callable[[Any], bool],
        new_priority: int,
    ) -> int:
        """
        条件にマッチするタスクの優先度を変更
        """
        return self._modify_priority(condition, lambda t: setattr(t, 'priority', new_priority))

    def boost_by_delta(
        self,
        condition: Callable[[Any], bool],
        delta: int,
    ) -> int:
        """
        条件にマッチするタスクの優先度を増減
        """
        def apply_delta(task):
            task.priority += delta
            
        return self._modify_priority(condition, apply_delta)
    
    def _modify_priority(self, condition: Callable[[Any], bool], modifier: Callable[[Any], None]) -> int:
        """優先度変更の共通ロジック (メモリ内タスクのみ反映)"""
        affected = 0
        to_readd = []
        
        for task_id, task in list(self._task_index.items()):
            if condition(task):
                # invalidate current entries in heap
                for entry in self._heap:
                    _, seq, p_entry = entry
                    if p_entry.task_id == task_id:
                        self._removed_seqs.add(seq)
                
                modifier(task)
                to_readd.append(task)
                affected += 1
        
        for task in to_readd:
            self.add(task)
            
        return affected

    def remove_tasks_for_assets(self, asset_ids: List[str]) -> int:
        """
        指定された資産に関連する未実行タスクをキューから削除
        """
        if not asset_ids:
            return 0
            
        asset_ids_set = set(asset_ids)
        new_heap = []
        removed_count = 0
        
        # ヒープ再構築
        while self._heap:
            entry = heapq.heappop(self._heap)
            neg_pri, seq, p_entry = entry
            
            if seq in self._removed_seqs:
                self._removed_seqs.discard(seq)
                continue
            
            task_id = p_entry.task_id
            
            # タスクを取得（メモリまたはディスク）
            task = self._task_index.get(task_id)
            if not task and not p_entry.in_memory:
                task = self._load_from_disk(task_id)
                if task:
                    # 判定のために一時的に保持（後で戻すなり捨てるなり）
                    self._task_index[task_id] = task

            if not task:
                continue

            # Priority check
            current_priority = getattr(task, 'priority', 0)
            if -neg_pri != current_priority:
                continue

            # Coverage/Gate に重要なタスクは prune しない
            if self._is_prune_protected_task(task):
                new_heap.append(entry)
                continue

            # 削除対象か判定
            task_asset_id = getattr(task, 'asset_id', None) or (task.params.get('asset_id') if hasattr(task, 'params') and task.params else None)
            task_target = task.params.get('target') if hasattr(task, 'params') and task.params else None
            
            should_remove = False
            if task_asset_id in asset_ids_set:
                should_remove = True
            elif task_target and any(aid in task_target for aid in asset_ids_set):
                should_remove = True
            
            if should_remove:
                task_id = getattr(task, 'id', None)
                if task_id and task_id in self._task_index:
                    del self._task_index[task_id]
                removed_count += 1
            else:
                new_heap.append(entry)
                
        self._heap = new_heap
        heapq.heapify(self._heap)
        self._removed_seqs.clear() # 再構築したのでゴミは消えた
        
        if removed_count > 0:
            logger.info("Removed %d tasks for assets: %s", removed_count, asset_ids)
            
        return removed_count

    def _is_prune_protected_task(self, task: Any) -> bool:
        """
        戦略最適化の間引き対象から除外すべきタスクか判定。
        シナリオカバレッジ維持に必要なタスクは削除しない。
        """
        params = task.params if hasattr(task, "params") and isinstance(task.params, dict) else {}
        source_category = str(params.get("source_category", "") or "").strip().lower()
        category = str(params.get("category", "") or "").strip().lower()

        protected_sources = {
            "scenario_probe_planner",
            "scenario_probe_guard",
            "coverage_backfill",
            "coverage_backfill_guard",
        }
        if source_category in protected_sources:
            return True

        if category == "csrf_candidate":
            return True

        if params.get("scenario_probe"):
            return True

        if bool(params.get("_coverage_guard_forced", False)):
            return True

        tags = getattr(task, "tags", []) or []
        tags_lower = {str(tag).strip().lower() for tag in tags}
        if "manual_verify" in tags_lower or "coverage_guard_forced" in tags_lower:
            return True

        task_name = str(getattr(task, "name", "") or "").upper()
        if task_name.startswith("SCN"):
            return True

        return False

    def boost_priority_for_assets(self, asset_ids: List[str], boost_value: int) -> int:
        """
        指定された資産に関連するタスクの優先度をブースト
        """
        if not asset_ids:
            return 0
            
        asset_ids_set = set(asset_ids)
        
        def condition(task):
            task_asset_id = getattr(task, 'asset_id', None) or (task.params.get('asset_id') if hasattr(task, 'params') and task.params else None)
            task_target = task.params.get('target') if hasattr(task, 'params') and task.params else None
            
            if task_asset_id in asset_ids_set:
                return True
            if task_target and any(aid in task_target for aid in asset_ids_set):
                return True
            return False
            
        return self.boost_by_delta(condition, boost_value)

    def get_tasks_summary(self) -> str:
        """
        現在積まれているタスクの傾向を要約して返す
        """
        valid_tasks = self.get_all()
        
        if not valid_tasks:
            return "Task queue is empty."
            
        categories = {}
        for task in valid_tasks:
            agent = getattr(task, 'agent_type', 'unknown')
            categories[agent] = categories.get(agent, 0) + 1
            
        summary = [f"Total tasks: {len(valid_tasks)}"]
        summary.append("Categories breakdown:")
        for agent, count in sorted(categories.items(), key=lambda x: -x[1]):
            summary.append(f"- {agent}: {count}")
            
        # 優先度の高いトップ3タスクを表示
        summary.append("\nHigh priority tasks:")
        for task in valid_tasks[:3]:
            summary.append(f"- [{getattr(task, 'priority', 0)}] {getattr(task, 'name', 'unnamed')} ({getattr(task, 'agent_type', 'unknown')})")
            
        return "\n".join(summary)

    def get_by_id(self, task_id: str) -> Optional[Any]:
        """ID でタスクを取得"""
        # インデックスにあるなら有効とみなす
        return self._task_index.get(task_id)
    
    def remove_by_id(self, task_id: str) -> bool:
        """ID でタスクを削除 (O(N))"""
        if task_id not in self._task_index:
            return False
        
        # ヒープを走査して対象エントリのseqを無効化
        for entry in self._heap:
            _, seq, p_entry = entry
            if p_entry.task_id == task_id:
                self._removed_seqs.add(seq)
                # 同じインスタンスのエントリが複数ある可能性（優先度変更の残骸など）も考慮し、
                # breakせずに全走査する方が安全か、あるいは1つでも消せば目的達成か。
                # 優先度変更の残骸はpriority mismatchで消えるが、seqで消しておいても良い。
                # 安全側に倒して break しない。
        
        del self._task_index[task_id]
        return True

    def get_pending_task_ids(self) -> List[str]:
        """待機中のタスクIDリストを取得"""
        return list(self._task_index.keys())
    
    def get_all(self) -> List[Any]:
        """全タスクを取得（デバッグ用） - 優先度順にソートされた状態のリストを返す"""
        temp_heap = list(self._heap)
        
        sorted_tasks = []
        
        while temp_heap:
            neg_pri, seq, p_entry = heapq.heappop(temp_heap)
            
            if seq in self._removed_seqs:
                continue
                
            task_id = p_entry.task_id
            if p_entry.in_memory:
                task = self._task_index.get(task_id)
            else:
                task = self._load_from_disk(task_id)
            
            if not task:
                continue

            current_priority = getattr(task, 'priority', 0)
            if -neg_pri != current_priority:
                continue
            
            sorted_tasks.append(task)
            
        return sorted_tasks
    
    def clear(self) -> None:
        """キューをクリア"""
        self._heap.clear()
        self._task_index.clear()
        self._removed_seqs.clear()
        self._seq = 0
    
    def _sort(self) -> None:
        """Deprecated"""
    
    def __len__(self) -> int:
        """有効なタスク数を返す"""
        return len(self._task_index)
    
    def __iter__(self) -> Iterator[Any]:
        """優先度順にイテレーション"""
        return iter(self.get_all())
    
    def to_list(self) -> List[Any]:
        """get_all のエイリアス (互換性用)"""
        return self.get_all()


def create_dynamic_queue(
    custom_rules: Optional[List[InjectionRule]] = None,
) -> DynamicTaskQueue:
    """DynamicTaskQueue 作成ヘルパー"""
    return DynamicTaskQueue(injection_rules=custom_rules)
