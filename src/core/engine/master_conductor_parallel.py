async def execute_parallel(self, max_workers: int = 5) -> dict:
    """
    Smart Parallel Execution with Dependency & Decision Awareness
    
    SmartSchedulerを使用して、依存関係と意思決定依存を考慮した並列実行を行う。
    
    Args:
        max_workers: 同時実行タスク数の上限
    
    Returns:
        実行結果サマリー
    """
    scheduler = SmartScheduler(max_workers=max_workers)
    
    # 既存のtask_queueをScheduledTaskに変換してスケジューラに登録
    for task in self.task_queue:
        # Decision Check関数を生成
        decision_check = self._create_decision_check_for_task(task)
        
        scheduled_task = ScheduledTask(
            id=task.id,
            name=task.name,
            agent_type=task.agent_type,
            action=task.action,
            params=task.params,
            priority=task.priority,
            depends_on=[task.parent_id] if task.parent_id else [],
            decision_check=decision_check,
        )
        scheduler.add_task(scheduled_task)
    
    # Execution Contextをスケジューラと共有
    scheduler.execution_context = {
        "tech_stack": self.context.target_info.get("tech_stack", []),
        "auth_required": self.context.target_info.get("auth_required", True),
        "discovered_assets": self.context.discovered_assets,
        "bypass_methods": self.context.bypass_methods,
    }
    
    # Task実行関数（asyncラッパー）
    async def task_executor(scheduled_task: ScheduledTask) -> dict:
        # ScheduledTaskを元のTask形式に戻す
        original_task = Task(
            id=scheduled_task.id,
            name=scheduled_task.name,
            agent_type=scheduled_task.agent_type,
            action=scheduled_task.action,
            params=scheduled_task.params,
            priority=scheduled_task.priority,
        )
        
        # _dispatch は async 関数なので直接 await する
        result = await self._dispatch(original_task)
        
        # コンテキスト更新
        if result.get("success"):
            self.context.update_success_rate(True)
            if result.get("new_assets"):
                self.context.discovered_assets.extend(result["new_assets"])
            if result.get("bypass_method"):
                self.context.add_bypass_method(result["bypass_method"])
            
            # 技術スタック更新（Decision Checkに影響）
            if result.get("technologies"):
                scheduler.update_context("tech_stack", 
                    self.context.target_info.get("tech_stack", []) + result["technologies"])
        else:
            self.context.update_success_rate(False)
        
        return result
    
    # 並列実行
    logger.info(f"Starting parallel execution with {len(scheduler.tasks)} tasks (max_workers={max_workers})")
    summary = await scheduler.run(task_executor)
    
    # 完了したタスクを completed_tasks に移行
    for task_id, scheduled_task in scheduler.tasks.items():
        original_task = Task(
            id=scheduled_task.id,
            name=scheduled_task.name,
            agent_type=scheduled_task.agent_type,
            action=scheduled_task.action,
            params=scheduled_task.params,
            state=TaskState(scheduled_task.state.value),
            result=scheduled_task.result,
            error=scheduled_task.error,
            priority=scheduled_task.priority,
        )
        self.completed_tasks.append(original_task)
    
    return summary

def _create_decision_check_for_task(self, task: Task) -> Optional[Callable[[dict], bool]]:
    """ 
    タスク固有のDecision Check関数を生成
    
    Args:
        task: 対象タスク
    
    Returns:
        decision_check関数 (Trueなら実行、Falseならスキップ)
    """
    # 例: ログインブルートフォースは、認証が必要な場合のみ実行
    if "login" in task.agent_type.lower() or "brute" in task.name.lower():
        def check_auth_required(context: dict) -> bool:
            return context.get("auth_required", True)
        return check_auth_required
    
    # 例: 技術スタック特化型タスク
    if task.agent_type == "wordpress_scanner":
        def check_wordpress(context: dict) -> bool:
            tech_stack = context.get("tech_stack", [])
            return "WordPress" in tech_stack or "wordpress" in [t.lower() for t in tech_stack]
        return check_wordpress
    
    # デフォルト: 常に実行
    return None
