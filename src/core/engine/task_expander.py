"""
TaskExpander: 粗粒度タスクをエンドポイント単位のサブタスクに展開する
"""

import json
import logging
import uuid
from pathlib import Path
from typing import List, Dict, Any

from src.core.agents.swarm.base import Task
from src.core.workspace.shared_workspace import SharedWorkspace

logger = logging.getLogger(__name__)

class TaskExpander:
    """
    targets_file などの一括処理用パラメータを持つタスクを、
    MasterConductor のキューで並列処理可能な個別サブタスクに展開する。
    """

    def __init__(self, workspace: SharedWorkspace):
        self.workspace = workspace

    def expand(self, parent_task: Task) -> List[Task]:
        """
        親タスクをエンドポイント単位のタスクに展開。
        
        Args:
            parent_task: 展開元の親タスク
            
        Returns:
            展開されたサブタスクのリスト
        """
        # 1. すでに解決済みのリストがあればそれを使用
        targets = parent_task.params.get("targets")
        
        # 2. なければファイルから読み込み
        if not targets:
            targets_file = parent_task.params.get("targets_file")
            if targets_file:
                targets = self._load_targets(targets_file)

        if not targets:
            return []

        # セッション情報を取得
        alt_sessions = self.workspace.user_sessions if hasattr(self.workspace, "user_sessions") else {}
        
        subtasks = []
        for target_url in targets:
            if not isinstance(target_url, str):
                continue
            # 各URLに対してサブタスクを生成
            subtask = self._create_subtask(parent_task, target_url, alt_sessions)
            subtasks.append(subtask)

        return subtasks

    def _load_targets(self, targets_file: str) -> List[str]:
        """targets_file (JSONL) から URL リストを取得"""
        urls = []
        try:
            p = Path(targets_file)
            if not p.exists():
                logger.warning("[TaskExpander] targets_file not found: %s", targets_file)
                return []

            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        url = data.get("url") or data.get("target")
                        if url:
                            urls.append(url)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error("[TaskExpander] Error loading targets: %s", e)
        
        return list(dict.fromkeys(urls))  # 重複排除

    def _create_subtask(self, parent: Task, target_url: str, alt_sessions: Dict[str, Any]) -> Task:
        """個別サブタスクの生成"""
        normalized_target = str(target_url or "").strip()
        if normalized_target.startswith("http:/") and not normalized_target.startswith("http://"):
            normalized_target = normalized_target.replace("http:/", "http://", 1)
        if normalized_target.startswith("https:/") and not normalized_target.startswith("https://"):
            normalized_target = normalized_target.replace("https:/", "https://", 1)

        # 固有のIDを生成 (URLベースで決定論的だと重複排除に有利)
        sub_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{parent.id}:{normalized_target}"))
        
        # パラメータを引き継ぎ
        sub_params = parent.params.copy()
        sub_params.pop("targets_file", None) # 一括ファイルは不要
        sub_params.pop("targets", None)      # 一括リストも不要
        sub_params.pop("resolved_targets", None)
        sub_params["target"] = normalized_target
        sub_params["alternative_sessions"] = alt_sessions
        
        # 優先度の計算
        priority = parent.priority
        tags = parent.params.get("tags", [])
        if "idor_candidate" in tags:
            priority += 30
        elif "api_endpoint" in tags:
            priority += 20
        elif "auth_endpoint" in tags:
            priority += 10

        return Task(
            id=sub_id,
            name=f"{parent.name} -> {normalized_target}",
            agent_type=parent.agent_type,
            priority=priority,
            params=sub_params,
            target=normalized_target,
            parent_id=parent.id
        )
