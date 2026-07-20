import logging
from typing import List, Dict, Any, Optional, Set
from src.core.engine import task_pruning_policy as task_pruning_policy_shared
from src.core.engine.task_queue import DynamicTaskQueue

logger = logging.getLogger(__name__)

class StrategyOptimizer:
    """
    MasterConductorの戦略参謀
    現在のタスクキューとコンテキストを分析し、タスクの間引きや優先度調整を行う
    """
    
    def __init__(self, llm_client: Any = None, config: Optional[Dict[str, Any]] = None):
        """
        Args:
            llm_client: LLMへのアクセス用クライアント
            config: 設定辞書
        """
        self.llm = llm_client
        self.config = config or {}
        self.mode = self.config.get("mode", "BUG_BOUNTY")
        
        # 戦略見直しのインターバル（ステップ数）
        self.review_interval = self.config.get("strategy_review_interval", 10)
        self.last_review_step = 0

    def should_review(self, current_step: int) -> bool:
        """戦略レビューを行うべきステップか判定"""
        return (current_step - self.last_review_step) >= self.review_interval

    def review_strategy(self, task_queue: DynamicTaskQueue, knowledge_graph: Any, current_step: int) -> Dict[str, Any]:
        """
        Analyse the current task queue and knowledge graph, then return
        optimisation actions. **Actual deletion is delegated to the
        TaskPruningPolicy; this method only supplies candidate information.**

        SGK-2026-0287 Step 6-3: StrategyOptimizer is now a candidate
        provider only. Direct ``remove_tasks_for_assets()`` calls have
        been removed.

        Args:
            task_queue: The task queue (read-only for analysis).
            knowledge_graph: Knowledge graph for inference.
            current_step: Current execution step.

        Returns:
            Action summary dict with keys:
            ``high_value_assets``, ``low_value_asset_candidates``,
            ``boosted``.
            The ``low_value_asset_candidates`` list is consumed by
            ``TaskPruningPolicy`` for final prune decisions.
        """
        self.last_review_step = current_step
        logger.info("Starting strategy review at step %d (Mode: %s)", current_step, self.mode)

        high_value_assets = self._identify_high_value_assets(knowledge_graph, task_queue)
        low_value_asset_candidates = self._identify_low_value_assets(knowledge_graph, task_queue)

        # Boost (kept as-is; boosting is not pruning)
        boosted_count = 0
        if high_value_assets:
            boosted_count = task_queue.boost_priority_for_assets(high_value_assets, 500)

        result = {
            "high_value_assets": high_value_assets,
            "low_value_asset_candidates": low_value_asset_candidates,
            "boosted": boosted_count,
        }

        if low_value_asset_candidates or boosted_count > 0:
            logger.info(
                "Strategy reviewed: low_value_candidates=%d, boosted=%d",
                len(low_value_asset_candidates), boosted_count,
            )

        return result

    def _identify_high_value_assets(self, kg: Any, queue: DynamicTaskQueue) -> List[str]:
        """高ROI資産（重点ターゲット）を特定する"""
        high_value = set()
        
        # 1. 知識グラフ(KG)からの推論
        if kg:
            # キュー内のユニークなドメイン/ターゲットを抽出
            domains = set()
            for task in queue:
                target = task.params.get("target", "") if hasattr(task, 'params') else ""
                if target:
                    # 簡易的なドメイン抽出
                    d = target.split("//")[-1].split("/")[0].split(":")[0]
                    if d: domains.add(d)
            
            for domain in domains:
                try:
                    surface = kg.get_attack_surface(domain)
                    # 既に脆弱性が発見されている資産は最優先
                    if surface.get("finding_count", 0) > 0:
                        high_value.add(domain)
                        logger.debug(f"[Strategy] High value: {domain} (existing findings)")
                    
                    # 特定の攻撃しやすい技術スタックがある場合も優先
                    techs = surface.get("technologies", [])
                    target_techs = {"Spring Boot", "Laravel", "WordPress", "PHP", "Git"}
                    if any(t in target_techs for t in techs):
                        high_value.add(domain)
                        logger.debug(f"[Strategy] High value: {domain} (vulnerable tech: {techs})")
                except Exception as e:
                    logger.debug(f"KG lookup failed for {domain}: {e}")

        # 2. URLキーワード (admin, api, login, auth, v1, config)
        keywords = {"admin", "api", "login", "auth", "v1", "v2", "config", "debug", "setting", "user", "passwd", "shadow", ".env"}
        
        # CTFモード特有
        if self.mode == "CTF":
            keywords.update({"flag", "goal", "secret", "key", "root", "entrypoint"})

        for task in queue:
            target = task.params.get("target", "") if hasattr(task, 'params') else ""
            if not target: continue
            
            target_lower = target.lower()
            
            # キーワードマッチ
            if any(kw in target_lower for kw in keywords):
                high_value.add(target)
                continue
            
            # ポート番号（特権ポートや非標準ポートの警戒）
            if any(p in target for p in [":8080", ":8443", ":9200", ":3000"]):
                high_value.add(target)
                
        # TODO: 既にクリティカルな脆弱性が発見されている資産も高ROIとする
        
        return list(high_value)

    def _identify_low_value_assets(self, kg: Any, queue: DynamicTaskQueue) -> List[str]:
        """低ROI資産（無視・間引き対象）を特定する"""
        low_value = set()
        seen_paths: Set[str] = set()
        
        # ルール1: 静的ファイル拡張子 (画像, フォント, 動画など)
        static_exts = {
            ".jpg", ".jpeg", ".png", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".svg",
            ".mp4", ".webp", ".pdf", ".zip", ".gz", ".tar"
        }
        
        # ルール2: 除外対象の外部リソース / 共通パス
        exclude_patterns = {
            "/node_modules/", "/static/javascript/", "/assets/images/",
            "jquery", "bootstrap", "font-awesome", "google-analytics"
        }

        for task in queue:
            if self._is_prune_protected_task(task):
                continue

            target = task.params.get("target", "") if hasattr(task, 'params') else ""
            if not target: continue
            
            target_lower = target.lower()
            
            # 1. 拡張子チェック
            if any(target_lower.endswith(ext) for ext in static_exts):
                low_value.add(target)
                continue
                
            # 2. パターンチェック (外部JSライブラリ等)
            if any(pat in target_lower for pat in exclude_patterns):
                low_value.add(target)
                continue
            
            # 3. 重複パスの間引き (クエリパラメータ違いを1つに集約)
            # URL のクエスチョンマーク以前を抽出
            base_path = target_lower.split("?")[0]
            if base_path in seen_paths:
                # すでに基本パスが処理対象に入っているなら、バリエーションは間引く
                # (SQLi等のパラメータ攻撃エージェントでない限り、重複は無駄)
                if not any(tag in task.tags for tag in ["injection", "auth", "logic"]):
                    low_value.add(target)
                    continue
            
            seen_paths.add(base_path)

        return list(low_value)

    def _is_prune_protected_task(self, task: Any) -> bool:
        """
        間引き対象から除外すべきタスクを判定。
        シナリオカバレッジの中核タスクは low-value 判定しない。
        """
        return task_pruning_policy_shared.is_coverage_critical_task(task)
