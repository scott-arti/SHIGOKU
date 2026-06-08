import asyncio
import logging
from typing import List, Any, Dict, Optional
from src.core.recon.factory import ReconRecipeFactory
from src.core.domain.model.target import TargetAsset
from src.core.swarm.worker.factory import get_worker_factory
from src.core.engine.task_queue import TaskContext
from src.core.domain.model.task import Task

logger = logging.getLogger(__name__)

class ReconOrchestrator:
    """
    パイプライン全体の指揮者
    TargetAssetを受け取り、適切なRecipeを選択して実行する
    """
    def __init__(self, knowledge_graph: Any, config: Any, network_client: Optional[Any] = None, llm_client: Optional[Any] = None):
        self.kg = knowledge_graph
        self.config = config
        self.network_client = network_client
        self.llm_client = llm_client
        self.background_tasks: List[asyncio.Task] = []
        self._results_cache: Dict[str, Any] = {}

    async def run_pipeline(self, target_assets: List[TargetAsset]) -> None:
        """
        メイン処理フロー: Fast Phase -> Deep Phase (Async)
        """
        global_mode = getattr(self.config, "environment", "BUG_BOUNTY")
        if hasattr(self.config, "ctf_target") and self.config.ctf_target:
            global_mode = "CTF"

        logger.info(f"[*] Starting Recon Pipeline for {len(target_assets)} assets in {global_mode} mode")

        for asset in target_assets:
            # 1. レシピの選択
            mode = ReconRecipeFactory.determine_mode(asset, global_mode)
            recipe = ReconRecipeFactory.create(mode, asset, self)
            
            logger.info("[*] Applying recipe %s for %s", mode.name, asset.raw_input)

            # 2. Fast Phase (同期実行) - MC起動前に完了させる
            try:
                await recipe.execute_fast_phase()
            except Exception as e:
                logger.error(f"Error in Fast Phase for {asset.raw_input}: {e}", exc_info=True)

            # 3. Deep Phase (非同期実行) - バックグラウンドでMCと並走
            deep_task = asyncio.create_task(self._run_deep_phase_safe(recipe))
            self.background_tasks.append(deep_task)

    async def _run_deep_phase_safe(self, recipe: Any) -> None:
        """Deep Phase を安全に実行し、エラーをキャッチする"""
        try:
            await recipe.execute_deep_phase()
        except Exception as e:
            logger.error(f"Error in Deep Phase for {recipe.asset.raw_input}: {e}", exc_info=True)

    async def run_tool(self, tool_name: str, target: Any) -> Any:
        """
        ProceduralWorkerを呼び出し、結果をKnowledgeGraphに格納するラッパー
        """
        logger.info(f"[*] Running tool: {tool_name} on {target}")
        
        # 1. Workerの取得
        # NOTE: OrchestratorはMC起動前なので、簡易的なTaskContextを作成
        context = TaskContext()
        factory = get_worker_factory(context, self.llm_client, self.network_client)
        
        # tool_name を worker_type に変換 (マッピングが必要)
        worker_type = self._map_tool_to_worker(tool_name)
        worker = factory.create_worker(worker_type)
        
        if not worker:
            logger.error(f"Worker for tool {tool_name} (mapped to {worker_type}) not found")
            return None

        # 2. 実行
        try:
            # ProceduralWorker.execute は sync
            # target がリストの場合は各要素を処理するか、Worker側の実装に任せる
            import uuid
            task = Task(
                id=f"task_{uuid.uuid4().hex[:8]}",
                name=f"tool_{tool_name}",
                target=str(target),
                params={"target": target}
            )
            result = worker.execute(task)

            # TaskResult オブジェクトを dict に変換
            if hasattr(result, 'data'):
                result = result.data

            # 3. 結果のキャッシュ (後続のツールやDeep Phaseで利用)
            self._results_cache[tool_name] = result

            # 4. KnowledgeGraph への保存
            self._save_results_to_kg(tool_name, target, result)

            return result
        except Exception as e:
            logger.error(f"Error running tool {tool_name}: {e}", exc_info=True)
            return None

    def get_results(self, tool_name: str) -> Any:
        """キャッシュされたツール実行結果を取得"""
        return self._results_cache.get(tool_name)

    def _map_tool_to_worker(self, tool_name: str) -> str:
        """ツール名からWorker名へのマッピング"""
        mapping = {
            "subfinder": "subdomain_enum",
            "httpx": "live_check",
            "naabu_fast": "port_scan",
            "naabu_full": "port_scan",
            "katana_std": "discovery",
            "katana_deep": "discovery",
            "gau": "historical_recon",
            "visual_recon": "visual_recon",
            "static_analysis": "static_analysis",
            "deadsub_check": "discovery"
        }
        return mapping.get(tool_name, tool_name)

    def _save_results_to_kg(self, tool_name: str, target: Any, result: Any) -> None:
        """
        結果を正規化してKnowledgeGraphに保存する
        """
        logger.debug(f"Saving {tool_name} results for {target} to KnowledgeGraph")
        if self.kg:
            try:
                self.kg.store_recon_result(tool_name, str(target), result)
            except Exception as e:
                logger.error(f"Error saving {tool_name} results to KG: {e}")
