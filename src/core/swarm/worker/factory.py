import logging
from typing import Dict, Any, Type, Optional

from src.core.engine.task_queue import TaskContext
from src.core.swarm.worker.base import BaseWorker
from src.core.models.llm import LLMClient

from src.core.swarm.worker.recon_workers import (
    PortScanWorker, DiscoveryWorker, SubdomainEnumWorker, LiveCheckWorker,
    HistoricalReconWorker, VisualReconWorker, StaticAnalysisWorker
)

class WorkerFactory:
    """
    Workerの生成と管理
    
    agent_type または action に基づいて適切な Worker を生成する。
    """
    
    # マッピング: agent_type -> Worker Class
    WORKER_MAP: Dict[str, Type[BaseWorker]] = {
        "port_scan": PortScanWorker,
        "discovery": DiscoveryWorker,
        "subdomain_enum": SubdomainEnumWorker,
        "live_check": LiveCheckWorker,
        "historical_recon": HistoricalReconWorker,
        "visual_recon": VisualReconWorker,
        "static_analysis": StaticAnalysisWorker,
    }

    def __init__(self, context: TaskContext, llm_client: Optional[LLMClient] = None, network_client: Optional[Any] = None):
        self.context = context
        self.llm_client = llm_client
        self.network_client = network_client

    def _get_worker_class(self, agent_type: str) -> Optional[Type[BaseWorker]]:
        """文字列名または直接のクラスからクラスを取得"""
        worker_cls = self.WORKER_MAP.get(agent_type)
        if not worker_cls:
            logging.getLogger(__name__).debug(f"No worker class found for agent_type: {agent_type}")
            return None
        
        # すでにクラスである場合はそのまま返す
        if isinstance(worker_cls, type):
            return worker_cls
            
        # 文字列の場合はマッピングから取得
        if isinstance(worker_cls, str):
            local_map = {
                "PortScanWorker": PortScanWorker,
                "DiscoveryWorker": DiscoveryWorker,
                "SubdomainEnumWorker": SubdomainEnumWorker,
                "LiveCheckWorker": LiveCheckWorker,
                "HistoricalReconWorker": HistoricalReconWorker,
                "VisualReconWorker": VisualReconWorker,
                "StaticAnalysisWorker": StaticAnalysisWorker,
            }
            return local_map.get(worker_cls)
            
        return None

    def create_worker(self, agent_type: str) -> Optional[BaseWorker]:
        """
        Workerインスタンスを生成
        """
        worker_cls = self._get_worker_class(agent_type)
        if not worker_cls:
            return None
            
        # Debug: check if worker_cls is a class
        if not isinstance(worker_cls, type):
            logging.getLogger(__name__).error(f"worker_cls for {agent_type} is NOT a class: {type(worker_cls)} ({worker_cls})")
            return None

        # LLMWorker の場合は llm_client が必要
        from src.core.swarm.worker.llm_worker import LLMWorker
        try:
            is_llm = issubclass(worker_cls, LLMWorker)
        except TypeError:
            logging.getLogger(__name__).error(f"TypeError during issubclass check for {agent_type}: {worker_cls}")
            return None

        if is_llm:
            if not self.llm_client:
                from src.core.swarm.worker.llm_worker import logger as llm_logger
                llm_logger.error(f"LLMClient is required for {agent_type} (LLMWorker)")
                return None
            return worker_cls(self.context, self.llm_client)
            
        # 通常の Worker (Procedural 等)
        return worker_cls(self.context)

def get_worker_factory(context: TaskContext, llm_client: Optional[LLMClient] = None, network_client: Optional[Any] = None) -> WorkerFactory:
    """WorkerFactoryのシングルトン的な取得（必要に応じて）"""
    return WorkerFactory(context, llm_client, network_client)
