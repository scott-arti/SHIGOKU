from typing import List, Optional, Dict, Any
import logging
from src.core.domain.model.task import Task, TaskResult
from src.core.swarm.worker.procedural import ProceduralWorker

logger = logging.getLogger(__name__)

class PortScanWorker(ProceduralWorker):
    """Naabuを使用したポートスキャンWorker"""
    def _execute_procedural(self, task: Task) -> TaskResult:
        target = task.target
        from src.tools.custom.naabu import NaabuTool
        tool = NaabuTool()
        try:
            # NaabuTool.run expects 'host'
            result = tool.run(host=target)
            return TaskResult(success=True, data=result)
        except Exception as e:
            return TaskResult(success=False, error=str(e))

class DiscoveryWorker(ProceduralWorker):
    """Katanaを使用したコンテンツ発見Worker"""
    def _execute_procedural(self, task: Task) -> TaskResult:
        target = task.target
        from src.tools.custom.katana import KatanaTool
        tool = KatanaTool()
        try:
            # KatanaTool.run expects 'target'
            url = target if target.startswith("http") else f"http://{target}"
            result = tool.run(target=url)
            return TaskResult(success=True, data=result)
        except Exception as e:
            return TaskResult(success=False, error=str(e))

class SubdomainEnumWorker(ProceduralWorker):
    """Subfinderを使用したサブドメイン列挙Worker"""
    def _execute_procedural(self, task: Task) -> TaskResult:
        target = task.target
        from src.tools.custom.subfinder import SubfinderTool
        tool = SubfinderTool()
        try:
            result = tool.run(domain=target)
            return TaskResult(success=True, data=result)
        except Exception as e:
            return TaskResult(success=False, error=str(e))

class LiveCheckWorker(ProceduralWorker):
    """httpxを使用した生存確認Worker"""
    def _execute_procedural(self, task: Task) -> TaskResult:
        target = task.target
        from src.tools.custom.httpx import HttpxTool
        tool = HttpxTool()
        try:
            # HttpxTool.run expects 'target'
            result = tool.run(target=target)
            return TaskResult(success=True, data=result)
        except Exception as e:
            return TaskResult(success=False, error=str(e))

class HistoricalReconWorker(ProceduralWorker):
    """gauを使用した過去URL調査Worker"""
    def _execute_procedural(self, task: Task) -> TaskResult:
        target = task.target
        from src.tools.custom.gau import GAUTool
        tool = GAUTool()
        try:
            result = tool.run(domain=target)
            return TaskResult(success=True, data=result)
        except Exception as e:
            return TaskResult(success=False, error=str(e))

class VisualReconWorker(ProceduralWorker):
    """gowitnessなどを使用した外観調査Worker"""
    def _execute_procedural(self, task: Task) -> TaskResult:
        target = task.target
        from src.tools.custom.gowitness import GowitnessTool
        tool = GowitnessTool()
        try:
            result = tool.run(url=target)
            return TaskResult(success=True, data=result)
        except Exception as e:
            return TaskResult(success=False, error=str(e))

class StaticAnalysisWorker(ProceduralWorker):
    """JSファイルなどの静的解析Worker"""
    def _execute_procedural(self, task: Task) -> TaskResult:
        target = task.target
        # Placeholder for real static analysis logic
        return TaskResult(success=True, data={"message": f"Static analysis for {target} not fully implemented as separate worker yet."})
