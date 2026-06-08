from abc import abstractmethod
import subprocess
import logging
from typing import List, Optional, Any, Dict

from src.core.domain.model.task import Task, TaskResult
from src.core.swarm.worker.base import BaseWorker

logger = logging.getLogger(__name__)

class ProceduralWorker(BaseWorker):
    """
    手続き型 Worker
    """
    
    def execute(self, task: Task) -> TaskResult:
        try:
            return self._execute_procedural(task)
        except Exception as e:
            logger.error(f"Procedural execution failed: {e}")
            return TaskResult(success=False, error=str(e))

    @abstractmethod
    def _execute_procedural(self, task: Task) -> TaskResult:
        pass

    def run_command(self, cmd: List[str], timeout: int = 60, cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> str:
        logger.debug(f"Executing command: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=env, check=True
            )
            from src.core.engine.flag_watcher import FlagWatcher
            FlagWatcher.get_instance().check(result.stdout, source=f"CMD:{' '.join(cmd)}")
            return result.stdout
        except subprocess.CalledProcessError as e:
            error_msg = f"Command failed with code {e.returncode}: {e.stderr}"
            logger.warning(error_msg)
            raise RuntimeError(error_msg) from e
        except subprocess.TimeoutExpired as e:
            logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            raise
