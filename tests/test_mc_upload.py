import asyncio
import logging
from unittest.mock import MagicMock, patch, AsyncMock
from src.core.engine.master_conductor import MasterConductor
from src.core.domain.model.task import Task
from src.core.agents.swarm.base import SwarmResult
from src.core.models.finding import Finding, Severity, VulnType

logging.basicConfig(level=logging.DEBUG)

def main():
    mc = MasterConductor(llm_client=MagicMock())
    task = Task(
        id="test_upload_1",
        name="Test Upload",
        agent_type="LogicSwarm",
        action="scan",
        params={"target": "http://localhost:4280/vulnerabilities/upload/", "tags": ["file_upload"]}
    )
    
    f = Finding(
        vuln_type=VulnType.FILE_UPLOAD,
        severity=Severity.HIGH,
        title="Test File Upload",
        description="test",
        target_url="http://locahlost",
        source_agent="logic"
    )
    
    mock_res = SwarmResult(
        findings=[f],
        status="success",
        execution_log=[],
        swarm_name="logic"
    )
    
    with patch('src.core.agents.swarm.base_manager.BaseManagerAgent.dispatch', new_callable=AsyncMock) as mock_execute:
        mock_execute.return_value = mock_res
        
        # We use execute_single_task to trace exactly what happens
        res = mc.execute_single_task(task)
        
    print(f"Task state: {task.state}")
    print(f"Task error: {task.error}")

if __name__ == "__main__":
    main()
