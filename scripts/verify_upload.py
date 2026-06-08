
import asyncio
import logging
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent))

from src.core.agents.swarm.logic.manager import LogicSwarm
from src.core.agents.swarm.base import Task

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def main():
    target_url = "http://localhost:4280/vulnerabilities/upload/"
    
    # Check if target is reachable
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=2) as resp:
                logger.info(f"Target is reachable: {resp.status}")
    except Exception as e:
        logger.warning(f"Target {target_url} is not reachable: {e}")
        logger.warning("Continuing anyway (Agent handles connection errors)")

    # Initialize LogicSwarm
    swarm = LogicSwarm(config={"aggressive": True})
    
    # Create Task
    task = Task(
        id="test-upload-task",
        name="File Upload Verification",
        action="scan",
        target=target_url,
        params={
            "method": "POST",
            "param_name": "uploaded",
            "headers": {
                "Cookie": "security=low; PHPSESSID=test" # Dummy auth
            }
        },
        tags=["upload"] # Important for routing
    )
    
    logger.info("Starting Scan...")
    result = await swarm.dispatch(task)
    findings = result.findings
    
    logger.info(f"Scan Completed. Found {len(findings)} issues.")
    for f in findings:
        logger.info(f"[{f.severity}] {f.title}: {f.description}")
        logger.info(f"Evidence: {f.evidence.response_body[:100]}...")

if __name__ == "__main__":
    asyncio.run(main())
