#!/usr/bin/env python3
import asyncio
import logging
import sys
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from unittest.mock import patch, AsyncMock

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parents[2]))

from src.core.agents.swarm.logic.manager import LogicManagerAgent
from src.core.agents.swarm.base import Task

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("e2e_idor")

class MockTargetServer(BaseHTTPRequestHandler):
    def do_GET(self):
        # Numeric ID manipulation target
        if self.path.startswith("/api/orders/"):
            # IDOR vulnerable endpoint
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(f'{{"order_id": "{self.path.split("/")[-1]}", "amount": 100}}'.encode())
        
        # UUID manipulation target
        elif self.path.startswith("/api/documents/"):
            # UUID IDOR endpoint
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(f'{{"doc_id": "{self.path.split("/")[-1]}", "secret": "data"}}'.encode())
            
        else:
            self.send_response(404)
            self.end_headers()

def run_server():
    server = HTTPServer(('127.0.0.1', 8890), MockTargetServer)
    server.serve_forever()

async def test_logic_manager_idor():
    logger.info("="*60)
    logger.info("E2E Validation: LogicManager -> IdorHunterSpecialist")
    logger.info("="*60)
    
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    await asyncio.sleep(1) # wait for server to start
    
    task_numeric = Task(
        id="test_idor_numeric",
        name="IDOR Numeric Check",
        target="http://127.0.0.1:8890/api/orders/100",
        params={"method": "GET", "use_proxy": False},
        tags=["idor"]
    )

    task_uuid = Task(
        id="test_idor_uuid",
        name="IDOR UUID Check",
        target="http://127.0.0.1:8890/api/documents/550e8400-e29b-41d4-a716-446655440000",
        params={"method": "GET", "use_proxy": False},
        tags=["idor"]
    )
    
    manager = LogicManagerAgent(config={"model": "dummy-model"})

    async def mock_agenerate_numeric(history, **kwargs):
        last_msg = history[-1]
        if last_msg["role"] == "user" and "Observation:" in last_msg["content"]:
            return type("MockResponse", (), {"choices": [type("Choice", (), {"message": type("Message", (), {"content": "Final Answer: IDOR testing completed."})})]})
        return type("MockResponse", (), {"choices": [type("Choice", (), {"message": type("Message", (), {"content": "Action: run_idor_check(url='http://127.0.0.1:8890/api/orders/100', method='GET', params={'use_proxy': False})"})})]})

    async def mock_agenerate_uuid(history, **kwargs):
        last_msg = history[-1]
        if last_msg["role"] == "user" and "Observation:" in last_msg["content"]:
            return type("MockResponse", (), {"choices": [type("Choice", (), {"message": type("Message", (), {"content": "Final Answer: UUID testing completed."})})]})
        return type("MockResponse", (), {"choices": [type("Choice", (), {"message": type("Message", (), {"content": "Action: run_idor_check(url='http://127.0.0.1:8890/api/documents/550e8400-e29b-41d4-a716-446655440000', method='GET', params={'use_proxy': False})"})})]})

    with patch("src.core.models.llm.LLMClient.agenerate") as mock_llm:
        # Test Numeric
        mock_llm.side_effect = mock_agenerate_numeric
        logger.info("Running LogicManager for Numeric IDOR...")
        result_num = await manager.dispatch(task_numeric)
        
        # Test UUID
        mock_llm.side_effect = mock_agenerate_uuid
        logger.info("Running LogicManager for UUID IDOR...")
        result_uuid = await manager.dispatch(task_uuid)

    logger.info("="*60)
    logger.info("RESULTS")
    
    success = True
    
    # Check numeric findings
    numeric_findings = [f for f in result_num.findings if "NUMERIC" in f.title]
    logger.info(f"Numeric IDOR findings: {len(numeric_findings)}")
    if len(numeric_findings) < 2:
        logger.error("Failed to find expected Numeric IDORs")
        success = False
        
    # Check UUID findings
    uuid_findings = [f for f in result_uuid.findings if "UUID" in f.title]
    logger.info(f"UUID IDOR findings: {len(uuid_findings)}")
    if len(uuid_findings) < 2:
        logger.error("Failed to find expected UUID IDORs")
        success = False

    if success:
        logger.info("✅ E2E IDOR Validation Passed!")
    else:
        logger.error("❌ E2E IDOR Validation Failed!")
        
    assert success

if __name__ == "__main__":
    asyncio.run(test_logic_manager_idor())
