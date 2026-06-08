import asyncio
import logging
import sys
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

# Add project root to sys.path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from src.core.agents.swarm.logic.idor import IdorHunterSpecialist
from src.core.agents.swarm.base import Task

# Mock API Server for testing IDOR
class MockAPIServer(BaseHTTPRequestHandler):
    def do_GET(self):
        # 1. Unauthenticated endpoint (Vulnerable)
        if self.path == "/api/user/profile":
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"user": "test", "data": "secret_info"}')
        
        # 2. IDOR vulnerable endpoint (/api/data/123)
        # We always return 200 regardless of ID (just for simulation)
        elif self.path.startswith("/api/data/"):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(f'{{"id": "{self.path.split("/")[-1]}", "content": "data"}}'.encode())

        # 3. UUID vulnerable endpoint (/api/docs/uuid)
        elif self.path.startswith("/api/docs/"):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(f'{{"doc_id": "{self.path.split("/")[-1]}", "content": "secret_doc"}}'.encode())
        
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        if self.path.startswith("/api/docs/"):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "deleted"}')
        else:
            self.send_response(404)
            self.end_headers()
            
    def do_POST(self):
        if self.path == "/api/profile/update":
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "updated"}')
        else:
            self.send_response(404)
            self.end_headers()

def run_server():
    server = HTTPServer(('127.0.0.1', 8888), MockAPIServer)
    server.serve_forever()

async def test_idor_specialist():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("test_idor")

    # Start mock server in thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    await asyncio.sleep(1) # Wait for server to start

    specialist = IdorHunterSpecialist()
    
    # Task 1: Unauthenticated access test
    task1 = Task(
        id="test_unauth",
        name="Test Unauth",
        target="http://127.0.0.1:8888/api/user/profile",
        params={
            "method": "GET", 
            "headers": {"Authorization": "Bearer valid_token"},
            "use_proxy": False # Local test integration
        },
        tags=["idor"]
    )
    
    logger.info("Running Unauthenticated Access Test...")
    findings = await specialist.execute(task1)
    
    for f in findings:
        logger.info(f"Finding Found: {f.title} ({f.severity.name})")
        logger.info(f"Evidence: {f.evidence}")

    # Task 2: ID Manipulation test
    task2 = Task(
        id="test_manipulation",
        name="Test Manipulation",
        target="http://127.0.0.1:8888/api/data/123",
        params={
            "method": "GET", 
            "headers": {"Authorization": "Bearer valid_token"},
            "use_proxy": False # Local test integration
        },
        tags=["idor"]
    )
    
    logger.info("Running Numeric ID Manipulation Test...")
    findings = await specialist.execute(task2)
    
    for f in findings:
        logger.info(f"Finding Found: {f.title} ({f.severity.name})")
        logger.info(f"Evidence: {f.evidence}")

    # Task 3: UUID Manipulation test
    task3 = Task(
        id="test_uuid_manipulation",
        name="Test UUID Manipulation",
        target="http://127.0.0.1:8888/api/docs/550e8400-e29b-41d4-a716-446655440000",
        params={
            "method": "GET", 
            "headers": {"Authorization": "Bearer valid_token"},
            "use_proxy": False
        },
        tags=["idor"]
    )
    
    logger.info("Running UUID Manipulation Test...")
    findings = await specialist.execute(task3)
    
    for f in findings:
        logger.info(f"Finding Found: {f.title} ({f.severity.name})")
        logger.info(f"Evidence: {f.evidence}")
        
    # Task 4: Safe mode test (Destructive operation)
    task4 = Task(
        id="test_safe_mode",
        name="Test Safe Mode for DELETE",
        target="http://127.0.0.1:8888/api/docs/550e8400-e29b-41d4-a716-446655440000",
        params={
            "method": "DELETE", 
            "headers": {"Authorization": "Bearer valid_token"},
            "use_proxy": False,
            "safe_mode": True
        },
        tags=["idor"]
    )
    
    logger.info("Running Safe Mode DELETE Test...")
    findings = await specialist.execute(task4)
    if not findings:
        logger.info("Safe mode correctly blocked ID manipulation test for DELETE.")
    else:
        logger.error("Safe mode FAILED, findings were returned for DELETE method.")
        
    # Task 5: Body ID manipulation
    task5 = Task(
        id="test_body_idor",
        name="Test Body IDOR",
        target="http://127.0.0.1:8888/api/profile/update",
        params={
            "method": "POST", 
            "headers": {"Authorization": "Bearer valid_token", "Content-Type": "application/json"},
            "body": '{"user_id": 999, "profile": {"theme": "dark"}}',
            "use_proxy": False,
            "safe_mode": False  # Bypass safe mode for this test
        },
        tags=["idor"]
    )
    
    logger.info("Running Body JSON Manipulation Test...")
    findings = await specialist.execute(task5)
    body_findings = [f for f in findings if "BODY" in f.title]
    for f in body_findings:
        logger.info(f"Finding Found: {f.title} ({f.severity.name})")
        logger.info(f"Evidence: {f.evidence}")

    # Task 6: Multi-Session BOLA test (Matrix Testing)
    task6 = Task(
        id="test_multi_session",
        name="Test Multi-Session BOLA",
        target="http://127.0.0.1:8888/api/user/profile",
        params={
            "method": "GET", 
            "headers": {"Authorization": "Bearer user_a_token"},
            "alternative_sessions": {
                "user_b": {"headers": {"Authorization": "Bearer user_b_token"}}
            },
            "use_proxy": False
        },
        tags=["idor"]
    )
    
    logger.info("Running Multi-Session Matrix BOLA Test...")
    findings = await specialist.execute(task6)
    matrix_findings = [f for f in findings if "BOLA" in f.title]
    for f in matrix_findings:
        logger.info(f"Finding Found: {f.title} ({f.severity.name})")
        logger.info(f"Evidence: {f.evidence}")

    logger.info("Verification finished.")

if __name__ == "__main__":
    asyncio.run(test_idor_specialist())
