#!/usr/bin/env python3
"""
E2E Full Flow Integration Test

Tests the complete pipeline:
1. Recon Phase: Simulate Katana output (endpoints, params, technologies)
2. Tagging & Ingestion: Ingest data into Neo4j Knowledge Graph
3. MC Planning: MasterConductor retrieves context from Neo4j and plans tasks
4. Swarm Execution: Simulate Swarm running and producing Nuclei findings
5. Finding Ingestion: Store scan results back to Neo4j
6. Report Generation: ReportRefinerAgent retrieves data from Neo4j and generates report
"""

import os
import sys
import json
import logging
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.knowledge.driver import get_db
from src.core.knowledge.schema import GraphSchema
from src.core.knowledge.ingestors.katana import KatanaIngestor
from src.core.knowledge.ingestors.nuclei import NucleiIngestor
from src.core.engine.master_conductor import MasterConductor
from src.core.agents.specialized.report_refiner_agent import ReportRefinerAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("E2E_TEST")

PROJECT_NAME = "e2e_test_project"


def cleanup_test_data():
    """Clean up previous test data from Neo4j"""
    db = get_db()
    if not db:
        logger.error("Failed to connect to Neo4j")
        return False
    
    with db.session() as session:
        session.run("MATCH (n {project: $project}) DETACH DELETE n", project=PROJECT_NAME)
        logger.info("Cleaned up previous test data for project: %s", PROJECT_NAME)
    return True


def phase1_recon_simulation() -> Path:
    """
    Phase 1: Simulate Recon output (Katana crawling results)
    Returns: Path to the generated Katana JSON file
    """
    logger.info("=" * 60)
    logger.info("PHASE 1: Recon Simulation (Katana Crawling)")
    logger.info("=" * 60)
    
    # Simulated Katana output - realistic structure
    katana_data = [
        {
            "endpoint": "https://target.example.com/api/v1/users?id=123&role=admin",
            "method": "GET",
            "technologies": ["Nginx/1.21", "Python/3.10", "Django/4.2"],
            "status_code": 200
        },
        {
            "endpoint": "https://target.example.com/api/v1/login",
            "method": "POST",
            "technologies": ["Nginx/1.21", "Python/3.10"],
            "status_code": 200
        },
        {
            "endpoint": "https://target.example.com/admin/dashboard?debug=true",
            "method": "GET",
            "technologies": ["Nginx/1.21", "React/18.2"],
            "status_code": 200
        },
        {
            "endpoint": "https://target.example.com/api/v1/upload?file=test.jpg",
            "method": "POST",
            "technologies": ["Nginx/1.21", "Python/3.10"],
            "status_code": 200
        },
        {
            "endpoint": "https://target.example.com/search?q=test&category=all",
            "method": "GET",
            "technologies": ["Nginx/1.21", "Elasticsearch/8.0"],
            "status_code": 200
        }
    ]
    
    # Write to temp file
    katana_file = Path(tempfile.gettempdir()) / "e2e_katana_output.json"
    with open(katana_file, "w", encoding="utf-8") as f:
        json.dump(katana_data, f, indent=2)
    
    logger.info("Generated Katana output with %d endpoints", len(katana_data))
    for entry in katana_data:
        logger.info("  - %s %s", entry["method"], entry["endpoint"])
    
    return katana_file


def phase2_ingestion_to_neo4j(katana_file: Path) -> bool:
    """
    Phase 2: Ingest Katana data into Neo4j Knowledge Graph
    """
    logger.info("=" * 60)
    logger.info("PHASE 2: Ingestion to Neo4j (Knowledge Graph Population)")
    logger.info("=" * 60)
    
    # Initialize schema
    GraphSchema.apply_constraints()
    logger.info("Applied graph schema (constraints and indexes)")
    
    # Ingest Katana data
    ingestor = KatanaIngestor()
    ingestor.ingest(katana_file, PROJECT_NAME)
    logger.info("Katana data ingested to Neo4j")
    
    # Verify ingestion
    db = get_db()
    with db.session() as session:
        # Count nodes
        result = session.run("""
            MATCH (e:Endpoint {project: $project})
            RETURN count(e) as endpoint_count
        """, project=PROJECT_NAME)
        endpoint_count = result.single()["endpoint_count"]
        
        result = session.run("""
            MATCH (p:Parameter {project: $project})
            RETURN count(p) as param_count
        """, project=PROJECT_NAME)
        param_count = result.single()["param_count"]
        
        result = session.run("""
            MATCH (e:Endpoint {project: $project})-[:BUILT_WITH]->(t:Technology)
            RETURN count(DISTINCT t) as tech_count
        """, project=PROJECT_NAME)
        tech_count = result.single()["tech_count"]
    
    logger.info("Neo4j Verification:")
    logger.info("  - Endpoints: %d", endpoint_count)
    logger.info("  - Parameters: %d", param_count)
    logger.info("  - Technologies: %d", tech_count)
    
    return endpoint_count > 0 and param_count > 0


async def phase3_mc_planning() -> dict:
    """
    Phase 3: MasterConductor retrieves context from Neo4j and plans tasks
    """
    logger.info("=" * 60)
    logger.info("PHASE 3: MasterConductor Context Retrieval & Planning")
    logger.info("=" * 60)
    
    # Create MC instance and mock project manager
    mc = MasterConductor()
    
    class MockPM:
        project_name = PROJECT_NAME
    mc.project_manager = MockPM()
    
    # Query context from Neo4j
    assets = mc._query_knowledge_graph("assets")
    tech_stack = mc._query_knowledge_graph("tech_stack")
    pending_params = mc._query_knowledge_graph("pending_params")
    
    logger.info("MC Context from Neo4j:")
    logger.info("  - Assets: %s", assets)
    logger.info("  - Tech Stack: %s", [t["technology"] for t in tech_stack])
    logger.info("  - Pending Params (untested): %s", 
                [(p["url"].split("?")[0], p["param"]) for p in pending_params])
    
    # Simulate task planning based on context
    planned_tasks = []
    
    # Django detected -> add Django-specific scans
    if any("Django" in t.get("technology", "") for t in tech_stack):
        planned_tasks.append({
            "name": "Django Debug Mode Check",
            "agent_type": "vuln_scanner",
            "priority": 80,
            "tags": ["django", "debug"]
        })
    
    # Parameters found -> add parameter fuzzing tasks
    for param in pending_params[:3]:  # Top 3
        planned_tasks.append({
            "name": f"Fuzz param '{param['param']}' on {param['url'].split('/')[-1].split('?')[0]}",
            "agent_type": "fuzzer",
            "priority": 70,
            "tags": ["sqli", "xss", param["param"]]
        })
    
    logger.info("MC Planned %d tasks based on context:", len(planned_tasks))
    for task in planned_tasks:
        logger.info("  - [%d] %s (%s)", task["priority"], task["name"], task["agent_type"])
    
    return {"tech_stack": tech_stack, "pending_params": pending_params, "tasks": planned_tasks}


def phase4_swarm_execution_simulation() -> Path:
    """
    Phase 4: Simulate Swarm execution producing Nuclei findings
    Returns: Path to the generated Nuclei JSON file
    """
    logger.info("=" * 60)
    logger.info("PHASE 4: Swarm Execution (Simulated Nuclei Scan)")
    logger.info("=" * 60)
    
    # Simulated Nuclei findings - realistic structure
    nuclei_findings = [
        {
            "template-id": "sqli-error-based",
            "info": {
                "name": "SQL Injection (Error Based) in User ID Parameter",
                "severity": "critical",
                "description": "The 'id' parameter is vulnerable to SQL injection attacks. Error-based injection confirmed."
            },
            "matched-at": "https://target.example.com/api/v1/users?id=123'",
            "curl-command": "curl -X GET 'https://target.example.com/api/v1/users?id=123%27' -H 'Cookie: session=abc123'",
            "request": "GET /api/v1/users?id=123' HTTP/1.1\nHost: target.example.com\nCookie: session=abc123",
            "response": "HTTP/1.1 500 Internal Server Error\n\nPG::SyntaxError: ERROR:  unterminated string literal",
            "extracted-results": ["PG::SyntaxError", "unterminated string literal"]
        },
        {
            "template-id": "xss-reflected",
            "info": {
                "name": "Reflected XSS in Search Query",
                "severity": "high",
                "description": "The search parameter reflects user input without proper sanitization."
            },
            "matched-at": "https://target.example.com/search?q=<script>alert(1)</script>",
            "curl-command": "curl -X GET 'https://target.example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E'",
            "request": "GET /search?q=<script>alert(1)</script> HTTP/1.1\nHost: target.example.com",
            "response": "HTTP/1.1 200 OK\n\n<html>...Results for: <script>alert(1)</script>...</html>",
            "extracted-results": ["<script>alert(1)</script>"]
        },
        {
            "template-id": "django-debug-mode",
            "info": {
                "name": "Django Debug Mode Enabled",
                "severity": "medium",
                "description": "Django DEBUG mode is enabled in production, exposing sensitive information."
            },
            "matched-at": "https://target.example.com/admin/dashboard?debug=true",
            "curl-command": "curl -X GET 'https://target.example.com/admin/dashboard?debug=true'",
            "request": "GET /admin/dashboard?debug=true HTTP/1.1\nHost: target.example.com",
            "response": "HTTP/1.1 200 OK\n\n<!DOCTYPE html>...<title>Page not found at /</title>...DATABASES...SECRET_KEY...",
            "extracted-results": ["SECRET_KEY", "DATABASES"]
        }
    ]
    
    # Write to temp file (JSON Lines format)
    nuclei_file = Path(tempfile.gettempdir()) / "e2e_nuclei_output.json"
    with open(nuclei_file, "w", encoding="utf-8") as f:
        for finding in nuclei_findings:
            f.write(json.dumps(finding) + "\n")
    
    logger.info("Swarm produced %d findings:", len(nuclei_findings))
    for finding in nuclei_findings:
        logger.info("  - [%s] %s", 
                    finding["info"]["severity"].upper(), 
                    finding["info"]["name"])
    
    return nuclei_file


def phase5_finding_ingestion(nuclei_file: Path) -> list:
    """
    Phase 5: Ingest Nuclei findings into Neo4j
    Returns: List of finding IDs
    """
    logger.info("=" * 60)
    logger.info("PHASE 5: Finding Ingestion to Neo4j")
    logger.info("=" * 60)
    
    ingestor = NucleiIngestor()
    ingestor.ingest(nuclei_file, PROJECT_NAME)
    logger.info("Nuclei findings ingested to Neo4j")
    
    # Retrieve finding IDs for report generation
    db = get_db()
    finding_ids = []
    with db.session() as session:
        result = session.run("""
            MATCH (f:Finding {project: $project})
            RETURN f.id as id, f.title as title, f.severity as severity
            ORDER BY 
                CASE f.severity 
                    WHEN 'critical' THEN 1 
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3 
                    ELSE 4 
                END
        """, project=PROJECT_NAME)
        
        for record in result:
            finding_ids.append({
                "id": record["id"],
                "title": record["title"],
                "severity": record["severity"]
            })
    
    logger.info("Neo4j now contains %d findings:", len(finding_ids))
    for f in finding_ids:
        logger.info("  - [%s] %s (ID: %s...)", f["severity"].upper(), f["title"], f["id"][:8])
    
    return finding_ids


async def phase6_report_generation(finding_ids: list) -> str:
    """
    Phase 6: ReportRefinerAgent generates report using Neo4j data
    """
    logger.info("=" * 60)
    logger.info("PHASE 6: Report Generation from Neo4j")
    logger.info("=" * 60)
    
    agent = ReportRefinerAgent()
    
    # Test retrieving evidence for the critical finding
    critical_finding = next((f for f in finding_ids if f["severity"] == "critical"), None)
    
    if not critical_finding:
        logger.warning("No critical finding found for report generation test")
        return ""
    
    logger.info("Retrieving evidence for: %s", critical_finding["title"])
    
    # Query finding details from Neo4j
    details = agent._query_finding_details(critical_finding["id"])
    
    logger.info("Evidence retrieved from Neo4j:")
    logger.info("  - Curl Command: %s", details.get("curl", "N/A")[:80] + "...")
    logger.info("  - Request: %s lines", len(details.get("request", "").split("\n")))
    logger.info("  - Response: %s chars", len(details.get("response", "")))
    logger.info("  - Extracted: %s", details.get("extracted", []))
    
    # Verify curl command is present (key for reproduction)
    if not details.get("curl"):
        logger.error("FAIL: Curl command not retrieved from Neo4j!")
        return ""
    
    logger.info("SUCCESS: All evidence correctly retrieved from Neo4j")
    
    # Generate a summary report (not calling LLM to avoid API costs in test)
    report = f"""
# Bug Bounty Report: {critical_finding['title']}

## Severity: {critical_finding['severity'].upper()}

## Technical Evidence (from Knowledge Graph)

### Curl Command for Reproduction
```bash
{details.get('curl', 'N/A')}
```

### HTTP Request
```http
{details.get('request', 'N/A')}
```

### HTTP Response (truncated)
```http
{details.get('response', 'N/A')[:500]}
```

### Extracted Data
{json.dumps(json.loads(details.get('extracted', '[]')), indent=2)}

---
*Report generated from Neo4j Knowledge Graph*
"""
    
    return report


async def run_e2e_test():
    """Run the complete E2E test"""
    logger.info("#" * 70)
    logger.info("# E2E FULL FLOW INTEGRATION TEST")
    logger.info("# Recon -> Neo4j -> MC -> Swarm -> Neo4j -> Report")
    logger.info("#" * 70)
    
    # Pre-check: Neo4j connection
    if not cleanup_test_data():
        logger.error("ABORT: Cannot connect to Neo4j. Is the container running?")
        return False
    
    try:
        # Phase 1: Recon simulation
        katana_file = phase1_recon_simulation()
        
        # Phase 2: Ingestion
        if not phase2_ingestion_to_neo4j(katana_file):
            logger.error("FAIL: Phase 2 - Ingestion failed")
            return False
        
        # Phase 3: MC Planning
        mc_context = await phase3_mc_planning()
        if not mc_context["tech_stack"]:
            logger.error("FAIL: Phase 3 - MC failed to retrieve tech stack")
            return False
        
        # Phase 4: Swarm execution
        nuclei_file = phase4_swarm_execution_simulation()
        
        # Phase 5: Finding ingestion
        finding_ids = phase5_finding_ingestion(nuclei_file)
        if not finding_ids:
            logger.error("FAIL: Phase 5 - No findings ingested")
            return False
        
        # Phase 6: Report generation
        report = await phase6_report_generation(finding_ids)
        if not report:
            logger.error("FAIL: Phase 6 - Report generation failed")
            return False
        
        # Save report to file
        report_file = Path(tempfile.gettempdir()) / "e2e_generated_report.md"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report)
        logger.info("Report saved to: %s", report_file)
        
        # Cleanup temp files
        katana_file.unlink(missing_ok=True)
        nuclei_file.unlink(missing_ok=True)
        
        logger.info("#" * 70)
        logger.info("# E2E TEST RESULT: SUCCESS")
        logger.info("#" * 70)
        logger.info("All phases completed successfully:")
        logger.info("  ✅ Phase 1: Recon Simulation")
        logger.info("  ✅ Phase 2: Neo4j Ingestion")
        logger.info("  ✅ Phase 3: MC Context Retrieval & Planning")
        logger.info("  ✅ Phase 4: Swarm Execution Simulation")
        logger.info("  ✅ Phase 5: Finding Ingestion")
        logger.info("  ✅ Phase 6: Report Generation from Neo4j")
        
        return True
        
    except Exception as e:
        logger.exception("E2E test failed with exception: %s", e)
        return False


if __name__ == "__main__":
    import asyncio
    success = asyncio.run(run_e2e_test())
    sys.exit(0 if success else 1)
