import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from types import SimpleNamespace
from src.core.agents.swarm.scanner.manager import ScannerSwarm, Task
from src.core.models.finding import Severity

class TestScannerSwarm:
    @pytest.mark.asyncio
    async def test_port_scan_specialist(self):
        swarm = ScannerSwarm()
        task = Task(id="1", name="scan", target="example.com", tags=["port_open"])
        
        # Direct specialist execution or swarm dispatch
        specialists = swarm.get_specialists(task.tags)
        assert len(specialists) == 1
        assert specialists[0].name == "PortScanSpecialist"
        specialists[0]._executor = MagicMock()
        specialists[0]._executor.execute = AsyncMock(return_value=SimpleNamespace(
            status=SimpleNamespace(value="success"),
            data=[{"port": 80, "service": "http", "state": "open"}],
        ))
        
        findings = await specialists[0].execute(task)
        assert len(findings) == 1
        assert "80/http" in findings[0].evidence.response_body
        assert findings[0].source_agent == "PortScanSpecialist"

    @pytest.mark.asyncio
    async def test_vuln_scan_specialist(self):
        swarm = ScannerSwarm()
        task = Task(id="2", name="vuln", target="example.com", tags=["cve"])
        
        specialists = swarm.get_specialists(task.tags)
        assert len(specialists) == 1
        assert specialists[0].name == "VulnScanSpecialist"
        specialists[0]._executor = MagicMock()
        specialists[0]._executor.execute = AsyncMock(return_value=SimpleNamespace(
            status=SimpleNamespace(value="success"),
            data=[
                {
                    "template-id": "cve-2023-1234",
                    "name": "Test CVE",
                    "severity": "critical",
                    "description": "Test Desc"
                }
            ],
        ))
        
        findings = await specialists[0].execute(task)
        assert len(findings) == 1
        assert "Test CVE" in findings[0].title
        assert findings[0].severity == Severity.CRITICAL
            
    @pytest.mark.asyncio
    async def test_ssl_scan_specialist(self):
         with patch("src.core.agents.swarm.scanner.manager.SSLScanner") as MockSSL:
            ss = MockSSL.return_value
            ss.scan = AsyncMock(return_value={
                "is_valid": False,
                "issues": ["Certificate expired"],
                "days_left": -10
            })
            
            swarm = ScannerSwarm()
            task = Task(id="3", name="ssl", target="example.com", tags=["ssl"])
            
            specialists = swarm.get_specialists(task.tags)
            assert len(specialists) == 1
            assert specialists[0].name == "SSLScanSpecialist"
            
            findings = await specialists[0].execute(task)
            assert len(findings) == 1
            assert "SSL Issues" in findings[0].title
            assert "Certificate expired" in findings[0].description
