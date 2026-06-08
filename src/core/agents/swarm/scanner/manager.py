import logging
import asyncio
import json
from typing import List, Dict, Any, Optional

from src.core.agents.swarm.base import SwarmManager, Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.adapters.external.base_external_adapter import ToolInput
from src.core.adapters.external.nmap_adapter import NmapAdapter
from src.core.adapters.external.nuclei_adapter import NucleiAdapter
from src.core.adapters.external.external_tool_executor import get_global_executor
from src.tools.scanners.ssl_scanner import SSLScanner
from src.core.agents.swarm.discovery.takeover import TakeoverSpecialist
from src.core.agents.swarm.scanner.webcache import WebCacheDeceptionSpecialist

logger = logging.getLogger(__name__)

class PortScanSpecialist(Specialist):
    name = "PortScanSpecialist"
    description = "Service behavior analysis via Port Scan"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._executor = get_global_executor()
        self._adapter = NmapAdapter()
        
    async def execute(self, task: Task) -> List[Finding]:
        target_host = task.target
        # target might be URL, need host
        if "://" in target_host:
            target_host = target_host.split("://")[1].split("/")[0].split(":")[0]
            
        logger.info(f"[{self.name}] Scanning ports for {target_host}")
        
        result = await self._executor.execute(
            self._adapter,
            ToolInput(
                target=target_host,
                options={
                    "ports": "1-1000",
                    "scan_type": "connect",
                    "service_detection": True,
                },
            ),
        )
        status_value = str(getattr(result.status, "value", result.status)).lower()
        ports = result.data if status_value == "success" and result.data else []
        
        findings = []
        if ports:
            # Aggregate finding
            open_ports = [f"{p['port']}/{p['service']}" for p in ports]
            findings.append(Finding(
                vuln_type=VulnType.OTHER, # Maybe SERVICE_DISCOVERY?
                severity=Severity.INFO,
                title=f"Open Ports on {target_host}",
                description=f"Found {len(open_ports)} open ports.",
                evidence=Evidence(
                    request_url=target_host,
                    response_body="\n".join(open_ports)
                ),
                target_url=target_host,
                source_agent=self.name,
                tags=["port_scan", "service_discovery"]
            ))
        return findings

class VulnScanSpecialist(Specialist):
    name = "VulnScanSpecialist"
    description = "CVE Scanning via Nuclei"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._executor = get_global_executor()
        self._adapter = NucleiAdapter()
        
    async def execute(self, task: Task) -> List[Finding]:
        findings = []
        result = await self._executor.execute(
            self._adapter,
            ToolInput(
                target=task.target,
                options={"tags": "cve,auth,misconfig", "severity": "critical,high,medium"},
            ),
        )
        status_value = str(getattr(result.status, "value", result.status)).lower()
        nuclei_res = result.data if status_value == "success" and result.data else []
        
        for res in nuclei_res:
            sev_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            severity = sev_map.get(res.get("severity", "info").lower(), Severity.INFO)
            
            findings.append(Finding(
                vuln_type=VulnType.OTHER, # We should map template ID to vuln type
                severity=severity,
                title=f"Nuclei: {res['name']}",
                description=res.get("description", "No description"),
                evidence=Evidence(
                    request_url=task.target,
                    response_body=json.dumps(res, ensure_ascii=False) if isinstance(res, dict) else str(res)
                ),
                target_url=task.target,
                source_agent=self.name,
                tags=["nuclei", res.get("template_id")]
            ))
            
        return findings

class SSLScanSpecialist(Specialist):
    name = "SSLScanSpecialist"
    description = "SSL/TLS Configuration Analysis"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.scanner = SSLScanner()
        
    async def execute(self, task: Task) -> List[Finding]:
        target_host = task.target
        target_port = 443
        
        if "://" in target_host:
            parts = target_host.split("://")[1].split("/")[0].split(":")
            target_host = parts[0]
            if len(parts) > 1:
                target_port = int(parts[1])
                
        logger.info(f"[{self.name}] Checking SSL for {target_host}:{target_port}")
        
        res = await self.scanner.scan(target_host, target_port)
        findings = []
        
        if not res["is_valid"] or res["issues"]:
            findings.append(Finding(
                vuln_type=VulnType.OTHER, # SSL_ISSUE
                severity=Severity.MEDIUM if "Expired" in str(res["issues"]) else Severity.LOW,
                title=f"SSL Issues on {target_host}",
                description="\n".join(res["issues"]),
                evidence=Evidence(
                    request_url=f"https://{target_host}:{target_port}",
                    response_body=str(res)
                ),
                target_url=task.target,
                source_agent=self.name,
                tags=["ssl", "tls"]
            ))
            
        return findings





class ScannerSwarm(SwarmManager):
    """Scanner Swarm: Integrates external security scanners
    
    Phase E-2: AIツール統合基盤との接続完了
    - AIToolBridge経由でNuclei/DalFoxをAIに公開
    - 旧Specialistも維持（後方互換・段階的移行）
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.specialists = [
            PortScanSpecialist(config),
            VulnScanSpecialist(config),
            SSLScanSpecialist(config),
            TakeoverSpecialist(config),
            WebCacheDeceptionSpecialist(config)
        ]
        
        # Phase E-2: AI Tool Bridge統合
        # 新外部ツール統合基盤のツールをAIに登録
        try:
            # SwarmManagerはregister_toolメソッドを持たないため、
            # 使用可能ツールリストとして保持
            self._external_tools = self._register_external_tools()
            logger.info(f"[ScannerSwarm] External tools registered: {list(self._external_tools.keys())}")
        except Exception as e:
            logger.warning(f"[ScannerSwarm] Failed to register external tools: {e}")
    
    def _register_external_tools(self) -> Dict[str, Any]:
        """新外部ツール統合基盤のツールを登録"""
        from src.core.adapters.external.ai_tool_bridge import (
            create_nuclei_bridge,
            create_dalfox_bridge,
            create_ffuf_bridge,
            create_nmap_bridge,
            create_arjun_bridge,
            create_gau_bridge,
        )
        
        tools = {}

        bridge_factories = (
            create_nuclei_bridge,
            create_dalfox_bridge,
            create_ffuf_bridge,
            create_nmap_bridge,
            create_arjun_bridge,
            create_gau_bridge,
        )

        for factory in bridge_factories:
            try:
                bridge = factory()
                tools[bridge.name] = {
                    "func": bridge.run,
                    "description": bridge.description,
                    "schema": bridge.to_schema(),
                }
            except Exception as e:
                logger.warning(f"[ScannerSwarm] Failed to create bridge from {factory.__name__}: {e}")
        
        return tools
    
    def get_external_tools(self) -> Dict[str, Any]:
        """AIツールとして使用可能な外部ツール一覧を取得"""
        return getattr(self, '_external_tools', {})

    def get_specialists(self, tags: List[str]) -> List[Specialist]:
        selected = []
        tags_set = set(tags)
        
        if "ssl" in tags_set or "tls" in tags_set or "certificate" in tags_set:
            selected.append(self.specialists[2]) # SSL
            
        if "cve" in tags or "vuln" in tags or "scanner" in tags:
            selected.append(self.specialists[1]) # Nuclei
            
        if "port_open" in tags or "service" in tags or "scanner" in tags:
            selected.append(self.specialists[0]) # Nmap
            
        if "takeover" in tags or "subdomain" in tags or "scanner" in tags:
            selected.append(self.specialists[3]) # Takeover
            
        if "webcache" in tags or "wcd" in tags or "scanner" in tags:
            selected.append(self.specialists[4]) # WebCacheDeception
            
        if not selected or "scanner" in tags:
            return self.specialists
            
        return selected
