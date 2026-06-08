"""
TakeoverSpecialist: Subdomain Takeover Vulnerability Scanner
"""

import logging
import re
import os
import tempfile
from typing import List, Dict, Any, Optional
from pathlib import Path

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.tools.custom.subjack import SubjackTool

logger = logging.getLogger(__name__)

class TakeoverSpecialist(Specialist):
    """
    サブドメイン乗っ取り (Subdomain Takeover) 可能性を検証する
    """
    name = "TakeoverSpecialist"
    description = "Checks for subdomain takeover vulnerabilities using subjack"
    timeout_seconds = 600
    is_aggressive = False
    
    async def execute(self, task: Task) -> List[Finding]:
        findings = []
        target = task.target
        
        logger.info("[%s] Checking subdomain takeover for target: %s", self.name, target)
        
        subs_to_check = []
        
        # 1. 共有ワークスペースから dead_subs.txt などを読み込む (存在する場合)
        if self.workspace:
            workspace_dir = self.workspace.root
            dead_subs_file = workspace_dir / "recon" / "dead_subs.txt"
            if dead_subs_file.exists():
                try:
                    with open(dead_subs_file, "r") as f:
                        for line in f:
                            sub = line.strip()
                            if sub:
                                subs_to_check.append(sub)
                except Exception as e:
                    logger.error("[%s] Failed to read dead_subs.txt: %s", self.name, e)

        # 2. タスクのターゲット自体も追加 (プロトコルを除外)
        if target:
            clean_target = re.sub(r"^https?://", "", target).split("/")[0]
            if clean_target not in subs_to_check:
                subs_to_check.append(clean_target)
            
        if not subs_to_check:
            logger.info("[%s] No subdomains to check for takeover.", self.name)
            return findings

        # 重複削除
        subs_to_check = list(set(subs_to_check))

        # 3. Subjack に渡すための一時ファイル作成
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix="takeover_subs_", suffix=".txt", text=True)
            with os.fdopen(fd, 'w') as f:
                f.write("\n".join(subs_to_check) + "\n")
                
            # 4. ツール実行
            import shutil
            if not shutil.which("subjack"):
                logger.warning("[%s] subjack binary not found. Skipping takeover scan.", self.name)
                return findings

            subjack_tool = SubjackTool()
            logger.debug("[%s] Running subjack on %d domains", self.name, len(subs_to_check))
            
            # 実行 (SubjackTool の run は同期想定)
            result_output = subjack_tool.run(subdomain_file=tmp_path)
            
            # 5. 結果のパース
            # Subjack の標準出力例: "[Service] subdomain.example.com"
            for line in result_output.splitlines():
                line = line.strip()
                if not line or "Error" in line:
                    if "Error" in line:
                        logger.error("[%s] Subjack error: %s", self.name, line)
                    continue
                    
                match = re.search(r"\[([\w\s]+)\]\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", line)
                if match:
                    service = match.group(1).strip()
                    domain = match.group(2).strip()
                    
                    finding = Finding(
                        title=f"Subdomain Takeover: {domain} ({service})",
                        severity=Severity.HIGH,
                        vuln_type=VulnType.MISCONFIGURATION,
                        target_url=f"http://{domain}",
                        description=f"Subdomain `{domain}` appears to be vulnerable to takeover via `{service}`.",
                        evidence=Evidence(request_url=domain, request_method="GET", response_body=line),
                        source_agent=self.name,
                        confidence=0.8,
                        tags=["takeover", "subdomain_takeover", "cloud_misconfig"]
                    )
                    findings.append(finding)
                    
        except Exception as e:
            logger.error("[%s] Takeover check failed: %s", self.name, e)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)

        return findings
