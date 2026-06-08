import asyncio
import logging
import re
import shutil
import tempfile
import json
import os
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class LeakDetector:
    """
    Leak Detection Engine
    Integrates:
    1. GitLeaks (for code scanning)
    2. ContextRegexScanner (for comment/text scanning)
    """
    
    def __init__(self):
        self.gitleaks_path = shutil.which("gitleaks")
        self.is_gitleaks_available = self.gitleaks_path is not None
        if not self.is_gitleaks_available:
            logger.warning("GitLeaks not found. Code scanning will be skipped.")
            
        # Context Patterns for Comments
        # "password is ..." "key = ..." type of leaks
        self.context_patterns = [
            re.compile(r"(?:password|passwd|pwd|secret|key|token|credential)\s*[:=]\s*(\S+)", re.IGNORECASE),
            re.compile(r"(?:api[_-]?key|access[_-]?token)\s*[:=]\s*(\S+)", re.IGNORECASE),
            re.compile(r"https://hooks\.slack\.com/services/\S+", re.IGNORECASE),
            re.compile(r"ghp_[a-zA-Z0-9]{36}", re.IGNORECASE),
        ]

    async def scan_repo(self, repo_url: str) -> List[Dict[str, Any]]:
        """
        Run GitLeaks against a remote repository.
        Using 'gitleaks detect --source ...' (Need to clone first?)
        GitLeaks supports scanning local directories.
        """
        if not self.is_gitleaks_available:
            return []
            
        findings = []
        
        # Temporary Clone & Scan
        with tempfile.TemporaryDirectory() as temp_dir:
            # 1. Shallow Clone
            logger.info(f"Cloning {repo_url} for scanning...")
            # We don't want to use gitpython dep if possible, use subprocess
            # Mask clone url token if present? repo_url usually public or includes token
            
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", repo_url, temp_dir,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE
            )
            _, stderr = await proc.communicate()
            
            if proc.returncode != 0:
                logger.error(f"Failed to clone {repo_url}: {stderr.decode()}")
                return []
                
            # 2. Run GitLeaks
            report_file = os.path.join(temp_dir, "gitleaks_report.json")
            cmd = [
                self.gitleaks_path, "detect",
                "--source", temp_dir,
                "--report-path", report_file,
                "--no-git" # Scan files, not history (since shallow clone)
            ]
            
            proc_gl = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc_gl.communicate()
            
            # 3. Parse Report
            if os.path.exists(report_file):
                try:
                    with open(report_file, "r") as f:
                        data = json.load(f)
                        for leak in data:
                            findings.append({
                                "type": "code_leak",
                                "rule": leak.get("RuleID"),
                                "file": leak.get("File"),
                                "snippet": leak.get("Secret"), # Be careful with logging
                                "severity": "HIGH"
                            })
                except Exception as e:
                    logger.error(f"Error parsing gitleaks report: {e}")
                    
        return findings

    def scan_text(self, text: str, source_url: str) -> List[Dict[str, Any]]:
        """
        Scan text (comments, descriptions) using regex Patterns
        """
        findings = []
        for pattern in self.context_patterns:
            matches = pattern.findall(text)
            for match in matches:
                secret_cand = match if isinstance(match, str) else match[0]
                # Filter out likely false positives (too short, etc)
                if len(secret_cand) < 8:
                    continue
                    
                findings.append({
                    "type": "context_leak",
                    "snippet": f"Found matching pattern in {source_url}",
                    "evidence": secret_cand,
                    "severity": "MEDIUM"
                })
        return findings
