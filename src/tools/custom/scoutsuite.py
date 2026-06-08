"""
Custom ScoutSuite Tool - Cloud Security Auditing.
"""
from typing import Dict, Any, Optional
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry


@ToolRegistry.register
class ScoutSuiteTool(BaseTool):
    """
    ScoutSuite for multi-cloud security auditing.
    
    Requires cloud credentials to be set via environment variables:
    - AWS: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
    - Azure: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
    - GCP: GOOGLE_APPLICATION_CREDENTIALS
    
    Profiles:
    - aws: AWS audit
    - azure: Azure audit
    - gcp: GCP audit
    """
    
    name = "scoutsuite"
    description = "Multi-cloud security auditing tool. Requires cloud credentials in environment."
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "provider": {
                            "type": "string",
                            "enum": ["aws", "azure", "gcp"],
                            "description": "Cloud provider to audit"
                        },
                        "services": {
                            "type": "string",
                            "description": "Comma-separated list of services to audit (e.g., 's3,iam,ec2')"
                        },
                        "output_dir": {
                            "type": "string",
                            "description": "Output directory for reports",
                            "default": "/workspace/scoutsuite_report"
                        }
                    },
                    "required": ["provider"]
                }
            }
        }

    def run(
        self,
        provider: str,
        services: Optional[str] = None,
        output_dir: str = "/workspace/scoutsuite_report"
    ) -> str:
        cmd = [
            "python3", "/opt/ScoutSuite/scout.py",
            provider,
            "--report-dir", output_dir,
            "--no-browser"
        ]
        
        if services:
            if any(char in services for char in [";", "|", "&", "$", "`"]):
                return "Error: Unsafe characters in services parameter."
            cmd += ["--services", services]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=1800, check=False
            )
            output = result.stdout
            if result.returncode == 0:
                output += f"\n\nReport saved to: {output_dir}"
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"
            return output or "ScoutSuite audit completed."
        except subprocess.TimeoutExpired:
            return "Error: ScoutSuite timed out (30min limit)."
        except Exception as e:
            return f"Error: {e}"
