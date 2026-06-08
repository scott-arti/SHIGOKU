"""
Custom cloud_enum Tool - Cloud Asset Discovery.
"""
from typing import Dict, Any, Optional
import subprocess
import shlex
from src.tools.base import BaseTool
from src.tools import ToolRegistry


@ToolRegistry.register
class CloudEnumTool(BaseTool):
    """
    cloud_enum for discovering cloud assets (S3, Azure, GCP).
    
    Profiles:
    - aws: AWS S3 buckets only
    - azure: Azure blobs only
    - gcp: GCP buckets only
    - all: All cloud providers
    """
    
    name = "cloud_enum"
    description = "Enumerate public cloud resources (S3, Azure Blobs, GCS) for a target keyword."
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "keyword": {
                            "type": "string",
                            "description": "Target keyword (company/project name)"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["aws", "azure", "gcp", "all"],
                            "description": "Cloud provider to scan",
                            "default": "all"
                        },
                        "extra_args": {
                            "type": "string",
                            "description": "Additional flags (sanitized)"
                        }
                    },
                    "required": ["keyword"]
                }
            }
        }

    def run(self, keyword: str, mode: str = "all", extra_args: Optional[str] = None) -> str:
        cmd = ["python3", "/opt/cloud_enum/cloud_enum.py", "-k", keyword]
        
        if mode == "aws":
            cmd += ["-l", "/opt/cloud_enum/enum_tools/fuzz.txt", "--disable-azure", "--disable-gcp"]
        elif mode == "azure":
            cmd += ["--disable-aws", "--disable-gcp"]
        elif mode == "gcp":
            cmd += ["--disable-aws", "--disable-azure"]
        # mode == "all" uses defaults

        if extra_args:
            if any(char in extra_args for char in [";", "|", "&", "$", "`"]):
                return "Error: Unsafe characters detected in extra_args."
            cmd += shlex.split(extra_args)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600, check=False
            )
            return result.stdout or "No cloud assets found."
        except subprocess.TimeoutExpired:
            return "Error: cloud_enum timed out."
        except Exception as e:
            return f"Error: {e}"
