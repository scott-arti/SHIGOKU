"""
Custom S3Scanner Tool - AWS S3 Bucket Scanner.
"""
from typing import Dict, Any
import subprocess
from src.tools.base import BaseTool
from src.tools import ToolRegistry

@ToolRegistry.register
class S3ScannerTool(BaseTool):
    """
    S3Scanner - Enumerate and check permissions on AWS S3 buckets.
    """
    
    name = "s3scanner"
    description = "Scan S3 buckets for misconfigurations and public access."
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "bucket_name": {
                            "type": "string",
                            "description": "S3 bucket name or file with bucket names"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["enumerate", "dump"],
                            "default": "enumerate"
                        }
                    },
                    "required": ["bucket_name"]
                }
            }
        }

    def run(self, bucket_name: str, mode: str = "enumerate") -> str:
        if any(c in bucket_name for c in [";", "|", "&", "$", "`"]):
            return "Error: Unsafe characters."
        
        cmd = ["s3scanner"]
        if mode == "enumerate":
            cmd += ["scan", "--bucket", bucket_name]
        elif mode == "dump":
            cmd += ["dump", "--bucket", bucket_name, "-o", "/tmp/s3dump"]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
            return result.stdout or result.stderr or "Scan complete."
        except FileNotFoundError:
            return "Error: s3scanner not installed."
        except Exception as e:
            return f"Error: {e}"
