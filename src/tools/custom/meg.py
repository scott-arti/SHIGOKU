"""
Custom meg Tool - Enhanced version with Stealth, Offensive, and Monitoring features.
Path: /home/bbb/go/bin/meg
"""
from typing import Dict, Any, Optional
import subprocess
import shlex

class MegTool:
    """
    カスタム改造版 meg (Mighty Meg) を使用するツール。
    多数のホストに対して多数のパスを効率的にフェッチする。
    
    独自機能:
    - Stealth: ジッター遅延、UA/プロキシローテーション
    - Offensive: Smart 403 Bypass (自動バイパス試行)
    - Monitoring: Webhook通知、レジューム機能
    - HTTP/3サポート
    """
    
    name = "meg"
    description = """Fetch many paths for many hosts efficiently using the enhanced meg tool.
    
Custom Features:
- Jitter (--jitter): Add random delay variation to avoid WAF detection
- UA Rotation (--user-agents): Rotate User-Agents per request
- Proxy Rotation (--proxy): Rotate proxies per request
- Smart 403 Bypass (--smart-bypass): Auto-try bypass techniques on 403 responses
- Resume (--resume): Skip already-fetched requests
- Webhook (--webhook): Send real-time notifications
- HTTP/3 (--http3): Use QUIC protocol

Usage: Provide paths file, hosts file, and optional output directory."""

    MEG_PATH = "/home/bbb/go/bin/meg"

    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "paths_file": {
                            "type": "string",
                            "description": "Path to file containing URL paths (one per line)"
                        },
                        "hosts_file": {
                            "type": "string",
                            "description": "Path to file containing hosts (one per line)"
                        },
                        "output_dir": {
                            "type": "string",
                            "description": "Output directory (default: ./out)"
                        },
                        "concurrency": {
                            "type": "integer",
                            "description": "Number of concurrent requests (default: 20)"
                        },
                        "delay": {
                            "type": "integer",
                            "description": "Delay between requests to same host in milliseconds (default: 5000)"
                        },
                        "jitter": {
                            "type": "integer",
                            "description": "Random delay variation percentage (0-100) for stealth"
                        },
                        "user_agents_file": {
                            "type": "string",
                            "description": "Path to User-Agent list file for rotation"
                        },
                        "proxy_file": {
                            "type": "string",
                            "description": "Path to proxy list file for rotation"
                        },
                        "smart_bypass": {
                            "type": "boolean",
                            "description": "Enable automatic 403 bypass techniques"
                        },
                        "resume": {
                            "type": "boolean",
                            "description": "Resume scan, skip already-fetched requests"
                        },
                        "webhook": {
                            "type": "string",
                            "description": "Webhook URL for real-time notifications (e.g., Slack)"
                        },
                        "http3": {
                            "type": "boolean",
                            "description": "Use HTTP/3 (QUIC) protocol"
                        },
                        "json_output": {
                            "type": "boolean",
                            "description": "Output in JSON Lines format"
                        },
                        "filter_size": {
                            "type": "string",
                            "description": "Filter by response size (e.g., '>100', '<100', '100')"
                        },
                        "filter_body": {
                            "type": "string",
                            "description": "Filter by body regex pattern"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Request timeout in milliseconds (default: 10000)"
                        },
                        "headers": {
                            "type": "string",
                            "description": "Custom headers (format: 'Header1: value1, Header2: value2')"
                        },
                        "verbose": {
                            "type": "boolean",
                            "description": "Enable verbose output"
                        }
                    },
                    "required": ["paths_file", "hosts_file"]
                }
            }
        }

    def run(
        self,
        paths_file: str,
        hosts_file: str,
        output_dir: Optional[str] = None,
        concurrency: Optional[int] = None,
        delay: Optional[int] = None,
        jitter: Optional[int] = None,
        user_agents_file: Optional[str] = None,
        proxy_file: Optional[str] = None,
        smart_bypass: bool = False,
        resume: bool = False,
        webhook: Optional[str] = None,
        http3: bool = False,
        json_output: bool = False,
        filter_size: Optional[str] = None,
        filter_body: Optional[str] = None,
        timeout: Optional[int] = None,
        headers: Optional[str] = None,
        verbose: bool = False
    ) -> str:
        """Execute custom meg with specified options."""
        
        cmd = [self.MEG_PATH]
        
        # Performance options
        if concurrency:
            cmd += ["-c", str(concurrency)]
        if delay:
            cmd += ["-d", str(delay)]
        if timeout:
            cmd += ["-t", str(timeout)]
        
        # Stealth options
        if jitter:
            cmd += ["--jitter", str(jitter)]
        if user_agents_file:
            cmd += ["--user-agents", user_agents_file]
        if proxy_file:
            cmd += ["--proxy", proxy_file]
        
        # Offensive options
        if smart_bypass:
            cmd.append("--smart-bypass")
        
        # Monitoring options
        if resume:
            cmd.append("--resume")
        if webhook:
            cmd += ["--webhook", webhook]
        
        # Network options
        if http3:
            cmd.append("--http3")
        
        # Output options
        if json_output:
            cmd.append("--json")
        if filter_size:
            cmd += ["--filter-size", filter_size]
        if filter_body:
            cmd += ["--filter-body", filter_body]
        if verbose:
            cmd.append("-v")
        
        # Headers
        if headers:
            for header in headers.split(","):
                cmd += ["-H", header.strip()]
        
        # Positional arguments
        cmd.append(paths_file)
        cmd.append(hosts_file)
        if output_dir:
            cmd.append(output_dir)
        
        # Execute
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800,  # 30 min timeout for large scans
                check=False
            )
            output = result.stdout
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"
            return output if output else "meg completed. Check output directory for results."
        except subprocess.TimeoutExpired:
            return "Error: meg timed out after 30 minutes."
        except FileNotFoundError:
            return f"Error: meg not found at {self.MEG_PATH}"
