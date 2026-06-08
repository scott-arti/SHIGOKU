"""
Generic Tool Adapter for SHIGOKU Phase D
Elegant FOSS tool integration with YAML-based configuration
"""
from __future__ import annotations
import asyncio
import subprocess
import json
import yaml
import logging
from typing import Dict, List, Any, Optional, Protocol
from dataclasses import dataclass
from abc import ABC, abstractmethod
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Standardized tool execution result"""
    tool_name: str
    return_code: int
    stdout: str
    stderr: str
    parsed_output: Dict[str, Any]
    execution_time: float
    
    @property
    def success(self) -> bool:
        return self.return_code == 0


class ToolParser(ABC):
    """
    Abstract base for tool output parsers
    
    Each tool (sqlmap, dalfox, etc.) implements its own parser
    by inheriting from this class.
    """
    
    @abstractmethod
    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        Parse tool output into standardized format
        
        Returns dict with keys like:
        - findings: List of vulnerability findings
        - tested_params: List of tested parameters
        - confidence: Confidence score
        - evidence: Evidence details
        """
        pass
    
    @abstractmethod
    def supports(self, tool_name: str) -> bool:
        """Check if this parser supports the given tool"""
        pass


class SubprocessToolAdapter:
    """
    Elegant subprocess-based tool adapter
    
    Features:
    - YAML-based tool configuration
    - Standardized output parsing via Parser classes
    - Timeout handling
    - Async execution
    """
    
    def __init__(
        self,
        tool_name: str,
        binary_path: str,
        default_args: List[str],
        parser: ToolParser,
        timeout: float = 300.0
    ):
        self.tool_name = tool_name
        self.binary_path = binary_path
        self.default_args = default_args
        self.parser = parser
        self.timeout = timeout
    
    async def execute(
        self,
        target: str,
        extra_args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None
    ) -> ToolResult:
        """
        Execute tool with given arguments
        
        Args:
            target: Target URL/endpoint
            extra_args: Additional arguments
            env: Environment variables
        
        Returns:
            Standardized ToolResult
        """
        # Build command
        cmd = [self.binary_path] + self.default_args
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(target)
        
        logger.debug(f"Executing {self.tool_name}: {' '.join(cmd)}")
        
        # Execute with timeout
        start_time = asyncio.get_event_loop().time()
        
        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env={**self._get_env(), **(env or {})}
                ),
                timeout=self.timeout
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.timeout
            )
            
            execution_time = asyncio.get_event_loop().time() - start_time
            
            # Decode output
            stdout_str = stdout.decode('utf-8', errors='replace')
            stderr_str = stderr.decode('utf-8', errors='replace')
            
            # Parse output
            parsed = self.parser.parse(stdout_str, stderr_str)
            
            return ToolResult(
                tool_name=self.tool_name,
                return_code=proc.returncode,
                stdout=stdout_str,
                stderr=stderr_str,
                parsed_output=parsed,
                execution_time=execution_time
            )
            
        except asyncio.TimeoutError:
            logger.warning(f"{self.tool_name} execution timed out after {self.timeout}s")
            return ToolResult(
                tool_name=self.tool_name,
                return_code=-1,
                stdout="",
                stderr=f"Timeout after {self.timeout}s",
                parsed_output={"error": "timeout"},
                execution_time=self.timeout
            )
        except Exception as e:
            logger.error(f"{self.tool_name} execution failed: {e}")
            return ToolResult(
                tool_name=self.tool_name,
                return_code=-1,
                stdout="",
                stderr=str(e),
                parsed_output={"error": str(e)},
                execution_time=0.0
            )
    
    def _get_env(self) -> Dict[str, str]:
        """Get base environment for tool execution"""
        import os
        return dict(os.environ)


class ToolRegistry:
    """
    Registry for managing tool adapters
    
    - Load tool configurations from YAML
    - Register parsers
    - Factory for creating adapter instances
    """
    
    def __init__(self):
        self._adapters: Dict[str, SubprocessToolAdapter] = {}
        self._parsers: Dict[str, ToolParser] = {}
        self._configs: Dict[str, Dict] = {}
    
    def register_parser(self, parser: ToolParser):
        """Register a tool output parser"""
        self._parsers[parser.__class__.__name__] = parser
        logger.debug(f"Registered parser: {parser.__class__.__name__}")
    
    def load_config(self, config_path: str):
        """
        Load tool configurations from YAML file
        
        Config format:
        ```yaml
        tools:
          sqlmap:
            binary: sqlmap
            default_args: ["--batch", "--level=1"]
            parser: SQLMapParser
            timeout: 300
        ```
        """
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        
        with open(path) as f:
            config = yaml.safe_load(f)
        
        for tool_name, tool_config in config.get("tools", {}).items():
            self._configs[tool_name] = tool_config
            logger.debug(f"Loaded config for tool: {tool_name}")
    
    def create_adapter(self, tool_name: str) -> SubprocessToolAdapter:
        """
        Create tool adapter from configuration
        
        Args:
            tool_name: Name of the tool (must be in config)
        
        Returns:
            Configured SubprocessToolAdapter
        """
        if tool_name not in self._configs:
            raise ValueError(f"No configuration for tool: {tool_name}")
        
        config = self._configs[tool_name]
        
        # Find parser
        parser_name = config.get("parser", f"{tool_name.title()}Parser")
        parser = self._parsers.get(parser_name)
        
        if parser is None:
            # Use generic parser as fallback
            parser = GenericParser()
            logger.warning(f"No parser found for {tool_name}, using generic parser")
        
        adapter = SubprocessToolAdapter(
            tool_name=tool_name,
            binary_path=config.get("binary", tool_name),
            default_args=config.get("default_args", []),
            parser=parser,
            timeout=config.get("timeout", 300.0)
        )
        
        self._adapters[tool_name] = adapter
        return adapter
    
    def get_adapter(self, tool_name: str) -> Optional[SubprocessToolAdapter]:
        """Get cached adapter or create new one"""
        if tool_name in self._adapters:
            return self._adapters[tool_name]
        
        if tool_name in self._configs:
            return self.create_adapter(tool_name)
        
        return None


# Example parsers

class SQLMapParser(ToolParser):
    """Parser for sqlmap output"""
    
    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse sqlmap JSON output"""
        findings = []
        
        # Try to parse as JSON first
        try:
            data = json.loads(stdout)
            # Extract findings from sqlmap JSON structure
            # This is simplified - actual sqlmap output is more complex
            if "data" in data:
                for item in data["data"]:
                    findings.append({
                        "type": "sql_injection",
                        "param": item.get("parameter"),
                        "technique": item.get("technique"),
                        "confidence": item.get("confidence", 0.0)
                    })
        except json.JSONDecodeError:
            # Parse text output
            if "is vulnerable" in stdout.lower():
                findings.append({
                    "type": "sql_injection",
                    "evidence": "sqlmap confirmed vulnerability",
                    "confidence": 0.9
                })
        
        return {
            "findings": findings,
            "tested_params": [],  # Would extract from output
            "raw_output": stdout[:1000]  # Truncated
        }
    
    def supports(self, tool_name: str) -> bool:
        return tool_name.lower() == "sqlmap"


class DalfoxParser(ToolParser):
    """Parser for Dalfox (XSS) output"""
    
    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse Dalfox output"""
        findings = []
        
        # Dalfox outputs findings in structured format
        # Simplified parsing
        if "[V]" in stdout:
            lines = stdout.split("\n")
            for line in lines:
                if "[V]" in line:
                    findings.append({
                        "type": "xss",
                        "evidence": line.strip(),
                        "confidence": 0.85
                    })
        
        return {
            "findings": findings,
            "tested_params": [],
            "raw_output": stdout[:1000]
        }
    
    def supports(self, tool_name: str) -> bool:
        return tool_name.lower() == "dalfox"


class GenericParser(ToolParser):
    """Generic parser for unknown tools"""
    
    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {
            "findings": [],
            "tested_params": [],
            "raw_output": stdout[:2000],
            "stderr": stderr[:1000]
        }
    
    def supports(self, tool_name: str) -> bool:
        return True  # Supports everything as fallback


# Global registry
_tool_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    """Get or create global tool registry"""
    global _tool_registry
    if _tool_registry is None:
        _tool_registry = ToolRegistry()
        # Register built-in parsers
        _tool_registry.register_parser(SQLMapParser())
        _tool_registry.register_parser(DalfoxParser())
    return _tool_registry
