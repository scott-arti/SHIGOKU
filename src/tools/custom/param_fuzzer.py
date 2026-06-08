"""
Custom parameter fuzzer tool.

Provides a callable wrapper around NativeParamFuzzer with self-correcting
mutation controls (timeout/retry/attempt caps).
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from src.tools.base import BaseTool
from src.tools import ToolRegistry
from src.core.attack.native_param_fuzzer import NativeParamFuzzer


@ToolRegistry.register
class ParamFuzzerTool(BaseTool):
    name = "param_fuzzer"
    description = "Discover hidden/vulnerable parameters with adaptive mutation and bounded retries."

    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL",
                        },
                        "method": {
                            "type": "string",
                            "description": "HTTP method",
                            "default": "GET",
                        },
                        "wordlist": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Parameter candidates",
                        },
                        "max_mutation_attempts": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 10,
                            "default": 3,
                        },
                        "timeout_seconds": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 60,
                            "default": 10,
                        },
                        "request_retries": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 5,
                            "default": 2,
                        },
                    },
                    "required": ["url", "wordlist"],
                },
            },
        }

    def run(
        self,
        url: str,
        wordlist: List[str],
        method: str = "GET",
        max_mutation_attempts: int = 3,
        timeout_seconds: int = 10,
        request_retries: int = 2,
    ) -> Dict[str, Any]:
        fuzzer = NativeParamFuzzer()
        fuzzer.max_mutation_attempts = max(1, min(10, int(max_mutation_attempts)))
        fuzzer.request_timeout_seconds = max(1, min(60, int(timeout_seconds)))
        fuzzer.request_retries = max(0, min(5, int(request_retries)))

        async def _run() -> Dict[str, Any]:
            results = await fuzzer.fuzz(url=url, method=method, wordlist=wordlist)
            return {
                "results": [
                    {
                        "parameter": r.parameter,
                        "vulnerable": r.vulnerable,
                        "confidence": r.confidence,
                        "evidence": r.evidence,
                    }
                    for r in results
                ],
                "summary": fuzzer.get_summary(),
            }

        try:
            return asyncio.run(_run())
        except RuntimeError:
            # Already running loop (e.g. notebook/runtime integration)
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(_run())
            finally:
                loop.close()
