from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
import datetime

class ErrorCode(Enum):
    # LLM 関連
    RATE_LIMIT_EXCEEDED = "rate_limit"
    API_TIMEOUT = "api_timeout"
    CONTEXT_LENGTH_EXCEEDED = "context_length"
    BILLING_LIMIT_REACHED = "billing_limit"
    LLM_API_ERROR = "llm_api_error"
    EMPTY_RESPONSE = "empty_response"
    
    # 設定・アーキテクチャ関連
    SCOPE_NOT_FOUND = "scope_not_found"
    CONFIG_INVALID = "config_invalid"
    
    # 実行関連
    AGENT_TIMEOUT = "agent_timeout"
    TOOL_EXECUTION_FAILED = "tool_failed"
    OUTPUT_VALIDATION_FAILED = "output_validation"
    NETWORK_ERROR = "network_error"
    MCP_COMMUNICATION_ERROR = "mcp_error"
    
    # セキュリティ
    SCOPE_VIOLATION = "scope_violation"
    ETHICS_GUARD_BLOCKED = "ethics_blocked"

    # その他
    UNKNOWN = "unknown"

@dataclass
class SHIGOKUError:
    code: ErrorCode
    message: str
    retryable: bool
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())
    
    @classmethod
    def from_exception(cls, exc: Exception, context: Optional[Dict[str, Any]] = None) -> "SHIGOKUError":
        """
        標準例外から自動的に SHIGOKUError へ分類するファクトリメソッド
        """
        exc_str = str(exc).lower()
        exc_type = type(exc).__name__
        ctx = context or {}
        
        # Timeout Error
        if isinstance(exc, TimeoutError) or "timeout" in exc_str:
            return cls(
                code=ErrorCode.API_TIMEOUT if "api" in exc_str else ErrorCode.AGENT_TIMEOUT,
                message=f"タイムアウトが発生しました: {str(exc)}",
                retryable=True,
                context=ctx
            )
            
        # Network Error (aiohttp, requests, etc)
        if "connection" in exc_str or "unreachable" in exc_str or "network" in exc_str or "gaierror" in exc_str:
            return cls(
                code=ErrorCode.NETWORK_ERROR,
                message=f"ネットワーク・接続エラー: {str(exc)}",
                retryable=True,
                context=ctx
            )
            
        # LLM Rate Limit
        if "rate limit" in exc_str or "too many requests" in exc_str or "429" in exc_str:
            return cls(
                code=ErrorCode.RATE_LIMIT_EXCEEDED,
                message=f"APIレートリミット超過: {str(exc)}",
                retryable=True,  # Backoff で再試行可能
                context=ctx
            )
            
        # LLM Context Length
        if "context_length_exceeded" in exc_str or "maximum context length" in exc_str:
            return cls(
                code=ErrorCode.CONTEXT_LENGTH_EXCEEDED,
                message=f"LLMコンテキスト長超過: {str(exc)}",
                retryable=False,
                context=ctx
            )
            
        # Error with MCP
        if "mcp" in exc_str:
            return cls(
                code=ErrorCode.MCP_COMMUNICATION_ERROR,
                message=f"MCPサーバー通信エラー: {str(exc)}",
                retryable=False, # 一部のMCPエラーは再起可能かもしれないが安全側に倒す
                context=ctx
            )
            
        # Tool execution / Subprocess
        if "subprocess.calledprocesserror" in exc_str.lower() or exc_type == "CalledProcessError":
            return cls(
                code=ErrorCode.TOOL_EXECUTION_FAILED,
                message=f"外部ツール実行失敗: {str(exc)}",
                retryable=False,
                context=ctx
            )
            
        # Ethics / Security
        if "scope" in exc_str and "violation" in exc_str:
            return cls(
                code=ErrorCode.SCOPE_VIOLATION,
                message=f"スコープ外へのアクセス試行: {str(exc)}",
                retryable=False,
                context=ctx
            )
        
        if "ethics" in exc_str and "blocked" in exc_str:
            return cls(
                code=ErrorCode.ETHICS_GUARD_BLOCKED,
                message=f"EthicsGuardによりブロック: {str(exc)}",
                retryable=False,
                context=ctx
            )
            
        # Default
        return cls(
            code=ErrorCode.UNKNOWN,
            message=f"未分類のエラー '{exc_type}': {str(exc)}",
            retryable=False,
            context=ctx
        )
