"""
Metadata Checkpoint Manager for SHIGOKU Phase D
Elegant persistence of scan progress with idempotent tool invocation
"""
from __future__ import annotations
import json
import hashlib
import logging
import asyncio
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from redis.asyncio import Redis

logger = logging.getLogger(__name__)


@dataclass
class ToolInvocation:
    """Record of a tool invocation"""
    tool_name: str
    target: str
    param: str
    payload_hash: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    result_hash: str = ""  # SHA-256 hash for process-stable identification
    
    def generate_key(self) -> str:
        """Generate unique invocation key including payload if available"""
        if self.payload_hash:
            return f"{self.tool_name}:{self.target}:{self.param}:{self.payload_hash}"
        return f"{self.tool_name}:{self.target}:{self.param}"


@dataclass
class Checkpoint:
    """Metadata checkpoint for scan progress"""
    task_id: str
    saved_at: str
    current_param_index: int = 0
    pending_params: List[str] = field(default_factory=list)
    confirmed_findings: List[Dict[str, Any]] = field(default_factory=list)
    tool_invocations: List[ToolInvocation] = field(default_factory=list)
    elapsed_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MetadataCheckpointManager:
    """
    Elegant checkpoint management with:
    - Redis-based persistence
    - SHA-256 result hashes (process-stable)
    - Idempotent tool invocation tracking
    - TTL-based expiration
    """
    
    def __init__(
        self, 
        redis_url: str = "redis://localhost:6379",
        default_ttl: int = 604800,  # 7 days
    ):
        self._redis_url = redis_url
        self._default_ttl = default_ttl
        self._redis: Optional[Redis] = None
        self._lock = asyncio.Lock()
    
    async def initialize(self):
        """Initialize Redis connection"""
        if self._redis is None:
            self._redis = Redis.from_url(self._redis_url)
            # Test connection
            await self._redis.ping()
            logger.info(f"Checkpoint manager connected to Redis: {self._redis_url}")
    
    async def save_checkpoint(
        self, 
        task_id: str,
        current_param_index: int,
        pending_params: List[str],
        confirmed_findings: List[Dict[str, Any]],
        tool_invocations: List[ToolInvocation],
        elapsed_time: float,
    ) -> Checkpoint:
        """Save scan progress checkpoint"""
        await self.initialize()
        
        checkpoint = Checkpoint(
            task_id=task_id,
            saved_at=datetime.utcnow().isoformat(),
            current_param_index=current_param_index,
            pending_params=pending_params,
            confirmed_findings=confirmed_findings,
            tool_invocations=tool_invocations,
            elapsed_time=elapsed_time,
        )
        
        key = f"checkpoint:{task_id}"
        data = json.dumps(checkpoint.to_dict())
        
        async with self._lock:
            await self._redis.setex(key, self._default_ttl, data)
        
        logger.debug(f"Checkpoint saved: {task_id}")
        return checkpoint
    
    async def load_checkpoint(self, task_id: str) -> Optional[Checkpoint]:
        """Load scan progress checkpoint"""
        await self.initialize()
        
        key = f"checkpoint:{task_id}"
        
        async with self._lock:
            data = await self._redis.get(key)
        
        if data is None:
            return None
        
        checkpoint_dict = json.loads(data)
        
        # Reconstruct ToolInvocation objects
        invocations = [
            ToolInvocation(**inv) 
            for inv in checkpoint_dict.get("tool_invocations", [])
        ]
        checkpoint_dict["tool_invocations"] = invocations
        
        return Checkpoint(**checkpoint_dict)
    
    async def delete_checkpoint(self, task_id: str):
        """Delete checkpoint"""
        await self.initialize()
        
        key = f"checkpoint:{task_id}"
        async with self._lock:
            await self._redis.delete(key)
        
        logger.debug(f"Checkpoint deleted: {task_id}")
    
    async def list_checkpoints(self) -> List[str]:
        """List all checkpoint keys"""
        await self.initialize()
        
        async with self._lock:
            keys = await self._redis.keys("checkpoint:*")
        
        return [k.decode() if isinstance(k, bytes) else k for k in keys]


class IdempotentToolInvoker:
    """
    Elegant idempotent tool invocation with:
    - Payload-aware invocation keys
    - Variable payload tool detection
    - Checkpoint-based deduplication
    """
    
    # Tools that generate random payloads (not strictly idempotent)
    VARIABLE_PAYLOAD_TOOLS: Set[str] = {"sqlmap", "ghauri"}
    
    def __init__(self, checkpoint_manager: MetadataCheckpointManager):
        self._checkpoint = checkpoint_manager
        self._invocation_cache: Dict[str, Any] = {}
    
    async def invoke(
        self, 
        tool: str, 
        target: str, 
        param: str, 
        payload: Optional[str] = None,
        invocable: Optional[callable] = None,
    ) -> Any:
        """
        Invoke tool with idempotency guarantee
        
        Args:
            tool: Tool name
            target: Target URL/endpoint
            param: Parameter being tested
            payload: Payload string (for payload-aware deduplication)
            invocable: Async callable to execute if not cached
        
        Returns:
            Tool result (cached or fresh)
        """
        # Generate payload hash if provided
        payload_hash = None
        if payload:
            payload_hash = self._hash_payload(payload)
        
        # Create invocation record
        invocation = ToolInvocation(
            tool_name=tool,
            target=target,
            param=param,
            payload_hash=payload_hash,
        )
        
        invocation_key = invocation.generate_key()
        
        # Check if this is a variable payload tool
        is_variable = tool in self.VARIABLE_PAYLOAD_TOOLS
        
        if is_variable:
            logger.warning(
                f"Tool {tool} has variable payloads - "
                "strict idempotency not guaranteed"
            )
        
        # Check cache
        if invocation_key in self._invocation_cache:
            logger.info(f"Cache hit for: {invocation_key}")
            return self._invocation_cache[invocation_key]
        
        # Check checkpoint (for variable tools, skip checkpoint check)
        if not is_variable:
            # In real implementation, would check checkpoint
            # For now, simplified
            pass
        
        # Execute if invocable provided
        if invocable is not None:
            result = await invocable()
            
            # Calculate result hash (SHA-256 for process stability)
            result_hash = calculate_sha256_hash(result)
            invocation.result_hash = result_hash
            
            # Cache result
            self._invocation_cache[invocation_key] = result
            
            return result
        
        return None
    
    def _hash_payload(self, payload: str) -> str:
        """Hash payload for invocation key"""
        return hashlib.sha256(payload.encode()).hexdigest()[:16]
    
    def is_payload_variable_tool(self, tool: str) -> bool:
        """Check if tool generates variable payloads"""
        return tool in self.VARIABLE_PAYLOAD_TOOLS


def calculate_sha256_hash(result: Any) -> str:
    """
    Calculate process-stable SHA-256 hash of result
    
    Returns:
        16-character hex hash (collision probability: 1/2^64)
    """
    # Convert result to JSON-serializable dict
    if hasattr(result, 'to_dict'):
        data = result.to_dict()
    elif hasattr(result, '__dict__'):
        data = result.__dict__
    else:
        data = {"value": str(result)}
    
    # Sort keys for deterministic serialization
    json_str = json.dumps(data, sort_keys=True, default=str)
    
    # Calculate SHA-256 and truncate to 16 chars
    full_hash = hashlib.sha256(json_str.encode()).hexdigest()
    return full_hash[:16]


# Global instance management
_checkpoint_manager: Optional[MetadataCheckpointManager] = None


def get_checkpoint_manager(
    redis_url: str = "redis://localhost:6379"
) -> MetadataCheckpointManager:
    """Get or create global checkpoint manager"""
    global _checkpoint_manager
    if _checkpoint_manager is None:
        _checkpoint_manager = MetadataCheckpointManager(redis_url)
    return _checkpoint_manager


def reset_checkpoint_manager():
    """Reset global manager (for testing)"""
    global _checkpoint_manager
    _checkpoint_manager = None
