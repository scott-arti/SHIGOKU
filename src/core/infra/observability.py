"""
Observability Infrastructure for SHIGOKU Phase D
Elegant tracing, metrics, and determinism support
"""
from __future__ import annotations
import random
import time
import json
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import deque
from contextvars import ContextVar
import asyncio

logger = logging.getLogger(__name__)

# Context-local trace ID
current_trace_id: ContextVar[Optional[str]] = ContextVar(
    "current_trace_id", default=None
)


@dataclass
class ExecutionEvent:
    """Single execution event record"""
    timestamp: float
    trace_id: str
    event_type: str
    payload: str
    response: Optional[str] = None
    latency_ms: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "trace_id": self.trace_id,
            "event_type": self.event_type,
            "payload": self.payload[:1000] if len(self.payload) > 1000 else self.payload,
            "response": self.response[:500] if self.response and len(self.response) > 500 else self.response,
            "latency_ms": self.latency_ms,
            "metadata": self.metadata,
        }


class ExecutionTracer:
    """
    Ring-buffer based execution tracer with:
    - Per-injection trace tracking
    - Replay support
    - Memory-efficient storage
    """
    
    def __init__(self, max_events: int = 10000):
        self._events: deque[ExecutionEvent] = deque(maxlen=max_events)
        self._lock = asyncio.Lock()
    
    async def record(
        self,
        event_type: str,
        payload: str,
        response: Optional[str] = None,
        latency_ms: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ExecutionEvent:
        """Record an execution event"""
        event = ExecutionEvent(
            timestamp=time.time(),
            trace_id=current_trace_id.get() or self._generate_trace_id(),
            event_type=event_type,
            payload=payload,
            response=response,
            latency_ms=latency_ms,
            metadata=metadata or {},
        )
        
        async with self._lock:
            self._events.append(event)
        
        return event
    
    async def get_trace(self, trace_id: str) -> List[ExecutionEvent]:
        """Get all events for a specific trace"""
        async with self._lock:
            return [e for e in self._events if e.trace_id == trace_id]
    
    async def get_recent_events(
        self, 
        event_type: Optional[str] = None,
        limit: int = 100
    ) -> List[ExecutionEvent]:
        """Get recent events with optional filtering"""
        async with self._lock:
            events = list(self._events)
            if event_type:
                events = [e for e in events if e.event_type == event_type]
            return events[-limit:]
    
    async def export_to_file(self, filepath: str):
        """Export all events to JSON file"""
        async with self._lock:
            events_data = [e.to_dict() for e in self._events]
        
        with open(filepath, "w") as f:
            json.dump(events_data, f, indent=2)
    
    def _generate_trace_id(self) -> str:
        """Generate unique trace ID"""
        return f"trace_{time.time():.6f}_{random.randint(1000, 9999)}"


class ReplayEngine:
    """
    Replay execution traces for:
    - Deterministic reproduction
    - Local debugging
    - Test case generation
    """
    
    def __init__(self, tracer: ExecutionTracer):
        self._tracer = tracer
    
    async def replay_trace(
        self, 
        trace_id: str,
        target_override: Optional[str] = None
    ) -> List[ReplayResult]:
        """
        Replay a trace for local reproduction
        
        Args:
            trace_id: Trace to replay
            target_override: Override target URL (e.g., localhost:8080)
        """
        events = await self._tracer.get_trace(trace_id)
        results = []
        
        for event in events:
            # Apply target override if provided
            payload = event.payload
            if target_override:
                payload = self._override_target(payload, target_override)
            
            # Execute replay
            result = await self._execute_replay(event.event_type, payload)
            results.append(result)
        
        return results
    
    def _override_target(self, payload: str, new_target: str) -> str:
        """Override target in payload for local replay"""
        # Simple URL override - could be more sophisticated
        # This is a placeholder for actual implementation
        return payload
    
    async def _execute_replay(
        self, 
        event_type: str, 
        payload: str
    ) -> ReplayResult:
        """Execute a single replay step"""
        # This would integrate with actual execution logic
        # For now, return a placeholder
        return ReplayResult(
            event_type=event_type,
            executed=True,
            response="replayed",
        )


@dataclass
class ReplayResult:
    """Result of a replay step"""
    event_type: str
    executed: bool
    response: Optional[str]
    error: Optional[str] = None


class MetricsCollector:
    """
    Prometheus-compatible metrics collection
    """
    
    def __init__(self):
        self._counters: Dict[str, int] = {}
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = {}
        self._lock = asyncio.Lock()
    
    async def inc_counter(self, name: str, value: int = 1):
        """Increment a counter metric"""
        async with self._lock:
            self._counters[name] = self._counters.get(name, 0) + value
    
    async def set_gauge(self, name: str, value: float):
        """Set a gauge metric"""
        async with self._lock:
            self._gauges[name] = value
    
    async def record_histogram(self, name: str, value: float):
        """Record a value to histogram"""
        async with self._lock:
            if name not in self._histograms:
                self._histograms[name] = []
            self._histograms[name].append(value)
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get all current metrics"""
        async with self._lock:
            # Calculate histogram stats
            histogram_stats = {}
            for name, values in self._histograms.items():
                if values:
                    histogram_stats[name] = {
                        "count": len(values),
                        "sum": sum(values),
                        "avg": sum(values) / len(values),
                        "min": min(values),
                        "max": max(values),
                    }
            
            return {
                "counters": self._counters.copy(),
                "gauges": self._gauges.copy(),
                "histograms": histogram_stats,
            }


class SeededRandom:
    """
    Deterministic random number generation for reproducibility
    Each context gets its own Random instance
    """
    
    def __init__(self, seed: Optional[int] = None):
        self._seed = seed
        self._local = ContextVar("seeded_random", default=None)
    
    def initialize(self, seed: int):
        """Initialize with seed for deterministic behavior"""
        rng = random.Random(seed)
        self._local.set(rng)
        return rng
    
    def get(self) -> random.Random:
        """Get current context's Random instance"""
        rng = self._local.get()
        if rng is None:
            # Fallback to global with seed
            if self._seed is not None:
                rng = random.Random(self._seed)
            else:
                rng = random.Random()
            self._local.set(rng)
        return rng
    
    def randint(self, a: int, b: int) -> int:
        """Random integer [a, b]"""
        return self.get().randint(a, b)
    
    def choice(self, seq):
        """Random choice from sequence"""
        return self.get().choice(seq)
    
    def shuffle(self, seq):
        """Shuffle sequence in place"""
        return self.get().shuffle(seq)
    
    def random(self) -> float:
        """Random float [0.0, 1.0)"""
        return self.get().random()


class ObservabilityManager:
    """
    Central observability management
    """
    
    def __init__(self, seed: Optional[int] = None):
        self.tracer = ExecutionTracer()
        self.replay = ReplayEngine(self.tracer)
        self.metrics = MetricsCollector()
        self.seeded_random = SeededRandom(seed)
    
    def set_trace_id(self, trace_id: str):
        """Set current execution trace ID"""
        current_trace_id.set(trace_id)
    
    def get_trace_id(self) -> Optional[str]:
        """Get current execution trace ID"""
        return current_trace_id.get()
    
    def initialize_seed(self, seed: int):
        """Initialize seeded random for determinism"""
        self.seeded_random.initialize(seed)
        logger.info(f"Observability initialized with seed: {seed}")


# Global instance
_observability: Optional[ObservabilityManager] = None


def get_observability(seed: Optional[int] = None) -> ObservabilityManager:
    """Get or create global observability manager"""
    global _observability
    if _observability is None:
        _observability = ObservabilityManager(seed)
    return _observability
