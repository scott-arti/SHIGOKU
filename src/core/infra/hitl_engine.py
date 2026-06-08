"""
Human-in-the-Loop (HITL) Strategy Engine for SHIGOKU Phase D
Elegant state machine with fallback notifications
"""
from __future__ import annotations
import asyncio
import logging
from enum import Enum, auto
from typing import Dict, List, Any, Optional, Callable, Protocol
from dataclasses import dataclass, field
from datetime import datetime
from abc import ABC, abstractmethod
import json

logger = logging.getLogger(__name__)


class HITLState(Enum):
    """HITL decision states"""
    PENDING = auto()
    HUMAN_REVIEWING = auto()
    CONFIRMED = auto()
    REJECTED = auto()
    TIMEOUT = auto()


@dataclass
class HITLDecision:
    """Result of HITL decision process"""
    confirmed: bool
    state: HITLState
    reviewer: Optional[str] = None
    comment: Optional[str] = None
    decided_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """Vulnerability finding for HITL review"""
    id: str
    type: str
    target: str
    endpoint: str
    payload: str
    evidence: str
    confidence: float
    severity: str = "medium"
    scenario: str = "default"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "target": self.target,
            "endpoint": self.endpoint,
            "payload": self.payload[:1000],  # Truncate
            "evidence": self.evidence[:500],
            "confidence": self.confidence,
            "severity": self.severity,
            "scenario": self.scenario,
        }


class HITLStrategy(ABC):
    """Abstract strategy for HITL decision making"""
    
    @abstractmethod
    async def decide(self, finding: Finding) -> HITLDecision:
        """Make decision on finding"""
        pass
    
    @abstractmethod
    def supports(self, scenario: str) -> bool:
        """Check if strategy supports given scenario"""
        pass


class Notifier(Protocol):
    """Protocol for notification backends"""
    
    async def notify(self, finding: Finding, message: str) -> bool:
        """Send notification, return success status"""
        pass


class WebSocketNotifier:
    """WebSocket-based real-time notification"""
    
    def __init__(self, timeout: float = 5.0):
        self._timeout = timeout
        self._connected = False
    
    async def notify(self, finding: Finding, message: str) -> bool:
        """Send WebSocket notification with timeout"""
        try:
            # Placeholder for actual WebSocket implementation
            # Would use websockets library or similar
            await asyncio.wait_for(
                self._send_ws_message(finding, message),
                timeout=self._timeout
            )
            return True
        except asyncio.TimeoutError:
            logger.warning(f"WebSocket notification timeout for finding {finding.id}")
            return False
        except Exception as e:
            logger.error(f"WebSocket notification failed: {e}")
            return False
    
    async def _send_ws_message(self, finding: Finding, message: str):
        """Actual WebSocket send (placeholder)"""
        # Implementation would use actual WebSocket connection
        await asyncio.sleep(0.1)  # Simulate send
        logger.debug(f"WS notification sent: {finding.id}")


class EmailNotifier:
    """Email fallback notification"""
    
    async def notify(self, finding: Finding, message: str) -> bool:
        """Send email notification"""
        try:
            # Placeholder for email implementation
            logger.info(f"Email notification sent for finding {finding.id}")
            return True
        except Exception as e:
            logger.error(f"Email notification failed: {e}")
            return False


class SlackNotifier:
    """Slack fallback notification"""
    
    async def notify(self, finding: Finding, message: str) -> bool:
        """Send Slack notification"""
        try:
            # Placeholder for Slack webhook implementation
            logger.info(f"Slack notification sent for finding {finding.id}")
            return True
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")
            return False


class HITLStateMachine:
    """
    State machine for HITL workflow
    - PENDING → HUMAN_REVIEWING → (CONFIRMED | REJECTED | TIMEOUT)
    """
    
    def __init__(self):
        self._states: Dict[str, HITLState] = {}
        self._lock = asyncio.Lock()
    
    async def get_state(self, finding_id: str) -> HITLState:
        """Get current state of finding"""
        async with self._lock:
            return self._states.get(finding_id, HITLState.PENDING)
    
    async def transition(
        self, 
        finding_id: str, 
        from_state: HITLState, 
        to_state: HITLState
    ) -> bool:
        """
        Attempt state transition
        
        Returns:
            True if transition successful, False otherwise
        """
        async with self._lock:
            current = self._states.get(finding_id, HITLState.PENDING)
            
            if current != from_state:
                logger.warning(
                    f"Invalid transition attempt: {finding_id} "
                    f"is {current.name}, not {from_state.name}"
                )
                return False
            
            self._states[finding_id] = to_state
            logger.debug(f"State transition: {finding_id} {from_state.name} -> {to_state.name}")
            return True
    
    async def set_state(self, finding_id: str, state: HITLState):
        """Force set state (for initialization/recovery)"""
        async with self._lock:
            self._states[finding_id] = state


class HITLDecisionEngine:
    """
    Elegant HITL decision engine with:
    - Strategy pattern for different scenarios
    - Fallback notifications (WebSocket → Email → Slack)
    - State machine for workflow management
    """
    
    def __init__(self):
        self._strategies: Dict[str, HITLStrategy] = {}
        self._state_machine = HITLStateMachine()
        self._primary_notifier = WebSocketNotifier()
        self._fallback_notifiers: List[Notifier] = [
            EmailNotifier(),
            SlackNotifier(),
        ]
    
    def register(self, scenario: str, strategy: HITLStrategy):
        """Register HITL strategy for scenario"""
        self._strategies[scenario] = strategy
        logger.info(f"Registered HITL strategy for scenario: {scenario}")
    
    async def route(self, finding: Finding) -> HITLDecision:
        """
        Route finding through HITL process
        
        Flow:
        1. Transition to HUMAN_REVIEWING
        2. Notify via WebSocket (with fallback)
        3. Execute strategy
        4. Record decision
        """
        # Transition state
        await self._state_machine.transition(
            finding.id,
            HITLState.PENDING,
            HITLState.HUMAN_REVIEWING
        )
        
        # Notify with fallback
        notification_sent = await self._notify_with_fallback(finding)
        if not notification_sent:
            logger.warning(f"All notification methods failed for finding {finding.id}")
        
        # Get strategy and decide
        strategy = self._strategies.get(finding.scenario)
        if strategy is None:
            logger.warning(f"No strategy for scenario {finding.scenario}, using default")
            decision = HITLDecision(
                confirmed=False,
                state=HITLState.REJECTED,
                comment=f"No HITL strategy for scenario: {finding.scenario}"
            )
        else:
            decision = await strategy.decide(finding)
        
        # Transition to final state
        final_state = HITLState.CONFIRMED if decision.confirmed else HITLState.REJECTED
        await self._state_machine.transition(
            finding.id,
            HITLState.HUMAN_REVIEWING,
            final_state
        )
        
        return decision
    
    async def _notify_with_fallback(self, finding: Finding) -> bool:
        """
        Send notification with fallback chain
        
        WebSocket (5s timeout) → Email → Slack
        """
        message = f"HITL判定要求: {finding.type} on {finding.target}"
        
        # Try primary (WebSocket)
        if await self._primary_notifier.notify(finding, message):
            return True
        
        # Fallback chain
        for notifier in self._fallback_notifiers:
            try:
                if await notifier.notify(finding, message):
                    return True
            except Exception as e:
                logger.error(f"Fallback notification failed: {e}")
        
        return False
    
    async def get_state(self, finding_id: str) -> HITLState:
        """Get current HITL state"""
        return await self._state_machine.get_state(finding_id)


# Strategy implementations

class WAFEvasionStrategy(HITLStrategy):
    """HITL strategy for WAF evasion confirmation"""
    
    def supports(self, scenario: str) -> bool:
        return scenario == "waf_block"
    
    async def decide(self, finding: Finding) -> HITLDecision:
        # Placeholder: would interact with human reviewer
        return HITLDecision(
            confirmed=True,  # Auto-confirm for now
            state=HITLState.CONFIRMED,
            comment="WAF block confirmed, evasion required"
        )


class TimeBasedConfirmStrategy(HITLStrategy):
    """HITL strategy for time-based vulnerability confirmation"""
    
    def supports(self, scenario: str) -> bool:
        return scenario == "time_based_confirm"
    
    async def decide(self, finding: Finding) -> HITLDecision:
        # Placeholder: would show timing data to human
        return HITLDecision(
            confirmed=finding.confidence > 0.8,
            state=HITLState.CONFIRMED if finding.confidence > 0.8 else HITLState.REJECTED,
            comment=f"Time-based detection with confidence {finding.confidence:.2f}"
        )


class SecondOrderHumanAssistStrategy(HITLStrategy):
    """HITL strategy for Second-Order SQLi assistance"""
    
    def supports(self, scenario: str) -> bool:
        return scenario == "second_order_hint"
    
    async def decide(self, finding: Finding) -> HITLDecision:
        # Always requires human confirmation for Second-Order
        return HITLDecision(
            confirmed=False,  # Human must confirm
            state=HITLState.HUMAN_REVIEWING,
            comment="Second-Order candidate requires manual verification"
        )


# Global instance
_hitl_engine: Optional[HITLDecisionEngine] = None


def get_hitl_engine() -> HITLDecisionEngine:
    """Get or create global HITL engine"""
    global _hitl_engine
    if _hitl_engine is None:
        _hitl_engine = HITLDecisionEngine()
        # Register default strategies
        _hitl_engine.register("waf_block", WAFEvasionStrategy())
        _hitl_engine.register("time_based_confirm", TimeBasedConfirmStrategy())
        _hitl_engine.register("second_order_hint", SecondOrderHumanAssistStrategy())
    return _hitl_engine
