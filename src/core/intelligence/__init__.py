"""Intelligence module for risk assessment, learning, and decision making."""
from src.core.intelligence.risk_predictor import (
    RiskPredictor,
    ActionRiskProfile,
    RiskAssessment,
    ActionType,
    RiskLevel,
    get_risk_predictor,
)
from src.core.learning.repository import get_learning_repository
from src.core.intelligence.self_reflection import (
    SelfReflection,
    ExecutionRecord,
    ExecutionOutcome,
    ReflectionInsight,
    get_self_reflection,
)
from src.core.intelligence.error_analyzer import (
    ErrorAnalyzer,
    ErrorRecord,
    ErrorCategory,
    RootCauseAnalysis,
    get_error_analyzer,
)
from src.core.intelligence.priority_booster import (
    PriorityBooster,
    BoostEvent,
    BoostTrigger,
    get_priority_booster,
)
from src.core.intelligence.failure_inference import (
    FailureInference,
    FailureContext,
    FailurePrediction,
    get_failure_inference,
)
from src.core.intelligence.decision_enhancer import (
    DecisionEnhancer,
    Decision,
    DecisionContext,
    EnhancedDecision,
    get_decision_enhancer,
)
from src.core.intelligence.diff_analyzer import (
    DiffAnalyzer,
    DiffResult,
    ScanSnapshot,
    get_diff_analyzer,
)
from src.core.intelligence.task_prioritizer import (
    TaskPrioritizer,
    get_task_prioritizer,
)
from src.core.intelligence.chain_builder import (
    AttackChainBuilder,
    AttackChain,
    AttackChainRule,
    get_chain_builder,
)
from src.core.intelligence.chain_proposal import (
    ChainProposalEngine,
    NullChainProposalEngine,
    LLMChainProposalEngine,
)
from src.core.intelligence.strategy_selector import (
    StrategySelector,
    StrategyDecision,
)

_default_self_reflection = None
_default_risk_predictor = None
_default_error_analyzer = None
_default_priority_booster = None
_default_decision_enhancer = None
_default_failure_inference = None
_default_diff_analyzer = None
_default_strategy_selector = None

def get_self_reflection():
    global _default_self_reflection
    if _default_self_reflection is None:
        _default_self_reflection = SelfReflection(repository=get_learning_repository())
    return _default_self_reflection

def get_risk_predictor():
    global _default_risk_predictor
    if _default_risk_predictor is None:
        _default_risk_predictor = RiskPredictor()
    return _default_risk_predictor

def get_error_analyzer():
    global _default_error_analyzer
    if _default_error_analyzer is None:
        _default_error_analyzer = ErrorAnalyzer(repository=get_learning_repository())
    return _default_error_analyzer

def get_priority_booster():
    global _default_priority_booster
    if _default_priority_booster is None:
        _default_priority_booster = PriorityBooster()
    return _default_priority_booster

def get_decision_enhancer():
    global _default_decision_enhancer
    if _default_decision_enhancer is None:
        _default_decision_enhancer = DecisionEnhancer(repository=get_learning_repository())
    return _default_decision_enhancer

def get_failure_inference():
    global _default_failure_inference
    if _default_failure_inference is None:
        _default_failure_inference = FailureInference()
    return _default_failure_inference

def get_diff_analyzer():
    global _default_diff_analyzer
    if _default_diff_analyzer is None:
        _default_diff_analyzer = DiffAnalyzer()
    return _default_diff_analyzer

def get_strategy_selector():
    global _default_strategy_selector
    if _default_strategy_selector is None:
        _default_strategy_selector = StrategySelector()
    return _default_strategy_selector

__all__ = [
    # Risk Predictor
    "RiskPredictor",
    "ActionRiskProfile",
    "RiskAssessment",
    "ActionType",
    "RiskLevel",
    "get_risk_predictor",
    # Self Reflection
    "SelfReflection",
    "ExecutionRecord",
    "ExecutionOutcome",
    "ReflectionInsight",
    "get_self_reflection",
    # Error Analyzer
    "ErrorAnalyzer",
    "ErrorRecord",
    "ErrorCategory",
    "RootCauseAnalysis",
    "get_error_analyzer",
    # Priority Booster
    "PriorityBooster",
    "get_priority_booster",
    # Failure Inference
    "FailureInference",
    "FailureContext",
    "FailurePrediction",
    "get_failure_inference",
    # Decision Enhancer
    "DecisionEnhancer",
    "Decision",
    "DecisionContext",
    "EnhancedDecision",
    "get_decision_enhancer",
    # Diff Analyzer
    "DiffAnalyzer",
    "DiffResult",
    "ScanSnapshot",
    "get_diff_analyzer",
    # Task Prioritizer
    "TaskPrioritizer",
    "get_task_prioritizer",
    # Attack Chain Builder
    "AttackChainBuilder",
    "AttackChain",
    "AttackChainRule",
    "get_chain_builder",
    "ChainProposalEngine",
    "NullChainProposalEngine",
    "LLMChainProposalEngine",
    # Strategy Selector
    "StrategySelector",
    "StrategyDecision",
    "get_strategy_selector",
]
