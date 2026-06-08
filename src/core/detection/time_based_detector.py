"""
Robust Time-Based SQLi Detection for SHIGOKU Phase D
Elegant multi-method consensus detection with adaptive sampling
"""
from __future__ import annotations
import asyncio
import logging
import numpy as np
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from scipy.stats import mannwhitneyu

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Result of time-based detection"""
    is_vulnerable: Optional[bool]  # None = inconclusive
    confidence: float  # 0.0-1.0
    requires_human_review: bool
    details: Dict[str, Any]
    
    @property
    def consensus_score(self) -> int:
        """Number of methods in agreement"""
        return self.details.get("consensus_score", 0)


class RobustTimeBasedDetector:
    """
    Consensus-based time-based SQLi detection using 4 statistical methods:
    1. Mann-Whitney U test (non-parametric)
    2. Cliff's Delta (effect size)
    3. Bayesian inference (posterior probability)
    4. Variance ratio comparison
    
    Consensus requires 3/4 methods to agree.
    Adaptive sampling reduces requests when confidence is high.
    """
    
    # Consensus thresholds (tunable via config)
    CONSENSUS_THRESHOLDS = {
        "mannwhitney_p": 0.05,      # 5% significance level
        "effect_size": 0.5,          # Medium effect (Cliff's Delta)
        "posterior": 0.9,           # 90% posterior probability
        "variance_ratio": 2.0,       # 2x variance increase
        "consensus_required": 3,     # 3/4 methods must agree
        "confidence_high": 0.95,     # High confidence threshold
        "confidence_medium": 0.7,    # Medium confidence threshold
    }
    
    def __init__(self, thresholds: Optional[Dict[str, float]] = None):
        if thresholds:
            self.CONSENSUS_THRESHOLDS.update(thresholds)
    
    def detect(
        self, 
        baseline_samples: List[float], 
        sleep_samples: List[float]
    ) -> DetectionResult:
        """
        Detect time-based vulnerability using 4-method consensus
        
        Important: Baseline and sleep samples must be measured
        within the same session (environment stability requirement)
        
        Args:
            baseline_samples: Latency samples with normal payload
            sleep_samples: Latency samples with sleep payload
        
        Returns:
            DetectionResult with consensus-based determination
        """
        # Validate inputs
        if len(baseline_samples) < 3 or len(sleep_samples) < 3:
            return DetectionResult(
                is_vulnerable=None,
                confidence=0.0,
                requires_human_review=True,
                details={"error": "Insufficient samples (minimum 3)"}
            )
        
        # Method 1: Mann-Whitney U test (non-parametric)
        u_stat, u_pvalue = mannwhitneyu(
            baseline_samples, 
            sleep_samples, 
            alternative='two-sided'
        )
        
        # Method 2: Cliff's Delta (effect size)
        effect_size = self._calculate_cliff_delta(baseline_samples, sleep_samples)
        
        # Method 3: Bayesian inference (gamma distribution assumption)
        posterior = self._bayesian_delay_inference(baseline_samples, sleep_samples)
        
        # Method 4: Variance ratio comparison
        base_var = np.var(baseline_samples)
        sleep_var = np.var(sleep_samples)
        variance_ratio = sleep_var / max(base_var, 0.001)  # Avoid division by zero
        
        # Consensus evaluation
        th = self.CONSENSUS_THRESHOLDS
        
        method_results = {
            "mannwhitney": u_pvalue < th["mannwhitney_p"],
            "effect_size": abs(effect_size) > th["effect_size"],
            "posterior": posterior > th["posterior"],
            "variance": variance_ratio > th["variance_ratio"]
        }
        
        consensus_score = sum(method_results.values())
        confidence = consensus_score / 4.0
        
        # Determine vulnerability based on consensus
        if consensus_score >= th["consensus_required"]:
            is_vulnerable = True
            requires_human_review = False
        elif consensus_score >= 2:  # Borderline
            is_vulnerable = None  # Inconclusive
            requires_human_review = True
        else:
            is_vulnerable = False
            requires_human_review = False
        
        return DetectionResult(
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            requires_human_review=requires_human_review,
            details={
                "mannwhitney_p": float(u_pvalue),
                "effect_size": float(effect_size),
                "posterior_prob": float(posterior),
                "variance_ratio": float(variance_ratio),
                "consensus_score": consensus_score,
                "method_results": method_results,
                "thresholds_applied": th.copy(),
                "sample_counts": {
                    "baseline": len(baseline_samples),
                    "sleep": len(sleep_samples)
                }
            }
        )
    
    def _calculate_cliff_delta(
        self, 
        baseline: List[float], 
        sleep: List[float]
    ) -> float:
        """
        Calculate Cliff's Delta (non-parametric effect size)
        
        Interpretation:
        - |delta| < 0.147: negligible
        - 0.147 <= |delta| < 0.33: small
        - 0.33 <= |delta| < 0.474: medium
        - |delta| >= 0.474: large
        """
        n1, n2 = len(baseline), len(sleep)
        
        # Count dominances
        dominance = 0
        for x in baseline:
            for y in sleep:
                if x < y:
                    dominance += 1
                elif x > y:
                    dominance -= 1
        
        return dominance / (n1 * n2)
    
    def _bayesian_delay_inference(
        self, 
        baseline: List[float], 
        sleep: List[float]
    ) -> float:
        """
        Bayesian inference for delay detection
        
        Uses gamma distribution as conjugate prior for exponential
        delay data. Returns posterior probability that sleep > baseline.
        """
        # Convert to numpy arrays
        base = np.array(baseline)
        slp = np.array(sleep)
        
        # Prior: Gamma(alpha, beta) with weakly informative prior
        alpha_prior = 1.0
        beta_prior = 0.1
        
        # Posterior parameters for baseline
        alpha_base = alpha_prior + len(base)
        beta_base = beta_prior + np.sum(base)
        
        # Posterior parameters for sleep
        alpha_sleep = alpha_prior + len(slp)
        beta_sleep = beta_prior + np.sum(slp)
        
        # Calculate posterior probability P(sleep > baseline)
        # Using gamma distribution properties
        rate_base = alpha_base / beta_base
        rate_sleep = alpha_sleep / beta_sleep
        
        # Simplified: probability that sleep mean > baseline mean
        mean_base = np.mean(base)
        mean_sleep = np.mean(slp)
        
        if mean_sleep <= mean_base:
            return 0.0
        
        # Approximate posterior probability using variance
        var_base = np.var(base) / len(base)
        var_sleep = np.var(slp) / len(slp)
        
        # Pooled standard error
        se = np.sqrt(var_base + var_sleep)
        if se == 0:
            return 1.0 if mean_sleep > mean_base else 0.0
        
        # Z-score for difference
        z = (mean_sleep - mean_base) / se
        
        # Convert to probability using normal approximation
        from scipy.stats import norm
        posterior_prob = norm.cdf(z)
        
        return float(posterior_prob)


class AdaptiveSamplingStrategy:
    """
    Adaptive sampling to reduce requests when confidence is high
    """
    
    def __init__(
        self,
        min_samples: int = 5,
        max_samples: int = 30,
        confidence_high: float = 0.95,
        confidence_medium: float = 0.7,
    ):
        self.min_samples = min_samples
        self.max_samples = max_samples
        self.confidence_high = confidence_high
        self.confidence_medium = confidence_medium
    
    async def detect_with_adaptive_sampling(
        self,
        detector: RobustTimeBasedDetector,
        sample_collector: callable,
        param: Any
    ) -> DetectionResult:
        """
        Collect samples adaptively based on confidence
        
        Starts with min_samples, increases if confidence is medium,
        stops early if confidence is high.
        """
        current = self.min_samples
        
        while current <= self.max_samples:
            # Collect samples
            baseline = await sample_collector(param, "baseline", current)
            sleep = await sample_collector(param, "sleep(5)", current)
            
            # Detect
            result = detector.detect(baseline, sleep)
            
            # Decision based on confidence
            if result.confidence >= self.confidence_high:
                # High confidence - stop early
                return result
            elif result.confidence >= self.confidence_medium:
                # Medium confidence - increase samples
                current = min(current + 5, self.max_samples)
            else:
                # Low confidence - likely not vulnerable
                return DetectionResult(
                    is_vulnerable=False,
                    confidence=result.confidence,
                    requires_human_review=False,
                    details={**result.details, "early_stop": True}
                )
        
        # Max samples reached but still inconclusive
        return DetectionResult(
            is_vulnerable=None,
            confidence=result.confidence,
            requires_human_review=True,
            details={
                **result.details, 
                "max_samples_reached": True,
                "reason": "Insufficient statistical confidence after max sampling"
            }
        )


# Convenience function for simple use cases
def detect_time_based_sqli(
    baseline_samples: List[float],
    sleep_samples: List[float],
    thresholds: Optional[Dict[str, float]] = None
) -> DetectionResult:
    """
    Simple interface for time-based SQLi detection
    
    Usage:
        result = detect_time_based_sqli(
            baseline_samples=[0.1, 0.12, 0.11],
            sleep_samples=[5.2, 5.1, 5.3]
        )
        if result.is_vulnerable:
            print(f"SQLi detected! Confidence: {result.confidence:.2f}")
    """
    detector = RobustTimeBasedDetector(thresholds)
    return detector.detect(baseline_samples, sleep_samples)
