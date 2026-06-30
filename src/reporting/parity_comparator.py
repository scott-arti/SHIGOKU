"""Phase 9 parity comparator: forced serial vs gated finding parity.

Reuses canonical extract_all_findings() for finding set extraction
and compares High/Critical findings for 100% parity required by
the Phase 9 release gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from src.reporting.finding_extractor import extract_all_findings

# Allowed differential axes between serial and gated runs.
# These differences do not invalidate finding parity.
ALLOWED_DIFFERENTIAL_AXES = frozenset({
    "status",
    "body_length",
    "json_shape",
    "dom_marker",
    "redirect_chain",
    "cache_header",
    "timing_delta",
})

# Severities that must achieve 100% parity
CRITICAL_SEVERITIES = frozenset({"high", "critical", "High", "Critical", "HIGH", "CRITICAL"})


@dataclass
class FindingKey:
    """Canonical key for deduplicating and comparing findings."""
    severity: str = ""
    finding_id: str = ""
    target: str = ""
    evidence_key: str = ""

    def to_tuple(self) -> Tuple[str, str, str, str]:
        return (self.severity, self.finding_id, self.target, self.evidence_key)

    def __hash__(self) -> int:
        return hash(self.to_tuple())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FindingKey):
            return NotImplemented
        return self.to_tuple() == other.to_tuple()


@dataclass
class ResponseDifferential:
    """Recorded response difference between serial and gated paths."""
    axis: str  # e.g. "status", "body_length", "timing_delta"
    serial_value: Any = None
    gated_value: Any = None
    allowed: bool = True  # True if axis is in ALLOWED_DIFFERENTIAL_AXES

    def is_blocking(self) -> bool:
        return not self.allowed


@dataclass
class ParityResult:
    """Outcome of forced-serial vs gated finding parity comparison."""
    parity_achieved: bool
    serial_finding_count: int
    gated_finding_count: int
    high_critical_serial_count: int
    high_critical_gated_count: int
    high_critical_parity: bool  # 100% required
    missing_in_gated: List[Dict[str, Any]] = field(default_factory=list)
    missing_in_serial: List[Dict[str, Any]] = field(default_factory=list)
    differentials: List[ResponseDifferential] = field(default_factory=list)
    parity_percentage: float = 0.0

    def to_evidence_dict(self) -> Dict[str, Any]:
        return {
            "serial_gated_match": self.parity_achieved,
            "high_critical_parity": 100.0 if self.high_critical_parity else 0.0,
            "serial_finding_count": self.serial_finding_count,
            "gated_finding_count": self.gated_finding_count,
            "high_critical_serial_count": self.high_critical_serial_count,
            "high_critical_gated_count": self.high_critical_gated_count,
            "missing_in_gated_count": len(self.missing_in_gated),
            "missing_in_serial_count": len(self.missing_in_serial),
            "blocking_differential_count": sum(1 for d in self.differentials if d.is_blocking()),
            "parity_percentage": self.parity_percentage,
        }


def _build_finding_key(finding: Dict[str, Any]) -> FindingKey:
    """Build canonical key from a finding dict."""
    severity = str(finding.get("severity", "") or "").lower()
    finding_id = str(finding.get("id", "") or finding.get("finding_id", "") or "")
    target = str(finding.get("target", "") or finding.get("source_url", "") or "")
    evidence_key = str(finding.get("evidence_key", "") or finding.get("_source_task_id", "") or "")
    return FindingKey(severity=severity, finding_id=finding_id, target=target, evidence_key=evidence_key)


def _is_high_critical(finding: Dict[str, Any]) -> bool:
    severity = str(finding.get("severity", "") or "").strip()
    return severity.lower() in {"high", "critical"}


def extract_finding_keys(
    session_data: Dict[str, Any],
    *,
    high_critical_only: bool = False,
) -> Set[FindingKey]:
    """Extract canonical finding keys from session data.

    Uses canonical extract_all_findings() and builds FindingKey
    for deduplication and comparison.

    Args:
        session_data: Raw session dict.
        high_critical_only: If True, only High/Critical severity findings.

    Returns:
        Set of FindingKey objects.
    """
    all_findings = extract_all_findings(session_data)
    keys: Set[FindingKey] = set()
    for f in all_findings:
        if high_critical_only and not _is_high_critical(f):
            continue
        keys.add(_build_finding_key(f))
    return keys


def compare_findings(
    serial_session: Dict[str, Any],
    gated_session: Dict[str, Any],
    *,
    high_critical_only: bool = True,
) -> ParityResult:
    """Compare forced serial vs gated path findings.

    Uses canonical extract_all_findings() for both paths, compares
    High/Critical finding sets for 100% parity (required by Phase 9 gate).

    Args:
        serial_session: Session data from forced serial (kill_switch=true) path.
        gated_session: Session data from gated parallel path.
        high_critical_only: If True, only compare High/Critical findings.

    Returns:
        ParityResult with parity_achieved, counts, missing findings, and differentials.
    """
    serial_keys = extract_finding_keys(serial_session, high_critical_only=high_critical_only)
    gated_keys = extract_finding_keys(gated_session, high_critical_only=high_critical_only)

    # Full counts (not filtered)
    all_serial = extract_finding_keys(serial_session, high_critical_only=False)
    all_gated = extract_finding_keys(gated_session, high_critical_only=False)

    missing_in_gated = serial_keys - gated_keys
    missing_in_serial = gated_keys - serial_keys

    # High/Critical only stats
    hc_serial = extract_finding_keys(serial_session, high_critical_only=True)
    hc_gated = extract_finding_keys(gated_session, high_critical_only=True)

    hc_parity = (hc_serial == hc_gated)

    total_keys = len(serial_keys | gated_keys)
    if total_keys == 0:
        parity_pct = 100.0
    else:
        matched = total_keys - len(missing_in_gated) - len(missing_in_serial)
        parity_pct = round(matched / total_keys * 100.0, 2)

    return ParityResult(
        parity_achieved=(len(missing_in_gated) == 0 and len(missing_in_serial) == 0),
        serial_finding_count=len(all_serial),
        gated_finding_count=len(all_gated),
        high_critical_serial_count=len(hc_serial),
        high_critical_gated_count=len(hc_gated),
        high_critical_parity=hc_parity,
        missing_in_gated=[
            {"severity": k.severity, "id": k.finding_id, "target": k.target, "evidence_key": k.evidence_key}
            for k in sorted(missing_in_gated, key=lambda k: k.to_tuple())
        ],
        missing_in_serial=[
            {"severity": k.severity, "id": k.finding_id, "target": k.target, "evidence_key": k.evidence_key}
            for k in sorted(missing_in_serial, key=lambda k: k.to_tuple())
        ],
        parity_percentage=parity_pct,
    )


def record_response_differential(
    axis: str,
    serial_value: Any,
    gated_value: Any,
) -> ResponseDifferential:
    """Record a single response differential between serial and gated paths.

    Args:
        axis: Differential axis name (status, body_length, etc.).
        serial_value: Value from forced serial path.
        gated_value: Value from gated parallel path.

    Returns:
        ResponseDifferential with allowed flag based on ALLOWED_DIFFERENTIAL_AXES.
    """
    allowed = axis.lower() in ALLOWED_DIFFERENTIAL_AXES
    return ResponseDifferential(
        axis=axis,
        serial_value=serial_value,
        gated_value=gated_value,
        allowed=allowed,
    )
