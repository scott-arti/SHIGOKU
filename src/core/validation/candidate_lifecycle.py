"""
SGK-2026-0444 T2 — candidate lifecycle (candidate_lifecycle.py).

Owns the candidate lifecycle state machine and the parked-store semantics:

- ``LifecycleState``: 5-state enum (needs_more / inconclusive_parked /
  needs_human / confirmed / refuted).
- ``CandidateRecord``: persisted projection of one candidate. URL fields and
  the evidence summary are ALREADY masked (0439 mask_url_query_values) when
  the record is built; the ledger applies the lowest-write-API masking
  boundary again on save (idempotent, never stores the token_map).
- ``CandidateLifecycleManager.apply_verdict``: the ONLY state-transition
  entry. Contract (approved design, plan appendix B):
  * record None -> new record (state=needs_more, budget_used=1).
  * record.state != needs_more -> NO-OP (parked/needs_human/terminal leave
    ONLY via revisit(); no blind retry).
  * needs_more -> CONFIRMED/REFUTED/NEEDS_HUMAN verdicts move to the
    terminal states with the verdict reason; INCONCLUSIVE parks immediately
    (D1 — never refuted); NEEDS_MORE parks on budget exhaustion
    (budget_used >= max_visits OR age > max_age_days) as needs_human when
    promise_score >= human_promise_threshold, else inconclusive_parked with
    reason="budget_exhausted" plus revisit triggers.
  * Structural invariant (D3): the lifecycle NEVER produces refuted except
    from verdict.state == REFUTED — no refute-without-proof.
- ``derive_triggers``: product-independent default trigger derivation from
  ``finding_payload(finding)`` (guarded; missing fields skipped).
- ``revisit``: only inconclusive_parked records whose triggers intersect
  new_information minus consumed resurrection_history are resurrected
  (budget reset, resurrection_count + 1). Non-matching parked records are
  NEVER touched.
- ``allocate_investigation_budget``: needs_more only, promise_score desc /
  last_investigated asc / first_seen asc, capped at run_budget.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urlsplit

from src.core.agents.swarm.injection.payout_grade import finding_payload
from src.core.security.pii_masker import get_pii_masker
from src.core.validation.finding_validator import HybridVerdict, VerdictState

logger = logging.getLogger(__name__)


class LifecycleState(str, Enum):
    """Candidate lifecycle states (str-backed for stable serialization)."""

    NEEDS_MORE = "needs_more"
    INCONCLUSIVE_PARKED = "inconclusive_parked"
    NEEDS_HUMAN = "needs_human"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"


@dataclass
class CandidateRecord:
    """Persisted projection of one candidate (masked; no raw secrets)."""

    finding_id: str
    state: LifecycleState
    reason: str                      # stable reason code (last verdict reason or "budget_exhausted")
    vuln_type: str
    title: str
    target_url_masked: str           # 0439-masked URL
    evidence_summary: dict           # masked projection: refs / request_url_masked / response_status
    first_seen: str                  # ISO8601 UTC
    last_investigated: str
    budget_used: int
    resurrection_count: int
    promise_score: float
    revisit_triggers: list = field(default_factory=list)       # [(type, value)] typed tokens
    resurrection_history: list = field(default_factory=list)   # tokens already consumed for resurrection


def _stringify(value: Any) -> str:
    """Enum-aware string projection ('' for None/empty)."""
    if isinstance(value, Enum):
        value = value.value
    return str(value or "")


class CandidateLifecycleManager:
    """State machine + trigger/budget logic for candidate records.

    ``now`` is injectable for deterministic tests (default: UTC now).
    """

    def __init__(
        self,
        *,
        max_visits: int = 3,
        max_age_days: int = 30,
        human_promise_threshold: float = 0.67,
        now: Optional[Callable[[], datetime]] = None,
    ):
        self.max_visits = max_visits
        self.max_age_days = max_age_days
        self.human_promise_threshold = human_promise_threshold
        self._now_fn: Callable[[], datetime] = (
            now if now is not None else (lambda: datetime.now(timezone.utc))
        )

    # ------------------------------------------------------------------
    # state transitions
    # ------------------------------------------------------------------

    def apply_verdict(
        self,
        record: Optional[CandidateRecord],
        verdict: HybridVerdict,
        finding: Any = None,
        *,
        extra_triggers: Iterable[tuple] = (),
    ) -> CandidateRecord:
        """Apply one verdict to a candidate (transition contract above).

        Parked / needs_human / terminal records are returned UNCHANGED
        (no-op) — they leave the parked state ONLY via ``revisit()``.
        """
        if record is None:
            return self._new_record(verdict, finding)
        if record.state != LifecycleState.NEEDS_MORE:
            return record
        record.promise_score = verdict.promise_score
        record.last_investigated = self._now_iso()
        record.budget_used += 1
        if verdict.state == VerdictState.CONFIRMED:
            record.state = LifecycleState.CONFIRMED
            record.reason = verdict.reason
        elif verdict.state == VerdictState.REFUTED:
            # D3: refuted is reachable ONLY from a REFUTED verdict.
            record.state = LifecycleState.REFUTED
            record.reason = verdict.reason
        elif verdict.state == VerdictState.NEEDS_HUMAN:
            record.state = LifecycleState.NEEDS_HUMAN
            record.reason = verdict.reason
        elif verdict.state == VerdictState.INCONCLUSIVE:
            # D1: park immediately — never refute without proof.
            self._park(record, reason=verdict.reason, finding=finding, extra_triggers=extra_triggers)
        elif self._budget_exhausted(record):
            if record.promise_score >= self.human_promise_threshold:
                record.state = LifecycleState.NEEDS_HUMAN
                record.reason = "budget_exhausted"
            else:
                self._park(
                    record,
                    reason="budget_exhausted",
                    finding=finding,
                    extra_triggers=extra_triggers,
                )
        # else: stays needs_more (budget not exhausted yet)
        return record

    def _new_record(self, verdict: HybridVerdict, finding: Any) -> CandidateRecord:
        now_iso = self._now_iso()
        payload = finding_payload(finding)
        evidence = payload.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        summary: dict = {"refs": list(verdict.evidence_refs)}
        request_url = evidence.get("request_url")
        if request_url:
            summary["request_url_masked"] = get_pii_masker().mask_url_query_values(str(request_url))
        status_raw = evidence.get("response_status")
        if status_raw is not None:
            summary["response_status"] = self._to_status_int(status_raw)
        target_url = payload.get("target_url")
        return CandidateRecord(
            finding_id=str(payload.get("id") or ""),
            state=LifecycleState.NEEDS_MORE,
            reason=verdict.reason,
            vuln_type=_stringify(payload.get("vuln_type")),
            title=str(payload.get("title") or ""),
            target_url_masked=(
                get_pii_masker().mask_url_query_values(str(target_url)) if target_url else ""
            ),
            evidence_summary=summary,
            first_seen=now_iso,
            last_investigated=now_iso,
            budget_used=1,
            resurrection_count=0,
            promise_score=verdict.promise_score,
            revisit_triggers=[],
            resurrection_history=[],
        )

    @staticmethod
    def _to_status_int(status_raw: Any) -> Optional[int]:
        """Guarded int(status) -> int, or None when absent/unparseable."""
        try:
            return int(status_raw) or None
        except (TypeError, ValueError):
            return None

    def _park(
        self,
        record: CandidateRecord,
        *,
        reason: str,
        finding: Any,
        extra_triggers: Iterable[tuple],
    ) -> None:
        record.state = LifecycleState.INCONCLUSIVE_PARKED
        record.reason = reason
        record.revisit_triggers = self._dedup(
            list(self.derive_triggers(finding)) + list(extra_triggers)
        )

    def _budget_exhausted(self, record: CandidateRecord) -> bool:
        return (
            record.budget_used >= self.max_visits
            or self._age_days(self._now(), record.first_seen) > self.max_age_days
        )

    # ------------------------------------------------------------------
    # revisit triggers
    # ------------------------------------------------------------------

    def derive_triggers(self, finding: Any) -> list:
        """Product-independent default trigger derivation.

        From ``finding_payload(finding)`` (guarded, missing fields skipped):
        ("vuln_type", vuln_type) when present; ("endpoint", normalized
        target_url); ("endpoint", normalized evidence.request_url);
        ("capability", source_agent) when non-empty; ("capability", tag) for
        each non-empty tag. Order-preserving dedup. None finding -> [].
        """
        if finding is None:
            return []
        payload = finding_payload(finding)
        triggers: list = []
        vuln_type = payload.get("vuln_type")
        if isinstance(vuln_type, Enum):
            vuln_type = vuln_type.value
        if str(vuln_type or "").strip():
            triggers.append(("vuln_type", str(vuln_type)))
        target_url = payload.get("target_url")
        if target_url:
            endpoint = self.normalize_endpoint(str(target_url))
            if endpoint:
                triggers.append(("endpoint", endpoint))
        evidence = payload.get("evidence")
        if isinstance(evidence, dict):
            request_url = evidence.get("request_url")
            if request_url:
                endpoint = self.normalize_endpoint(str(request_url))
                if endpoint:
                    triggers.append(("endpoint", endpoint))
        source_agent = payload.get("source_agent")
        if str(source_agent or "").strip():
            triggers.append(("capability", str(source_agent)))
        tags = payload.get("tags")
        if isinstance(tags, (list, tuple)):
            for tag in tags:
                tag_str = str(tag or "").strip()
                if tag_str:
                    triggers.append(("capability", tag_str))
        return self._dedup(triggers)

    def revisit(self, records: Iterable[CandidateRecord], new_information: Iterable[tuple]) -> list:
        """Resurrect parked candidates whose triggers match new information.

        For each inconclusive_parked record:
        matched = (new_information & revisit_triggers) - resurrection_history.
        Non-empty matched -> resurrected COPY (state=needs_more,
        budget_used=0, resurrection_count+1, history extended and sorted,
        last_investigated=now). Non-matching parked records are NEVER
        touched (blind-retry prevention). Returns only the resurrected
        records.
        """
        new_set = set(new_information)
        resurrected: list = []
        for record in records:
            if record.state != LifecycleState.INCONCLUSIVE_PARKED:
                continue
            matched = (
                (new_set & set(record.revisit_triggers)) - set(record.resurrection_history)
            )
            if not matched:
                continue
            resurrected.append(
                replace(
                    record,
                    state=LifecycleState.NEEDS_MORE,
                    budget_used=0,
                    resurrection_count=record.resurrection_count + 1,
                    resurrection_history=sorted(set(record.resurrection_history) | matched),
                    last_investigated=self._now_iso(),
                )
            )
        return resurrected

    # ------------------------------------------------------------------
    # budget / ranking
    # ------------------------------------------------------------------

    def allocate_investigation_budget(
        self, records: Iterable[CandidateRecord], run_budget: int = 10
    ) -> list:
        """needs_more records only, ranked by (promise desc, last_investigated
        asc, first_seen asc), capped at run_budget."""
        candidates = [r for r in records if r.state == LifecycleState.NEEDS_MORE]
        candidates.sort(key=lambda r: (-r.promise_score, r.last_investigated, r.first_seen))
        return candidates[:run_budget]

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_endpoint(url: str) -> str:
        """Normalize a URL to a stable endpoint trigger token.

        Requires scheme + hostname (else ""). Lowercases scheme+host, keeps
        the port, strips query/fragment/userinfo. Path: strip trailing "/"
        (keep "/" for empty/root). Unparseable URLs (bad port, no scheme,
        no host) -> "".
        """
        if not url:
            return ""
        try:
            parsed = urlsplit(str(url))
            scheme = (parsed.scheme or "").lower()
            if not scheme or not parsed.hostname:
                return ""
            port = parsed.port  # raises ValueError on invalid port
            host = parsed.hostname.lower()
            if port is not None:
                host = f"{host}:{port}"
        except ValueError:
            return ""
        path = parsed.path or "/"
        if path != "/":
            path = path.rstrip("/")
        return f"{scheme}://{host}{path}"

    @staticmethod
    def hash_account_token(token: str) -> str:
        """sha256 hexdigest, first 12 chars — for ("account", ...) trigger
        tokens so raw account identifiers are never stored."""
        return hashlib.sha256(str(token).encode("utf-8")).hexdigest()[:12]

    @staticmethod
    def _age_days(now: datetime, first_seen_iso: str) -> float:
        """Age in days; unparseable first_seen -> inf (fail-closed park)."""
        try:
            first = datetime.fromisoformat(str(first_seen_iso))
        except (ValueError, TypeError):
            return float("inf")
        if first.tzinfo is None:
            first = first.replace(tzinfo=timezone.utc)
        ref = now
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)
        return (ref - first).total_seconds() / 86400.0

    @staticmethod
    def _dedup(items: Iterable) -> list:
        """Order-preserving dedup."""
        seen = set()
        out = []
        for item in items:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out

    def _now(self) -> datetime:
        return self._now_fn()

    def _now_iso(self) -> str:
        return self._now().isoformat()
