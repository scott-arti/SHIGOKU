from __future__ import annotations

import json
import time
from typing import Any, Callable, Optional, Protocol

from src.core.models.finding import Finding


class ChainProposalEngine(Protocol):
    def propose(
        self,
        findings: list[Finding],
        runtime_context: Optional[dict[str, Any]] = None,
    ) -> list[dict[str, Any]]:
        ...


class NullChainProposalEngine:
    last_skip_reason: Optional[str] = None

    def propose(
        self,
        findings: list[Finding],
        runtime_context: Optional[dict[str, Any]] = None,
    ) -> list[dict[str, Any]]:
        return []

    def get_diagnostics(self) -> dict[str, Any]:
        return {
            "proposal_engine": self.__class__.__name__,
            "proposal_model": "",
            "proposal_timeout_ms": 0,
            "proposal_max_candidates": 0,
            "proposal_budget_remaining": 0,
            "proposal_budget_consumed": 0,
        }


class LLMChainProposalEngine:
    REQUIRED_KEYS = {
        "objective",
        "path",
        "required_findings",
        "missing_evidence",
        "exploitability_evidence",
        "foothold_reliability",
        "expected_attempts_to_success",
        "business_impact_hypothesis",
        "recommended_probe",
        "reasoning_summary",
    }

    def __init__(
        self,
        *,
        response_provider: Callable[[list[Finding], Optional[dict[str, Any]]], str],
        timeout_ms: int,
        max_candidates: int,
        session_budget: int,
        model_name: str = "",
    ) -> None:
        self._response_provider = response_provider
        self._timeout_ms = max(1, int(timeout_ms or 1))
        self._max_candidates = max(1, int(max_candidates or 1))
        self._session_budget = max(0, int(session_budget or 0))
        self._remaining_budget = self._session_budget
        self._model_name = str(model_name or "").strip()
        self.last_skip_reason: Optional[str] = None

    @classmethod
    def from_llm_client(
        cls,
        *,
        llm_client: Any,
        model_name: str,
        timeout_ms: int,
        max_candidates: int,
        session_budget: int,
    ) -> "LLMChainProposalEngine":
        def _provider(findings: list[Finding], runtime_context: Optional[dict[str, Any]]) -> str:
            prompt = _build_chain_proposal_prompt(findings, runtime_context)
            response = llm_client.generate(
                messages=[
                    {"role": "system", "content": _CHAIN_PROPOSAL_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                model=model_name,
                response_format={"type": "json_object"},
                temperature=0.1,
                timeout=max(0.001, float(timeout_ms) / 1000.0),
                force_cloud=True,
            )
            return _extract_response_content(response)

        return cls(
            response_provider=_provider,
            timeout_ms=timeout_ms,
            max_candidates=max_candidates,
            session_budget=session_budget,
            model_name=model_name,
        )

    def propose(
        self,
        findings: list[Finding],
        runtime_context: Optional[dict[str, Any]] = None,
    ) -> list[dict[str, Any]]:
        if self._remaining_budget <= 0:
            self.last_skip_reason = "budget_exceeded"
            return []

        self._remaining_budget -= 1
        started_at = time.monotonic()
        try:
            raw = self._response_provider(findings, runtime_context)
        except TimeoutError:
            self.last_skip_reason = "timeout"
            return []

        elapsed_ms = (time.monotonic() - started_at) * 1000.0
        if elapsed_ms > float(self._timeout_ms):
            self.last_skip_reason = "timeout"
            return []

        try:
            payload = json.loads(str(raw))
        except (TypeError, ValueError):
            self.last_skip_reason = "invalid_json"
            return []

        if not isinstance(payload, dict):
            self.last_skip_reason = "invalid_json"
            return []

        candidates = payload.get("candidates", [])
        if not isinstance(candidates, list):
            self.last_skip_reason = "invalid_json"
            return []

        validated: list[dict[str, Any]] = []
        for candidate in candidates:
            normalized = self._normalize_candidate(candidate)
            if normalized is not None:
                validated.append(normalized)
            if len(validated) >= self._max_candidates:
                break

        if not validated:
            self.last_skip_reason = "schema_validation_failed"
            return []

        self.last_skip_reason = None
        return validated

    def get_diagnostics(self) -> dict[str, Any]:
        return {
            "proposal_engine": self.__class__.__name__,
            "proposal_model": self._model_name,
            "proposal_timeout_ms": self._timeout_ms,
            "proposal_max_candidates": self._max_candidates,
            "proposal_budget_remaining": self._remaining_budget,
            "proposal_budget_consumed": self._session_budget - self._remaining_budget,
        }

    def _normalize_candidate(self, candidate: Any) -> Optional[dict[str, Any]]:
        if not isinstance(candidate, dict):
            return None
        if not self.REQUIRED_KEYS.issubset(candidate.keys()):
            return None

        path = [str(item).strip().lower() for item in candidate.get("path", []) if str(item).strip()]
        required_findings = [str(item).strip() for item in candidate.get("required_findings", []) if str(item).strip()]
        missing_evidence = [str(item).strip() for item in candidate.get("missing_evidence", []) if str(item).strip()]
        exploitability_evidence = [str(item).strip() for item in candidate.get("exploitability_evidence", []) if str(item).strip()]
        if not path or not required_findings:
            return None

        try:
            reliability = float(candidate.get("foothold_reliability", 0.0) or 0.0)
            expected_attempts = int(candidate.get("expected_attempts_to_success", 1) or 1)
        except (TypeError, ValueError):
            return None

        return {
            "objective": str(candidate.get("objective", "")).strip().lower(),
            "path": path,
            "required_findings": required_findings,
            "missing_evidence": missing_evidence,
            "exploitability_evidence": exploitability_evidence,
            "foothold_reliability": max(0.0, min(1.0, reliability)),
            "expected_attempts_to_success": max(1, expected_attempts),
            "business_impact_hypothesis": str(candidate.get("business_impact_hypothesis", "")).strip(),
            "recommended_probe": str(candidate.get("recommended_probe", "")).strip(),
            "reasoning_summary": str(candidate.get("reasoning_summary", "")).strip(),
        }


_CHAIN_PROPOSAL_SYSTEM_PROMPT = (
    "You are a security chain proposal engine. "
    "Output strict JSON only with top-level key 'candidates'. "
    "Do not include markdown."
)


def _build_chain_proposal_prompt(
    findings: list[Finding],
    runtime_context: Optional[dict[str, Any]] = None,
) -> str:
    serialized_findings = []
    for finding in findings:
        serialized_findings.append(
            {
                "id": getattr(finding, "id", ""),
                "vuln_type": str(getattr(getattr(finding, "vuln_type", ""), "value", "")).strip().lower(),
                "severity": str(getattr(getattr(finding, "severity", ""), "value", "")).strip().lower(),
                "title": str(getattr(finding, "title", "")).strip(),
                "description": str(getattr(finding, "description", "")).strip(),
                "target_url": str(getattr(finding, "target_url", "")).strip(),
                "tags": [str(item).strip().lower() for item in (getattr(finding, "tags", []) or []) if str(item).strip()],
                "additional_info": getattr(finding, "additional_info", {}) or {},
            }
        )
    prompt_payload = {
        "task": "propose_vulnerability_chains",
        "runtime_context": runtime_context or {},
        "findings": serialized_findings,
        "output_schema": {
            "candidates": [
                {
                    "objective": "string",
                    "path": ["string"],
                    "required_findings": ["finding_id"],
                    "missing_evidence": ["string"],
                    "exploitability_evidence": ["string"],
                    "foothold_reliability": "0.0-1.0",
                    "expected_attempts_to_success": "integer >= 1",
                    "business_impact_hypothesis": "string",
                    "recommended_probe": "string",
                    "reasoning_summary": "string",
                }
            ]
        },
    }
    return json.dumps(prompt_payload, ensure_ascii=False, sort_keys=True)


def _extract_response_content(response: Any) -> str:
    choices = getattr(response, "choices", None)
    if choices:
        first = choices[0]
        message = getattr(first, "message", None)
        content = getattr(message, "content", None) if message is not None else None
        if content is not None:
            return str(content)
    return str(response)
