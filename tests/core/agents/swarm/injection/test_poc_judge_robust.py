"""
SGK-2026-0461 Option B — poc_judge robust wrapper (poc_judge_robust.py).

Proves (additive; the frozen bar files poc_judge.md / finding_validator.py /
sealed_reproduction_checker.py are NOT modified):
- clean JSON parses with a single LLM call
- JSON salvage: trailing prose, leading prose, fenced JSON, first-object
  extraction (no fabrication)
- bounded retry ONLY on parse failure; a legitimate rejection
  (payout_grade=false) is never re-rolled
- fail-closed: all attempts unparseable -> ValueError (wiring maps to
  ai_judge=None -> needs_more; never confirmed)
- per-call timeout clamping (DEFAULT_TIMEOUT_SECONDS)
- run-wide budget still applies (JudgeBudgetExhausted)
- AI reason is pii-masked before it reaches the verdict path
"""
from __future__ import annotations

import json

import pytest

from src.core.agents.swarm.injection.poc_judge_robust import (
    DEFAULT_TIMEOUT_SECONDS,
    RobustPoCJudge,
    _BoundedLLMClient,
)
from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.validation.finding_validator import PoCJudge
from src.core.validation.sealed_reproduction_checker import (
    BudgetedPoCJudge,
    JudgeBudgetExhausted,
    PoCJudgeBudget,
)

API_URL = "http://target.example/app/api/v2/user/"


def _llm_client(contents):
    """A fake LLM client: pops one content per generate() call and records
    the kwargs (incl. the forced timeout) on ``.calls``."""

    class _Fake:
        def __init__(self):
            self.calls = []

        def generate(self, messages, **kwargs):
            self.calls.append(kwargs)
            content = contents.pop(0)
            return {"choices": [{"message": {"content": content}}]}

    return _Fake()


def _valid_json(payout_grade=True) -> str:
    """A complete, structurally valid poc_judge judgement JSON."""
    return json.dumps(
        {
            "payout_grade": payout_grade,
            "is_real": True,
            "has_actual_impact": True,
            "counter_evidence": False,
            "needs_human": False,
            "evidence_refs": ["ref-1"],
            "markers": ["reflected_payload"],
            "reason": "solid reproduction evidence",
        },
        ensure_ascii=False,
    )


def _finding(title: str = "Robust judge finding") -> Finding:
    return Finding(
        vuln_type=VulnType.XSS,
        severity=Severity.MEDIUM,
        title=title,
        description="d",
        target_url=API_URL,
        evidence=Evidence(
            request_method="GET",
            request_url=f"{API_URL}?q=1",
            response_status=200,
            response_body="<script>alert(1)</script>",
        ),
        impact="XSS",
        reproduction_steps=["GET"],
        additional_info={},
    )


def _robust(fake) -> RobustPoCJudge:
    """RobustPoCJudge around a real (frozen) PoCJudge.

    The fake client is wrapped in ``_BoundedLLMClient`` so the JSON-salvage /
    timeout-clamping layer is actually exercised (the frozen PoCJudge itself
    is byte-identical and still applies its own fail-closed parse).
    """
    return RobustPoCJudge(inner=PoCJudge(client=_BoundedLLMClient(fake)))


class TestRobustPoCJudge:
    def test_judge_parses_clean_json(self):
        fake = _llm_client([_valid_json()])
        res = _robust(fake).judge(_finding())
        assert res.payout_grade is True
        assert len(fake.calls) == 1

    def test_judge_salvages_trailing_prose(self):
        fake = _llm_client([_valid_json() + "\n以上です。"])
        res = _robust(fake).judge(_finding())
        assert res.payout_grade is True
        assert len(fake.calls) == 1

    def test_judge_salvages_leading_prose(self):
        fake = _llm_client(["以下は判定です\n" + _valid_json()])
        res = _robust(fake).judge(_finding())
        assert res.payout_grade is True

    def test_judge_salvages_fenced_json_with_prose(self):
        fake = _llm_client(["```json\n" + _valid_json() + "\n```\n補足"])
        res = _robust(fake).judge(_finding())
        assert res.payout_grade is True

    def test_judge_salvages_first_object(self):
        # Two JSON objects concatenated: the FIRST object's verdict wins.
        fake = _llm_client(
            [_valid_json(payout_grade=True) + "\n" + _valid_json(payout_grade=False)]
        )
        res = _robust(fake).judge(_finding())
        assert res.payout_grade is True

    def test_judge_retries_on_unparseable_then_succeeds(self):
        fake = _llm_client(["not json at all", _valid_json()])
        res = _robust(fake).judge(_finding())
        assert res.payout_grade is True
        assert len(fake.calls) == 2

    def test_judge_fail_closed_after_all_attempts(self):
        fake = _llm_client(["garbage", "garbage"])
        with pytest.raises(ValueError):
            _robust(fake).judge(_finding())
        assert len(fake.calls) == 2  # max_attempts

    def test_legitimate_rejection_never_retried(self):
        fake = _llm_client([_valid_json(payout_grade=False)])
        res = _robust(fake).judge(_finding())
        assert res.payout_grade is False
        assert len(fake.calls) == 1  # exactly once, no re-roll

    def test_timeout_forced_on_generate(self):
        fake = _llm_client([_valid_json(), _valid_json()])
        bounded = _BoundedLLMClient(fake)
        bounded.generate([{"role": "user", "content": "x"}])
        bounded.generate([{"role": "user", "content": "x"}], timeout=9999.0)
        assert len(fake.calls) == 2
        for kwargs in fake.calls:
            assert kwargs["timeout"] <= DEFAULT_TIMEOUT_SECONDS
        # an explicit larger timeout must be clamped, never exceeded
        assert fake.calls[1]["timeout"] <= DEFAULT_TIMEOUT_SECONDS

    def test_budget_wrapper_still_applies(self):
        fake = _llm_client([_valid_json(), _valid_json()])
        budgeted = BudgetedPoCJudge(_robust(fake), PoCJudgeBudget(max_calls=1))
        assert budgeted.judge(_finding()).payout_grade is True
        with pytest.raises(JudgeBudgetExhausted):
            budgeted.judge(_finding())

    def test_masker_applied_to_reason(self):
        payload = json.loads(_valid_json())
        payload["reason"] = "auth used Bearer abc123 (token=abc123)"
        fake = _llm_client([json.dumps(payload, ensure_ascii=False)])
        res = _robust(fake).judge(_finding())
        assert "[PII" in res.reason_masked or "abc123" not in res.reason_masked
