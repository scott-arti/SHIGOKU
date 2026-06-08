"""XCTO-10 runtime wiring RED tests.

TDD target: wire learning updates into real payload selection / request execution flow.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.core.payloads.xss_waf_evasion import (
    OutcomeType,
    XSSContext,
    XSSPayload,
    XSSWAFEvasionSuite,
    WafTechnique,
)


@dataclass
class _DummyStats:
    trials: int
    successes: int


class _DummyOptimizer:
    def __init__(self) -> None:
        self.classify_called = False
        self.updated = []

    def get_payloads_for_context(self, context, max_payloads):
        a = XSSPayload(raw="A", context=context, technique=WafTechnique.ENCODING)
        b = XSSPayload(raw="B", context=context, technique=WafTechnique.ENCODING)
        return [a, b]

    def optimize_order_only(self, payloads, context):
        return list(reversed(payloads))

    def classify_outcome(self, **kwargs):
        self.classify_called = True
        return OutcomeType.SUCCESS if kwargs.get("success") else OutcomeType.SOFT_FAIL

    def update_payload_outcome_atomic(self, context, payload_id, outcome):
        self.updated.append((context, payload_id, outcome))
        return _DummyStats(trials=1, successes=1 if outcome == OutcomeType.SUCCESS else 0)



def test_xcto10_runtime_get_payloads_uses_optimizer_ordering():
    suite = XSSWAFEvasionSuite()
    suite._optimizer = _DummyOptimizer()

    payloads = suite.get_payloads(XSSContext.UNKNOWN, max_payloads=2, with_variants=False)

    assert payloads[:2] == ["B", "A"], "runtime must apply optimize_order_only ordering"


def test_xcto10_runtime_record_payload_outcome_wires_classify_and_update():
    suite = XSSWAFEvasionSuite()
    suite._optimizer = _DummyOptimizer()

    result = suite.record_payload_outcome(
        context=XSSContext.UNKNOWN,
        payload_id="B",
        success=True,
        timed_out=False,
        blocked=False,
        parse_error=False,
    )

    assert suite._optimizer.classify_called is True
    assert suite._optimizer.updated == [(XSSContext.UNKNOWN, "B", OutcomeType.SUCCESS)]
    assert result["trials"] == 1 and result["successes"] == 1
