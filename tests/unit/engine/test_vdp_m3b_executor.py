"""
SGK-2026-0423 Lane F / Lane J-2 — M3b authorized state-changing executor
path (TDD).

The production M3b send boundary in ``VdpFollowUpExecutor``:

- an m3b spec (``m3b_authorized`` + ``hitl_ticket``) with a state-changing
  plan may send EXACTLY ONE mutation (``request_count == 1``);
- the ticket is verified against the REAL HITL ledger via the injected
  ``hitl_ticket_validator`` — an arbitrary string is NEVER approval
  (audit J-2 A); without a validator the gate fails closed;
- the sent fact is persisted in the ``StateChangeGuard`` via ``mark_sent``
  IMMEDIATELY after the send loop completes (before evidence build/writer) —
  the no-auto-resend property holds even when the session save fails;
- without authorization the executor stops at ``manual_review`` BEFORE any
  network activity;
- a transport failure (body None) never marks the attempt sent;
- the same spec never sends twice (idempotency), and a FRESH idempotency
  guard with the same StateChangeGuard blocks at
  ``state_change_already_sent``;
- read-only plans are unaffected (no authorization needed, no mark_sent).

Zero sockets: the injected fake network client is the only transport.
"""
from __future__ import annotations

from src.core.engine.vdp_budget import VdpExecutionBudget
from src.core.engine.vdp_follow_up_executor import VdpFollowUpExecutor
from src.core.models.vdp_contract import (
    CapabilityLevel,
    IdempotencyGuard,
    ProgramCapabilityMatrix,
    StateChangeGuard,
)

from tests.unit.engine.test_vdp_follow_up_resilience import (
    _Net,
    _W,
    _run,
    _scope,
    _spec,
)


def _m3b_spec(**overrides) -> dict:
    """An authorized state-changing follow-up spec (POST mutation)."""
    spec = _spec(
        gap="state_change_not_verified",
        risk_class="state_changing",
        method="POST",
        m3b_authorized=True,
        hitl_ticket="T-1",
    )
    spec.update(overrides)
    return spec


def _m3b_ex(**kw):
    """Like ``resilience._ex`` but with the M3b state-change preconditions
    (``state_change_permission`` / ``hitl``) available — the caller supplies
    them ONLY for authorized m3b specs (dispatch-side contract)."""
    net = kw.pop("net", None) or _Net()
    budget = kw.pop("budget", None) or VdpExecutionBudget(
        max_requests=100, per_asset_burst=100, per_hypothesis_burst=100
    )
    writer = kw.pop("writer", None) or _W()
    ex = VdpFollowUpExecutor(
        scope_definition=kw.pop("scope", None) or _scope(),
        capability_matrix=kw.pop(
            "matrix", None
        ) or ProgramCapabilityMatrix(rules={"follow_up_probe": CapabilityLevel.ALLOWED}),
        budget=budget,
        network_client=net,
        evidence_writer=writer,
        idempotency_guard=kw.pop("idem", None) or IdempotencyGuard(),
        state_change_guard=kw.pop("scg", None) or StateChangeGuard(),
        available_preconditions={
            "scope": True, "budget": True, "request_budget": True,
            "action_permission": True, "protected_resource": True,
            "state_change_permission": True, "hitl": True,
        },
        **kw,
    )
    return ex, net, writer, budget


class TestM3bAuthorizationGate:
    def test_m3b_unauthorized_blocked_before_network(self):
        """A state-changing spec WITHOUT m3b_authorized stops at
        manual_review (m3b_not_authorized) with ZERO communication."""
        (ex, net, writer, _b) = _m3b_ex()
        spec = _spec(
            gap="state_change_not_verified",
            risk_class="state_changing",
            method="POST",
        )
        result = _run(ex.execute(spec))
        assert result.status == "manual_review"
        assert result.reason == "m3b_not_authorized"
        assert net.count == 0

    def test_m3b_authorized_but_missing_ticket_blocked(self):
        """m3b_authorized without a non-empty HITL ticket is NOT authorized
        (the gate requires both)."""
        (ex, net, writer, _b) = _m3b_ex()
        spec = _m3b_spec(hitl_ticket="  ")
        result = _run(ex.execute(spec))
        assert result.status == "manual_review"
        assert result.reason == "m3b_not_authorized"
        assert net.count == 0

    def test_m3b_authorized_without_validator_is_refused(self):
        """m3b_authorized + a ticket string but NO ledger validator → the
        executor has no way to verify the ticket → m3b_not_authorized
        (fail-closed; production always supplies a validator)."""
        (ex, net, writer, _b) = _m3b_ex()
        result = _run(ex.execute(_m3b_spec()))
        assert result.status == "manual_review"
        assert result.reason == "m3b_not_authorized"
        assert net.count == 0

    def test_m3b_arbitrary_ticket_string_refused_by_ledger(self):
        """The audit's exact case: an ARBITRARY non-empty ticket string with
        a ledger validator that rejects it → manual_review
        hitl_ticket_invalid, zero network. A string alone is never
        approval."""
        (ex, net, writer, _b) = _m3b_ex(
            hitl_ticket_validator=lambda t: t == "T-1"
        )
        spec = _m3b_spec(hitl_ticket="arbitrary-string-not-in-ledger")
        result = _run(ex.execute(spec))
        assert result.status == "manual_review"
        assert result.reason == "hitl_ticket_invalid"
        assert net.count == 0

    def test_m3b_approved_ticket_validator_passes(self):
        """An approved ticket (validator returns True) passes the gate."""
        (ex, net, writer, _b) = _m3b_ex(
            hitl_ticket_validator=lambda t: t == "T-1"
        )
        result = _run(ex.execute(_m3b_spec()))
        assert result.status == "executed"
        assert net.count == 1


class TestM3bSendBoundary:
    def test_m3b_authorized_executes_and_marks_sent(self):
        """Authorized m3b spec (ledger validator confirms the ticket) →
        executed with exactly one send; the StateChangeGuard persists the
        attempt as sent-but-not-confirmed (production mark_sent at the send
        boundary) and the result carries the send fact."""
        (ex, net, writer, _b) = _m3b_ex(
            hitl_ticket_validator=lambda t: t == "T-1"
        )
        spec = _m3b_spec()
        result = _run(ex.execute(spec))
        assert result.status == "executed"
        assert result.state_change_sent is True
        assert net.count == 1
        guard_state = ex.state_change_guard.to_dict()
        assert result.attempt_id in guard_state["sent_but_not_confirmed"]
        assert result.evidence is not None
        assert result.evidence["execution_result"]["state_change_sent"] is True
        # neutral facts only — the success marker is NEVER recorded here
        assert "state_change_verified" not in result.evidence["execution_result"]

    def test_evidence_writer_failure_marks_state_change_sent(self):
        """The audit's exact gap (Lane L-2): the HTTP send happened and
        mark_sent was called BEFORE the evidence writer failed — the
        degraded result must still carry ``state_change_sent is True`` so
        the WAL records "sent" and a new process never resends."""
        class _FullWriter:
            async def enqueue_evidence(self, evidence):
                raise RuntimeError("queue full")

        (ex, net, writer, _b) = _m3b_ex(
            writer=_FullWriter(),
            hitl_ticket_validator=lambda t: t == "T-1",
        )
        result = _run(ex.execute(_m3b_spec()))
        assert result.status == "degraded"
        assert result.reason == "evidence_write_backpressure"
        assert result.state_change_sent is True  # the send already happened
        assert net.count == 1
        guard_state = ex.state_change_guard.to_dict()
        assert result.attempt_id in guard_state["sent_but_not_confirmed"]
        assert result.evidence is not None  # evidence dict still returned

    def test_m3b_no_resend_same_executor(self):
        """The SAME spec on the SAME executor never sends twice
        (idempotency duplicate before any network activity)."""
        (ex, net, writer, _b) = _m3b_ex(
            hitl_ticket_validator=lambda t: t == "T-1"
        )
        spec = _m3b_spec()
        first = _run(ex.execute(spec))
        assert first.status == "executed"
        assert net.count == 1

        again = _run(ex.execute(spec))
        assert again.status == "manual_review"
        assert "attempt:idempotency_duplicate" in again.reason
        assert net.count == 1  # no auto-resend

    def test_m3b_no_resend_fresh_idempotency_marked_guard(self):
        """A FRESH idempotency guard (lost checkpoint) with the SAME
        StateChangeGuard cannot resend: prevent_double_send raises and the
        executor blocks with ``state_change_already_sent`` — zero network."""
        validator = lambda t: t == "T-1"  # noqa: E731
        spec = _m3b_spec()
        (ex1, net1, _w1, _b1) = _m3b_ex(hitl_ticket_validator=validator)
        first = _run(ex1.execute(spec))
        assert first.status == "executed"
        assert net1.count == 1
        guard = ex1.state_change_guard  # the persisted sent fact

        (ex2, net2, _w2, _b2) = _m3b_ex(
            idem=IdempotencyGuard(), scg=guard,
            hitl_ticket_validator=validator,
        )
        second = _run(ex2.execute(spec))
        assert second.status == "blocked"
        assert second.reason == "state_change_already_sent"
        assert net2.count == 0

    def test_m3b_send_failure_does_not_mark_sent(self):
        """Transport failure → degraded network_error; the attempt is NOT
        marked sent (nothing was transmitted) and no evidence exists."""

        class _BoomNet(_Net):
            async def request(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                raise TimeoutError("dependency stopped")

        (ex, net, writer, _b) = _m3b_ex(
            net=_BoomNet(), hitl_ticket_validator=lambda t: t == "T-1"
        )
        result = _run(ex.execute(_m3b_spec()))
        assert result.status == "degraded"
        assert result.reason == "network_error"
        assert result.state_change_sent is False  # nothing was transmitted
        assert net.count == 1
        assert result.evidence is None
        assert ex.state_change_guard.to_dict()["sent_but_not_confirmed"] == []

    def test_m3b_single_request_not_controls(self):
        """State-changing sends are forced to exactly ONE request (a single
        mutation — repeated A/B/A controls are read-only only)."""
        (ex, net, writer, _b) = _m3b_ex(
            hitl_ticket_validator=lambda t: t == "T-1"
        )
        result = _run(ex.execute(_m3b_spec()))
        assert result.status == "executed"
        assert result.requests_made == 1
        assert net.count == 1


class TestReadOnlyUnaffected:
    def test_readonly_plans_unaffected(self):
        """A plain read-only spec behaves exactly as before: executed with
        one send, NO authorization required, NO mark_sent recorded, and the
        result never claims a state change was sent."""
        (ex, net, writer, _b) = _m3b_ex()
        result = _run(ex.execute(_spec()))  # payload_request_mismatch
        assert result.status == "executed"
        assert result.state_change_sent is False
        assert net.count == 1
        assert ex.state_change_guard.to_dict()["sent_but_not_confirmed"] == []
        evidence = result.evidence
        assert evidence is not None
        assert evidence["execution_result"].get("state_change_sent") is None
