"""
SGK-2026-0423 Lane P-1 — cross-account comparison observation layer tests.

The executor records TRUTHFUL structured markers from real A/B account GET
comparisons (two authenticated requests on the same URL) so a read-only M3a
run can legitimately produce confirmed verdicts through the canonical
Evidence Validator. Secrets live only in the executor's credential store —
they never appear in specs, attempts, evidence, or results.

Marker truth-table (implemented in the executor):
- ``second_account_compared`` = "true" whenever the B-account GET completed
  with a definitive outcome (200 granted, 401/403 denied).
- ``authz_impact_proven`` / ``semantic_diff_observed`` = "true" ONLY when
  the non-owner account received the owner's sensitive record (B 200 +
  A-body has a generic ``owner`` key + key-sorted bodies identical + shared
  fields beyond ``owner``/``id``). Never set for public endpoints, denied
  access, network errors, or when the comparison did not run.
"""
from __future__ import annotations

import asyncio
import json

from src.core.engine.vdp_budget import VdpExecutionBudget
from src.core.engine.vdp_evidence_validator import (
    REASON_EVIDENCE_CONTRACT_SATISFIED,
    REASON_SUCCESS_CONDITION_NOT_PROVEN,
    Ed25519EvidenceSigner,
    VdpEvidenceValidator,
)
from src.core.engine.vdp_follow_up import build_next_action_record
from src.core.engine.vdp_follow_up_executor import (
    EXECUTED,
    VdpFollowUpExecutor,
    build_follow_up_task_id,
)
from src.core.models.vdp_contract import (
    AttemptRecord,
    CapabilityLevel,
    EvidenceRecordV1,
    HypothesisRecord,
    IdempotencyGuard,
    ProgramCapabilityMatrix,
    StateChangeGuard,
)
from src.core.security.ethics_guard import ScopeDefinition


def _hyp(**kwargs) -> HypothesisRecord:
    d = {
        "hypothesis_id": "hyp-ca-1",
        "observation_id": "obs-ca-1",
        "asset": "https://api.example.com/records/42",
        "capability": "object_read_write_delete",
        "hypothesis_text": "t",
        "trust_boundary": "unauthenticated",
        "actors": ["acct-a"],
        "risk_class": "read_only",
    }
    d.update(kwargs)
    return HypothesisRecord(**d)


def _scope() -> ScopeDefinition:
    return ScopeDefinition(
        program_name="t",
        in_scope_domains=["api.example.com"],
        out_of_scope_domains=[],
        max_requests_per_minute=1000,
    )


class _AuthNet:
    """Fake transport serving per-credential responses.

    The response is keyed by the Authorization secret the executor attached
    at send time, so the test also proves the right account secret reached
    the wire per request.
    """

    def __init__(self, account_table=None, default_status=200, default_body="ok"):
        # secret -> {"status": int, "body": str}
        self.account_table = dict(account_table or {})
        self.default_status = default_status
        self.default_body = default_body
        self.calls = []

    async def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        headers = kwargs.get("headers") or {}
        auth = str(headers.get("Authorization", "") or "")
        secret = auth[len("Bearer "):] if auth.startswith("Bearer ") else auth
        entry = self.account_table.get(secret)
        if entry is None:
            return _Resp(self.default_status, self.default_body)
        return _Resp(int(entry.get("status", 200)), str(entry.get("body", "")))

    @property
    def count(self):
        return len(self.calls)

    def secret_for_call(self, index: int) -> str:
        headers = self.calls[index][1].get("headers") or {}
        return (headers.get("Authorization", "") or "").replace("Bearer ", "")


class _Resp:
    def __init__(self, status, body, location=""):
        self.status = status
        self.body = body
        self.elapsed = 0.01
        self.headers = {"location": location} if location else {}


class _W:
    def __init__(self):
        self.evidence = []

    async def enqueue_evidence(self, evidence: dict):
        self.evidence.append(evidence)


def _spec(gap="authz_impact_not_proven", **overrides) -> dict:
    hyp = _hyp()
    na = build_next_action_record("vrd-ca-1", hyp, gap)
    spec = {
        "task_id": build_follow_up_task_id(na.next_action_id, hyp.hypothesis_id, "acct-a"),
        "hypothesis_id": hyp.hypothesis_id,
        "next_action_id": na.next_action_id,
        "evidence_gap": gap,
        "url": "https://api.example.com/records/42",
        "method": "GET",
        "param_names": [],
        "actor": "acct-a",
        "risk_class": "read_only",
        "auth_a_id": "acct-a",
        "auth_b_id": "acct-b",
    }
    spec.update(overrides)
    return spec


def _ex(**kw):
    net = kw.pop("net", None) or _AuthNet()
    budget = kw.pop("budget", None) or VdpExecutionBudget(
        max_requests=100, per_asset_burst=100, per_hypothesis_burst=100
    )
    writer = kw.pop("writer", None) or _W()
    creds = kw.pop("account_credentials", None) or {
        "acct-a": "secret-a",
        "acct-b": "secret-b",
    }
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
        account_credentials=creds,
        available_preconditions={
            "scope": True,
            "budget": True,
            "request_budget": True,
            "action_permission": True,
            "protected_resource": True,
            "authA_authB": True,
            "owned_resources": True,
        },
        **kw,
    )
    return ex, net, writer, budget


def _run(coro):
    return asyncio.run(coro)


def _validator_hypothesis(**kwargs) -> HypothesisRecord:
    """Full-contract hypothesis for the canonical validator path."""
    d = {
        "hypothesis_id": "hyp-ca-1",
        "observation_id": "obs-ca-1",
        "asset": "https://api.example.com/records/42",
        "capability": "object_read_write_delete",
        "hypothesis_text": "owner-only record readable by a non-owner",
        "trust_boundary": "api_endpoint",
        "actors": ["acct-a", "acct-b"],
        "risk_class": "read_only",
        "success_condition": "owner-only record + sensitive fields shared with non-owner",
        "falsification_condition": "no owner/permission difference between accounts",
        "required_evidence": [
            "authz_impact_not_proven",
            "semantic_diff_owner_permission_sensitive_field",
        ],
        "state": "attempted",
    }
    d.update(kwargs)
    return HypothesisRecord(**d)


def _signer() -> Ed25519EvidenceSigner:
    return Ed25519EvidenceSigner(private_key=bytes.fromhex("22" * 32))


GRANTED = {
    "secret-a": {"status": 200, "body": '{"owner":"acct-a","sensitive":"X"}'},
    "secret-b": {"status": 200, "body": '{"owner":"acct-a","sensitive":"X"}'},
}


class TestCrossAccountComparison:
    def test_granted_cross_account_read_records_impact_markers(self):
        net = _AuthNet(account_table=dict(GRANTED))
        (ex, net, writer, budget) = _ex(net=net)
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        assert result.requests_made == 2
        assert net.count == 2
        # the right secrets reached the wire, in A-then-B order
        assert net.secret_for_call(0) == "secret-a"
        assert net.secret_for_call(1) == "secret-b"
        er = result.evidence["execution_result"]
        assert er["cross_account_compared"] is True
        assert er["account_a_status"] == 200
        assert er["account_b_status"] == 200
        assert er["owner_record_accessible_to_non_owner"] is True
        assert er["sensitive_fields_shared_with_non_owner"] is True
        assert er["request_count"] == 2
        assert er["authz_impact_proven"] == "true"
        assert er["semantic_diff_observed"] == "true"

    def test_denied_non_owner_read_never_markers(self):
        net = _AuthNet(
            account_table={
                "secret-a": {"status": 200, "body": '{"owner":"acct-a","sensitive":"X"}'},
                "secret-b": {"status": 403, "body": '{"error":"forbidden"}'},
            }
        )
        (ex, net, writer, budget) = _ex(net=net)
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        assert result.requests_made == 2
        er = result.evidence["execution_result"]
        assert er["cross_account_compared"] is True
        assert er["account_b_status"] == 403
        assert er["owner_record_accessible_to_non_owner"] is False
        assert er["sensitive_fields_shared_with_non_owner"] is False
        assert er["second_account_compared"] == "true"
        assert "authz_impact_proven" not in er
        assert "semantic_diff_observed" not in er
        # canonical validator keeps the verdict candidate (missing evidence)
        validator = VdpEvidenceValidator(signer=_signer())
        verdict = validator.evaluate(
            _validator_hypothesis(),
            [AttemptRecord.from_dict(result.attempt)],
            [EvidenceRecordV1.from_dict(result.evidence)],
        )
        assert verdict.status == "candidate"
        assert REASON_SUCCESS_CONDITION_NOT_PROVEN in verdict.reason_codes

    def test_public_endpoint_no_owner_semantics_no_markers(self):
        net = _AuthNet(
            account_table={
                "secret-a": {"status": 200, "body": '{"data":"public"}'},
                "secret-b": {"status": 200, "body": '{"data":"public"}'},
            }
        )
        (ex, net, writer, budget) = _ex(net=net)
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        er = result.evidence["execution_result"]
        assert er["cross_account_compared"] is True
        assert er["account_b_status"] == 200
        assert er["owner_record_accessible_to_non_owner"] is False
        assert er["sensitive_fields_shared_with_non_owner"] is False
        assert "authz_impact_proven" not in er
        assert "semantic_diff_observed" not in er
        validator = VdpEvidenceValidator(signer=_signer())
        verdict = validator.evaluate(
            _validator_hypothesis(),
            [AttemptRecord.from_dict(result.attempt)],
            [EvidenceRecordV1.from_dict(result.evidence)],
        )
        assert verdict.status == "candidate"
        assert REASON_SUCCESS_CONDITION_NOT_PROVEN in verdict.reason_codes

    def test_comparison_requires_accounts(self):
        # no auth ids -> existing single-request neutral-fact behavior
        (ex, net, writer, budget) = _ex()
        result = _run(ex.execute(_spec(auth_a_id="", auth_b_id="")))
        assert result.status == EXECUTED
        assert result.requests_made == 1
        assert net.count == 1
        er = result.evidence["execution_result"]
        assert "cross_account_compared" not in er
        assert "authz_impact_proven" not in er
        assert "semantic_diff_observed" not in er
        assert "second_account_compared" not in er
        assert er["request_count"] == 1
        # ids present but the credential store cannot resolve BOTH secrets
        # -> same single-request fallback, no comparison markers
        (ex2, net2, writer2, budget2) = _ex(account_credentials={"acct-a": "secret-a"})
        result2 = _run(ex2.execute(_spec()))
        assert result2.status == EXECUTED
        assert result2.requests_made == 1
        assert net2.count == 1
        er2 = result2.evidence["execution_result"]
        assert "cross_account_compared" not in er2
        assert "second_account_compared" not in er2

    def test_owner_only_record_without_sensitive_fields_never_impact_markers(self):
        """owner record shared but with NO fields beyond owner/id: the owner
        attribution fact is recorded, but sensitive-field sharing and the
        impact markers are NOT (spec: sensitive requires keys beyond
        owner/id)."""
        net = _AuthNet(
            account_table={
                "secret-a": {"status": 200, "body": '{"owner":"acct-a","id":"42"}'},
                "secret-b": {"status": 200, "body": '{"owner":"acct-a","id":"42"}'},
            }
        )
        (ex, net, writer, budget) = _ex(net=net)
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        er = result.evidence["execution_result"]
        assert er["cross_account_compared"] is True
        assert er["account_b_status"] == 200
        assert er["owner_record_accessible_to_non_owner"] is True
        assert er["sensitive_fields_shared_with_non_owner"] is False
        assert "authz_impact_proven" not in er
        assert "semantic_diff_observed" not in er

    def test_second_account_compared_set_on_completed_comparison(self):
        net = _AuthNet(
            account_table={
                "secret-a": {"status": 200, "body": '{"owner":"acct-a","sensitive":"X"}'},
                "secret-b": {"status": 403, "body": '{"error":"forbidden"}'},
            }
        )
        (ex, net, writer, budget) = _ex(net=net)
        result = _run(ex.execute(_spec(gap="untested_no_second_account")))
        assert result.status == EXECUTED
        assert result.requests_made == 2
        er = result.evidence["execution_result"]
        assert er["cross_account_compared"] is True
        assert er["account_a_status"] == 200
        assert er["account_b_status"] == 403
        assert er["second_account_compared"] == "true"
        assert "authz_impact_proven" not in er
        assert "semantic_diff_observed" not in er

    def test_secrets_never_in_evidence_or_result(self):
        net = _AuthNet(account_table=dict(GRANTED))
        (ex, net, writer, budget) = _ex(net=net)
        spec = _spec()
        result = _run(ex.execute(spec))
        assert result.status == EXECUTED
        dumped = json.dumps(
            {
                "spec": spec,
                "result": result.__dict__,
                "evidence": writer.evidence,
            },
            default=str,
        )
        assert "secret-a" not in dumped
        assert "secret-b" not in dumped
        assert "Authorization" not in dumped
        assert "Bearer" not in dumped

    def test_confirmed_only_via_canonical_path(self):
        net = _AuthNet(account_table=dict(GRANTED))
        (ex, net, writer, budget) = _ex(net=net)
        result = _run(ex.execute(_spec()))
        assert result.status == EXECUTED
        attempt = AttemptRecord.from_dict(result.attempt)
        evidence = EvidenceRecordV1.from_dict(result.evidence)
        validator = VdpEvidenceValidator(signer=_signer())
        # test-1 comparison evidence + full contract -> confirmed with proof
        verdict = validator.evaluate(_validator_hypothesis(), [attempt], [evidence])
        assert verdict.status == "confirmed"
        assert verdict.validation_proof != ""
        assert REASON_EVIDENCE_CONTRACT_SATISFIED in verdict.reason_codes
        # test-2 (denied) evidence -> candidate, never confirmed
        net2 = _AuthNet(
            account_table={
                "secret-a": {"status": 200, "body": '{"owner":"acct-a","sensitive":"X"}'},
                "secret-b": {"status": 403, "body": '{"error":"forbidden"}'},
            }
        )
        (ex2, net2, writer2, _b2) = _ex(net=net2)
        result2 = _run(ex2.execute(_spec()))
        attempt2 = AttemptRecord.from_dict(result2.attempt)
        evidence2 = EvidenceRecordV1.from_dict(result2.evidence)
        verdict2 = validator.evaluate(_validator_hypothesis(), [attempt2], [evidence2])
        assert verdict2.status == "candidate"
        assert REASON_SUCCESS_CONDITION_NOT_PROVEN in verdict2.reason_codes
        # test-3 (public) evidence -> candidate, never confirmed
        net3 = _AuthNet(
            account_table={
                "secret-a": {"status": 200, "body": '{"data":"public"}'},
                "secret-b": {"status": 200, "body": '{"data":"public"}'},
            }
        )
        (ex3, net3, writer3, _b3) = _ex(net=net3)
        result3 = _run(ex3.execute(_spec()))
        attempt3 = AttemptRecord.from_dict(result3.attempt)
        evidence3 = EvidenceRecordV1.from_dict(result3.evidence)
        verdict3 = validator.evaluate(_validator_hypothesis(), [attempt3], [evidence3])
        assert verdict3.status == "candidate"
        assert REASON_SUCCESS_CONDITION_NOT_PROVEN in verdict3.reason_codes
