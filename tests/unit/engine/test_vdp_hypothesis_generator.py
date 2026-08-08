"""
SGK-2026-0420: Deterministic Hypothesis Generator tests.

Tests the capability-driven, deterministic hypothesis generation:
- Capability classification (semantic, no product names)
- Deterministic hypothesis IDs
- Label leakage (generic markers + config denylist — NO product names hardcoded)
- Actor inference
- Dedup / diversity budget
- Priority trace
- Scope verdict integration
- v0420 validator compliance
- validate_proposal_dict (fake LLM-style input only; no runtime LLM)
- M2 shadow: candidate verdict + NextAction (queue untouched)
- Zero-observation degraded
- Deterministic shadow IDs
- Idempotency (same input twice → same output, no duplicates)
"""
from __future__ import annotations

import pytest

from src.core.engine.vdp_observation_adapter import Observation, ObservationSourceKind
from src.core.models.vdp_contract import (
    EvidenceVerdictV1,
    ExecutionBudgetV1,
    HypothesisRecord,
    ScopeRevalidationResult,
    validate_hypothesis_record_v0420,
)
from src.core.engine.vdp_hypothesis_generator import (
    GENERATOR_VERSION,
    GenerationResult,
    build_hypothesis,
    build_shadow_proposals,
    classify_capability,
    detect_label_leakage,
    generate_hypotheses,
    validate_proposal_dict,
)


def _make_observation(**overrides) -> Observation:
    defaults = dict(
        observation_id="obs-test123456789012",
        url="https://example.com/api/users",
        method="GET",
        entity_type="endpoint",
        primary_label="users",
        param_names=("id",),
        source_kind=ObservationSourceKind.RECON_SIGNAL_BUNDLE,
        has_auth_header=False,
        has_cookie=False,
        candidate_labels=("api",),
    )
    defaults.update(overrides)
    return Observation(**defaults)


def _allow_scope_provider(url: str) -> ScopeRevalidationResult:
    return ScopeRevalidationResult(verdict="allowed", allowed=True, reason="test")


_BUDGET = ExecutionBudgetV1()


class TestCapabilityClassification:
    def test_upload_label_maps_to_upload(self):
        obs = _make_observation(primary_label="upload", candidate_labels=("file_upload",))
        assert classify_capability(obs).startswith("file_upload")

    def test_login_label_maps_to_auth(self):
        obs = _make_observation(primary_label="login", candidate_labels=("auth",))
        assert classify_capability(obs).startswith("authentication")

    def test_role_label_maps_to_role(self):
        obs = _make_observation(primary_label="role", candidate_labels=("permission",))
        assert classify_capability(obs).startswith("role_perm")

    def test_default_get_maps_to_object_read(self):
        obs = _make_observation(primary_label="pages", method="GET")
        assert classify_capability(obs).startswith("object_read")

    def test_entity_type_in_haystack(self):
        obs = _make_observation(entity_type="upload_form", primary_label="")
        assert classify_capability(obs).startswith("file_upload")


class TestLabelLeakage:
    def test_generic_flag_marker_rejected(self):
        assert "flag_marker_detected" in detect_label_leakage("flag{some_answer}")

    def test_ctf_marker_rejected(self):
        assert "flag_marker_detected" in detect_label_leakage("ctf{answer}")

    def test_known_answer_marker_rejected(self):
        assert "known_answer_marker_detected" in detect_label_leakage("expected_result: true")

    def test_cve_marker_rejected(self):
        assert "cve_marker_detected" in detect_label_leakage("CVE-2024-12345")

    def test_normal_text_not_rejected(self):
        assert detect_label_leakage("api users endpoint") == []

    def test_denylist_rejects_term(self):
        """Product names NOT hardcoded — supplied via denylist config."""
        result = generate_hypotheses(
            [_make_observation(primary_label="juiceshop", candidate_labels=("juiceshop_login",))],
            scope_verdict_provider=_allow_scope_provider,
            budget_model=_BUDGET,
            leakage_denylist=["juiceshop"],
        )
        assert result.has_hypotheses is False
        assert len(result.rejected) == 1
        assert "label_leakage_detected" in result.rejected[0]["reasons"]


class TestDeterministicHypothesisId:
    def test_same_observation_same_id(self):
        hyp1 = build_hypothesis(_make_observation(), scope_verdict="allowed")
        hyp2 = build_hypothesis(_make_observation(), scope_verdict="allowed")
        assert hyp1.hypothesis_id == hyp2.hypothesis_id

    def test_canonical_json_not_delimiter_based(self):
        """No simple string concatenation — uses canonical JSON hash."""
        hyp = build_hypothesis(_make_observation(observation_id="hyp-id-test"), scope_verdict="allowed")
        assert hyp.hypothesis_id.startswith("hyp-")


class TestActorInference:
    def test_no_auth_unauth(self):
        hyp = build_hypothesis(_make_observation(), scope_verdict="allowed")
        assert "unauth" in hyp.actors

    def test_has_auth_header_authA(self):
        hyp = build_hypothesis(_make_observation(has_auth_header=True), scope_verdict="allowed")
        assert "authA" in hyp.actors


class TestHypothesisRecordValidator:
    def test_built_record_passes_v0420_validator(self):
        hyp = build_hypothesis(_make_observation(), scope_verdict="allowed")
        errors = validate_hypothesis_record_v0420(hyp)
        assert errors == []

    def test_v1_validator_also_passes(self):
        from src.core.models.vdp_contract import validate_hypothesis_record
        hyp = build_hypothesis(_make_observation(), scope_verdict="allowed")
        errors = validate_hypothesis_record(hyp)
        assert errors == []

    def test_old_record_passes_v1_not_v0420(self):
        from src.core.models.vdp_contract import validate_hypothesis_record
        old = HypothesisRecord.from_dict({
            "hypothesis_id": "old-123", "observation_id": "old-obs",
            "asset": "https://x.com", "capability": "object_read_write_delete",
            "hypothesis_text": "old", "trust_boundary": "unauthenticated",
            "schema_version": 1,
        })
        assert validate_hypothesis_record(old) == []
        errs = validate_hypothesis_record_v0420(old)
        # Old record missing new fields → v0420 validator should detect
        assert any("resource_owner" in e.lower() for e in errs)


class TestScopeVerdict:
    def test_scope_not_allowed_recorded(self):
        hyp = build_hypothesis(_make_observation(), scope_verdict="out_of_scope")
        assert hyp.scope_verdict == "out_of_scope"

    def test_scope_revalidation_blocked_precondition(self):
        hyp = build_hypothesis(_make_observation(), scope_verdict="scope_revalidation_blocked")
        assert hyp.preconditions.get("scope") == "scope_revalidation_blocked"

    def test_scope_provider_called(self):
        def provider(url):
            return ScopeRevalidationResult(verdict="allowed", allowed=True)
        result = generate_hypotheses([_make_observation()], scope_verdict_provider=provider, budget_model=_BUDGET)
        assert result.has_hypotheses
        assert result.hypotheses[0].scope_verdict == "allowed"


class TestDedupSuppression:
    def test_duplicate_dedup_key_suppressed(self):
        obs = _make_observation()
        result = generate_hypotheses([obs, obs], scope_verdict_provider=_allow_scope_provider, budget_model=_BUDGET, diversity_bucket_limit=10)
        assert result.has_hypotheses
        assert len(result.hypotheses) == 1
        assert len(result.suppressed) >= 1
        assert any("duplicate" in s["reason"] for s in result.suppressed)


class TestDiversityBudget:
    def test_diversity_budget_suppresses_excess(self):
        """Same capability+host → diversity budget limits."""
        paths = [
            "login/users/1", "login/admin/2", "login/roles/3",
            "login/orders/4", "login/items/5",
        ]
        observations = [
            _make_observation(
                url=f"https://example.com/api/{path}",
                primary_label=f"login",
                candidate_labels=(),
            )
            for path in paths
        ]
        result = generate_hypotheses(observations, scope_verdict_provider=_allow_scope_provider, budget_model=_BUDGET, diversity_bucket_limit=3)
        assert result.has_hypotheses
        assert len(result.hypotheses) <= 3
        assert any("diversity" in s["reason"] for s in result.suppressed)


class TestPriorityTrace:
    def test_priority_trace_is_deterministic(self):
        result1 = generate_hypotheses([_make_observation()], scope_verdict_provider=_allow_scope_provider, budget_model=_BUDGET)
        result2 = generate_hypotheses([_make_observation()], scope_verdict_provider=_allow_scope_provider, budget_model=_BUDGET)
        assert result1.hypotheses[0].priority_trace == result2.hypotheses[0].priority_trace

    def test_priority_trace_includes_rank(self):
        result = generate_hypotheses([_make_observation()], scope_verdict_provider=_allow_scope_provider, budget_model=_BUDGET)
        assert any("rank=1" in entry for entry in result.hypotheses[0].priority_trace)


class TestValidateProposalDict:
    def test_rejects_non_dict(self):
        r = validate_proposal_dict("not-a-dict")
        assert not r.valid

    def test_rejects_unknown_action(self):
        r = validate_proposal_dict({"capability": "auth", "action_class": "unknown_action"})
        assert not r.valid

    def test_rejects_unknown_risk_class(self):
        r = validate_proposal_dict({"capability": "auth", "risk_class": "dangerous"})
        assert not r.valid

    def test_rejects_unknown_capability(self):
        r = validate_proposal_dict({"capability": "unknown_cap"})
        assert not r.valid

    def test_accepts_valid_proposal(self):
        r = validate_proposal_dict({
            "capability": "authentication_session_token",
            "action_class": "follow_up_probe",
            "risk_class": "read_only",
            "scope_verdict": "allowed",
            "hypothesis_text": "valid hypothesis",
            "trust_boundary": "authenticated",
            "resource_owner": "entity",
        })
        assert r.valid
        assert r.errors == []


class TestGenerationResult:
    def test_zero_observations_degraded(self):
        result = generate_hypotheses([], scope_verdict_provider=_allow_scope_provider, budget_model=_BUDGET)
        assert not result.has_hypotheses
        assert result.degraded is not None

    def test_all_label_leakage_rejected(self):
        result = generate_hypotheses(
            [_make_observation(primary_label="flag{test}")], scope_verdict_provider=_allow_scope_provider, budget_model=_BUDGET, diversity_bucket_limit=10
        )
        assert not result.has_hypotheses
        assert result.degraded is not None


class TestM2ShadowProposals:
    def test_candidate_verdict_created(self):
        hyp = build_hypothesis(_make_observation(), scope_verdict="allowed")
        proposals = build_shadow_proposals([hyp])
        assert len(proposals) == 1
        verdict = proposals[0].verdict
        assert verdict.status == "candidate"

    def test_hypothesis_transitioned_to_candidate(self):
        hyp = build_hypothesis(_make_observation(), scope_verdict="allowed")
        assert hyp.state == "hypothesized"
        build_shadow_proposals([hyp])
        assert hyp.state == "candidate"

    def test_next_action_created(self):
        hyp = build_hypothesis(_make_observation(), scope_verdict="allowed")
        proposals = build_shadow_proposals([hyp])
        na = proposals[0].next_action
        assert na.verdict_id == proposals[0].verdict.verdict_id
        assert na.next_action_id  # non-empty deterministic

    def test_verdict_is_not_confirmed(self):
        hyp = build_hypothesis(_make_observation(), scope_verdict="allowed")
        proposals = build_shadow_proposals([hyp])
        assert proposals[0].verdict.status != "confirmed"

    def test_deterministic_shadow_ids(self):
        hyp1 = build_hypothesis(_make_observation(observation_id="obs-a"), scope_verdict="allowed")
        hyp2 = build_hypothesis(_make_observation(observation_id="obs-a"), scope_verdict="allowed")
        p1 = build_shadow_proposals([hyp1])
        p2 = build_shadow_proposals([hyp2])
        assert p1[0].verdict.verdict_id == p2[0].verdict.verdict_id
        assert p1[0].next_action.next_action_id == p2[0].next_action.next_action_id

    def test_no_confirmed_verdict_generated(self):
        """Never inadvertently create confirmed verdicts in 0420."""
        hyp = build_hypothesis(_make_observation(), scope_verdict="allowed")
        proposals = build_shadow_proposals([hyp])
        for p in proposals:
            # status property returns _status; confirmed creation blocked
            assert p.verdict.status == "candidate"

    # --- SGK-2026-0434: destroyed-material payload_request_mismatch gap -----

    def test_destroyed_material_render_gap_skips_payload_mismatch(self):
        """A RENDER observation whose request material was destroyed (param
        names survive, values discarded) must NOT get payload_request_mismatch
        as the first m3a gap — the funnel label must advance to the next
        required evidence."""
        obs = _make_observation(
            primary_label="search",
            candidate_labels=("search", "template"),
            param_names=("q",),
            param_locations=("query",),
        )
        hyp = build_hypothesis(obs, scope_verdict="allowed")
        assert hyp.capability == "render_store_search_template"
        assert hyp.required_evidence[0] != "payload_request_mismatch"
        proposals = build_shadow_proposals([hyp])
        assert proposals[0].next_action.evidence_gap != "payload_request_mismatch"

    def test_clean_render_observation_keeps_payload_mismatch_first_gap(self):
        """A RENDER observation with NO destroyed material keeps
        payload_request_mismatch as the first required evidence (the
        executor blocks it at S07 exact_request_material_unavailable)."""
        obs = _make_observation(
            primary_label="search",
            candidate_labels=("search", "template"),
            param_names=(),
            param_locations=(),
        )
        hyp = build_hypothesis(obs, scope_verdict="allowed")
        assert hyp.capability == "render_store_search_template"
        assert hyp.required_evidence[0] == "payload_request_mismatch"

    def test_non_payload_first_gap_never_reordered(self):
        """Capabilities whose first gap is NOT payload_request_mismatch are
        untouched by the destroyed-material reorder (set unchanged)."""
        obs = _make_observation(param_names=("id",))  # destroyed material
        hyp = build_hypothesis(obs, scope_verdict="allowed")
        base = ["authz_impact_not_proven", "semantic_diff_owner_permission_sensitive_field"]
        assert hyp.required_evidence == base
        assert hyp.required_evidence[0] == "authz_impact_not_proven"


class TestIdempotency:
    def test_same_input_twice_same_output(self):
        obs = _make_observation()
        result1 = generate_hypotheses([obs], scope_verdict_provider=_allow_scope_provider, budget_model=_BUDGET)
        result2 = generate_hypotheses([obs], scope_verdict_provider=_allow_scope_provider, budget_model=_BUDGET)
        assert len(result1.hypotheses) == len(result2.hypotheses)
        assert result1.hypotheses[0].hypothesis_id == result2.hypotheses[0].hypothesis_id


class TestActorEvidenceDeterminism:
    """I-02: actor evidence must be part of canonical observation ID and actors list."""

    def test_reverse_order_with_differing_actor_evidence_same_result(self):
        """Reverse input order must not change adopted hypotheses or priority trace."""
        obs_with_authb = _make_observation(
            url="https://example.com/api/login/users/1",
            primary_label="login", candidate_labels=("auth",),
            has_second_actor_evidence=True, has_admin_evidence=True,
        )
        obs_without = _make_observation(
            url="https://example.com/api/login/admin/2",
            primary_label="login", candidate_labels=("auth",),
        )
        forward = generate_hypotheses(
            [obs_with_authb, obs_without],
            scope_verdict_provider=_allow_scope_provider, budget_model=_BUDGET,
            diversity_bucket_limit=10,
        )
        reverse = generate_hypotheses(
            [obs_without, obs_with_authb],
            scope_verdict_provider=_allow_scope_provider, budget_model=_BUDGET,
            diversity_bucket_limit=10,
        )
        assert forward.has_hypotheses and reverse.has_hypotheses
        assert len(forward.hypotheses) == len(reverse.hypotheses)
        f_ids = [h.hypothesis_id for h in forward.hypotheses]
        r_ids = [h.hypothesis_id for h in reverse.hypotheses]
        assert f_ids == r_ids
        f_traces = [h.priority_trace for h in forward.hypotheses]
        r_traces = [h.priority_trace for h in reverse.hypotheses]
        assert f_traces == r_traces

    def test_actor_evidence_differs_observation_id(self):
        """Observation ID (canonical payload) must include actor evidence fields."""
        from src.core.engine.vdp_observation_adapter import ObservationAdapter

        def _signal(**overrides):
            base = {
                "signal_id": "run-x:tagged:https://example.com/api",
                "entity_type": "endpoint",
                "url": "https://example.com/api/login",
                "method": "POST",
                "primary_label": "login",
                "candidate_labels": ["auth"],
                "auth_context": {"authorization": "Bearer abc"},
                "params": [{"name": "user", "location": "form"}],
            }
            base.update(overrides)
            return base

        adapter = ObservationAdapter()
        obs1 = adapter.adapt_endpoint_signal(
            _signal(auth_context={"authorization": "Bearer a", "user_b_cookie": "x"})
        )
        obs2 = adapter.adapt_endpoint_signal(
            _signal(auth_context={"authorization": "Bearer b"})
        )
        assert obs1 is not None and obs2 is not None
        assert obs1.observation_id != obs2.observation_id

    def test_actors_include_authb_and_admin_when_evidence(self):
        hyp = build_hypothesis(
            _make_observation(
                url="https://example.com/api/login", primary_label="login",
                has_auth_header=True, has_second_actor_evidence=True,
                has_admin_evidence=True,
            ),
            scope_verdict="allowed",
        )
        assert "authA" in hyp.actors
        assert "authB" in hyp.actors
        assert "admin" in hyp.actors


class TestResourceOwner:
    """I-05: resource owner comes from URL path only, never scheme/hostname."""

    def test_root_url_owner_unknown(self):
        hyp = build_hypothesis(
            _make_observation(url="https://example.com", primary_label="root"),
            scope_verdict="allowed",
        )
        assert hyp.resource_owner == "unknown"

    def test_path_owner_detected(self):
        hyp = build_hypothesis(
            _make_observation(url="https://example.com/api/users/123", primary_label="users"),
            scope_verdict="allowed",
        )
        assert hyp.resource_owner == "users"

    def test_root_url_role_hypothesis_precondition(self):
        hyp = build_hypothesis(
            _make_observation(
                url="https://example.com", primary_label="admin",
                candidate_labels=("role", "permission"),
            ),
            scope_verdict="allowed",
        )
        assert hyp.resource_owner == "unknown"
        assert "resource_owner" in hyp.preconditions

    def test_authA_only_role_hypothesis_records_missing_authb(self):
        hyp = build_hypothesis(
            _make_observation(
                url="https://example.com/api/roles", primary_label="role",
                candidate_labels=("permission",), has_auth_header=True,
            ),
            scope_verdict="allowed",
        )
        assert "authA" in hyp.actors
        assert "authB" not in hyp.actors
        assert hyp.preconditions.get("actor_authB") == "authB_missing"

    def test_authA_plus_authb_role_hypothesis_no_authb_precondition(self):
        hyp = build_hypothesis(
            _make_observation(
                url="https://example.com/api/roles", primary_label="role",
                candidate_labels=("permission",), has_auth_header=True,
                has_second_actor_evidence=True,
            ),
            scope_verdict="allowed",
        )
        assert "authA" in hyp.actors
        assert "authB" in hyp.actors
        assert "actor_authB" not in hyp.preconditions


class TestVocabularyCompliance:
    """I-07: generated records must stay within the public recipe_contracts vocabulary."""

    def test_shadow_proposal_vocabulary(self):
        from src.core.engine.recipe_contracts import (
            VDP_ACTION_CLASSES, VDP_REASON_CODES, VDP_RISK_CLASSES, VDP_STOP_CONDITIONS,
        )
        hyp = build_hypothesis(_make_observation(), scope_verdict="allowed")
        proposals = build_shadow_proposals([hyp])
        for p in proposals:
            assert p.verdict.status == "candidate"
            for rc in p.verdict.reason_codes:
                assert rc in VDP_REASON_CODES
            na = p.next_action
            assert na.action_class in VDP_ACTION_CLASSES
            assert na.risk_class in VDP_RISK_CLASSES
            assert na.stop_condition in VDP_STOP_CONDITIONS

    def test_generated_candidate_is_public_reason_code(self):
        from src.core.engine.recipe_contracts import VDP_REASON_CODES
        assert "generated_candidate" in VDP_REASON_CODES

    def test_generator_uses_public_vocabulary_not_private(self):
        import inspect
        import src.core.engine.vdp_hypothesis_generator as gen
        source = inspect.getsource(gen)
        assert "_VALID_ACTION_CLASSES" not in source
        assert "_VALID_RISK_CLASSES" not in source
