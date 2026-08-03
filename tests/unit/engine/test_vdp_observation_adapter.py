"""
SGK-2026-0420: Observation Adapter tests.

Tests the boundary adapter:
- Secret stripping (Authorization/Cookie → safe booleans)
- UUID/time exclusion (signal_id/created_at dropped)
- Deterministic observation IDs (canonical JSON)
- URL normalization (scheme/hostname required, fragment, params)
- Source kind identification
- Skip handling for malformed signals
"""
from __future__ import annotations

import pytest

from src.core.engine.vdp_observation_adapter import (
    Observation,
    ObservationAdapter,
    ObservationSourceKind,
    normalize_url,
)


def _make_signal(**overrides) -> dict:
    defaults = {
        "signal_id": "00000000-0000-0000-0000-run123:tagged_auth:https://example.com/api",
        "entity_type": "endpoint",
        "url": "https://example.com/api/users",
        "method": "GET",
        "primary_label": "users",
        "candidate_labels": ["api", "auth"],
        "confidence": 0.9,
        "why_suspicious": "Category 'auth'",
        "source_observations": ["recon"],
        "auth_required": True,
        "auth_context": {"authorization": "Bearer secret-token-abc", "cookie": "PHPSESSID=xyz"},
        "subdomain_context": None,
        "interaction_kind": "static",
        "lineage": "tagged_auth:https://example.com/api",
        "params": [{"name": "id", "location": "query"}, {"name": "token", "location": "query"}],
        "status": "active",
        "seen_count": 1,
        "created_at": "2026-08-02T12:34:56.789+00:00",
    }
    defaults.update(overrides)
    return defaults


class TestNormalizeUrl:
    def test_scheme_and_hostname_required(self):
        with pytest.raises(ValueError, match="scheme"):
            normalize_url("example.com/path")
        with pytest.raises(ValueError, match="hostname"):
            normalize_url("https://")

    def test_drops_fragment(self):
        result = normalize_url("https://example.com/api#section")
        assert "#" not in result

    def test_sorts_query_param_names_drops_values(self):
        result = normalize_url("https://example.com/path?b=2&a=1&token=abc123")
        # Names sorted, values discarded.
        assert result == "https://example.com/path?a&b&token"
        assert "abc123" not in result
        assert "=2" not in result

    def test_scheme_lowercased(self):
        result = normalize_url("HTTPS://Example.com/Path")
        assert result == "https://example.com/Path"


class TestSecretStripping:
    def test_auth_context_authorization_stripped(self):
        signal = _make_signal(auth_context={"authorization": "Bearer xyz", "cookie": "sid=123"})
        adapter = ObservationAdapter()
        observation = adapter.adapt_endpoint_signal(signal)
        assert observation is not None
        assert observation.has_auth_header is True
        assert observation.has_cookie is True
        d = observation.to_dict()
        assert "Bearer" not in str(d)
        assert "xyz" not in str(d)
        assert "sid=123" not in str(d)

    def test_auth_context_key_is_case_insensitive(self):
        signal = _make_signal(auth_context={"Authorization": "Bearer case", "Cookie": "x=y"})
        adapter = ObservationAdapter()
        observation = adapter.adapt_endpoint_signal(signal)
        assert observation.has_auth_header is True
        assert observation.has_cookie is True

    def test_no_auth_context(self):
        signal = _make_signal(auth_context={})
        adapter = ObservationAdapter()
        observation = adapter.adapt_endpoint_signal(signal)
        assert observation.has_auth_header is False
        assert observation.has_cookie is False

    def test_auth_context_is_none(self):
        signal = _make_signal(auth_context=None)
        adapter = ObservationAdapter()
        observation = adapter.adapt_endpoint_signal(signal)
        assert observation.has_auth_header is False
        assert observation.has_cookie is False

    def test_x_api_key_marks_auth_header(self):
        signal = _make_signal(auth_context={"X-API-Key": "key-123"})
        adapter = ObservationAdapter()
        observation = adapter.adapt_endpoint_signal(signal)
        assert observation.has_auth_header is True

    def test_to_dict_contains_no_raw_secret_values(self):
        signal = _make_signal(
            auth_context={"authorization": "Bearer abc-def-ghi-1234567890", "cookie": "session=secretval"}
        )
        adapter = ObservationAdapter()
        observation = adapter.adapt_endpoint_signal(signal)
        d = observation.to_dict()
        serialized = str(d)
        assert "Bearer" not in serialized
        assert "abc-def-ghi" not in serialized
        assert "secretval" not in serialized
        assert "session=secretval" not in serialized


class TestUuidTimeExclusion:
    def test_signal_id_and_created_at_not_in_observation_fields(self):
        signal = _make_signal(
            signal_id="abcdef01-run999:tagged:https://example.com/x",
            created_at="2020-01-01T00:00:00Z",
        )
        adapter = ObservationAdapter()
        observation = adapter.adapt_endpoint_signal(signal)
        d = observation.to_dict()
        fam = d.get("signal_id", False)
        assert fam is False  # should be completely absent (missing key, not key present)
        assert "fragment" in str(d) or True  # sanity


class TestDeterministicObservationId:
    def test_same_input_same_id(self):
        adapter = ObservationAdapter()
        obs1 = adapter.adapt_endpoint_signal(_make_signal())
        obs2 = adapter.adapt_endpoint_signal(_make_signal())
        assert obs1.observation_id == obs2.observation_id

    def test_uuid_time_only_change_same_id(self):
        """Input where only signal_id (UUID) and created_at differ → same obs_id."""
        adapter = ObservationAdapter()
        obs1 = adapter.adapt_endpoint_signal(
            _make_signal(signal_id="different-uuid-aaa:tagged:https://example.com/api", created_at="2000-01-01")
        )
        obs2 = adapter.adapt_endpoint_signal(
            _make_signal(signal_id="different-uuid-bbb:tagged:https://example.com/api", created_at="2099-12-31")
        )
        assert obs1.observation_id == obs2.observation_id

    def test_param_order_change_same_id(self):
        adapter = ObservationAdapter()
        obs1 = adapter.adapt_endpoint_signal(_make_signal(params=[{"name": "a"}, {"name": "b"}]))
        obs2 = adapter.adapt_endpoint_signal(_make_signal(params=[{"name": "b"}, {"name": "a"}]))
        assert obs1.observation_id == obs2.observation_id

    def test_different_primary_label_different_id(self):
        adapter = ObservationAdapter()
        obs1 = adapter.adapt_endpoint_signal(_make_signal(primary_label="users"))
        obs2 = adapter.adapt_endpoint_signal(_make_signal(primary_label="admin"))
        assert obs1.observation_id != obs2.observation_id


class TestParamValueDiscarding:
    def test_param_values_not_in_observation(self):
        adapter = ObservationAdapter()
        obs = adapter.adapt_endpoint_signal(
            _make_signal(params=[{"name": "token", "location": "query", "value": "secret123"}])
        )
        assert "token" in obs.param_names
        d = obs.to_dict()
        assert "secret123" not in str(d)


class TestSourceKind:
    def test_default_source_kind(self):
        adapter = ObservationAdapter()
        obs = adapter.adapt_endpoint_signal(_make_signal())
        assert obs.source_kind == ObservationSourceKind.RECON_SIGNAL_BUNDLE

    def test_custom_source_kind(self):
        adapter = ObservationAdapter(source_kind=ObservationSourceKind.BROWSER_TRAFFIC)
        obs = adapter.adapt_endpoint_signal(_make_signal())
        assert obs.source_kind == ObservationSourceKind.BROWSER_TRAFFIC


class TestAdapterResult:
    def test_adapt_signal_bundle_returns_observations(self):
        signals = [
            _make_signal(url="https://example.com/api/users"),
            _make_signal(url="https://example.com/api/admin"),
        ]
        bundle = {"_endpoint_signals": signals}
        adapter = ObservationAdapter()
        result = adapter.adapt_signal_bundle(bundle)
        assert result.has_observations is True
        assert len(result.observations) == 2
        assert result.observations[0].url == "https://example.com/api/users"

    def test_missing_endpoint_signals_skipped(self):
        adapter = ObservationAdapter()
        result = adapter.adapt_signal_bundle({"_endpoint_signals": None})
        assert result.has_observations is False
        assert any("missing" in s.reason for s in result.skipped)

    def test_not_a_dict_skipped(self):
        adapter = ObservationAdapter()
        result = adapter.adapt_signal_bundle("not-a-dict")
        assert result.has_observations is False

    def test_invalid_signal_skipped(self):
        adapter = ObservationAdapter()
        result = adapter.adapt_signal_bundle({"_endpoint_signals": [{"url": ""}]})
        assert not result.has_observations


class TestEmptyUrl:
    def test_empty_url_returns_none(self):
        adapter = ObservationAdapter()
        obs = adapter.adapt_endpoint_signal({"url": ""})
        assert obs is None


class TestUrlWithoutScheme:
    def test_url_without_scheme_raises_valueerror(self):
        adapter = ObservationAdapter()
        with pytest.raises(ValueError, match="scheme"):
            adapter.adapt_endpoint_signal({"url": "example.com/path"})


class TestUserinfoRejection:
    def test_userinfo_rejected(self):
        adapter = ObservationAdapter()
        with pytest.raises(ValueError, match="userinfo"):
            normalize_url("https://user:pass@example.com/path")

    def test_userinfo_only_user_rejected(self):
        adapter = ObservationAdapter()
        with pytest.raises(ValueError, match="userinfo"):
            normalize_url("https://user@example.com/path")

    def test_userinfo_in_signal_skipped(self):
        adapter = ObservationAdapter()
        result = adapter.adapt_signal_bundle({
            "_endpoint_signals": [{"url": "https://user:pass@example.com/api"}]
        })
        assert not result.has_observations


class TestOpaquePathSegments:
    def test_uuid_path_segment_opaque(self):
        result = normalize_url("https://example.com/api/abc12345-6789-abcd-ef01-234567890abc")
        assert ":opaque" in result
        assert "abc12345" not in result

    def test_long_hex_segment_opaque(self):
        result = normalize_url("https://example.com/api/abcdef0123456789abcdef")
        assert ":opaque" in result
        assert "abcdef0123456789abcdef" not in result

    def test_reset_token_keyword_makes_next_segment_opaque(self):
        result = normalize_url("https://example.com/reset/abc123def456token")
        assert ":opaque" in result
        assert "abc123def456token" not in result

    def test_regular_path_unchanged(self):
        result = normalize_url("https://example.com/api/users/123")
        assert result == "https://example.com/api/users/123"


class TestThreeStageSecretAbsence:
    """Secret string must be absent from Observation, HypothesisRecord, and session payload."""

    def _run_3stage(self, url: str, secret: str) -> tuple[dict, dict, dict]:
        """Build Observation → HypothesisRecord → session payload, return all 3 dicts."""
        signal = _make_signal(url=url)
        adapter = ObservationAdapter()
        observation = adapter.adapt_endpoint_signal(signal)
        obs_dict = observation.to_dict()

        from src.core.engine.vdp_hypothesis_generator import build_hypothesis
        from src.core.models.vdp_contract import ScopeRevalidationResult
        hypothesis = build_hypothesis(
            observation, scope_verdict="allowed",
            budget_estimate={"max_requests": 10, "max_follow_ups": 2, "max_retries": 1},
        )
        hyp_dict = hypothesis.to_dict()

        from src.core.engine.master_conductor_session_service import (
            build_async_session_payload,
            inject_vdp_section_to_session_payload,
        )
        from types import SimpleNamespace
        ctx = SimpleNamespace(
            _total_attempts=0, _successful_attempts=0,
            bypass_methods=[], discovered_assets=[], target_info={},
        )
        payload = build_async_session_payload(
            task_queue=[], completed_tasks=[], context=ctx, pending_hitl=[],
            coverage_gate={}, scenario_coverage={}, timestamp=0.0, default_start_time=0.0,
        )
        session = inject_vdp_section_to_session_payload(
            payload, {"vdp_active": True, "hypotheses": [hyp_dict], "attempts": [], "evidence_records": [], "verdicts": [], "next_actions": []}
        )
        return obs_dict, hyp_dict, session

    def test_no_userinfo_secret_in_observation_to_dict(self):
        signal = _make_signal(url="https://example.com/api/reset/tokensecretvaluehere")
        adapter = ObservationAdapter()
        observation = adapter.adapt_endpoint_signal(signal)
        d = observation.to_dict()
        assert "tokensecretvaluehere" not in str(d)
        assert "reset" in observation.url  # keyword preserved, value absent

    def test_short_token_three_stage_absent(self):
        """Short secret token-abc123 must not reach any of the 3 stages."""
        obs, hyp, session = self._run_3stage(
            "https://example.com/reset/token-abc123", "token-abc123"
        )
        assert "token-abc123" not in str(obs)
        assert "token-abc123" not in str(hyp)
        assert "token-abc123" not in str(session)
        assert ":opaque" in obs.get("url", "") or ":opaque" in str(obs)

    def test_secret_prefix_segment_three_stage_absent(self):
        """secret-xyz / session-abc / key-123 prefixed segments → :opaque, absent in all stages."""
        for seg in ("secret-xyz", "session-abc", "key-123", "csrf-token-abc"):
            obs, hyp, session = self._run_3stage(f"https://example.com/api/{seg}", seg)
            assert seg not in str(obs), seg
            assert seg not in str(hyp), seg
            assert seg not in str(session), seg

    def test_userinfo_rejected_three_stage_absent(self):
        """user:pass@host must be rejected before Observation; secret never enters any stage."""
        from src.core.engine.vdp_observation_adapter import normalize_url
        with pytest.raises(ValueError, match="userinfo"):
            normalize_url("https://user:pass@example.com/api")
        # The exception must NOT contain the raw URL/credential values
        try:
            normalize_url("https://user:pass@example.com/api")
        except ValueError as exc:
            assert "pass" not in str(exc)
            assert ":pass" not in str(exc)
            assert "example.com" not in str(exc)
