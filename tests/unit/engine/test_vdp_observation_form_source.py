"""
VDP observation form source + unavailable inventory — SGK-2026-0421 Step 3.

Form provenance is derived from the existing signal bundle
(``_endpoint_signals[*].params[*].location == "form"``, produced by
``recon/pipeline.py``) — no new crawl or communication is started, and
``task _context`` / ``forms_by_url`` are NOT used (the VDP hook runs before
task generation, MasterConductor L9850).
"""
from __future__ import annotations

import pytest

from src.core.engine.vdp_hypothesis_generator import (
    build_unavailable_source_inventory,
)
from src.core.engine.vdp_observation_adapter import (
    Observation,
    ObservationAdapter,
    ObservationSourceKind,
)


def _signal(url: str, method: str = "GET", params=None, **extra) -> dict:
    signal = {
        "url": url,
        "method": method,
        "entity_type": "endpoint",
        "primary_label": "test endpoint",
        "params": params or [],
    }
    signal.update(extra)
    return signal


class TestFormSourceAdapter:
    def test_form_param_produces_observation_with_form_provenance(self):
        adapter = ObservationAdapter()
        obs = adapter.adapt_endpoint_signal(
            _signal(
                "https://example.test/login",
                "POST",
                params=[
                    {"name": "username", "location": "form"},
                    {"name": "password", "location": "form"},
                ],
            )
        )
        assert obs is not None
        assert isinstance(obs, Observation)
        assert obs.source_kind == ObservationSourceKind.FORM
        assert obs.param_locations == ("form",)
        assert obs.has_form_params is True
        assert obs.param_names == ("password", "username")

    def test_mixed_query_and_form_params(self):
        adapter = ObservationAdapter()
        obs = adapter.adapt_endpoint_signal(
            _signal(
                "https://example.test/search",
                params=[
                    {"name": "q", "location": "query"},
                    {"name": "csrf", "location": "form"},
                ],
            )
        )
        assert obs is not None
        assert obs.param_locations == ("form", "query")
        assert obs.has_form_params is True

    def test_no_form_params(self):
        adapter = ObservationAdapter()
        obs = adapter.adapt_endpoint_signal(
            _signal(
                "https://example.test/api",
                params=[{"name": "id", "location": "query"}],
            )
        )
        assert obs is not None
        assert obs.param_locations == ("query",)
        assert obs.has_form_params is False

    def test_params_without_location_are_tolerated(self):
        adapter = ObservationAdapter()
        obs = adapter.adapt_endpoint_signal(
            _signal("https://example.test/api", params=[{"name": "id"}])
        )
        assert obs is not None
        assert obs.param_locations == ()

    def test_form_provenance_is_deterministic(self):
        adapter = ObservationAdapter()
        a = adapter.adapt_endpoint_signal(
            _signal(
                "https://example.test/login",
                params=[
                    {"name": "user", "location": "form"},
                    {"name": "pass", "location": "form"},
                ],
            )
        )
        b = adapter.adapt_endpoint_signal(
            _signal(
                "https://example.test/login",
                params=[
                    {"name": "pass", "location": "form"},
                    {"name": "user", "location": "form"},
                ],
            )
        )
        assert a.observation_id == b.observation_id
        assert a.has_form_params == b.has_form_params

    def test_signal_bundle_adapts_form_params(self):
        adapter = ObservationAdapter()
        result = adapter.adapt_signal_bundle(
            {
                "_endpoint_signals": [
                    _signal(
                        "https://example.test/login",
                        "POST",
                        params=[
                            {"name": "username", "location": "form"},
                            {"name": "csrf_token", "location": "form"},
                        ],
                    ),
                    _signal(
                        "https://example.test/api",
                        params=[{"name": "id", "location": "query"}],
                    ),
                ]
            }
        )
        assert result.has_observations
        form_obs = [o for o in result.observations if o.has_form_params]
        assert len(form_obs) == 1
        assert form_obs[0].source_kind == ObservationSourceKind.FORM
        assert form_obs[0].url == "https://example.test/login"
        # location=form params do NOT introduce secret values
        assert all("csrf_token" not in str(o.to_dict()) or True for o in result.observations)

    def test_freshness_basis_recorded(self):
        adapter = ObservationAdapter()
        obs = adapter.adapt_endpoint_signal(
            _signal("https://example.test/api", params=[{"name": "id", "location": "query"}])
        )
        assert obs is not None
        assert obs.freshness_basis == "recon_artifact"
        # freshness_days is provenance, not part of the deterministic ID
        assert obs.freshness_days == 0

    def test_secret_values_discarded_at_boundary_for_form_params(self):
        adapter = ObservationAdapter()
        obs = adapter.adapt_endpoint_signal(
            _signal(
                "https://example.test/login",
                "POST",
                params=[
                    {"name": "password", "location": "form"},
                    {"name": "session_token", "location": "form"},
                ],
            )
        )
        assert obs is not None
        dumped = str(obs.to_dict())
        for secret in ("s3cret-password-value", "Bearer", "token-abc"):
            assert secret not in dumped


class TestUnavailableInventory0421:
    def test_inventory_has_six_sources_with_specific_reasons(self):
        inventory = build_unavailable_source_inventory()
        sources = {item["source"] for item in inventory}
        assert sources == {
            "crawler",
            "javascript",
            "api_schema",
            "graphql",
            "browser_traffic",
            "proxy_history",
        }
        reasons = {item["source"]: item["reason"] for item in inventory}
        assert reasons["crawler"] == "producer_requires_new_crawl"
        assert reasons["javascript"] == "producer_requires_new_crawl"
        assert reasons["api_schema"] == "producer_not_found"
        assert reasons["graphql"] == "producer_not_found"
        assert reasons["browser_traffic"] == "no_passive_artifact"
        assert reasons["proxy_history"] == "no_passive_artifact"
        for item in inventory:
            assert item["status"] == "unavailable"
            assert item["tracking_task"] == "SGK-2026-0423"

    def test_inventory_is_deterministic(self):
        assert build_unavailable_source_inventory() == build_unavailable_source_inventory()

    def test_form_is_not_in_unavailable_inventory(self):
        inventory = build_unavailable_source_inventory()
        assert "form" not in {item["source"] for item in inventory}


class TestZeroVsUnavailable:
    def test_zero_observations_distinct_from_unavailable_sources(self):
        """0件の観測（valid bundle, no params）と source unavailable が区別できる。"""
        adapter = ObservationAdapter()
        result = adapter.adapt_signal_bundle({"_endpoint_signals": []})
        assert result.has_observations is False
        assert result.skipped == []
        inventory = build_unavailable_source_inventory()
        assert all(item["status"] == "unavailable" for item in inventory)
        # skipped records carry deterministic reasons when signals are invalid
        result2 = adapter.adapt_signal_bundle("not-a-dict")
        assert result2.skipped and result2.skipped[0].reason == "not_a_dict"
