"""
Unit tests for guard metrics collector (Step 9: SGK-2026-0335).

Covers:
- All 6 counters increment correctly
- Labeled counter with layer/decision/reason_code dimensions
- Histogram percentile approximation
- Thread safety (concurrent increments)
- Singleton accessor pattern
- Reset functionality
- Integration: evaluate_at_layer records metrics
- Integration: loader failure records active_bundle_read_failure
- Integration: compiler failure records compile_failed / manual_review_required
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from src.core.security.guard_metrics import (
    GuardMetricsCollector,
    LabeledCounter,
    SimpleCounter,
    SimpleHistogram,
    get_guard_metrics,
    reset_guard_metrics,
)
from src.core.security.compiled_guard_models import (
    GuardDecision,
    GuardInput,
    LoadedGuardPolicy,
)
from src.core.security.guard_enforcement import (
    EnforcementStage,
    evaluate_at_layer,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_metrics():
    """Reset the singleton between tests."""
    reset_guard_metrics()
    yield
    reset_guard_metrics()


@pytest.fixture
def collector() -> GuardMetricsCollector:
    return get_guard_metrics()


# ---------------------------------------------------------------------------
# 1. Core counter/histogram tests
# ---------------------------------------------------------------------------


class TestLabeledCounter:
    def test_inc_and_get(self, collector):
        collector.guard_decision_total.inc("layer=mc,decision=block,reason=deny")
        collector.guard_decision_total.inc("layer=mc,decision=block,reason=deny")
        collector.guard_decision_total.inc("layer=network,decision=allow,reason=in_scope")
        assert collector.guard_decision_total.get("layer=mc,decision=block,reason=deny") == 2
        assert collector.guard_decision_total.get("layer=network,decision=allow,reason=in_scope") == 1
        assert collector.guard_decision_total.get("nonexistent") == 0

    def test_snapshot(self, collector):
        collector.guard_decision_total.inc("a=b")
        snap = collector.guard_decision_total.snapshot()
        assert snap["a=b"] == 1

    def test_independent_instances(self):
        c1 = LabeledCounter()
        c2 = LabeledCounter()
        c1.inc("x=y")
        assert c2.get("x=y") == 0


class TestSimpleCounter:
    def test_inc(self, collector):
        collector.policy_fail_closed_total.inc()
        collector.policy_fail_closed_total.inc()
        assert collector.policy_fail_closed_total.get() == 2

    def test_delta(self, collector):
        collector.policy_fail_closed_total.inc(5)
        assert collector.policy_fail_closed_total.get() == 5


class TestSimpleHistogram:
    def test_empty(self, collector):
        snap = collector.bundle_import_to_ready_seconds.snapshot()
        assert snap["count"] == 0

    def test_values(self, collector):
        collector.bundle_import_to_ready_seconds.observe(1.0)
        collector.bundle_import_to_ready_seconds.observe(2.0)
        snap = collector.bundle_import_to_ready_seconds.snapshot()
        assert snap["count"] == 2
        assert snap["min"] == 1.0
        assert snap["max"] == 2.0
        assert snap["sum"] == 3.0
        assert snap["avg"] == 1.5


# ---------------------------------------------------------------------------
# 2. Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_counter_increments(self, collector):
        def _inc():
            for _ in range(100):
                collector.guard_decision_total.inc("t=test")

        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = [ex.submit(_inc) for _ in range(10)]
            for f in futures:
                f.result()

        assert collector.guard_decision_total.get("t=test") == 1000

    def test_concurrent_fail_closed(self, collector):
        def _inc():
            for _ in range(50):
                collector.record_policy_fail_closed()

        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = [ex.submit(_inc) for _ in range(4)]
            for f in futures:
                f.result()

        assert collector.policy_fail_closed_total.get() == 200


# ---------------------------------------------------------------------------
# 3. Singleton pattern
# ---------------------------------------------------------------------------


class TestSingleton:
    def test_same_instance(self):
        a = get_guard_metrics()
        b = get_guard_metrics()
        assert a is b

    def test_reset_creates_new(self):
        a = get_guard_metrics()
        reset_guard_metrics()
        b = get_guard_metrics()
        assert a is not b

    def test_reset_clears_data(self):
        collector = get_guard_metrics()
        collector.record_policy_fail_closed()
        assert collector.policy_fail_closed_total.get() == 1
        reset_guard_metrics()
        c2 = get_guard_metrics()
        assert c2.policy_fail_closed_total.get() == 0


# ---------------------------------------------------------------------------
# 4. Snapshot
# ---------------------------------------------------------------------------


class TestSnapshot:
    def test_all_keys_present(self, collector):
        snap = collector.snapshot()
        assert "guard_decision_total" in snap
        assert "policy_fail_closed_total" in snap
        assert "active_bundle_read_failure_total" in snap
        assert "compile_failed_total" in snap
        assert "manual_review_required_total" in snap
        assert "bundle_import_to_ready_seconds" in snap

    def test_initial_zeros(self, collector):
        snap = collector.snapshot()
        assert snap["policy_fail_closed_total"] == 0
        assert snap["active_bundle_read_failure_total"] == 0
        assert snap["compile_failed_total"] == 0
        assert snap["manual_review_required_total"] == 0

    def test_snapshot_is_copy(self, collector):
        collector.record_policy_fail_closed()
        snap1 = collector.snapshot()
        collector.record_policy_fail_closed()
        snap2 = collector.snapshot()
        assert snap1["policy_fail_closed_total"] == 1
        assert snap2["policy_fail_closed_total"] == 2


# ---------------------------------------------------------------------------
# 5. Integration: evaluate_at_layer records metrics
# ---------------------------------------------------------------------------


class TestMetricsIntegrationEvaluateAtLayer:
    def test_policy_unavailable_records_fail_closed(self, collector):
        """When policy is None, evaluate_at_layer records fail-closed."""
        gi = GuardInput(host="example.com")
        decision = evaluate_at_layer(
            policy=None,
            guard_input=gi,
            layer="mc",
            stage=EnforcementStage.WORKER_EXTERNAL_HARD,
        )
        assert decision.decision == "block"
        snap = collector.snapshot()
        assert snap["policy_fail_closed_total"] == 1
        labels = snap["guard_decision_total"]
        assert "layer=mc,decision=block,reason_code=policy_unavailable" in labels

    def test_valid_policy_block_records_decision(self, collector):
        """Block by valid policy records guard_decision_total."""
        policy = LoadedGuardPolicy(
            bundle_id="b-1",
            policy_id="p-1",
            provider="test",
            program_name="test",
            program_alias="test",
            compiled_policy_path="/tmp/p.yaml",
            compiled_policy_hash="sha256:aa",
            raw_policy={
                "scope": {"allow_hosts": ["example.com"]},
                "rules": {"phases": {}, "attack_classes": {}},
                "audit": {"rule_origins": []},
            },
        )
        gi = GuardInput(host="out-of-scope.com")
        decision = evaluate_at_layer(
            policy=policy,
            guard_input=gi,
            layer="network",
            stage=EnforcementStage.WORKER_EXTERNAL_HARD,
        )
        assert decision.decision == "block"
        snap = collector.snapshot()
        labels = snap["guard_decision_total"]
        assert any("layer=network" in k and "decision=block" in k for k in labels)

    def test_shadow_stage_records_decision(self, collector):
        """Shadow mode still records the (shadow_) decision."""
        policy = LoadedGuardPolicy(
            bundle_id="b-1",
            policy_id="p-1",
            provider="test",
            program_name="test",
            program_alias="test",
            compiled_policy_path="/tmp/p.yaml",
            compiled_policy_hash="sha256:bb",
            raw_policy={
                "scope": {"allow_hosts": ["example.com"]},
                "rules": {"phases": {}, "attack_classes": {}},
                "audit": {"rule_origins": []},
            },
        )
        gi = GuardInput(host="out-of-scope.com")
        decision = evaluate_at_layer(
            policy=policy,
            guard_input=gi,
            layer="external",
            stage=EnforcementStage.SHADOW_READ_ONLY,
        )
        assert decision.decision == "allow"
        assert decision.reason_code.startswith("shadow_")
        snap = collector.snapshot()
        labels = snap["guard_decision_total"]
        assert any("decision=allow" in k and "shadow_" in k for k in labels)

    def test_allow_records_decision(self, collector):
        """Valid allow also recorded."""
        policy = LoadedGuardPolicy(
            bundle_id="b-1",
            policy_id="p-1",
            provider="test",
            program_name="test",
            program_alias="test",
            compiled_policy_path="/tmp/p.yaml",
            compiled_policy_hash="sha256:cc",
            raw_policy={
                "scope": {"allow_hosts": ["example.com"]},
                "rules": {"phases": {}, "attack_classes": {}},
                "audit": {"rule_origins": []},
            },
        )
        gi = GuardInput(host="example.com")
        evaluate_at_layer(
            policy=policy,
            guard_input=gi,
            layer="mc",
            stage=EnforcementStage.MC_ONLY,
        )
        snap = collector.snapshot()
        labels = snap["guard_decision_total"]
        assert any("layer=mc" in k and "decision=allow" in k for k in labels)


# ---------------------------------------------------------------------------
# 6. Integration: loader failure records active_bundle_read_failure
# ---------------------------------------------------------------------------


class TestMetricsIntegrationLoader:
    def test_missing_dir_records_failure(self, collector, tmp_path):
        from src.core.security.compiled_guard_loader import load_active_policy_from_bundle_dir

        nonexistent = tmp_path / "nonexistent"
        result = load_active_policy_from_bundle_dir(nonexistent)
        assert result.reason_code == "active_bundle_missing"
        snap = collector.snapshot()
        assert snap["active_bundle_read_failure_total"] >= 1


# ---------------------------------------------------------------------------
# 7. Integration: compiler records compile_failed / manual_review_required
# ---------------------------------------------------------------------------


class TestMetricsIntegrationCompiler:
    def test_empty_bundle_records_compile_failed(self, collector):
        from src.core.security.compiled_guard_compiler import compile_guard_policy
        from src.core.security.program_adapter_base import NormalizedFacts

        facts = NormalizedFacts()
        facts.program = {"provider": "hackerone", "program_name": "test"}
        facts.assets = []
        facts.rule_candidates = []
        facts.review_candidates = []
        facts.extraction_audit = []

        policy = compile_guard_policy(facts, {"review_findings": []}, {"overrides": {}})
        assert policy["compile_status"] == "compile_failed"
        snap = collector.snapshot()
        assert snap["compile_failed_total"] == 1

    def test_blocking_pending_records_manual_review(self, collector):
        from src.core.security.compiled_guard_compiler import compile_guard_policy
        from src.core.security.program_adapter_base import NormalizedAsset, NormalizedFacts

        facts = NormalizedFacts()
        facts.program = {"provider": "hackerone", "program_name": "test"}
        facts.assets = [
            NormalizedAsset(
                asset_id="a1",
                canonical_key="example.com",
                asset_kind="host_exact",
                submission_allowed=True,
                runtime_surface="http",
                source_ref="scope.csv#row=1",
            )
        ]
        facts.rule_candidates = []
        facts.review_candidates = []
        facts.extraction_audit = []

        review_findings = {
            "review_findings": [
                {
                    "finding_id": "RF-001",
                    "category": "temporal_scope",
                    "subject": "example.com",
                    "risk_level": "high",
                    "source_refs": ["policy.md"],
                    "machine_guess": {"effect": "allow"},
                    "status": "pending",
                    "blocking": True,
                }
            ]
        }

        policy = compile_guard_policy(facts, review_findings, {"overrides": {}})
        assert policy["compile_status"] == "manual_review_required"
        snap = collector.snapshot()
        assert snap["manual_review_required_total"] == 1


# ---------------------------------------------------------------------------
# 8. Integration: bundle_import_to_ready_seconds recorded by compile_bundle
# ---------------------------------------------------------------------------


class TestMetricsIntegrationBundleImportToReady:
    def test_compile_ready_records_histogram(self, collector, tmp_path):
        """compile_bundle with ready status records bundle_import_to_ready_seconds."""
        from src.core.security.bundle_manager import BundleManager

        # Set up a minimal bundle fixture
        bundle_dir = tmp_path / "minimal_bundle"
        bundle_dir.mkdir()
        import yaml
        (bundle_dir / "source_manifest.yaml").write_text(
            "schema_version: 1\nprovider: hackerone\nprogram_name: Test\n"
            "captured_at_utc: '2026-07-02T00:00:00Z'\ndefault_timezone: UTC\n"
            "bundle_id: test-bundle-id\npolicy_path: policy.md\n"
            "scope_sources:\n  - kind: hackerone_csv\n    path: scope.csv\n"
        )
        (bundle_dir / "policy.md").write_text("# Test policy\n")
        (bundle_dir / "scope.csv").write_text(
            "identifier,asset_type,instruction,eligible_for_bounty,"
            "eligible_for_submission,availability_requirement,"
            "confidentiality_requirement,integrity_requirement,max_severity\n"
            "example.com,URL,,true,true,,,,\n"
        )
        (bundle_dir / "review_findings.yaml").write_text("review_findings: []\n")
        (bundle_dir / "overrides.yaml").write_text("overrides: {}\n")

        mgr = BundleManager()
        result = mgr.compile_bundle(bundle_dir)
        assert result["compile_status"] == "ready"

        snap = collector.snapshot()
        hist = snap["bundle_import_to_ready_seconds"]
        assert hist["count"] >= 1
        assert hist["min"] > 0
