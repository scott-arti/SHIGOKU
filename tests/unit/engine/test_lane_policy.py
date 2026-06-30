"""
T-1.1 through T-1.6: LanePolicy tests.

Tests:
  - T-1.1+S-4: PHASE0_CLASS_TO_LANE covers all 24 specialists (hard gate)
  - T-1.2: unknown default → sequential_required
  - T-1.3: reason_code never empty
  - T-1.4: lane classification deterministic
  - T-1.5: Phase 2 vs Phase 0 disagreement flagged
  - T-1.6: swarm-level most restrictive classification
"""
import pytest
from src.core.engine.lane_policy import LanePolicy, PHASE0_CLASS_TO_LANE
from src.core.agents.swarm.phase0 import load_inventory


@pytest.fixture(scope="module")
def lane_policy():
    return LanePolicy()


@pytest.fixture(scope="module")
def inventory():
    return load_inventory()


# ---------------------------------------------------------------------------
# T-1.1 + S-4: Hard gate — all specialists in inventory fit PHASE0_CLASS_TO_LANE
# ---------------------------------------------------------------------------

class TestSpecialistClassToLaneMapping:
    """T-1.1 + S-4: Every specialist's classification must map to a valid lane."""

    def test_all_inventory_specialists_classified(self, lane_policy):
        """Every specialist in Phase 0 inventory gets a valid lane classification."""
        valid_lanes = {"read_only", "stateful_read", "mutating", "aggressive_exclusive", "sequential_required"}
        valid_classifications = set(PHASE0_CLASS_TO_LANE.keys())

        for name, classification in lane_policy._specialist_classifications.items():
            assert classification in valid_classifications, (
                f"Specialist '{name}' has classification '{classification}' "
                f"not in PHASE0_CLASS_TO_LANE keys: {valid_classifications}"
            )

    def test_all_classifications_map_to_valid_lane(self, lane_policy):
        """Every mapped lane is one of the 5 valid lanes."""
        valid_lanes = {"read_only", "stateful_read", "mutating", "aggressive_exclusive", "sequential_required"}
        for name in lane_policy._specialist_classifications:
            lane, ps, rl, compat, disagree, reason = lane_policy.classify_specialist(name)
            assert lane in valid_lanes, (
                f"Specialist '{name}' mapped to lane '{lane}' not in {valid_lanes}"
            )
            assert reason != "", f"Specialist '{name}' has empty reason_code"

    def test_rate_limited_specialists_have_correct_axes(self, lane_policy):
        """T-1.1: rate_limited class → read_only lane, parallel_safe=true, rate_limited=true."""
        for name, classification in lane_policy._specialist_classifications.items():
            if classification == "rate_limited":
                lane, ps, rl, _, _, _ = lane_policy.classify_specialist(name)
                assert lane == "read_only", f"{name}: expected read_only, got {lane}"
                assert ps is True, f"{name}: expected parallel_safe=True, got {ps}"
                assert rl is True, f"{name}: expected rate_limited=True, got {rl}"

    def test_parallel_safe_specialists_have_correct_axes(self, lane_policy):
        """parallel_safe class → read_only lane, parallel_safe=true, rate_limited=false."""
        for name, classification in lane_policy._specialist_classifications.items():
            if classification == "parallel_safe":
                lane, ps, rl, _, _, _ = lane_policy.classify_specialist(name)
                assert lane == "read_only", f"{name}: expected read_only, got {lane}"
                assert ps is True, f"{name}: expected parallel_safe=True, got {ps}"
                assert rl is False, f"{name}: expected rate_limited=False, got {rl}"

    def test_stateful_specialists_have_correct_axes(self, lane_policy):
        """stateful class → stateful_read lane, parallel_safe=false, rate_limited=false."""
        for name, classification in lane_policy._specialist_classifications.items():
            if classification == "stateful":
                lane, ps, rl, _, _, _ = lane_policy.classify_specialist(name)
                assert lane == "stateful_read", f"{name}: expected stateful_read, got {lane}"
                assert ps is False, f"{name}: expected parallel_safe=False, got {ps}"
                assert rl is False, f"{name}: expected rate_limited=False, got {rl}"

    def test_aggressive_exclusive_specialists_have_correct_axes(self, lane_policy):
        """aggressive_exclusive class → aggressive_exclusive lane, parallel_safe=false, rate_limited=false."""
        for name, classification in lane_policy._specialist_classifications.items():
            if classification == "aggressive_exclusive":
                lane, ps, rl, _, _, _ = lane_policy.classify_specialist(name)
                assert lane == "aggressive_exclusive", f"{name}: expected aggressive_exclusive, got {lane}"
                assert ps is False, f"{name}: expected parallel_safe=False, got {ps}"
                assert rl is False, f"{name}: expected rate_limited=False, got {rl}"

    def test_unknown_treatment_from_inventory(self, lane_policy, inventory):
        """unknown.default_treatment must reference sequential_required."""
        rules = inventory.get("classification_rules", [])
        for rule in rules:
            if rule.get("classification") == "unknown":
                treatment = rule.get("default_treatment", "")
                assert "sequential_required" in treatment.lower(), (
                    f"unknown.default_treatment does not reference sequential_required: {treatment!r}"
                )
        # Also verify LanePolicy accepted it (didn't raise ValueError)
        assert lane_policy._unknown_treatment == "sequential_required"


# ---------------------------------------------------------------------------
# T-1.2: unknown defaults → sequential_required
# ---------------------------------------------------------------------------

class TestUnknownDefaults:
    """T-1.2: Unknown or missing specialists default to sequential_required (safe side)."""

    def test_unknown_specialist_sequential_required(self, lane_policy):
        """An unknown specialist name → sequential_required lane."""
        lane, ps, rl, compat, disagree, reason = lane_policy.classify_specialist("NonExistentSpecialist")
        assert lane == "sequential_required"
        assert ps is False
        assert rl is False
        assert reason == "unclassified_safety_default"

    def test_unknown_swarm_sequential_required(self, lane_policy):
        """An unknown swarm name → sequential_required lane."""
        lane, ps, rl, compat, disagree, reason = lane_policy.classify_swarm("UnknownSwarm")
        assert lane == "sequential_required"
        assert ps is False
        assert rl is False
        assert reason == "unclassified_safety_default"

    def test_unknown_agent_type_sequential_required(self, lane_policy):
        """Agent type that doesn't match any swarm → sequential_required."""
        lane, ps, rl, compat, disagree, reason = lane_policy.classify("SomeRandomAgent")
        assert lane == "sequential_required"
        assert ps is False
        assert rl is False

    def test_unknown_default_is_not_read_only(self, lane_policy):
        """T-1.2 critical: unknown MUST NOT be read_only (unlike Phase 2 default)."""
        lane, _, _, _, _, _ = lane_policy.classify("SomeRandomAgent")
        assert lane != "read_only", "Unknown agent MUST NOT default to read_only"


# ---------------------------------------------------------------------------
# T-1.3: reason_code never empty
# ---------------------------------------------------------------------------

class TestReasonCodeRequired:
    """T-1.3: Every lane decision must have a non-empty reason_code."""

    def test_classify_specialist_has_reason(self, lane_policy):
        for name in lane_policy._specialist_classifications:
            _, _, _, _, _, reason = lane_policy.classify_specialist(name)
            assert reason != "", f"Specialist '{name}' has empty reason_code"

    def test_classify_swarm_has_reason(self, lane_policy):
        for swarm_name in lane_policy._swarm_to_specialists:
            _, _, _, _, _, reason = lane_policy.classify_swarm(swarm_name)
            assert reason != "", f"Swarm '{swarm_name}' has empty reason_code"

    def test_classify_has_reason(self, lane_policy):
        for agent_type in ["InjectionManagerAgent", "AuthNinja", "ScannerSwarm", "FuzzingSwarm"]:
            _, _, _, _, _, reason = lane_policy.classify(agent_type)
            assert reason != "", f"Agent '{agent_type}' has empty reason_code"


# ---------------------------------------------------------------------------
# T-1.4: lane classification deterministic
# ---------------------------------------------------------------------------

class TestLaneClassificationDeterministic:
    """T-1.4: Same input always produces same lane (replay-safe)."""

    def test_specialist_deterministic(self, lane_policy):
        """Same specialist name → same decision every time."""
        result1 = lane_policy.classify_specialist("SmartSQLiHunter")
        for _ in range(10):
            result2 = lane_policy.classify_specialist("SmartSQLiHunter")
            assert result1 == result2, "Same specialist produced different classification"

    def test_swarm_deterministic(self, lane_policy):
        """Same swarm name → same decision every time."""
        result1 = lane_policy.classify_swarm("injection", {"category": "attack_inject"})
        for _ in range(10):
            result2 = lane_policy.classify_swarm("injection", {"category": "attack_inject"})
            assert result1 == result2, "Same swarm produced different classification"

    def test_agent_deterministic(self, lane_policy):
        """Same agent_type → same decision every time."""
        result1 = lane_policy.classify("InjectionManagerAgent", {"category": "attack_inject"})
        for _ in range(10):
            result2 = lane_policy.classify("InjectionManagerAgent", {"category": "attack_inject"})
            assert result1 == result2, "Same agent produced different classification"


# ---------------------------------------------------------------------------
# T-1.5: Phase 2 category vs Phase 0 specialist disagreement flagged
# ---------------------------------------------------------------------------

class TestPhase2Disagreement:
    """T-1.5: When Phase 2 compat_lane differs from Phase 0 authority lane, flag it."""

    def test_injection_attack_inject_disagreement(self, lane_policy):
        """attack_inject category → Phase2=mutating, Phase0=rate_limited(+aggressive_exclusive in swarm).
        The injection swarm's most restrictive is aggressive_exclusive, so lane=aggressive_exclusive.
        Phase 2 CATEGORY_TO_LANE for attack_inject is 'mutating'.
        Since aggressive_exclusive != mutating, disagreement is True."""
        _, _, _, compat_lane, disagreement, _ = lane_policy.classify_swarm(
            "injection", {"category": "attack_inject"}
        )
        assert compat_lane == "mutating"
        assert disagreement is True

    def test_injection_attack_auth_disagreement(self, lane_policy):
        """attack_auth category → Phase2=mutating. Injection swarm lane=aggressive_exclusive.
        disagreement=True."""
        _, _, _, compat_lane, disagreement, _ = lane_policy.classify_swarm(
            "injection", {"category": "attack_auth"}
        )
        assert compat_lane == "mutating"
        assert disagreement is True

    def test_secret_default_no_disagreement(self, lane_policy):
        """SecretSwarm with default category → Phase2=read_only, Phase0=read_only. No disagreement."""
        _, _, _, compat_lane, disagreement, _ = lane_policy.classify_swarm(
            "secret", {"category": "default"}
        )
        assert compat_lane == "read_only"
        assert disagreement is False

    def test_intel_passive_no_disagreement(self, lane_policy):
        """intelligence with intel_passive → Phase2=read_only, Phase0=rate_limited→read_only.
        Both read_only, no disagreement."""
        _, _, _, compat_lane, disagreement, _ = lane_policy.classify_swarm(
            "intelligence", {"category": "intel_passive"}
        )
        assert compat_lane == "read_only"
        assert disagreement is False

    def test_no_metadata_no_compat_lane(self, lane_policy):
        """Without metadata, compat_lane is None and no disagreement."""
        _, _, _, compat_lane, disagreement, _ = lane_policy.classify_swarm("injection")
        assert compat_lane is None
        assert disagreement is False


# ---------------------------------------------------------------------------
# T-1.6: swarm-level most restrictive classification
# ---------------------------------------------------------------------------

class TestSwarmMostRestrictive:
    """T-1.6: Swarm lane = most restrictive specialist in the swarm."""

    def test_injection_swarm_most_restrictive(self, lane_policy):
        """Injection has parallel_safe, rate_limited, stateful, aggressive_exclusive.
        Most restrictive = aggressive_exclusive."""
        lane, ps, rl, _, _, reason = lane_policy.classify_swarm("injection")
        assert lane == "aggressive_exclusive"
        assert ps is False

    def test_auth_swarm_most_restrictive(self, lane_policy):
        """Auth swarm has only stateful specialists. Most restrictive = stateful → stateful_read."""
        lane, ps, rl, _, _, reason = lane_policy.classify_swarm("auth")
        assert lane == "stateful_read"
        assert ps is False

    def test_logic_swarm_most_restrictive(self, lane_policy):
        """Logic has rate_limited, aggressive_exclusive, stateful.
        Most restrictive = aggressive_exclusive."""
        lane, ps, rl, _, _, reason = lane_policy.classify_swarm("logic")
        assert lane == "aggressive_exclusive"
        assert ps is False

    def test_secret_swarm_read_only(self, lane_policy):
        """Secret swarm: parallel_safe only → read_only."""
        lane, ps, rl, _, _, reason = lane_policy.classify_swarm("secret")
        assert lane == "read_only"
        assert ps is True
        assert rl is False

    def test_scanner_swarm_read_only(self, lane_policy):
        """Scanner swarm: parallel_safe only → read_only."""
        lane, ps, rl, _, _, reason = lane_policy.classify_swarm("scanner")
        assert lane == "read_only"
        assert ps is True

    def test_discovery_swarm_rate_limited(self, lane_policy):
        """Discovery swarm: rate_limited → read_only with rate_limited=True."""
        lane, ps, rl, _, _, reason = lane_policy.classify_swarm("discovery")
        assert lane == "read_only"
        assert ps is True
        assert rl is True

    def test_intelligence_swarm_rate_limited(self, lane_policy):
        """Intelligence swarm: rate_limited → read_only with rate_limited=True."""
        lane, ps, rl, _, _, reason = lane_policy.classify_swarm("intelligence")
        assert lane == "read_only"
        assert ps is True
        assert rl is True

    def test_fuzzing_swarm_aggressive_exclusive(self, lane_policy):
        """Fuzzing swarm: aggressive_exclusive only."""
        lane, ps, rl, _, _, reason = lane_policy.classify_swarm("fuzzing")
        assert lane == "aggressive_exclusive"
        assert ps is False


# ---------------------------------------------------------------------------
# T-1.6 additional: agent_to_swarm mapping
# ---------------------------------------------------------------------------

class TestAgentToSwarm:
    """Agent type → swarm name normalization."""

    def test_injection_manager_agent(self, lane_policy):
        swarm = lane_policy._agent_to_swarm("InjectionManagerAgent")
        assert swarm == "injection"

    def test_auth_ninja(self, lane_policy):
        swarm = lane_policy._agent_to_swarm("AuthNinja")
        assert swarm == "auth"

    def test_scanner_swarm(self, lane_policy):
        swarm = lane_policy._agent_to_swarm("ScannerSwarm")
        assert swarm == "scanner"

    def test_fuzzing_swarm(self, lane_policy):
        swarm = lane_policy._agent_to_swarm("FuzzingSwarm")
        assert swarm == "fuzzing"

    def test_secret_swarm(self, lane_policy):
        swarm = lane_policy._agent_to_swarm("SecretSwarm")
        assert swarm == "secret"

    def test_discovery_swarm(self, lane_policy):
        swarm = lane_policy._agent_to_swarm("DiscoverySwarm")
        assert swarm == "discovery"

    def test_intelligence_swarm(self, lane_policy):
        swarm = lane_policy._agent_to_swarm("IntelligenceSwarm")
        assert swarm == "intelligence"

    def test_recon_agent(self, lane_policy):
        """Recon agent maps to discovery swarm."""
        swarm = lane_policy._agent_to_swarm("ReconAgent")
        assert swarm == "discovery"

    def test_biz_logic_hunter(self, lane_policy):
        swarm = lane_policy._agent_to_swarm("BizLogicHunter")
        assert swarm == "logic"
