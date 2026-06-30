"""
Phase 0 Inventory Tests (TDD)

These tests define the expected structure and content of the Phase 0
concurrency inventory. They all FAIL initially because the inventory
data does not exist yet. Implementation creates the inventory to pass them.

Plan: SGK-2026-0309 / SGK-2026-0291 Section 4 Phase 0
"""
import os
import pytest
from typing import Dict, List, Any

# --- Test constants ---
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
INVENTORY_PATH = os.path.join(
    PROJECT_ROOT, "src", "core", "agents", "swarm", "phase0", "concurrency_map.yaml"
)

TARGET_FILES = [
    "src/core/engine/master_conductor.py",
    "src/core/engine/parallel_orchestrator.py",
    "src/core/engine/swarm_dispatcher.py",
    "src/core/agents/swarm/base.py",
    "src/core/agents/swarm/base_manager.py",
    "src/core/agents/swarm/injection/manager.py",
]

REQUIRED_TOP_KEYS = [
    "meta",
    "execution_flow",
    "parallel_sequential_classification",
    "responsibility_assignment",
    "mutable_state_inventory",
    "specialist_classification",
    "contract_candidates",
    "blockers_and_nontargets",
    "adaptiveskip_protection",
    "traceability",
]

LAYERS = [
    "mc_outer",
    "swarm_dispatcher",
    "swarm_manager",
    "specialist_internal",
]

CLASSIFICATION_VALUES = [
    "parallel_safe",
    "sequential_required",
    "rate_limited",
    "stateful",
    "aggressive_exclusive",
    "unknown",
]

STATE_CLASSIFICATIONS = [
    "dispatch_local",
    "shared_immutable",
    "shared_mutable",
    "external_state",
]

# ─── Fixtures ────────────────────────────────────────────────────


def _load_inventory() -> Dict[str, Any]:
    """Load the Phase 0 inventory YAML, if it exists."""
    try:
        import yaml
    except ImportError:
        pytest.skip("PyYAML not available")
    if not os.path.exists(INVENTORY_PATH):
        pytest.skip(f"Inventory file not found: {INVENTORY_PATH}")
    with open(INVENTORY_PATH, "r") as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="module")
def inventory():
    """Module-scoped fixture loading the inventory once."""
    return _load_inventory()


# ─── Structure Tests ─────────────────────────────────────────────


class TestInventoryExists:
    """TDD Gate: inventory file must exist."""

    def test_inventory_file_exists(self):
        """Phase 0 inventory YAML file must be present."""
        assert os.path.exists(INVENTORY_PATH), (
            f"Phase 0 inventory not found at {INVENTORY_PATH}. "
            "Create it at src/core/agents/swarm/phase0/concurrency_map.yaml"
        )

    def test_inventory_is_valid_yaml(self):
        """Inventory must be valid YAML that we can load."""
        if not os.path.exists(INVENTORY_PATH):
            pytest.skip("File does not exist yet")
        import yaml
        with open(INVENTORY_PATH, "r") as f:
            data = yaml.safe_load(f)
        assert data is not None, "Inventory YAML must not be empty/None"
        assert isinstance(data, dict), "Inventory YAML must be a dict at root"


class TestTopLevelStructure:
    """Inventory must have all required top-level sections."""

    def test_all_required_keys_present(self, inventory):
        for key in REQUIRED_TOP_KEYS:
            assert key in inventory, f"Missing required top-level key: {key}"

    def test_meta_section(self, inventory):
        meta = inventory.get("meta", {})
        assert "task_id" in meta, "meta.task_id required"
        assert meta.get("task_id") == "SGK-2026-0309"
        assert "parent_task_id" in meta, "meta.parent_task_id required"
        assert meta.get("parent_task_id") == "SGK-2026-0291"
        assert "generated_at" in meta, "meta.generated_at required"

    def test_target_files_present(self, inventory):
        meta = inventory.get("meta", {})
        target_files = meta.get("target_files", [])
        for tf in TARGET_FILES:
            assert tf in target_files, f"Target file {tf} not listed in meta.target_files"
            full_path = os.path.join(PROJECT_ROOT, tf)
            assert os.path.exists(full_path), (
                f"Referenced target file does not exist: {full_path}"
            )


# ─── Content Tests ───────────────────────────────────────────────


class TestExecutionFlow:
    """Execution flow must cover all 4 layers with code references."""

    def test_layers_present(self, inventory):
        flow = inventory.get("execution_flow", {})
        for layer in LAYERS:
            assert layer in flow, f"Missing execution_flow layer: {layer}"

    def test_each_layer_has_code_refs(self, inventory):
        flow = inventory.get("execution_flow", {})
        for layer in LAYERS:
            entries = flow.get(layer, [])
            assert isinstance(entries, list), f"{layer} must be a list"
            for entry in entries:
                assert "file" in entry, f"{layer} entry missing 'file'"
                assert "function" in entry, f"{layer} entry missing 'function'"
                assert "line" in entry, f"{layer} entry missing 'line'"


class TestParallelSequentialClassification:
    """Each item must have file/function/line reference and valid classification."""

    def test_sections_present(self, inventory):
        ps = inventory.get("parallel_sequential_classification", {})
        for layer in LAYERS:
            assert layer in ps, f"Missing classification section: {layer}"

    def test_classifications_are_valid(self, inventory):
        ps = inventory.get("parallel_sequential_classification", {})
        for layer in LAYERS:
            for entry in ps.get(layer, []):
                assert "classification" in entry, f"{layer} entry missing classification"
                assert entry["classification"] in CLASSIFICATION_VALUES, (
                    f"Invalid classification '{entry['classification']}' in {layer}. "
                    f"Must be one of {CLASSIFICATION_VALUES}"
                )

    def test_code_references(self, inventory):
        ps = inventory.get("parallel_sequential_classification", {})
        for layer in LAYERS:
            for entry in ps.get(layer, []):
                assert "file" in entry, f"{layer} entry missing 'file'"
                assert "function" in entry, f"{layer} entry missing 'function'"
                assert "line" in entry, f"{layer} entry missing 'line'"
                assert isinstance(entry["line"], int) or entry["line"] is None, (
                    f"{layer} entry line must be int or null (for multi-line patterns): "
                    f"got {type(entry['line']).__name__}"
                )
                assert "primitive" in entry, (
                    f"{layer} entry missing 'primitive' (await/for/gather/semaphore/...)"
                )

class TestMutableStateInventory:
    """All shared state must be inventoried and classified."""

    def test_inventory_has_entries(self, inventory):
        msi = inventory.get("mutable_state_inventory", [])
        assert len(msi) > 0, "Mutable state inventory must not be empty"

    def test_each_entry_has_required_fields(self, inventory):
        required = ["name", "location", "state_classification", "protection_reason"]
        for entry in inventory.get("mutable_state_inventory", []):
            for field in required:
                assert field in entry, f"State entry missing '{field}'"
            assert entry["state_classification"] in STATE_CLASSIFICATIONS, (
                f"Invalid state_classification: {entry['state_classification']}"
            )

    def test_key_shared_state_accounted_for(self, inventory):
        msi = inventory.get("mutable_state_inventory", [])
        names = {e.get("name", "") for e in msi}
        # These are critical shared states the plan explicitly calls out
        # If any are missing, the test fails (documentation incomplete)
        required_states = [
            "current_context",
            "swarm_pool",
            "semaphore",
            "event_bus",
            "rate_limiter",
        ]
        missing = [s for s in required_states if not any(s.lower() in n.lower() for n in names)]
        assert not missing, (
            f"Critical shared states not inventoried: {missing}"
        )


class TestSpecialistClassification:
    """All specialists must be classified into parallel_safe/sequential_required/..."""

    def test_classification_table_exists(self, inventory):
        sc = inventory.get("specialist_classification", [])
        assert len(sc) > 0, "specialist_classification table must not be empty"

    def test_each_specialist_has_classification(self, inventory):
        for entry in inventory.get("specialist_classification", []):
            assert "name" in entry, "Specialist entry missing 'name'"
            assert "classification" in entry, "Specialist entry missing 'classification'"
            assert entry["classification"] in CLASSIFICATION_VALUES
            assert "rationale" in entry, "Specialist entry missing 'rationale'"
            assert "code_references" in entry, "Specialist entry missing 'code_references'"

    def test_unknown_has_blocker_reason(self, inventory):
        for entry in inventory.get("specialist_classification", []):
            if entry.get("classification") == "unknown":
                assert "blocker_reason" in entry, (
                    f"Specialist '{entry.get('name')}' is 'unknown' but has no blocker_reason"
                )
                assert "next_step" in entry, (
                    f"Specialist '{entry.get('name')}' is 'unknown' but has no next_step"
                )


class TestAdaptiveSkipProtection:
    """Adaptive skip on High/Critical finding must be explicitly documented as protected."""

    def test_adaptive_skip_documented(self, inventory):
        asp = inventory.get("adaptiveskip_protection", {})
        assert asp, "adaptiveskip_protection section must exist"
        assert "protected" in asp, "Must have 'protected' field"
        assert asp.get("protected") is True, "Adaptive skip must be marked as protected=True"
        assert "location" in asp, "Must have 'location' field (file/function/line)"
        assert "semantics" in asp, "Must describe the skip semantics"


# ─── Traceability Tests ──────────────────────────────────────────


class TestTraceability:
    """Every fixed item must trace to parent plan sections 4.1 / 4.2 / 4.4."""

    def test_traceability_section_exists(self, inventory):
        t = inventory.get("traceability", {})
        assert t, "traceability section must exist"
        for section in ["4.1", "4.2", "4.4"]:
            assert section in t, f"traceability must map to parent plan section {section}"

    def test_contract_candidates_traceable(self, inventory):
        cc = inventory.get("contract_candidates", [])
        trace = inventory.get("traceability", {})
        for candidate in cc:
            assert "traces_to" in candidate, (
                f"Contract candidate '{candidate.get('name')}' missing traces_to"
            )

    def test_nontargets_align_with_plan(self, inventory):
        nt = inventory.get("blockers_and_nontargets", {})
        nontargets = nt.get("initial_nontargets", [])
        # Verify the plan's explicit non-targets are represented
        plan_nontargets = [
            "swarm_manager_specialist_full_parallelization",
            "injectionmanager_phase1_url_full_parallelization",
            "mutating_aggressive_lane_default_enable",
            "session_report_schema_delete_rename",
            "external_dependency_addition",
            "scope_unknown_active_mutating_aggressive_execution",
            "adaptive_skip_semantics_change",
        ]
        nt_names = {item.get("id", "") for item in nontargets}
        for pnt in plan_nontargets:
            assert pnt in nt_names, f"Plan non-target not represented: {pnt}"


# ─── Blockers & Go/No-Go Tests ──────────────────────────────────


class TestBlockersAndGoNoGo:
    """Phase 0 must explicitly list Phase 1-4 Go/No-Go conditions."""

    def test_blockers_section(self, inventory):
        bng = inventory.get("blockers_and_nontargets", {})
        assert "phase1_4_go_conditions" in bng, "Go conditions for Phase 1-4 required"
        assert "phase1_4_nogo_conditions" in bng, "No-Go conditions for Phase 1-4 required"

    def test_go_conditions_not_empty(self, inventory):
        bng = inventory.get("blockers_and_nontargets", {})
        go = bng.get("phase1_4_go_conditions", [])
        assert len(go) > 0, "Go conditions list must not be empty"

    def test_nogo_conditions_not_empty(self, inventory):
        bng = inventory.get("blockers_and_nontargets", {})
        nogo = bng.get("phase1_4_nogo_conditions", [])
        assert len(nogo) > 0, "No-Go conditions list must not be empty"


# ─── Classification Rules ────────────────────────────────────────


class TestClassificationRules:
    """Classification rule table must exist and define each category."""

    def test_rules_table_exists(self, inventory):
        rules = inventory.get("classification_rules", [])
        assert len(rules) > 0, "classification_rules table must not be empty"

    def test_each_classification_defined(self, inventory):
        rules = inventory.get("classification_rules", [])
        defined = {r.get("classification", "") for r in rules}
        for cv in CLASSIFICATION_VALUES:
            if cv != "unknown":
                assert cv in defined, f"Classification '{cv}' not defined in rules table"

    def test_unknown_handling_defined(self, inventory):
        rules = inventory.get("classification_rules", [])
        unknown_rule = next((r for r in rules if r.get("classification") == "unknown"), None)
        assert unknown_rule is not None, "Must define handling for 'unknown' classification"
        assert "default_treatment" in unknown_rule, "unknown must have default_treatment"
        assert "promotion_criteria" in unknown_rule, "unknown must have promotion_criteria"
