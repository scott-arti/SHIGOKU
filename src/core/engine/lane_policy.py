from __future__ import annotations

"""Phase 4 shadow mode lane policy.

Reads the Phase 0 concurrency inventory to classify specialists and swarms.
Phase 0 specialist classification is the authoritative source for lane assignment.
Phase 2 CATEGORY_TO_LANE is used only for compat_lane comparison.
"""

PHASE0_CLASS_TO_LANE: dict[str, tuple[str, bool, bool, str]] = {
    # (lane, parallel_safe, rate_limited, reason_code)
    "parallel_safe":       ("read_only",             True,  False, "class_parallel_safe"),
    "rate_limited":        ("read_only",             True,  True,  "class_rate_limited_budget_required"),
    "stateful":            ("stateful_read",         False, False, "class_stateful_session_order"),
    "aggressive_exclusive":("aggressive_exclusive",  False, False, "class_aggressive_exclusive"),
    "sequential_required": ("sequential_required",   False, False, "class_sequential_required"),
    "unknown":             ("sequential_required",   False, False, "unclassified_safety_default"),
}


class LanePolicy:
    """Phase 4 lane classification policy.

    Reads the Phase 0 concurrency inventory to classify specialists and swarms.
    Phase 0 specialist classification is the authoritative source for lane assignment.
    Phase 2 CATEGORY_TO_LANE is used only for compat_lane comparison.
    """

    def __init__(self):
        """Load inventory from concurrency_map.yaml."""
        from src.core.agents.swarm.phase0 import load_inventory
        self._inventory = load_inventory()
        self._specialist_classifications: dict[str, str] = {}
        self._swarm_to_specialists: dict[str, list[str]] = self._build_swarm_specialist_map()
        self._unknown_treatment = self._resolve_unknown_treatment()
        # Build specialist name -> classification lookup
        for entry in self._inventory.get("specialist_classification", []):
            name = entry.get("name", "")
            classification = entry.get("classification", "unknown")
            if name:
                self._specialist_classifications[name] = classification

    def _resolve_unknown_treatment(self) -> str:
        """Read unknown.default_treatment from classification_rules.
        Must be 'sequential_required' equivalent. Returns the default_treatment string.
        """
        rules = self._inventory.get("classification_rules", [])
        for rule in rules:
            if rule.get("classification") == "unknown":
                treatment = rule.get("default_treatment", "")
                # Verify it references sequential_required
                if "sequential_required" not in treatment.lower():
                    raise ValueError(
                        f"unknown.default_treatment is not sequential_required: {treatment!r}"
                    )
                return "sequential_required"
        return "sequential_required"

    def _build_swarm_specialist_map(self) -> dict[str, list[str]]:
        """Map swarm names to their specialists based on known groupings.
        
        BaseManagerAgent subclasses: injection, auth, logic, discovery
        Plain SwarmManager subclasses: secret, scanner, intelligence, fuzzing
        """
        # Build swarm→specialist mapping from inventory file paths.
        # swarms_by_file: map the YAML 'file' field to swarm name.
        swarm_by_file_prefix: dict[str, str] = {
            "src/core/agents/swarm/injection/": "injection",
            "src/core/agents/swarm/auth/": "auth",
            "src/core/agents/swarm/logic/": "logic",
            "src/core/agents/swarm/discovery/": "discovery",
            "src/core/agents/swarm/secret/": "secret",
            "src/core/agents/swarm/scanner/": "scanner",
            "src/core/agents/swarm/intelligence/": "intelligence",
            "src/core/agents/swarm/fuzzing/": "fuzzing",
            # Specialist files outside the above (biz_logic_hunter.py)
            "src/core/agents/swarm/biz_logic_hunter.py": "logic",
        }
        mapping: dict[str, list[str]] = {swarm: [] for swarm in swarm_by_file_prefix.values()}
        for entry in self._inventory.get("specialist_classification", []):
            name = entry.get("name", "")
            file = entry.get("file", "")
            if not name:
                continue
            # Determine swarm from file path
            assigned = False
            for prefix, swarm in swarm_by_file_prefix.items():
                if file.startswith(prefix):
                    mapping[swarm].append(name)
                    assigned = True
                    break
            if not assigned:
                # Unknown file → don't assign, falls back to default handling
                pass
        return mapping

    def classify_specialist(self, specialist_name: str, task_metadata: dict | None = None
                           ) -> tuple[str, bool, bool, str | None, bool, str]:
        """Classify a specialist by name.
        
        Returns: (lane, parallel_safe, rate_limited, compat_lane, lane_disagreement, reason_code)
        """
        classification = self._specialist_classifications.get(specialist_name, "unknown")
        if classification not in PHASE0_CLASS_TO_LANE:
            classification = "unknown"
        
        lane, parallel_safe, rate_limited, reason_code = PHASE0_CLASS_TO_LANE.get(
            classification, PHASE0_CLASS_TO_LANE["unknown"])
        
        # Phase 2 compat_lane from CATEGORY_TO_LANE
        from src.core.engine.parallel_orchestrator import CATEGORY_TO_LANE
        compat_lane = None
        lane_disagreement = False
        if task_metadata:
            category = task_metadata.get("category", task_metadata.get("agent_type", "default"))
            compat_lane = CATEGORY_TO_LANE.get(category, "read_only")
            if compat_lane != lane:
                lane_disagreement = True
        
        return lane, parallel_safe, rate_limited, compat_lane, lane_disagreement, reason_code

    def classify_swarm(self, swarm_name: str, task_metadata: dict | None = None
                       ) -> tuple[str, bool, bool, str | None, bool, str]:
        """Classify a swarm by its most restrictive specialist.
        
        Swarm lane = most restrictive specialist classification in the swarm.
        Restrictiveness order: read_only < rate_limited < stateful < aggressive_exclusive < sequential_required/unknown
        
        If swarm→specialist mapping can't resolve, returns sequential_required (safe side).
        """
        specialists = self._swarm_to_specialists.get(swarm_name, [])
        if not specialists:
            # Unknown swarm: safe-side sequential_required
            return ("sequential_required", False, False, None, False, "unclassified_safety_default")
        
        _RESTRICTIVENESS = {
            "read_only": 0, "rate_limited": 0,  # rate_limited maps to read_only lane but has rate_limited=true
            "stateful": 1, "aggressive_exclusive": 2, "sequential_required": 3, "unknown": 3,
        }
        
        most_restrictive_class = None
        most_restrictive_rank = -1
        
        for spec_name in specialists:
            class_ = self._specialist_classifications.get(spec_name, "unknown")
            rank = _RESTRICTIVENESS.get(class_, 3)
            if rank > most_restrictive_rank:
                most_restrictive_rank = rank
                most_restrictive_class = class_
        
        if most_restrictive_class is None:
            most_restrictive_class = "unknown"
        
        # However, rate_limited vs parallel_safe within the swarm: 
        # if the most restrictive is rate_limited, the swarm gets read_only + rate_limited=true
        # But if there's a stateful, that overrides everything.
        # The key insight: restrictiveness order for *lane selection*:
        # parallel_safe → read_only; rate_limited → read_only (+rate_limited); stateful → stateful_read;
        # aggressive_exclusive → aggressive_exclusive; sequential_required → sequential_required
        
        # Re-rank for lane selection (rate_limited and parallel_safe both produce read_only lane)
        _LANE_RANK = {
            "parallel_safe": 0, "rate_limited": 1, "stateful": 2,
            "aggressive_exclusive": 3, "sequential_required": 4, "unknown": 4,
        }
        
        most_restrictive_for_lane = None
        highest_lane_rank = -1
        has_rate_limited = False
        
        for spec_name in specialists:
            class_ = self._specialist_classifications.get(spec_name, "unknown")
            if class_ == "rate_limited":
                has_rate_limited = True
            rank = _LANE_RANK.get(class_, 4)
            if rank > highest_lane_rank:
                highest_lane_rank = rank
                most_restrictive_for_lane = class_
        
        if most_restrictive_for_lane is None:
            most_restrictive_for_lane = "unknown"
        
        classification = most_restrictive_for_lane
        if classification not in PHASE0_CLASS_TO_LANE:
            classification = "unknown"
        
        lane, parallel_safe, rate_limited, reason_code = PHASE0_CLASS_TO_LANE.get(
            classification, PHASE0_CLASS_TO_LANE["unknown"])
        
        # If the most restrictive is rate_limited, rate_limited should be True
        if classification == "rate_limited" or (has_rate_limited and classification == "rate_limited"):
            rate_limited = True
        
        # Phase 2 compat_lane
        from src.core.engine.parallel_orchestrator import CATEGORY_TO_LANE
        compat_lane = None
        lane_disagreement = False
        if task_metadata:
            category = task_metadata.get("category", task_metadata.get("agent_type", "default"))
            compat_lane = CATEGORY_TO_LANE.get(category, "read_only")
            if compat_lane != lane:
                lane_disagreement = True
        
        return lane, parallel_safe, rate_limited, compat_lane, lane_disagreement, reason_code

    def classify(self, agent_type: str, task_metadata: dict | None = None
                ) -> tuple[str, bool, bool, str | None, bool, str]:
        """Classify a task by its agent_type (swarm name).
        
        Returns: (lane, parallel_safe, rate_limited, compat_lane, lane_disagreement, reason_code)
        """
        # Normalize agent_type to swarm name
        swarm_name = self._agent_to_swarm(agent_type)
        return self.classify_swarm(swarm_name, task_metadata)

    @staticmethod
    def _agent_to_swarm(agent_type: str) -> str:
        """Map agent_type string to swarm name."""
        agent_lower = (agent_type or "").lower().replace("_", "").replace("-", "").replace("agent", "").replace("swarm", "").replace("manager", "")
        
        if "injection" in agent_lower or "inject" in agent_lower:
            return "injection"
        if "auth" in agent_lower:
            return "auth"
        if "logic" in agent_lower or "biz" in agent_lower or "idor" in agent_lower:
            return "logic"
        if "discovery" in agent_lower or "recon" in agent_lower:
            return "discovery"
        if "secret" in agent_lower:
            return "secret"
        if "scanner" in agent_lower or "scan" in agent_lower:
            return "scanner"
        if "intelligence" in agent_lower or "intel" in agent_lower:
            return "intelligence"
        if "fuzzing" in agent_lower or "fuzz" in agent_lower:
            return "fuzzing"
        return "unknown"
