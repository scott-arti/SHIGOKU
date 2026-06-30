"""
Phase 0: Swarm Parallelization Baseline & Exclusions

This module contains the canonical concurrency inventory produced by
SGK-2026-0309 Phase 0. It does NOT change any runtime behavior.
All data is structured in concurrency_map.yaml and validated by tests.

Usage:
    from src.core.agents.swarm.phase0 import load_inventory

    inv = load_inventory()
    print(inv['parallel_sequential_classification']['swarm_manager'])
"""

import os
from typing import Dict, Any

_INVENTORY_PATH = os.path.join(os.path.dirname(__file__), "concurrency_map.yaml")


def load_inventory() -> Dict[str, Any]:
    """Load the Phase 0 concurrency inventory from YAML."""
    import yaml

    with open(_INVENTORY_PATH, "r") as f:
        return yaml.safe_load(f)


def get_inventory_path() -> str:
    """Return the absolute path to the inventory file."""
    return _INVENTORY_PATH
