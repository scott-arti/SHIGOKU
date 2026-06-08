#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "[fast-check] Running focused MC/Recon regression suite..."
pytest -q \
  tests/core/engine/test_master_conductor_api_candidate_routing.py \
  tests/core/engine/test_master_conductor_vuln_family_gate.py \
  tests/core/engine/test_master_conductor_realtime_budget.py \
  tests/recon/test_tagged_uncategorized_promotion.py

echo "[fast-check] Done."
