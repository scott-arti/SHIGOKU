"""
SGK-2026-0423 Lane P-2 — one-shot holdout evaluator.

Runs with ``network_mode: none`` (reads local files only). It is the
PRIVILEGED reader of the hold out: consumes

- ``SECRETS_PATH``     — the hold out (secret.json, RO mount);
- ``THRESHOLDS_PATH``  — thresholds frozen HOST-side BEFORE the runtime run
                        (the runtime never reads them);
- ``SESSION_PATH``     — the runtime session (read-only);
- ``REGISTRY_PATH``    — the runtime's public-key registry (read-only,
                         public keys only — no secret material);
- ``RESULT_PATH``      — writable output for the evaluation result;
- ``FIXTURE_BASE_URL`` — the fixture base URL (used to derive probe URLs).

Steps: validate the threshold artifact, build the labels dict FROM THE
HOLD OUT (ground_truth = the granted asset routes with their capability;
probe strings derived from the hold out values — an opaque URL with an id
segment the runtime never saw, a derived payload token, and a generic
product name), read the session, verify confirmed verdicts against the
public-key registry, ``run_holdout_evaluation`` -> ``save_evaluation_result``
and run the ``assert_thresholds_frozen_for_eval_version`` self-check.

The result artifact and the console output are ANONYMIZED: metric names,
values, directions and met flags only — never raw labels, URLs, or
payloads.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

from src.core.engine.vdp_key_registry import VdpKeyRegistry
from src.core.engine.vdp_session_reader import read_session_compat
from src.reporting.vdp_canonical import extract_vdp_canonical
from src.reporting.vdp_dataset import ThresholdArtifact, load_thresholds
from src.reporting.vdp_holdout_runner import (
    assert_thresholds_frozen_for_eval_version,
    run_holdout_evaluation,
    save_evaluation_result,
)

RUNNER_VERSION = "vdp-holdout-evaluator-0.1.0"
CODE_VERSION = "sgk-2026-0423-lane-p2-0.1.0"
CONFIG_VERSION = "vdp-opaque-holdout-0.1.0"
PRODUCT_PROBE = "opaque-product"


def _require_env(name: str) -> Path:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} environment variable is required")
    return Path(value)


def build_labels(holdout: dict, base_url: str) -> dict:
    """Build the labels dict from the hold out.

    - ``ground_truth``: the GRANTED asset routes (b_can_read) with their
      capability — the confirmed verdicts must match them 1:1.
    - probes: derived from the hold out values such that a clean runtime can
      never legitimately contain them — the opaque URL with a synthetic id
      segment (the runtime only ever crawled the base paths), a derived
      payload token, and a generic product name.
    """
    granted = [
        route for route in holdout.get("routes", [])
        if isinstance(route, dict) and route.get("b_can_read")
    ]
    probe_id = re.sub(r"[^0-9a-f]", "", str(granted[0].get("opaque", "") or ""))[:8]
    if not probe_id:
        probe_id = "0" * 8
    labels = {
        "class": {
            "urls": [
                f"{base_url}{route.get('opaque', '')}/holdout-{probe_id}"
                for route in granted
            ],
            "payloads": [f"holdout-payload-{probe_id}"],
            "product_names": [PRODUCT_PROBE],
        },
        "ground_truth": [
            {
                "class": "asset-access",
                "capability": str(
                    route.get("capability") or "object_read_write_delete"
                ),
                "method": "GET",
                "endpoint": str(route.get("opaque", "") or ""),
            }
            for route in granted
        ],
    }
    return labels


def _session_input_hash(session_path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(session_path.read_bytes())
    return "sha256:" + digest.hexdigest()


def _print_anonymized_metrics(thresholds: ThresholdArtifact, metrics: dict) -> None:
    """Counts/directions/bounds/met only — NO raw labels, URLs, payloads."""
    for threshold in thresholds.metrics:
        entry = metrics.get(threshold.name) or {}
        value = entry.get("value", 0.0)
        met = bool(entry.get("met", False))
        print(
            f"iso_eval:metric:{threshold.name}:value={value}:"
            f"direction={threshold.direction}:bound={threshold.value}:met={str(met).lower()}"
        )


def main() -> int:
    secrets_path = _require_env("SECRETS_PATH")
    thresholds_path = _require_env("THRESHOLDS_PATH")
    session_path = _require_env("SESSION_PATH")
    result_path = _require_env("RESULT_PATH")
    registry_path = _require_env("REGISTRY_PATH")
    base_url = os.environ.get("FIXTURE_BASE_URL", "http://fixture-target:8000")

    try:
        thresholds = load_thresholds(thresholds_path)
        if thresholds.schema_version != 1:
            raise RuntimeError(
                f"thresholds schema_version {thresholds.schema_version} != 1"
            )
        if not str(thresholds.eval_version or "").strip():
            raise RuntimeError("thresholds eval_version is empty")
        if not thresholds.metrics:
            raise RuntimeError("thresholds metrics list is empty")

        holdout = json.loads(secrets_path.read_text(encoding="utf-8"))
        labels = build_labels(holdout, base_url)

        session = read_session_compat(session_path)
        if session is None:
            raise RuntimeError(f"session unreadable: {session_path}")
        registry = VdpKeyRegistry.load(registry_path)
        summary = extract_vdp_canonical(
            session, public_key_provider=registry.public_key_provider()
        )

        result = run_holdout_evaluation(
            summary,
            labels,
            thresholds,
            eval_version=thresholds.eval_version,
            runner_version=RUNNER_VERSION,
            session_ref=session_path.name,
            code_version=CODE_VERSION,
            config_version=CONFIG_VERSION,
            feature_flags={"stage": "m3a", "network": "internal-only"},
            input_hash=_session_input_hash(session_path),
            termination_state="succeeded",
        )
        save_evaluation_result(result, result_path)

        # --- self-check: a changed threshold artifact can never re-claim
        # an existing eval-version result ---
        assert_thresholds_frozen_for_eval_version(result_path, thresholds)

        print(f"iso_eval:outcome:{result.outcome}")
        print(f"iso_eval:leakage:{len(result.leakage_hits)}")
        print(f"iso_eval:threshold_fingerprint:{result.threshold_fingerprint}")
        print(f"iso_eval:artifact_hash:{result.artifact_hash}")
        print(f"iso_eval:gaps:{result.gaps}")
        _print_anonymized_metrics(thresholds, result.metrics)
        return 0
    except Exception as exc:  # unexpected failure: surface, do not swallow
        print(f"iso_eval:fatal:{type(exc).__name__}:{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
