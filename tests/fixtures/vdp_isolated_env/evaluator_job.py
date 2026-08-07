"""
Lane O-1 one-shot holdout evaluator — SGK-2026-0423.

Disposable holdout evaluation job that runs with ``network_mode: none``
(reads local files only). It consumes:

- ``LABELS_PATH``      — hidden-holdout label artifact (plain JSON; this
                         container IS the privileged reader — the OS
                         boundary is the container itself, not a uid check);
- ``THRESHOLDS_PATH``  — thresholds frozen HOST-side BEFORE the runtime
                         run (the runtime never reads them);
- ``SESSION_PATH``     — the runtime session (read-only);
- ``RESULT_PATH``      — writable output for the evaluation result.

Steps: validate the threshold artifact (schema_version/eval_version),
load the labels, ``read_session_compat`` -> ``extract_vdp_canonical`` ->
``run_holdout_evaluation`` -> ``save_evaluation_result``, then run the
``assert_thresholds_frozen_for_eval_version`` self-check. Prints an
ANONYMIZED outcome (outcome, leakage count, metric names/values/met flags
and threshold directions/bounds only — never raw labels, URLs, or
payloads). The RESULT_PATH JSON is grep-verifiable free of raw label
values.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

from src.core.engine.vdp_session_reader import read_session_compat
from src.reporting.vdp_canonical import extract_vdp_canonical
from src.reporting.vdp_dataset import ThresholdArtifact, load_thresholds
from src.reporting.vdp_holdout_runner import (
    assert_thresholds_frozen_for_eval_version,
    run_holdout_evaluation,
    save_evaluation_result,
)

RUNNER_VERSION = "vdp-iso-evaluator-0.1.0"
CODE_VERSION = "sgk-2026-0423-lane-o1-0.1.0"
CONFIG_VERSION = "vdp-iso-fixture-0.1.0"


def _require_env(name: str) -> Path:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} environment variable is required")
    return Path(value)


def load_labels(path: Path) -> dict:
    """Plain JSON load (privileged reader) with the same normalization as
    the production loader — the OS boundary is the container itself."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"labels unreadable: {type(exc).__name__}") from exc
    klass = data.get("class") if isinstance(data, dict) else None
    if not isinstance(klass, dict):
        raise RuntimeError("labels malformed: missing class dict")
    labels = {
        "urls": [str(u) for u in (klass.get("urls") or [])],
        "payloads": [str(p) for p in (klass.get("payloads") or [])],
        "product_names": [str(n) for n in (klass.get("product_names") or [])],
        "ground_truth": [],
    }
    ground_truth = data.get("ground_truth")
    if ground_truth:
        entries = []
        for entry in ground_truth:
            if not isinstance(entry, dict):
                continue
            entries.append({
                "class": str(entry.get("class") or ""),
                "capability": str(entry.get("capability") or ""),
                "method": str(entry.get("method") or ""),
                "endpoint": str(entry.get("endpoint") or ""),
            })
        labels["ground_truth"] = entries
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
    labels_path = _require_env("LABELS_PATH")
    thresholds_path = _require_env("THRESHOLDS_PATH")
    session_path = _require_env("SESSION_PATH")
    result_path = _require_env("RESULT_PATH")

    try:
        # --- thresholds: frozen host-side; validate schema/eval_version ---
        thresholds = load_thresholds(thresholds_path)
        if thresholds.schema_version != 1:
            raise RuntimeError(
                f"thresholds schema_version {thresholds.schema_version} != 1"
            )
        if not str(thresholds.eval_version or "").strip():
            raise RuntimeError("thresholds eval_version is empty")
        if not thresholds.metrics:
            raise RuntimeError("thresholds metrics list is empty")

        labels = load_labels(labels_path)

        session = read_session_compat(session_path)
        if session is None:
            raise RuntimeError(f"session unreadable: {session_path}")
        summary = extract_vdp_canonical(session)

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
