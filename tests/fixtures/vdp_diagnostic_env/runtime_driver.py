"""
SGK-2026-0425 M4 — diagnostic runtime driver.

Drives the REAL deterministic VDP pipeline against the generated opaque
fixture surface (``fixture_target.py``), read-only:

  1. GET ``/health`` (S00 execution-contract evidence) and ``/`` (index);
  2. crawl every RELATIVE case link (GET only); ABSOLUTE hrefs (the S02
     fault shape, userinfo-carrying) are NEVER crawled — no credential
     material ever leaves this process over the wire — but they still feed
     the adapter boundary, which rejects them fail-closed;
  3. build GENERIC recon-format endpoint signals (no product info, no
     credentials; auth_context=None);
  4. run ``ObservationAdapter.adapt_signal_bundle`` (real module) -> typed
     Observations; per-signal outcomes are recorded deterministically;
  5. run ``generate_hypotheses`` (real module) with an always-allowed scope
     provider, a canonical ``ExecutionBudgetV1`` and the fixture's generic
     leakage denylist ("diag-probe" — mirrors the production config-supplied
     denylist semantics);
  6. emit per-fingerprint diagnostic events for S00..S03 (the stages the
     current pipeline can genuinely observe; S04..S12 have no M1 hooks yet
     and are therefore NOT emitted — the deterministic ``event_simulator.py``
     bridges that gap for the harness);
  7. write ``runtime_events.jsonl`` (diagnostic event vocabulary) +
     ``canonical_summary.json`` (canonical-ish counts for the evaluator) and
     print the anonymized ``runtime_result:<json>`` line.

Event fingerprints are the production ``normalize_url`` output, so the
evaluator can join events to sealed cases via the manifest. Event ids are
deterministic (sha256 over run_id|fingerprint|stage) — no wall clock, no
UUID, no random in artifacts.

Environment:
  FIXTURE_BASE_URL (default http://fixture-target:8000)
  OUT_DIR          (writable output directory)
  DIAG_RUN_ID      (run identifier, shared with fixture/evaluator)
  TARGET_NAME      (generic target label)
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from src.core.engine.vdp_observation_adapter import (
    ObservationAdapter,
    normalize_url,
)
from src.core.engine.vdp_hypothesis_generator import generate_hypotheses
from src.core.models.vdp_contract import ExecutionBudgetV1, ScopeRevalidationResult

FIXTURE_BASE_URL = os.environ.get("FIXTURE_BASE_URL", "http://fixture-target:8000")
OUT_DIR = Path(os.environ.get("OUT_DIR", "out"))
DIAG_RUN_ID = os.environ.get("DIAG_RUN_ID", "diag-run")
TARGET_NAME = os.environ.get("TARGET_NAME", "vdp-diag-fixture")

CRAWL_TIMEOUT = 5  # seconds
RUNNER_VERSION = "vdp-diagnostic-runtime-0.1.0"
LEAKAGE_DENYLIST = ["diag-probe"]  # generic fixture marker (config semantics)

_HREF_RE = re.compile(r'href="([^"]+)"')


def _get(url: str) -> tuple:
    """One GET; returns (status, body). status is "timeout"/"error" on
    transport failure. 4xx/5xx bodies are read via HTTPError."""
    try:
        with urllib.request.urlopen(url, timeout=CRAWL_TIMEOUT) as resp:
            return int(getattr(resp, "status", 200) or 200), str(
                resp.read().decode("utf-8", errors="replace")
            )
    except urllib.error.HTTPError as exc:
        body = str(exc.read().decode("utf-8", errors="replace"))
        return int(exc.code or 0), body
    except Exception:
        return "timeout", ""


def _evid(fingerprint: str, stage: str) -> str:
    """Deterministic event id (no wall clock / UUID in artifacts)."""
    digest = hashlib.sha256(
        f"{DIAG_RUN_ID}|{fingerprint}|{stage}".encode("utf-8")
    ).hexdigest()
    return f"ev-{digest[:16]}"


def _event(fingerprint: str, stage: str, outcome: str,
           reason_codes: list | None = None,
           predecessor_ids: list | None = None,
           successor_ids: list | None = None,
           source_refs: list | None = None) -> dict:
    """One event dict in the frozen vdp_diagnostic_trace vocabulary."""
    return {
        "event_id": _evid(fingerprint, stage),
        "run_id": DIAG_RUN_ID,
        "stage_id": stage,
        "outcome": outcome,
        "reason_codes": sorted(set(reason_codes or [])),
        "predecessor_ids": list(predecessor_ids or []),
        "successor_ids": list(successor_ids or []),
        "opaque_asset_fingerprint": fingerprint,
        "producer_id": "generated-fixture",
        "agent_id": "vdp-runtime-driver",
        "tool_id": "vdp-diagnostic-env",
        "recipe_id": "",
        "budget_snapshot_hash": hashlib.sha256(
            f"{DIAG_RUN_ID}|{fingerprint}|{stage}|budget".encode("utf-8")
        ).hexdigest()[:16],
        "source_refs": list(source_refs or []),
        "schema_version": 1,
        "taxonomy_version": "v2",
    }


def _signal(url: str, signal_id: str, params: list | None = None) -> dict:
    """One GENERIC endpoint signal (no route-specific labels, no auth)."""
    return {
        "signal_id": signal_id,
        "entity_type": "endpoint",
        "url": url,
        "method": "GET",
        "primary_label": "resource",
        "candidate_labels": ["object"],
        "confidence": 0.9,
        "auth_context": None,  # credentials never enter the observation path
        "params": params or [],
        "status": "active",
    }


def crawl() -> tuple:
    """GET health + index, discover case links, GET relative links only.
    Returns (health_status, observations, signals, per_href) where
    per_href maps href -> {"fingerprint", "crawled": bool}."""
    health_status, _ = _get(f"{FIXTURE_BASE_URL}/health")
    index_status, index_body = _get(f"{FIXTURE_BASE_URL}/")
    observations = [{"method": "GET", "path": "/", "status": index_status}]
    signals: list[dict] = []
    per_href: dict = {}
    n = 0
    for href in _HREF_RE.findall(index_body):
        href = href.strip()
        if not href:
            continue
        if href.startswith("/"):
            path = urlparse(href).path
            status, _ = _get(f"{FIXTURE_BASE_URL}{href}")
            observations.append({"method": "GET", "path": path, "status": status})
            fingerprint = normalize_url(f"{FIXTURE_BASE_URL}{href}")
            crawled = True
        elif href.startswith("http://") or href.startswith("https://"):
            # Absolute href (S02 fault shape): never crawled (userinfo must
            # never go over the wire); the signal still feeds the adapter
            # boundary, which rejects userinfo fail-closed.
            parsed = urlparse(href)
            observations.append(
                {"method": "GET", "path": parsed.path, "status": 0,
                 "note": "absolute_href_not_crawled"}
            )
            fingerprint = normalize_url(f"{FIXTURE_BASE_URL}{parsed.path}")
            crawled = False
        else:
            continue  # javascript:/mailto:/... are not part of the surface
        if fingerprint in per_href:
            continue
        per_href[href] = {"fingerprint": fingerprint, "crawled": crawled}
        n += 1
        signals.append(_signal(
            href if href.startswith("http") else f"{FIXTURE_BASE_URL}{href}",
            f"diag-obs-{n:02d}",
        ))
    return health_status, observations, signals, per_href


def adapt_per_signal(adapter: ObservationAdapter, signals: list) -> dict:
    """Per-signal adapter outcome (deterministic): fingerprint ->
    {"observation": Observation|None, "skip_reason": str|None}."""
    outcomes: dict = {}
    for signal in signals:
        url = str(signal.get("url") or "")
        try:
            fp = normalize_url(url)
        except ValueError:
            fp = normalize_url(
                f"{FIXTURE_BASE_URL}{urlparse(url).path}"
            ) if urlparse(url).path else ""
        try:
            observation = adapter.adapt_endpoint_signal(signal)
        except (ValueError, TypeError) as exc:
            observation = None
            skip = str(exc)
        else:
            skip = None
        outcomes[fp] = {"observation": observation, "skip_reason": skip}
    return outcomes


def _chain_events(fingerprint: str, chain: list) -> list:
    """Build event dicts for one fingerprint's stage chain, with
    predecessor/successor ids pointing only at EMITTED events (reference
    integrity per the diagnostic section contract)."""
    events = []
    for i, (stage, outcome, reason_codes, refs) in enumerate(chain):
        preds = [events[i - 1]["event_id"]] if i > 0 else []
        succs = [_evid(fingerprint, chain[i + 1][0])] if i + 1 < len(chain) else []
        events.append(_event(
            fingerprint, stage, outcome,
            reason_codes=reason_codes,
            predecessor_ids=preds,
            successor_ids=succs,
            source_refs=refs,
        ))
    return events


def main() -> int:
    out_dir = OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "run_id": DIAG_RUN_ID,
        "target": TARGET_NAME,
        "runner": RUNNER_VERSION,
        "health_status": 0,
        "observations": [],
        "signals": 0,
        "adapter_skipped": 0,
        "hypotheses": [],
        "attempts": [],
        "evidence_records": [],
        "verdicts": [],
        "next_actions": [],
        "generation_rejected": 0,
        "generation_suppressed": 0,
        "generation_degraded": None,
        "per_fingerprint": {},
        "events": [],
        "first_failed_stage": None,
        "max_instrumented_stage": "S03",
    }
    try:
        health_status, observations, signals, per_href = crawl()
        summary["health_status"] = health_status
        summary["observations"] = observations
        summary["signals"] = len(signals)

        # --- REAL observation adapter ---
        adapter = ObservationAdapter()
        outcomes = adapt_per_signal(adapter, signals)
        typed_observations = [
            o["observation"]
            for o in outcomes.values()
            if o["observation"] is not None
        ]
        summary["adapter_skipped"] = len(signals) - len(typed_observations)

        # --- REAL hypothesis generator (deterministic, no LLM) ---
        def scope_provider(url: str) -> ScopeRevalidationResult:
            return ScopeRevalidationResult.allow()

        generation = generate_hypotheses(
            typed_observations,
            scope_verdict_provider=scope_provider,
            budget_model=ExecutionBudgetV1(),
            leakage_denylist=LEAKAGE_DENYLIST,
        )
        summary["hypotheses"] = [h.hypothesis_id for h in generation.hypotheses]
        summary["generation_rejected"] = len(generation.rejected)
        summary["generation_suppressed"] = len(generation.suppressed)
        summary["generation_degraded"] = generation.degraded

        hypothesis_by_observation = {
            h.observation_id: h for h in generation.hypotheses
        }

        # --- per-fingerprint stage map (S00..S03, genuine boundaries) ---
        per_fingerprint: dict = {}
        events: list[dict] = []
        fingerprints = list(outcomes.keys())
        if not fingerprints:
            # S01 fault: no case links at all — emit a run-level S01 cut.
            run_level = f"{FIXTURE_BASE_URL}/"
            per_fingerprint[run_level] = {
                "S00": "reached", "S01": "failed", "S02": "not_reached",
                "S03": "not_reached",
            }
            chain = [
                ("S00", "reached", [], ["health=ok" if health_status == 200
                                        else "health=unavailable"]),
                ("S01", "failed", ["asset_not_in_inventory"], []),
            ]
            events.extend(_chain_events(run_level, chain))
        else:
            for fingerprint in sorted(fingerprints):
                outcome = outcomes[fingerprint]
                observation = outcome["observation"]
                s00_outcome = "reached" if health_status == 200 else "failed"
                if observation is None:
                    stages = {"S00": s00_outcome, "S01": "reached",
                              "S02": "failed", "S03": "not_reached"}
                else:
                    hypothesis = hypothesis_by_observation.get(
                        observation.observation_id
                    )
                    stages = {"S00": s00_outcome, "S01": "reached",
                              "S02": "reached",
                              "S03": "reached" if hypothesis is not None
                              else "failed"}
                per_fingerprint[fingerprint] = stages

                chain = []
                for s in ("S00", "S01", "S02", "S03"):
                    if stages[s] == "reached":
                        chain.append((s, "reached", [], []))
                        continue
                    # chain cut: events stop at the first failed stage
                    reason = {
                        "S00": ["dependency_unavailable"],
                        "S01": ["asset_not_in_inventory"],
                        "S02": ["parse_rejected"],
                        "S03": ["capability_misclassified"],
                    }[s]
                    refs = []
                    if s == "S02" and outcome["skip_reason"]:
                        refs.append(f"skip={outcome['skip_reason']}")
                    chain.append((s, "failed", reason, refs))
                    break
                events.extend(_chain_events(fingerprint, chain))

        events.sort(key=lambda ev: (ev["opaque_asset_fingerprint"], ev["stage_id"]))
        summary["per_fingerprint"] = per_fingerprint
        summary["events"] = [ev["event_id"] for ev in events]
        first_failed = next(
            (ev["stage_id"] for ev in events if ev["outcome"] == "failed"), None
        )
        summary["first_failed_stage"] = first_failed

        (out_dir / "runtime_events.jsonl").write_text(
            "\n".join(json.dumps(ev, sort_keys=True) for ev in events) + "\n",
            encoding="utf-8",
        )
        (out_dir / "canonical_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        result = {
            "run_id": DIAG_RUN_ID,
            "health_status": health_status,
            "observations": len(observations),
            "signals": len(signals),
            "adapter_skipped": summary["adapter_skipped"],
            "hypotheses": len(summary["hypotheses"]),
            "generation_rejected": summary["generation_rejected"],
            "generation_suppressed": summary["generation_suppressed"],
            "generation_degraded": (
                summary["generation_degraded"] or {}
            ).get("reason") if summary["generation_degraded"] else None,
            "events": len(events),
            "max_instrumented_stage": summary["max_instrumented_stage"],
            "first_failed_stage": first_failed,
        }
        print(f"runtime_result:{json.dumps(result, sort_keys=True)}")
        return 0
    except Exception as exc:  # unexpected failure: surface, do not swallow
        print(f"runtime_result:{{\"fatal\":\"{type(exc).__name__}\"}}",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
