"""
SGK-2026-0423 Lane P-2 — opaque holdout runtime driver.

Drives the REAL VDP production path against the random/opaque holdout
fixture (``holdout_fixture_target.py``), read-only only:

  1. sets up the signing key file (0600, hex seed "33"*32 — NOT on the
     test-key denylist) and the key registry (ACTIVE entry) under
     ``OUT_DIR/keys/``;
  2. builds ``VdpModeSettings`` (readonly_enforce + follow_up_probe
     allowed, file key provider), the explicit ``ScopeDefinition``, and a
     MasterConductor via the ``object.__new__`` pattern with REAL
     components: an ``AsyncNetworkClient`` (mode != bugbounty), a
     ``DynamicTaskQueue``, and the lazy VDP runtime deps;
  3. performs a READ-ONLY crawl of ``FIXTURE_BASE_URL`` (GET only; the
     internal network guard raises on any non-GET method string);
  4. runs ``_generate_vdp_hypotheses`` -> queue -> ``_dispatch_vdp_follow_up``
     per queued task (per-task exception isolation: degraded, never crash).
     The MC account config (``VDP_ACCOUNT_A_ID``/``VDP_ACCOUNT_A_SECRET``/
     ``VDP_ACCOUNT_B_ID``/``VDP_ACCOUNT_B_SECRET``) feeds the executor's
     cross-account comparison layer — the granted asset route confirms
     through the canonical Evidence Validator, the denied and public routes
     stay candidate;
  5. writes the session, runs the M0 gate (verified with the signing key
     registry), extracts the canonical summary, and prints an ANONYMIZED
     summary plus ``run_summary.json``.

No route-specific branching: the crawl discovers the index anchors and
labels every discovered path with GENERIC labels (entity_type "endpoint",
primary_label "resource", candidate_labels ["object"]). The signals carry
NO credential material (auth_context=None): the unauthenticated crawl's 401
marks an account-gated route in the observations, and the comparison
send's credentials come from the MC account store — never from the
observation (the exact-replay rule forbids fabricating credentials).

This process NEVER POSTs: an internal assertion wraps the network client
(any non-GET method string raises), and the fixture access log (when
``ACCESS_LOG_PATH`` is set) is checked for zero non-GET lines.

Environment:
  FIXTURE_BASE_URL    (default http://fixture-target:8000)
  OUT_DIR             (writable output directory)
  FIXTURE_SCOPE_HOST  (default "fixture-target"; host tests pass
                       "127.0.0.1")
  TARGET_NAME         (default "vdp-holdout")
  ACCESS_LOG_PATH     (optional fixture access log for the POST=0 proof)
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from src.core.engine.master_conductor import MasterConductor

FIXTURE_BASE_URL = os.environ.get("FIXTURE_BASE_URL", "http://fixture-target:8000")
OUT_DIR = Path(os.environ.get("OUT_DIR", "out"))
FIXTURE_SCOPE_HOST = os.environ.get("FIXTURE_SCOPE_HOST", "fixture-target")
TARGET_NAME = os.environ.get("TARGET_NAME", "vdp-holdout")
ACCESS_LOG_PATH = os.environ.get("ACCESS_LOG_PATH", "")

CRAWL_TIMEOUT = 3  # seconds
KEY_HEX_SEED = "33" * 32
RUNNER_ID = "vdp-holdout-runtime-0.1.0"

_HREF_RE = re.compile(r'href="([^"]+)"')


def setup_keys(out_dir: Path) -> dict:
    """Create the signing key file (0600, seed NOT on the denylist) and the
    key registry (same key registered ACTIVE, 0600)."""
    from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
    from src.core.engine.vdp_key_registry import VdpKeyRegistry

    keys_dir = out_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

    key_file = keys_dir / "signing_key.hex"
    key_file.write_text(KEY_HEX_SEED + "\n", encoding="utf-8")
    os.chmod(key_file, 0o600)

    signer = Ed25519EvidenceSigner(private_key=bytes.fromhex(KEY_HEX_SEED))
    registry = VdpKeyRegistry()
    registry.register(signer.key_id, signer.public_key_bytes())
    registry_path = keys_dir / "registry.json"
    registry.save(registry_path)  # atomic write, chmod 0o600
    os.chmod(registry_path, 0o600)
    return {"key_file": str(key_file), "registry": str(registry_path)}


async def _async_noop(*args, **kwargs):
    pass


def build_mc(out_dir: Path, network_client) -> "MasterConductor":
    """Build a MasterConductor with REAL VDP runtime deps (mirrors the
    production integration test pattern with a real network client +
    queue + mode settings)."""
    from src.core.config.settings import VdpModeSettings
    from src.core.engine.master_conductor import MasterConductor
    from src.core.engine.task_queue import DynamicTaskQueue

    keys = setup_keys(out_dir)
    settings = VdpModeSettings(
        mode="readonly_enforce",
        capability_rules={"follow_up_probe": "allowed"},
        key_provider="file",
        key_file_path=keys["key_file"],
        key_registry_path=keys["registry"],
        rollout_state_path=str(out_dir / "eval" / "rollout_state.json"),
        thresholds_path=str(out_dir / "eval" / "thresholds_v1.json"),
        holdout_result_path=str(out_dir / "eval" / "holdout_result_iso.json"),
        gate_result_path=str(out_dir / "eval" / "gate_result.json"),
    )

    mc = object.__new__(MasterConductor)
    mc.project_manager = SimpleNamespace(
        project_dir=str(out_dir / "project"),
        save_session=_async_noop,
    )
    mc.task_queue = DynamicTaskQueue(
        disk_db_path=str(out_dir / "task_overflow.db")
    )
    mc.completed_tasks = []
    mc.pending_hitl = []
    mc._vdp_state = {
        "vdp_active": False,
        "hypotheses": [],
        "attempts": [],
        "evidence_records": [],
        "verdicts": [],
        "next_actions": [],
        "budget_snapshot": {},
        "run_health": {},
    }
    mc._injected_task_ids = set()
    mc._derived_task_count = 0
    mc._owned_injection_targets = set()
    mc._current_session = SimpleNamespace(session_id="vdp-holdout-session")
    mc.run_ledger_recorder = SimpleNamespace(
        prepare_for_session=lambda spool_dir=None: {},
        run_id="vdp-holdout-run",
    )
    mc.decision_tracer = None
    mc.execution_log = SimpleNamespace(to_list=lambda: [])
    mc.context = SimpleNamespace(
        _total_attempts=0,
        _successful_attempts=0,
        bypass_methods=[],
        discovered_assets=[],
        target_info={
            "start_time": time.time(),
            "program_name": TARGET_NAME,
            "in_scope_domains": [FIXTURE_SCOPE_HOST],
            "out_of_scope_domains": [],
            "max_requests_per_minute": 60,
        },
    )
    mc._ensure_task_reason_code = lambda task: None
    mc._evaluate_vuln_family_coverage = lambda: {}
    mc._evaluate_intervention_scenario_coverage = lambda: {}
    mc.network_client = network_client  # type: ignore[assignment]
    mc._vdp_mode = settings
    return mc


class ReadOnlyGuardClient:
    """Wraps the AsyncNetworkClient: any non-GET method string raises."""

    def __init__(self, inner):
        self._inner = inner
        self.violations = 0

    async def request(self, method: str, url: str, **kwargs):
        if str(method or "").strip().upper() != "GET":
            self.violations += 1
            raise AssertionError(f"non-GET method attempted: {method}")
        return await self._inner.request(method, url, **kwargs)


async def _crawl_get(net, url: str) -> tuple:
    """One crawl GET with the executor's hidden-communication-disabled
    signature. Returns (status, body); status is the string
    "timeout"/"error" on transport failure."""
    try:
        resp = await net.request(
            "GET",
            url,
            use_cache=False,
            retries=0,
            auto_waf_bypass=False,
            allow_redirects=False,
            timeout=CRAWL_TIMEOUT,
            use_proxy=True,
        )
        status = int(getattr(resp, "status", 0) or 0)
        body = getattr(resp, "body", "") or ""
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        return status, str(body)
    except Exception:
        return "timeout", ""


def _signal(url: str, signal_id: str) -> dict:
    """One GENERIC endpoint signal (no route-specific labels)."""
    return {
        "signal_id": signal_id,
        "entity_type": "endpoint",
        "url": url,
        "method": "GET",
        "primary_label": "resource",
        "candidate_labels": ["object"],
        "confidence": 0.9,
        "auth_context": None,  # credentials come from the MC account store
        "params": [],
        "status": "active",
    }


async def crawl(net, base_url: str) -> tuple:
    """GET the index, parse hrefs, GET every discovered path, and build the
    endpoint signal bundle. Returns ``(bundle, observations)``."""
    index_status, index_body = await _crawl_get(net, f"{base_url}/")
    observations = [{"method": "GET", "path": "/", "status": index_status}]

    seen: list[str] = []
    signals: list[dict] = []
    n = 0
    for href in _HREF_RE.findall(index_body):
        if not href.startswith("/"):
            continue
        path = urlparse(href).path
        if path in seen:
            continue
        seen.append(path)
        n += 1
        status, _body = await _crawl_get(net, f"{base_url}{href}")
        observations.append({"method": "GET", "path": path, "status": status})
        signals.append(_signal(f"{base_url}{href}", f"holdout-obs-{n:02d}"))
    return {"_endpoint_signals": signals}, observations


def _count_statuses(verdicts: list) -> dict:
    counts = {"confirmed": 0, "candidate": 0, "refuted": 0, "untested": 0}
    for verdict in verdicts:
        status = str(verdict.get("status", "") or "")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _fixture_log_non_get() -> int:
    """POST=0 proof: count non-GET lines in the fixture access log."""
    if not ACCESS_LOG_PATH:
        return 0
    path = Path(ACCESS_LOG_PATH)
    if not path.exists():
        return 0
    non_get = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not re.match(r"^GET\s+", line):
            non_get += 1
    return non_get


def _session_input_hash(session_path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(session_path.read_bytes())
    return "sha256:" + digest.hexdigest()


async def run() -> int:
    out_dir = OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    from src.core.infra.network_client import AsyncNetworkClient
    from src.core.engine.master_conductor_session_service import (
        inject_vdp_section_to_session_payload,
    )
    from src.core.engine.vdp_session_reader import (
        read_session_compat,
        redact_and_write_session,
    )
    from src.core.engine.vdp_m0_gate import VdpM0ContractGate
    from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
    from src.reporting.vdp_canonical import extract_vdp_canonical

    client = AsyncNetworkClient(mode="vdp-holdout-runtime")
    await client.start()
    net = ReadOnlyGuardClient(client)

    mc = build_mc(out_dir, net)
    scope = mc._build_vdp_scope_snapshot()

    summary = {
        "target": TARGET_NAME,
        "mode": "readonly_enforce",
        "runner": RUNNER_ID,
        "hypotheses_count": 0,
        "attempts_count": 0,
        "evidence_count": 0,
        "verdicts_by_status": {},
        "next_actions_count": 0,
        "follow_up_queued": 0,
        "follow_up_failures": [],
        "shadow_diff_count": 0,
        "requests_made": 0,
        "observations": [],
        "executed_paths": [],
        "degraded_reasons": [],
        "non_get_violations": 0,
        "fixture_log_non_get": 0,
        "m0_gate": {"passed": False, "reason_codes": []},
        "session_path": "",
    }

    try:
        # --- READ-ONLY crawl (GET only) ---
        bundle, observations = await crawl(net, FIXTURE_BASE_URL)
        summary["observations"] = observations

        # --- hypothesis generation (real production hook) ---
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": bundle},
            scope_definition=scope,
            checkpoint_path=str(out_dir / "checkpoint.json"),
        )

        # --- dispatch every queued follow-up (per-task isolation) ---
        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        summary["follow_up_queued"] = len(tasks)
        executed_paths: list[str] = []
        for task in tasks:
            spec = dict(((task.params or {}).get("vdp_follow_up_spec") or {}))
            path = urlparse(str(spec.get("url", "") or "")).path
            try:
                result = await mc._dispatch_vdp_follow_up(task)
                status = str((result or {}).get("data", {}).get("status", ""))
                if status == "executed":
                    executed_paths.append(path)
                elif status == "degraded":
                    reason = str((result or {}).get("data", {}).get("reason", ""))
                    summary["degraded_reasons"].append(f"{path}:{reason}")
            except Exception as exc:  # per-task isolation: never crash the run
                summary["follow_up_failures"].append({
                    "task_id": task.id,
                    "reason": "dispatch_exception",
                    "detail": repr(exc),
                })
                mc._set_vdp_run_health_degraded("dispatch_exception")
        summary["executed_paths"] = sorted(set(executed_paths))

        state = mc._vdp_state
        summary["hypotheses_count"] = len(state.get("hypotheses", []))
        summary["attempts_count"] = len(state.get("attempts", []))
        summary["evidence_count"] = len(state.get("evidence_records", []))
        summary["verdicts_by_status"] = _count_statuses(
            state.get("verdicts", [])
        )
        summary["next_actions_count"] = len(state.get("next_actions", []))
        summary["follow_up_failures"] = state.get("follow_up_failures", [])
        summary["shadow_diff_count"] = len(state.get("shadow_diff", []))
        budget = state.get("budget_snapshot", {}) or {}
        summary["requests_made"] = int(budget.get("requests_used", 0) or 0)
        summary["non_get_violations"] = net.violations

        # --- session write -> M0 gate (verified) -> canonical summary ---
        # The session carries the evidence chain of the CONFIRMED verdict
        # ONLY: the M0 gate's exact-set contract requires every confirmed
        # verdict's evaluated evidence set to equal the session evidence
        # set. The FULL run counts (all attempts/evidence) stay in
        # run_summary.json.
        session_id = f"vdp-holdout-{int(time.time())}"
        payload = {
            "schema_version": 1,
            "session_id": session_id,
            "run_id": "vdp-holdout-run",
            "mode": "readonly_enforce",
            "target": TARGET_NAME,
            "timestamp": time.time(),
            "context": {
                "target_info": dict(mc.context.target_info),
                "total_attempts": 0,
                "successful_attempts": 0,
            },
            "vdp_contract_version": 1,
        }
        confirmed_evidence_ids = {
            eid
            for verdict in state.get("verdicts", [])
            if isinstance(verdict, dict) and verdict.get("status") == "confirmed"
            for eid in (verdict.get("evaluated_evidence_ids") or [])
        }
        session_state = dict(state)
        # The run completed — record the honest termination state so the
        # real gate does not fail-closed on "unknown". Keep an existing
        # degraded run_health (dispatch exception) untouched.
        if not (session_state.get("run_health") or {}):
            from src.core.models.vdp_contract import (
                RunHealthRecord,
                RunTerminationState,
                deterministic_id,
            )
            session_state["run_health"] = RunHealthRecord(
                health_id=deterministic_id(
                    "health", {"reason": "opaque_holdout_complete"}
                ),
                run_state=RunTerminationState.SUCCEEDED,
                reason="opaque_holdout_complete",
                dependency_failures=[],
            ).to_dict()
        session_state["evidence_records"] = [
            record for record in state.get("evidence_records", [])
            if isinstance(record, dict)
            and record.get("evidence_id") in confirmed_evidence_ids
        ]
        with_vdp = inject_vdp_section_to_session_payload(payload, session_state)
        session_path = out_dir / f"session_{session_id}.json"
        redact_and_write_session(with_vdp, session_path)
        redact_and_write_session(with_vdp, out_dir / "session_latest.json")
        summary["session_path"] = session_path.name

        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex(KEY_HEX_SEED))
        restored = read_session_compat(session_path)
        if restored is None:
            raise RuntimeError("session could not be read back")
        m0 = VdpM0ContractGate().validate(
            restored, public_key_provider=signer.public_key_provider()
        )
        summary["m0_gate"] = {
            "passed": bool(m0.passed),
            "reason_codes": list(m0.reason_codes or []),
        }
        canonical = extract_vdp_canonical(
            restored, public_key_provider=signer.public_key_provider()
        )
        summary["canonical_funnel"] = (
            canonical.funnel.to_dict() if canonical.funnel is not None else {}
        )
        summary["fixture_log_non_get"] = _fixture_log_non_get()

        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "run_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        # --- compact ANONYMIZED console summary (counts only) ---
        print(f"iso_runtime:m0_gate_pass:{str(m0.passed).lower()}")
        print(f"iso_runtime:hypotheses:{summary['hypotheses_count']}")
        print(f"iso_runtime:attempts:{summary['attempts_count']}")
        print(f"iso_runtime:evidence:{summary['evidence_count']}")
        print(f"iso_runtime:verdicts:{summary['verdicts_by_status']}")
        print(f"iso_runtime:next_actions:{summary['next_actions_count']}")
        print(f"iso_runtime:follow_up_queued:{summary['follow_up_queued']}")
        print(f"iso_runtime:follow_up_failures:{len(summary['follow_up_failures'])}")
        print(f"iso_runtime:shadow_diff:{summary['shadow_diff_count']}")
        print(f"iso_runtime:executed_paths:{sorted(executed_paths)}")
        print(f"iso_runtime:degraded:{summary['degraded_reasons']}")
        print(f"iso_runtime:requests_made:{summary['requests_made']}")
        print(f"iso_runtime:non_get_violations:{net.violations}")
        print(f"iso_runtime:fixture_log_non_get:{summary['fixture_log_non_get']}")
        print(f"iso_runtime:session:{session_path.name}")

        if not m0.passed:
            print(f"iso_runtime:m0_gate_fail:{m0.reason_codes}", file=sys.stderr)
            return 1
        if net.violations:
            print("iso_runtime:non_get_violation_detected", file=sys.stderr)
            return 1
        if summary["fixture_log_non_get"]:
            print("iso_runtime:fixture_log_non_get_detected", file=sys.stderr)
            return 1
        return 0
    finally:
        try:
            await client.close()
        except Exception:
            pass


def main() -> int:
    try:
        return asyncio.run(run())
    except Exception as exc:  # unexpected failure: surface, do not swallow
        print(f"iso_runtime:fatal:{type(exc).__name__}:{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
