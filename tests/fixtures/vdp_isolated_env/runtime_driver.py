"""
Lane O-1 M3a read-only runtime driver — SGK-2026-0423.

Drives the REAL VDP M3a production path against a local disposable
fixture (``fixture_target.py``), read-only only:

  1. sets up the signing key file (0600, hex seed "33"*32 — NOT on the
     test-key denylist) and the key registry (ACTIVE entry) under
     ``OUT_DIR/keys/``;
  2. builds ``VdpModeSettings`` (readonly_enforce + follow_up_probe
     allowed), the explicit ``ScopeDefinition``, and a MasterConductor via
     the ``object.__new__`` pattern with REAL components: an
     ``AsyncNetworkClient`` (mode != bugbounty), a ``DynamicTaskQueue``,
     and the lazy VDP runtime deps;
  3. performs a READ-ONLY crawl of ``FIXTURE_BASE_URL`` (GET only; the
     internal network guard raises on any non-GET method string);
  4. runs ``_generate_vdp_hypotheses`` -> queue -> ``_dispatch_vdp_follow_up``
     per queued task (per-task exception isolation: degraded, never crash);
  5. writes the session (``inject_vdp_section_to_session_payload`` +
     ``redact_and_write_session``), runs the M0 gate, extracts the canonical
     summary, and prints an ANONYMIZED summary plus ``run_summary.json``.

KILL_SWITCH=1: no crawl, hook runs with an empty bundle, nothing is queued,
zero requests — prints ``kill_switch_stop:0-queued:0-requests`` and exits 0.

This process NEVER POSTs: an internal assertion wraps the network client
(any non-GET method string raises), and the fixture access log (when
``ACCESS_LOG_PATH`` is set) is checked for zero non-GET lines.

Environment:
  FIXTURE_BASE_URL    (default http://fixture-target:8000)
  OUT_DIR             (writable output directory)
  FIXTURE_SCOPE_HOST  (default "fixture-target"; host smoke test passes
                       "127.0.0.1" — the ScopeDefinition in_scope_domains
                       must match the URL host exactly)
  KILL_SWITCH         (0/1)
  TARGET_NAME         (default "vdp-iso-fixture")
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
KILL_SWITCH = os.environ.get("KILL_SWITCH", "0") == "1"
TARGET_NAME = os.environ.get("TARGET_NAME", "vdp-iso-fixture")
ACCESS_LOG_PATH = os.environ.get("ACCESS_LOG_PATH", "")

CRAWL_TIMEOUT = 3  # seconds; /slow yields a timeout observation
KEY_HEX_SEED = "33" * 32
RUNNER_ID = "vdp-iso-runtime-0.1.0"

_HREF_RE = re.compile(r'href="([^"]+)"')


# ---------------------------------------------------------------------------
# key setup (0600 key file + ACTIVE registry entry)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# MC construction (real components, __new__ pattern)
# ---------------------------------------------------------------------------


async def _async_noop(*args, **kwargs):
    pass


def build_mc(out_dir: Path, network_client) -> "MasterConductor":
    """Build a MasterConductor with REAL VDP runtime deps (mirrors
    ``tests/core/engine/test_master_conductor_vdp_follow_up.py::_new_mc``
    but with a real network client + queue + mode settings)."""
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
        decision_records_path=str(out_dir / "eval" / "decision_records.json"),
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
    mc._current_session = SimpleNamespace(session_id="vdp-iso-session")
    mc.run_ledger_recorder = SimpleNamespace(
        prepare_for_session=lambda spool_dir=None: {},
        run_id="vdp-iso-run",
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
    mc.network_client = network_client
    mc._vdp_mode = settings
    return mc


# ---------------------------------------------------------------------------
# read-only network guard (internal assertion: only GET ever leaves this
# process; violations raise so the run cannot silently continue)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# read-only crawl
# ---------------------------------------------------------------------------


async def _crawl_get(net, url: str) -> tuple:
    """One crawl GET with the executor's hidden-communication-disabled
    signature (no cache/retry/WAF bypass/redirects). Returns (status, body);
    status is the string "timeout"/"error" on transport failure."""
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


def _signal(url: str, primary_label: str, candidate_labels: list,
            params: list, signal_id: str, method: str = "GET") -> dict:
    """Recon-format endpoint signal (see ``_signal_bundle()`` in
    tests/core/engine/test_master_conductor_vdp_follow_up.py)."""
    return {
        "signal_id": signal_id,
        "entity_type": "endpoint",
        "url": url,
        "method": method,
        "primary_label": primary_label,
        "candidate_labels": candidate_labels,
        "confidence": 0.9,
        "auth_context": None,
        "params": params,
        "status": "active",
    }


async def crawl(net, base_url: str) -> tuple:
    """GET the index, parse hrefs, GET every discovered path, and build the
    endpoint signal bundle. Returns ``(bundle, observations)`` where
    ``observations`` is the anonymized ``[{method, path, status}]`` crawl
    record (paths are fixture-generic)."""
    index_status, index_body = await _crawl_get(net, f"{base_url}/")
    observations = [{"method": "GET", "path": "/", "status": index_status}]

    seen: list[str] = []
    signals: list[dict] = []
    n = 0

    def _add(path: str, primary: str, candidates: list, params: list) -> None:
        nonlocal n
        n += 1
        signals.append(_signal(
            f"{base_url}{path}", primary, candidates, params, f"iso-obs-{n:02d}"
        ))

    for href in _HREF_RE.findall(index_body):
        if not href.startswith("/"):
            continue
        parsed = urlparse(href)
        path = parsed.path
        if path in seen:
            continue
        seen.append(path)

        status, _body = await _crawl_get(net, f"{base_url}{href}")
        observations.append({"method": "GET", "path": path, "status": status})

        if path == "/readonly-ok":
            _add(path, "readonly-ok", ["object"], [])
        elif path == "/items/sample-1":
            _add(path, "items", ["object"], [])
        elif path == "/rate-limited":
            _add(path, "rate-limited", ["render"], [])
        elif path == "/server-error":
            _add(path, "server-error", ["object"], [])
        elif path == "/slow":
            _add(path, "slow", ["render"], [])
        elif path == "/redirect-out-of-scope":
            # "redirect" classifies to external_url -> oob gap -> manual.
            _add(path, "redirect-out-of-scope", [], [])
        elif path == "/search":
            # query param present -> exact replay impossible -> manual.
            _add(path, "search", ["render"],
                 [{"name": "q", "location": "query"}])
        else:
            _add(path, path.lstrip("/").replace("/", "-"), [], [])

    # A POST observation proves the readonly guard path: the hypothesis is
    # recorded, the follow-up stays manual, and NO POST is ever sent.
    signals.append(_signal(
        f"{base_url}/readonly-ok", "readonly-ok", ["object"],
        [], "iso-obs-post-01", method="POST",
    ))
    return {"_endpoint_signals": signals}, observations


# ---------------------------------------------------------------------------
# session + summary
# ---------------------------------------------------------------------------


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
    from src.reporting.vdp_canonical import extract_vdp_canonical

    # Real production client in a NON-bugbounty mode (compiled guard
    # enforcement is only active in bugbounty mode); use_proxy=True falls
    # back to direct connections when no proxy is configured.
    client = AsyncNetworkClient(mode="vdp-iso-fixture")
    await client.start()
    net = ReadOnlyGuardClient(client)

    mc = build_mc(out_dir, net)
    scope = mc._build_vdp_scope_snapshot()

    summary = {
        "target": TARGET_NAME,
        "mode": "readonly_enforce",
        "kill_switch": KILL_SWITCH,
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
        if KILL_SWITCH:
            # No crawl: the hook runs with an EMPTY bundle; the kill switch
            # stops queue injection before enqueue -> zero requests total.
            mc._generate_vdp_hypotheses(
                {"_signal_bundle": {}},
                scope_definition=scope,
                checkpoint_path=str(out_dir / "checkpoint.json"),
            )
            queued = [
                t for t in mc.task_queue if t.agent_type == "vdp_follow_up"
            ]
            assert not queued, f"kill switch queued {len(queued)} tasks"
            summary["hypotheses_count"] = len(mc._vdp_state.get("hypotheses", []))
            _write_summary(out_dir, summary)
            print("kill_switch_stop:0-queued:0-requests")
            print("iso_runtime:hypotheses:0")
            return 0

        # --- READ-ONLY crawl (GET only) ---
        bundle, observations = await crawl(net, FIXTURE_BASE_URL)
        summary["observations"] = observations

        # --- M3a hypothesis generation (real production hook) ---
        mc._generate_vdp_hypotheses(
            {"_signal_bundle": bundle},
            scope_definition=scope,
            checkpoint_path=str(out_dir / "checkpoint.json"),
        )

        # --- dispatch every queued vdp_follow_up task (per-task isolation) ---
        tasks = [
            t for t in mc.task_queue if t.agent_type == "vdp_follow_up"
        ]
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

        # --- session write -> M0 gate -> canonical summary ---
        session_id = f"vdp-iso-{int(time.time())}"
        payload = {
            "schema_version": 1,
            "session_id": session_id,
            "run_id": "vdp-iso-run",
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
        with_vdp = inject_vdp_section_to_session_payload(payload, state)
        session_path = out_dir / f"session_{session_id}.json"
        redact_and_write_session(with_vdp, session_path)
        # Stable pointer for the one-shot evaluator (compose flow).
        redact_and_write_session(with_vdp, out_dir / "session_latest.json")
        summary["session_path"] = session_path.name

        restored = read_session_compat(session_path)
        if restored is None:
            raise RuntimeError("session could not be read back")
        m0 = VdpM0ContractGate().validate(restored)
        summary["m0_gate"] = {
            "passed": bool(m0.passed),
            "reason_codes": list(m0.reason_codes or []),
        }
        canonical = extract_vdp_canonical(restored)
        summary["canonical_funnel"] = (
            canonical.funnel.to_dict() if canonical.funnel is not None else {}
        )
        summary["fixture_log_non_get"] = _fixture_log_non_get()

        _write_summary(out_dir, summary)

        # --- compact ANONYMIZED console summary (counts only; no secrets) ---
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


def _write_summary(out_dir: Path, summary: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "run_summary.json"
    target.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def main() -> int:
    try:
        return asyncio.run(run())
    except Exception as exc:  # unexpected failure: surface, do not swallow
        print(f"iso_runtime:fatal:{type(exc).__name__}:{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
