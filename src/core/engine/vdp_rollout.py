"""
SGK-2026-0423 — VDP staged rollout gate (Lane C, engine layer).

M0-M4 rollout ladder, kill switch, rollback, and shadow/enforce diff
recording for the VDP (Vulnerability Disclosure Program) pipeline.

Security invariants:
- The effective stage is the mode-derived capability baseline, which can
  be RAISED only through verified progression evidence artifacts (never
  config alone): a raise requires an enforce-mode baseline (M3a+),
  progression records for ALL prior stages, and — for M4 — REAL Go
  evidence: the frozen thresholds artifact, a holdout result (outcome
  "pass" with matching eval_version, an intact recomputed artifact_hash,
  and a threshold fingerprint equal to the EXACT thresholds artifact the
  gate reads — 閾値をholdout閲覧前に固定し、後付け調整しない), the LATEST
  holdout decision record (decision "go", bound to the evaluation by
  eval_version + artifact_hash — a stale Go after a later Hold/No-Go is
  never adopted), and a real gate result (decision "go", known termination
  run_state, report/session consistency pass). ``stage_flags`` disable
  stages downward and a persisted ``RolloutStateStore`` (rollback) can
  never raise capability.
- A corrupt/unreadable rollout state store fails CLOSED: the gate reports
  effective M0 with ``rollout_state_unreadable`` (communication-disabled).
- M3b+ (state-changing enforce) requires progression evidence for ALL prior
  stages (m0..previous) and an active signing key + HITL ticket before any
  communication; missing evidence is fail-closed (no claim without proof).
- ``load_progression_records`` returns ``[]`` for missing/unreadable/
  malformed files — no progression is ever claimed without evidence.
- Shadow/enforce diff entries and decision records contain NO secrets.

This module is Lane C of SGK-2026-0423: it owns the rollout gate and the
shadow/enforce diff trace only. Lane A (``vdp_key_registry``) owns the key
lifecycle and enforce/no-home-fallback decision; the full rollout gate here
is the superset of Lane A's ``effective_stage``.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.config.settings import (
    VDP_STAGES,
    VDP_STAGE_RANKS,
    derive_stage_from_mode,
    is_enforce_stage,
    min_stage,
)
from src.core.models.vdp_contract import canonical_json_bytes
from src.reporting.vdp_dataset import ThresholdArtifact, thresholds_fingerprint


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


#: Decision-record stage that records the holdout Go judgment (M4 evidence).
M4_GO_EVIDENCE_STAGE = "holdout"


class RolloutStage(str, Enum):
    """M0-M4 rollout ladder (values match ``VDP_STAGES``)."""

    M0 = "m0"
    M1 = "m1"
    M2 = "m2"
    M3A = "m3a"
    M3B = "m3b"
    M3C = "m3c"
    M4 = "m4"


class RolloutStateError(Exception):
    """Malformed or unreadable rollout state store."""


class StageVerdict:
    """Result of a rollout gate check (allow/deny + trace reason)."""

    __slots__ = ("allow", "stage", "reason")

    def __init__(self, *, allow: bool, stage: str, reason: str = "") -> None:
        self.allow = allow
        self.stage = stage
        self.reason = reason

    @classmethod
    def allow_ok(cls, stage: str) -> "StageVerdict":
        return cls(allow=True, stage=stage, reason="")

    @classmethod
    def deny(cls, reason: str, *, stage: str = "") -> "StageVerdict":
        return cls(allow=False, stage=stage, reason=reason)


class VdpRolloutGate:
    """Staged rollout gate for VDP capability (M0-M4 ladder).

    ``settings_like`` may be a ``VdpModeSettings`` OR any namespace; ALL
    reads go through ``getattr`` with safe defaults so pre-0423 test
    namespaces (mode/label_leakage_denylist/kill_switch/capability_rules
    only) keep working unchanged.

    Effective stage semantics (SGK-2026-0423 Lane E):
    - ``state_error`` (unreadable/corrupt rollout state store) is ABSOLUTE:
      the gate returns M0 with ``rollout_state_unreadable`` before any
      other logic (communication-disabled).
    - A RAISE request (explicit stage above the mode-derived stage) is
      honored ONLY through verified progression evidence: the mode must
      already be an enforce mode (M3a+ — record-only modes may not silently
      start communicating), progression records for ALL prior stages must
      exist, and M4 additionally requires the frozen thresholds artifact.
      When the raise is denied, the effective stage stays at the
      mode-derived stage and the denial reason records which requirement
      failed (M4 with full progression but missing thresholds lands at M3c).
    - A cap (explicit stage at or below the mode-derived stage) sets the
      effective stage to the explicit stage (``explicit_stage_cap``).
    - ``stage_flags`` cascade disables stages downward (unchanged), then a
      persisted store rollback can only LOWER further (unchanged).
    """

    #: Stages that require full progression evidence (all prior stages).
    PROGRESSION_STAGES = ("m3b", "m3c", "m4")

    def __init__(
        self,
        settings_like,
        *,
        state_store: Optional["RolloutStateStore"] = None,
        progression_records: Optional[list] = None,
        state_error: bool = False,
    ) -> None:
        self._settings = settings_like
        self._state_store = state_store
        self._progression = progression_records
        self._state_error = bool(state_error)
        self._progression_path = (
            str(getattr(settings_like, "progression_records_path", "") or "")
        )
        self._cap_reasons: Optional[List[str]] = None

    # ------------------------------------------------------------------
    # Stage derivation
    # ------------------------------------------------------------------

    def mode_stage(self) -> str:
        """Stage derived from the legacy mode vocabulary (max M3a)."""
        return derive_stage_from_mode(getattr(self._settings, "mode", "off") or "off")

    def explicit_stage(self) -> str:
        """Explicit rollout stage; defaults to the mode-derived stage.

        An unknown explicit stage fails closed to the mode-derived stage
        (mirrors the ``VdpModeSettings`` stage validator for duck-typed
        namespaces).
        """
        explicit = str(getattr(self._settings, "stage", "") or "")
        if explicit in VDP_STAGE_RANKS:
            return explicit
        return self.mode_stage()

    def effective_stage(self) -> str:
        """Effective stage for the current configuration.

        The mode-derived stage is the capability baseline. It can RAISE
        beyond the mode vocabulary ONLY through verified progression
        evidence artifacts (never config alone), and can always be LOWERED
        by explicit stage caps, ``stage_flags``, and a persisted store
        rollback. A ``state_error`` (corrupt/unreadable rollout state)
        fails closed to M0 (communication-disabled) before all other logic.
        """
        reasons: List[str] = []
        if self._state_error:
            self._cap_reasons = ["rollout_state_unreadable"]
            return "m0"
        mode = self.mode_stage()
        explicit = self.explicit_stage()
        current = mode
        if VDP_STAGE_RANKS.get(explicit, 0) > VDP_STAGE_RANKS.get(mode, 0):
            # RAISE request: allowed only through verified progression
            # evidence; record-only modes may not silently start
            # communicating (enforce-mode baseline is checked first).
            if not is_enforce_stage(mode):
                reasons.append("stage_raise_requires_enforce_mode")
                if explicit == "m4":
                    reasons.extend(self._m4_go_evidence_ready())
            elif not self._progression_passed_for(explicit):
                reasons.append(f"stage_raise_requires_progression:{explicit}")
                if explicit == "m4":
                    reasons.extend(self._m4_go_evidence_ready())
            elif explicit == "m4":
                m4_unmet = self._m4_go_evidence_ready()
                if m4_unmet:
                    # m0..m3c proven but the REAL M4 Go evidence (holdout
                    # result, decision record, gate result, thresholds) is
                    # incomplete: the highest fully proven rung is m3c.
                    current = "m3c"
                    reasons.extend(m4_unmet)
                else:
                    current = explicit
            else:
                current = explicit
        else:
            current = explicit
            if (
                explicit != mode
                and VDP_STAGE_RANKS.get(explicit, 0) < VDP_STAGE_RANKS.get(mode, 0)
            ):
                reasons.append("explicit_stage_cap")
        flags = getattr(self._settings, "stage_flags", None) or {}
        if flags:
            rank = VDP_STAGE_RANKS.get(current, 0)
            while rank > 0 and flags.get(VDP_STAGES[rank], True) is False:
                reasons.append(f"stage_flag_disabled:{VDP_STAGES[rank]}")
                rank -= 1
            current = VDP_STAGES[rank]
        if self._state_store is not None:
            store_stage = str(
                getattr(self._state_store, "current_stage", None) or ""
            )
            if store_stage in VDP_STAGE_RANKS:
                lowered = min_stage(current, store_stage)
                if lowered != current:
                    reasons.append("store_rollback_cap")
                    current = lowered
        self._cap_reasons = reasons
        return current

    def cap_reasons(self) -> List[str]:
        """Reasons for any capping applied (empty when no caps)."""
        if self._cap_reasons is None:
            self.effective_stage()
        return list(self._cap_reasons or [])

    def is_enforce(self) -> bool:
        """True when the effective stage performs real communication (M3a+)."""
        return is_enforce_stage(self.effective_stage())

    # ------------------------------------------------------------------
    # Operation checks
    # ------------------------------------------------------------------

    def can_operate_at(self, stage: str) -> StageVerdict:
        """Whether ``stage`` is reachable under the effective stage.

        - Deny ``stage_capped`` when the requested stage ranks above the
          effective stage.
        - Deny ``progression_not_met:<stage>`` for m3b/m3c/m4 unless
          progression evidence exists for ALL prior stages (m0..previous).
        - m0/m1/m2/m3a are allowed without progression artifacts (their real
          gates live in the existing admission/executor machinery).
        """
        stage = str(stage or "")
        effective = self.effective_stage()
        if VDP_STAGE_RANKS.get(stage, 0) > VDP_STAGE_RANKS.get(effective, 0):
            return StageVerdict.deny("stage_capped", stage=stage)
        if stage in self.PROGRESSION_STAGES and not self._progression_passed_for(
            stage
        ):
            return StageVerdict.deny(f"progression_not_met:{stage}", stage=stage)
        return StageVerdict.allow_ok(stage)

    def pre_communication_check(
        self,
        *,
        risk_class: str,
        capability_level: str = "allowed",
        hitl_ticket: str = "",
        key_active: bool = False,
    ) -> StageVerdict:
        """Fail-closed gate immediately before ANY communication.

        Read-only probes (non-state-changing, non-confirmation-required)
        pass through — the existing admission gates apply at executor level.
        The state-changing path requires, in order:
          M3b+ effective stage, progression evidence, a HITL ticket, and an
          ACTIVE signing key.
        """
        risk_class = str(risk_class or "")
        capability_level = str(capability_level or "allowed")
        if risk_class != "state_changing" and capability_level != "confirmation_required":
            return StageVerdict.allow_ok(self.effective_stage())
        effective = self.effective_stage()
        if VDP_STAGE_RANKS.get(effective, 0) < VDP_STAGE_RANKS.get("m3b", 0):
            return StageVerdict.deny(
                "stage_below_m3b_for_state_change", stage=effective
            )
        if not self.can_operate_at(effective).allow:
            return StageVerdict.deny("progression_not_met", stage=effective)
        if not str(hitl_ticket or "").strip():
            return StageVerdict.deny("hitl_ticket_required", stage=effective)
        if not key_active:
            return StageVerdict.deny("signing_key_not_active", stage=effective)
        return StageVerdict.allow_ok(effective)

    # ------------------------------------------------------------------
    # Progression evidence
    # ------------------------------------------------------------------

    def _progression_passed_for(self, stage: str) -> bool:
        prior = [
            s for s in VDP_STAGES if VDP_STAGE_RANKS[s] < VDP_STAGE_RANKS.get(stage, 0)
        ]
        if not prior:
            return True
        progression = self._progression
        if progression is None:
            progression = load_progression_records(self._progression_path)
        passed = {
            str(record.get("stage", ""))
            for record in progression
            if isinstance(record, dict)
            and str(record.get("stage", "")) in VDP_STAGES
            and record.get("passed") is True
        }
        return all(s in passed for s in prior)

    def _m4_thresholds_ready(self) -> bool:
        """True when the frozen hidden-holdout threshold artifact is present
        and valid (M4 gate).

        Mirrors the frozen-threshold artifact contract of
        ``src.reporting.vdp_dataset`` WITHOUT importing reporting modules
        (the engine layer stays independent): a JSON dict with
        ``schema_version == 1``, a non-empty ``eval_version``, and a
        non-empty ``metrics`` list. Any failure (empty path, missing file,
        unreadable, malformed JSON, wrong shape) is False — fail-closed.
        """
        thresholds_path = str(
            getattr(self._settings, "thresholds_path", "") or ""
        )
        if not thresholds_path:
            return False
        source = Path(thresholds_path)
        if not source.exists():
            return False
        try:
            raw = source.read_text(encoding="utf-8")
        except OSError:
            return False
        try:
            data = json.loads(raw)
        except ValueError:
            return False
        if not isinstance(data, dict):
            return False
        metrics = data.get("metrics")
        return (
            data.get("schema_version") == 1
            and bool(str(data.get("eval_version", "") or "").strip())
            and isinstance(metrics, list)
            and len(metrics) > 0
        )

    # ------------------------------------------------------------------
    # M4 Go evidence (Lane J-1 audit wave 3)
    # ------------------------------------------------------------------

    def _m4_go_evidence_ready(self) -> List[str]:
        """Unmet M4 Go-evidence reasons (empty list == M4 fully proven).

        M4 reachability requires REAL Go evidence — hand-written progression
        + threshold JSONs alone are not enough (the pre-audit state):
        - enforce-mode baseline + full progression (kept from Lane E);
        - frozen thresholds artifact (shape sub-check, kept);
        - holdout result artifact: outcome "pass", eval_version equal to the
          thresholds artifact, artifact_hash recomputed intact with the
          runner's exact semantics, and a ``threshold_fingerprint`` equal to
          the fingerprint of the EXACT thresholds artifact the gate now
          reads (Lane L-1: 閾値をholdout閲覧前に固定し、後付け調整しない —
          thresholds changed under the same eval_version deny M4);
        - the LATEST holdout decision record (``stage == "holdout"`` by
          ``recorded_at``; ties: last in file order) with decision "go",
          eval_version equal to the thresholds artifact, and an artifact
          hash equal to the evaluated holdout result — a stale older Go
          after a later Hold/No-Go is never adopted;
        - a real gate result: decision "go", a known termination run_state
          (never "unknown"), and report/session consistency pass.

        Every missing/malformed piece fails closed with its own reason.
        """
        reasons: List[str] = []
        if not is_enforce_stage(self.mode_stage()):
            reasons.append("m4_requires_enforce_mode")
        if not self._progression_passed_for("m4"):
            reasons.append("m4_requires_progression")

        thresholds = self._load_json_artifact(
            str(getattr(self._settings, "thresholds_path", "") or "")
        )
        if thresholds is None or not self._m4_thresholds_ready():
            reasons.append("m4_requires_thresholds")

        holdout = self._load_json_artifact(
            str(getattr(self._settings, "holdout_result_path", "") or "")
        )
        if holdout is None:
            reasons.append("m4_requires_holdout_result")
        else:
            if str(holdout.get("outcome", "") or "") != "pass":
                reasons.append("m4_holdout_outcome_not_pass")
            if (
                thresholds is not None
                and str(holdout.get("eval_version", "") or "")
                != str(thresholds.get("eval_version", "") or "")
            ):
                reasons.append("m4_holdout_eval_version_mismatch")
            if not self._holdout_artifact_hash_ok(holdout):
                reasons.append("m4_holdout_artifact_hash_mismatch")
            if (
                thresholds is not None
                and self._thresholds_fingerprint_of(thresholds)
                != str(holdout.get("threshold_fingerprint", "") or "")
            ):
                # Lane L-1: the holdout result must carry the fingerprint of
                # the EXACT thresholds artifact read here — post-evaluation
                # threshold adjustment under the same eval_version is denied.
                reasons.append("m4_threshold_fingerprint_mismatch")

        # The LATEST holdout decision governs: a stale older Go must never
        # be adopted after a later Hold/No-Go. ``recorded_at`` ISO strings
        # compare lexicographically (UTC "Z" form); ties resolve to the LAST
        # record in file order.
        holdout_entries = [
            record
            for record in load_decision_records(
                str(getattr(self._settings, "decision_records_path", "") or "")
            )
            if record.stage == M4_GO_EVIDENCE_STAGE
        ]
        if not holdout_entries:
            reasons.append("m4_requires_decision_record")
        else:
            latest_index = max(
                range(len(holdout_entries)),
                key=lambda i: (holdout_entries[i].recorded_at, i),
            )
            latest = holdout_entries[latest_index]
            if latest.decision != "go":
                reasons.append("m4_decision_record_not_go")
            if (
                thresholds is not None
                and str(latest.eval_version or "")
                != str(thresholds.get("eval_version", "") or "")
            ):
                reasons.append("m4_decision_eval_version_mismatch")
            if (
                holdout is not None
                and str(latest.artifact_hash or "")
                != str(holdout.get("artifact_hash", "") or "")
            ):
                reasons.append("m4_decision_artifact_hash_mismatch")

        gate = self._load_json_artifact(
            str(getattr(self._settings, "gate_result_path", "") or "")
        )
        if gate is None:
            reasons.append("m4_requires_gate_result")
        else:
            if str(gate.get("decision", "") or "") != "go":
                reasons.append("m4_gate_decision_not_go")
            run_state = self._gate_run_state(gate)
            if not run_state or run_state == "unknown":
                reasons.append("m4_gate_termination_unknown")
            if not self._gate_consistency_ok(gate):
                reasons.append("m4_gate_consistency_not_consistent")

        return reasons

    @staticmethod
    def _load_json_artifact(path: str) -> Optional[dict]:
        """Load a JSON-object artifact; empty/missing/unreadable/malformed
        -> None (fail-closed)."""
        if not path:
            return None
        source = Path(path)
        if not source.exists():
            return None
        try:
            raw = source.read_text(encoding="utf-8")
        except OSError:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    @staticmethod
    def _holdout_artifact_hash_ok(holdout: dict) -> bool:
        """Recompute the holdout artifact hash EXACTLY like
        ``save_evaluation_result``: sha256 over canonical JSON of every
        field except ``artifact_hash``."""
        stored = str(holdout.get("artifact_hash", "") or "")
        if not stored:
            return False
        payload = {k: v for k, v in holdout.items() if k != "artifact_hash"}
        recomputed = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        return stored == recomputed

    @staticmethod
    def _thresholds_fingerprint_of(thresholds: dict) -> str:
        """Fingerprint of the frozen thresholds artifact — EXACTLY mirroring
        ``src.reporting.vdp_dataset.thresholds_fingerprint`` (the value the
        holdout runner recorded in the result's ``threshold_fingerprint``).
        A malformed artifact fingerprints as "" (fail-closed -> mismatch)."""
        try:
            artifact = ThresholdArtifact.from_dict(thresholds)
        except Exception:  # pydantic ValidationError and friends — fail closed
            return ""
        return thresholds_fingerprint(artifact)

    @staticmethod
    def _gate_run_state(gate: dict) -> str:
        """Termination run_state from a gate result: ``gates.
        termination_state.run_state``, falling back to a top-level
        ``run_state``; missing -> "" (unknown)."""
        gates = gate.get("gates")
        termination = (
            gates.get("termination_state") if isinstance(gates, dict) else None
        )
        if isinstance(termination, dict):
            return str(termination.get("run_state", "") or "")
        return str(gate.get("run_state", "") or "")

    @staticmethod
    def _gate_consistency_ok(gate: dict) -> bool:
        """Report/session consistency of a gate result: ``gates.
        report_session_consistency.status`` (fallback: top-level ``status``)
        must be "pass" AND ``gates.report_session_consistency.
        consistency_status`` must be "consistent". Missing pieces are unmet
        (fail-closed)."""
        gates = gate.get("gates")
        rsc = (
            gates.get("report_session_consistency")
            if isinstance(gates, dict)
            else None
        )
        if isinstance(rsc, dict):
            status = str(rsc.get("status", "") or "") or str(
                gate.get("status", "") or ""
            )
            consistency = str(rsc.get("consistency_status", "") or "")
        else:
            status = str(gate.get("status", "") or "")
            consistency = ""
        return status == "pass" and consistency == "consistent"


class RolloutStateStore:
    """Persisted rollout/rollback state (can only LOWER effective stage).

    ``current_stage`` is the operator-approved stage; ``rollback()`` reverts
    to ``previous_stage`` or the settings-baseline sentinel ``""`` ("no
    store cap") when there is no previous stage.
    """

    _VALID_STAGES: tuple = (*VDP_STAGES, "")

    def __init__(
        self,
        current_stage: str,
        previous_stage: Optional[str] = None,
        events: Optional[list] = None,
    ) -> None:
        self._current_stage = str(current_stage or "")
        self._previous_stage = previous_stage
        self._events: List[dict] = list(events or [])

    @property
    def current_stage(self) -> str:
        return self._current_stage

    @property
    def previous_stage(self) -> Optional[str]:
        return self._previous_stage

    @property
    def events(self) -> List[dict]:
        return self._events

    def to_dict(self) -> dict:
        return {
            "current_stage": self._current_stage,
            "previous_stage": self._previous_stage,
            "events": [dict(e) for e in self._events],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RolloutStateStore":
        if not isinstance(data, dict):
            raise RolloutStateError("rollout_state_malformed")
        current = data.get("current_stage")
        if not isinstance(current, str) or current not in cls._VALID_STAGES:
            raise RolloutStateError("rollout_state_malformed")
        previous = data.get("previous_stage")
        if previous is not None and (
            not isinstance(previous, str) or previous not in VDP_STAGES
        ):
            raise RolloutStateError("rollout_state_malformed")
        events = data.get("events")
        if events is not None and not isinstance(events, list):
            raise RolloutStateError("rollout_state_malformed")
        return cls(current_stage=current, previous_stage=previous, events=events or [])

    def save(self, path) -> None:
        """Atomic write: temp file in the same directory + os.replace."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self.to_dict(), handle, indent=2, sort_keys=True)
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, target)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    @staticmethod
    def load(path) -> Optional["RolloutStateStore"]:
        """Load a store; missing file -> None, malformed -> RolloutStateError."""
        source = Path(path)
        if not source.exists():
            return None
        try:
            raw = source.read_text(encoding="utf-8")
        except OSError as exc:
            raise RolloutStateError("rollout_state_unreadable") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise RolloutStateError("rollout_state_malformed_json") from exc
        return RolloutStateStore.from_dict(data)

    def rollback(self, reason: str) -> None:
        """Revert to the previous approved stage (or the "" baseline)."""
        self._current_stage = self._previous_stage or ""
        self._previous_stage = None
        self._events.append(
            {"ts": _now_iso(), "kind": "rollback", "reason": str(reason or "")}
        )


def load_progression_records(path) -> List[dict]:
    """Load progression evidence records.

    Missing/unreadable/malformed -> [] (fail-closed: no progression claimed
    without evidence). Valid JSON list of dicts kept as-is; the pass filter
    (stage in VDP_STAGES, ``passed is True``) is applied by the gate.
    """
    if not path:
        return []
    source = Path(path)
    if not source.exists():
        return []
    try:
        raw = source.read_text(encoding="utf-8")
    except OSError:
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    if not isinstance(data, list):
        return []
    return [record for record in data if isinstance(record, dict)]


class ShadowDiffRecorder:
    """Append-only shadow/enforce diff trace inside ``_vdp_state``.

    Entries are plain dicts with a deterministic key order and NO secrets;
    they record which NextActions were enforced vs. remained shadow-only.
    """

    #: Deterministic key order for every entry.
    _KEYS = (
        "next_action_id",
        "verdict_id",
        "hypothesis_id",
        "attempt_id",
        "reason_code",
        "stage",
        "decision",
        "diff_type",
    )

    @staticmethod
    def record(
        vdp_state: dict,
        *,
        next_action_id: str = "",
        verdict_id: str = "",
        hypothesis_id: str = "",
        attempt_id: str = "",
        reason_code: str = "",
        stage: str = "",
        decision: str,
        diff_type: str,
    ) -> None:
        """Append one diff entry with EXACTLY the fixed keys (in order)."""
        values = {
            "next_action_id": str(next_action_id or ""),
            "verdict_id": str(verdict_id or ""),
            "hypothesis_id": str(hypothesis_id or ""),
            "attempt_id": str(attempt_id or ""),
            "reason_code": str(reason_code or ""),
            "stage": str(stage or ""),
            "decision": str(decision or ""),
            "diff_type": str(diff_type or ""),
        }
        vdp_state.setdefault("shadow_diff", []).append(
            {key: values[key] for key in ShadowDiffRecorder._KEYS}
        )


class KillSwitchGuard:
    """Immediate serial revert switch (stops queue injection AND
    pre-communication)."""

    REASON = "kill_switch_active"

    @staticmethod
    def is_active(settings_like) -> bool:
        return bool(getattr(settings_like, "kill_switch", False))


@dataclass
class RolloutDecisionRecord:
    """One Go/Hold/No-Go rollout decision (reproducible decision log)."""

    stage: str
    decision: str  # "go" | "hold" | "no_go"
    reasons: List[str] = field(default_factory=list)
    recorded_at: str = ""
    eval_version: str = ""
    artifact_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "stage": self.stage,
            "decision": self.decision,
            "reasons": list(self.reasons),
            "recorded_at": self.recorded_at,
            "eval_version": self.eval_version,
            "artifact_hash": self.artifact_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RolloutDecisionRecord":
        return cls(
            stage=str(data.get("stage", "") or ""),
            decision=str(data.get("decision", "") or ""),
            reasons=[
                str(item)
                for item in (data.get("reasons") or [])
                if isinstance(item, str)
            ],
            recorded_at=str(data.get("recorded_at", "") or ""),
            eval_version=str(data.get("eval_version", "") or ""),
            artifact_hash=str(data.get("artifact_hash", "") or ""),
        )


def write_decision_record(path, entry: RolloutDecisionRecord) -> None:
    """Atomically append one decision record (JSON list file, no secrets)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    records = load_decision_records(path)
    records.append(entry)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(
                [record.to_dict() for record in records],
                handle,
                indent=2,
                sort_keys=True,
            )
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def load_decision_records(path) -> List[RolloutDecisionRecord]:
    """Load decision records; missing/unreadable/malformed -> []."""
    source = Path(path)
    if not source.exists():
        return []
    try:
        raw = source.read_text(encoding="utf-8")
    except OSError:
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    if not isinstance(data, list):
        return []
    records: List[RolloutDecisionRecord] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        records.append(RolloutDecisionRecord.from_dict(item))
    return records
