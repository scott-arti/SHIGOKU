"""
VDP M0 Contract Gate — SGK-2026-0419 Item 3.3.

Validates that all VDP contract records in a session payload pass:
- Schema validation (all records validate without errors)
- ID traceability (IDs form a coherent chain)
- Scope verdict presence (all attempts have scope verdicts)

Returns a structured pass/fail result with reason details.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.core.models.vdp_contract import (
    VDP_CONTRACT_SCHEMA_VERSION,
    AttemptRecord,
    EvidenceRecordV1,
    EvidenceVerdictV1,
    HypothesisRecord,
    NextActionRecord,
    validate_hypothesis_record,
    validate_attempt_record,
    validate_evidence_record,
    validate_verdict_record,
    validate_next_action_record,
)


@dataclass
class M0GateResult:
    """Result of the M0 contract gate validation."""
    passed: bool
    reason_codes: List[str] = field(default_factory=list)
    detail: str = ""
    schema_errors: List[str] = field(default_factory=list)
    id_trace_errors: List[str] = field(default_factory=list)
    scope_verdict_errors: List[str] = field(default_factory=list)

    @classmethod
    def ok(cls) -> "M0GateResult":
        return cls(passed=True, detail="All VDP contract records valid")

    @classmethod
    def pass_(cls) -> "M0GateResult":
        return cls(passed=True, detail="All VDP contract records valid")

    @classmethod
    def fail(
        cls,
        reason_codes: List[str] | str = "",
        detail: str = "",
        schema_errors: List[str] | None = None,
        id_trace_errors: List[str] | None = None,
        scope_verdict_errors: List[str] | None = None,
    ) -> "M0GateResult":
        if isinstance(reason_codes, str):
            reason_codes = [reason_codes] if reason_codes else []
        return cls(
            passed=False,
            reason_codes=reason_codes,
            detail=detail,
            schema_errors=schema_errors or [],
            id_trace_errors=id_trace_errors or [],
            scope_verdict_errors=scope_verdict_errors or [],
        )


class VdpM0ContractGate:
    """M0 gate: validates VDP contract records in a session payload.

    Checks:
    1. **Schema validation**: Each hypothesis/attempt/evidence/verdict/next_action
       record must pass its respective ``validate_*()`` function.
    2. **ID traceability**: IDs must form a coherent chain
       (hypothesis_id -> attempt_id -> evidence_id -> verdict_id -> next_action_id).
    3. **Scope verdict presence**: Every attempt must have a scope_verdict.
    """

    # Reason code constants
    SCHEMA_VALIDATION_FAILED = "m0_schema_validation_failed"
    ID_TRACEABILITY_BROKEN = "m0_id_traceability_broken"
    SCOPE_VERDICT_MISSING = "m0_scope_verdict_missing"
    MISSING_CONTRACT_SECTION = "m0_missing_contract_section"

    def validate(
        self,
        session_payload: Any,
        *,
        public_key_provider: Any = None,
    ) -> M0GateResult:
        """Validate all VDP contract records in a session payload (fail-closed).

        Performs strict validation:
        0. Input type check: session_payload must be a dict, vdp_contract must be a dict.
        1. Schema version present at top level and in vdp_contract section.
        2. Parse each record type; TypeError/ValueError/KeyError during parsing → fail.
        3. At least one hypothesis if vdp_contract section exists.
        4. Run all 5 ``validate_*()`` functions on each record.
        5. ID traceability: every referenced ID must exist.
        6. On success: ``M0GateResult.pass_()``.

        Args:
            session_payload: The session payload (must be a dict).
            public_key_provider: Optional Ed25519 public-key provider dict or
                callable for restoring confirmed verdicts (SGK-2026-0422
                canonical v2 proofs). When None, the default dev/test
                provider is used; fail-closed when no key is available.
        """
        # 0. Input type check
        if not isinstance(session_payload, dict):
            return M0GateResult.fail(
                reason_codes="parse_error",
                detail="session_payload is not a dict",
            )

        # 1. Check vdp_contract_version — must match VDP_CONTRACT_SCHEMA_VERSION
        vdp_section = session_payload.get("vdp_contract")

        # vdp_section type check: must be dict, not string or list
        if vdp_section is not None and not isinstance(vdp_section, dict):
            return M0GateResult.fail(
                reason_codes="parse_error",
                detail=f"vdp_contract section is not a dict (got {type(vdp_section).__name__})",
            )

        # No vdp_contract section → nothing to validate, pass
        if not vdp_section or not isinstance(vdp_section, dict):
            return M0GateResult.pass_()

        vdp_version = vdp_section.get("vdp_contract_version")
        if vdp_version is None:
            return M0GateResult.fail(
                reason_codes="schema_version_missing",
                detail="vdp_contract_version missing from vdp_contract section",
            )
        if not isinstance(vdp_version, int) or type(vdp_version) is not int:
            return M0GateResult.fail(
                reason_codes="schema_version_missing",
                detail=f"vdp_contract_version is not an int: {type(vdp_version).__name__}",
            )
        if vdp_version == 0:
            return M0GateResult.fail(
                reason_codes="schema_version_missing",
                detail="vdp_contract_version is 0 (missing or unset)",
            )
        if vdp_version != VDP_CONTRACT_SCHEMA_VERSION:
            return M0GateResult.fail(
                reason_codes="schema_version_missing",
                detail=f"vdp_contract_version is {vdp_version}, must be {VDP_CONTRACT_SCHEMA_VERSION}",
            )

        # 1b. vdp_active must be a strict bool
        vdp_active = vdp_section.get("vdp_active")
        if vdp_active is None:
            return M0GateResult.fail(
                reason_codes="parse_error",
                detail="vdp_active missing from vdp_contract section",
            )
        if type(vdp_active) is not bool:
            return M0GateResult.fail(
                reason_codes="parse_error",
                detail=f"vdp_active is not a strict bool: {type(vdp_active).__name__}",
            )

        # 1c. Inactive + VDP data → reject (fail-closed)
        if not vdp_active:
            data_keys = (
                "hypotheses", "attempts", "evidence_records",
                "verdicts", "next_actions",
            )
            has_data = any(vdp_section.get(k) for k in data_keys) or any(
                vdp_section.get(k) for k in ("budget_snapshot", "run_health")
            )
            if has_data:
                return M0GateResult.fail(
                    reason_codes="parse_error",
                    detail="vdp_active=False but VDP data sections are present — inconsistent state",
                )

        # 2. Parse records — validate each section IS a list before parsing
        parse_errors: List[str] = []
        
        raw_hypotheses = vdp_section.get("hypotheses", [])
        raw_attempts = vdp_section.get("attempts", [])
        raw_evidence = vdp_section.get("evidence_records", [])
        raw_verdicts = vdp_section.get("verdicts", [])
        raw_next_actions = vdp_section.get("next_actions", [])
        
        if not isinstance(raw_hypotheses, list):
            return M0GateResult.fail("parse_error", f"hypotheses is not a list: {type(raw_hypotheses).__name__}")
        if not isinstance(raw_attempts, list):
            return M0GateResult.fail("parse_error", f"attempts is not a list: {type(raw_attempts).__name__}")
        if not isinstance(raw_evidence, list):
            return M0GateResult.fail("parse_error", f"evidence_records is not a list: {type(raw_evidence).__name__}")
        if not isinstance(raw_verdicts, list):
            return M0GateResult.fail("parse_error", f"verdicts is not a list: {type(raw_verdicts).__name__}")
        if not isinstance(raw_next_actions, list):
            return M0GateResult.fail("parse_error", f"next_actions is not a list: {type(raw_next_actions).__name__}")
        
        hypotheses = self._parse_strict(raw_hypotheses, HypothesisRecord, parse_errors, "hypotheses")
        attempts = self._parse_strict(raw_attempts, AttemptRecord, parse_errors, "attempts")
        evidence_records = self._parse_strict(raw_evidence, EvidenceRecordV1, parse_errors, "evidence_records")
        # Verdicts parsed with public-key proof verification: confirmed
        # verdicts are restored ONLY via the canonical v2 restore path
        # (or the engine-side legacy verifier for hmac-sha256 proofs),
        # then validated against actual evidence records in
        # _validate_confirmations.
        verdicts = self._parse_strict_verdicts(
            raw_verdicts,
            parse_errors,
            "verdicts",
            evidence_dicts=raw_evidence if isinstance(raw_evidence, list) else [],
            public_key_provider=public_key_provider,
        )
        next_actions = self._parse_strict(raw_next_actions, NextActionRecord, parse_errors, "next_actions")

        if parse_errors:
            return M0GateResult.fail(
                reason_codes="parse_error",
                detail="; ".join(parse_errors),
                schema_errors=parse_errors,
            )

        # 2b. Confirmed verdict validation: every confirmed verdict must have
        # non-empty evidence_ids, existing evidence, correct hypothesis lineage,
        # and non-empty validator_version.
        conf_errors = self._validate_confirmations(
            verdicts, raw_verdicts, hypotheses, attempts, evidence_records
        )
        if conf_errors:
            return M0GateResult.fail(
                reason_codes="parse_error",
                detail="; ".join(conf_errors),
                schema_errors=conf_errors,
            )

        # 3. Mandatory: at least one hypothesis — only when VDP is active.
        # Inactive + no data is a conventional session and passes here.
        if vdp_active and not hypotheses:
            return M0GateResult.fail(
                reason_codes="parse_error",
                detail="vdp_contract section present, vdp_active=True but no valid hypotheses found",
            )

        # 3b. Check every record has schema_version != 0
        for i, rec in enumerate(hypotheses):
            if rec.schema_version == 0:
                return M0GateResult.fail(
                    reason_codes="schema_version_missing",
                    detail=f"hypotheses[{i}] {rec.hypothesis_id}: schema_version is 0 (missing)",
                )
        for i, rec in enumerate(attempts):
            if rec.schema_version == 0:
                return M0GateResult.fail(
                    reason_codes="schema_version_missing",
                    detail=f"attempts[{i}] {rec.attempt_id}: schema_version is 0 (missing)",
                )
        for i, rec in enumerate(evidence_records):
            if rec.schema_version == 0:
                return M0GateResult.fail(
                    reason_codes="schema_version_missing",
                    detail=f"evidence_records[{i}] {rec.evidence_id}: schema_version is 0 (missing)",
                )
        for i, rec in enumerate(verdicts):
            if rec.schema_version == 0:
                return M0GateResult.fail(
                    reason_codes="schema_version_missing",
                    detail=f"verdicts[{i}] {rec.verdict_id}: schema_version is 0 (missing)",
                )
        for i, rec in enumerate(next_actions):
            if rec.schema_version == 0:
                return M0GateResult.fail(
                    reason_codes="schema_version_missing",
                    detail=f"next_actions[{i}] {rec.next_action_id}: schema_version is 0 (missing)",
                )

        # 4. Schema validation
        schema_errors = self._check_schema(hypotheses, attempts, evidence_records, verdicts, next_actions)
        if schema_errors:
            return M0GateResult.fail(
                reason_codes=self.SCHEMA_VALIDATION_FAILED,
                detail=f"Schema validation failed: {len(schema_errors)} error(s)",
                schema_errors=schema_errors,
            )

        # 5. ID traceability
        id_trace_errors = self._check_id_traceability(
            hypotheses, attempts, evidence_records, verdicts, next_actions
        )
        if id_trace_errors:
            return M0GateResult.fail(
                reason_codes=self.ID_TRACEABILITY_BROKEN,
                detail=f"ID traceability broken: {len(id_trace_errors)} error(s)",
                id_trace_errors=id_trace_errors,
            )

        # 6. Scope verdict presence
        scope_errors = self._check_scope_verdicts(attempts)
        if scope_errors:
            return M0GateResult.fail(
                reason_codes=self.SCOPE_VERDICT_MISSING,
                detail=f"Scope verdict missing: {len(scope_errors)} error(s)",
                scope_verdict_errors=scope_errors,
            )

        return M0GateResult.pass_()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_strict(
        raw_list: list,
        cls: type,
        errors: List[str],
        section_name: str,
    ) -> list:
        """Parse a list of dicts into record objects, collecting parse errors.

        Catches only TypeError, ValueError, KeyError — not broad Exception.
        Silently skips non-dict entries.
        """
        results = []
        for i, item in enumerate(raw_list):
            if not isinstance(item, dict):
                errors.append(
                    f"{section_name}[{i}]: expected dict, got {type(item).__name__}"
                )
                continue
            try:
                results.append(cls.from_dict(item))
            except (TypeError, ValueError, KeyError) as e:
                errors.append(
                    f"{section_name}[{i}]: {type(e).__name__}: {e}"
                )
        return results

    @staticmethod
    def _parse_strict_verdicts(
        raw_list: list,
        errors: List[str],
        section_name: str,
        *,
        evidence_dicts: Optional[list] = None,
        public_key_provider: Any = None,
    ) -> list:
        """Parse verdicts. Confirmed verdicts are restored ONLY via the
        canonical v2 restore path (Ed25519 public-key proof verification)
        or, for legacy ``hmac-sha256`` proofs, via the engine-side legacy
        verifier (fail-closed when the legacy key is unavailable).
        All other statuses use the public from_dict()."""
        results = []
        for i, item in enumerate(raw_list):
            if not isinstance(item, dict):
                errors.append(
                    f"{section_name}[{i}]: expected dict, got {type(item).__name__}"
                )
                continue
            try:
                if item.get("status") == "confirmed":
                    proof = str(item.get("validation_proof") or "")
                    if proof.startswith("hmac-sha256"):
                        from src.core.engine.vdp_legacy_proof_verifier import (
                            restore_legacy_confirmed_verdict,
                        )

                        results.append(restore_legacy_confirmed_verdict(item))
                    else:
                        from src.core.models.vdp_contract import (
                            default_public_key_provider,
                            restore_confirmed_from_dict,
                        )

                        provider = (
                            public_key_provider
                            if public_key_provider is not None
                            else default_public_key_provider()
                        )
                        results.append(
                            restore_confirmed_from_dict(
                                item,
                                list(evidence_dicts) if evidence_dicts else [],
                                public_key_provider=provider,
                            )
                        )
                else:
                    results.append(EvidenceVerdictV1.from_dict(item))
            except (TypeError, ValueError, KeyError) as e:
                errors.append(
                    f"{section_name}[{i}]: {type(e).__name__}: {e}"
                )
        return results

    @staticmethod
    def _validate_confirmations(
        verdicts: list,
        raw_verdicts: list,
        hypotheses: list,
        attempts: list,
        evidence_records: list,
    ) -> List[str]:
        """Validate confirmed verdicts against actual evidence/attempt/hypothesis records.

        Every confirmed verdict must have:
        - Non-empty evaluated_evidence_ids
        - All evidence IDs exist in parsed evidence_records
        - Each evidence's attempt links to the same hypothesis as the verdict
        - Non-empty validator_version
        """
        errors: List[str] = []
        hyp_ids = {h.hypothesis_id for h in hypotheses}
        ev_ids = {e.evidence_id: e for e in evidence_records}
        att_map = {a.attempt_id: a for a in attempts}

        for i, (verdict, raw) in enumerate(zip(verdicts, raw_verdicts)):
            if verdict.status != "confirmed":
                continue

            eids = verdict.evaluated_evidence_ids
            if not eids:
                errors.append(
                    f"verdict[{i}] {verdict.verdict_id}: confirmed with empty evaluated_evidence_ids"
                )
                continue

            for eid in eids:
                ev = ev_ids.get(eid)
                if ev is None:
                    errors.append(
                        f"verdict[{i}] {verdict.verdict_id}: evidence_id '{eid}' not found in evidence_records"
                    )
                    continue

                att = att_map.get(ev.attempt_id)
                if att is None:
                    errors.append(
                        f"verdict[{i}] {verdict.verdict_id}: evidence '{eid}' attempt '{ev.attempt_id}' not found"
                    )
                elif att.hypothesis_id != verdict.hypothesis_id:
                    errors.append(
                        f"verdict[{i}] {verdict.verdict_id}: evidence '{eid}' belongs to "
                        f"hypothesis '{att.hypothesis_id}', not verdict hypothesis '{verdict.hypothesis_id}'"
                    )

            if not verdict.validator_version or not verdict.validator_version.strip():
                errors.append(
                    f"verdict[{i}] {verdict.verdict_id}: confirmed with empty validator_version"
                )

        return errors

    @staticmethod
    def _check_schema(
        hypotheses: List[HypothesisRecord],
        attempts: List[AttemptRecord],
        evidence_records: List[EvidenceRecordV1],
        verdicts: List[EvidenceVerdictV1],
        next_actions: List[NextActionRecord],
    ) -> List[str]:
        errors: List[str] = []

        for i, rec in enumerate(hypotheses):
            errs = validate_hypothesis_record(rec)
            for e in errs:
                errors.append(f"hypothesis[{i}] {rec.hypothesis_id}: {e}")

        for i, rec in enumerate(attempts):
            errs = validate_attempt_record(rec)
            for e in errs:
                errors.append(f"attempt[{i}] {rec.attempt_id}: {e}")

        for i, rec in enumerate(evidence_records):
            errs = validate_evidence_record(rec)
            for e in errs:
                errors.append(f"evidence[{i}] {rec.evidence_id}: {e}")

        for i, rec in enumerate(verdicts):
            errs = validate_verdict_record(rec)
            for e in errs:
                errors.append(f"verdict[{i}] {rec.verdict_id}: {e}")

        for i, rec in enumerate(next_actions):
            errs = validate_next_action_record(rec)
            for e in errs:
                errors.append(f"next_action[{i}] {rec.next_action_id}: {e}")

        return errors

    @staticmethod
    def _check_id_traceability(
        hypotheses: List[HypothesisRecord],
        attempts: List[AttemptRecord],
        evidence_records: List[EvidenceRecordV1],
        verdicts: List[EvidenceVerdictV1],
        next_actions: List[NextActionRecord],
    ) -> List[str]:
        errors: List[str] = []
        hyp_ids = {h.hypothesis_id for h in hypotheses}

        # Attempt -> Hypothesis traceability
        for att in attempts:
            if att.hypothesis_id and att.hypothesis_id not in hyp_ids:
                errors.append(
                    f"attempt {att.attempt_id} references unknown hypothesis_id={att.hypothesis_id}"
                )

        # Evidence -> Attempt traceability
        att_ids = {a.attempt_id for a in attempts}
        for ev in evidence_records:
            if ev.attempt_id and ev.attempt_id not in att_ids:
                errors.append(
                    f"evidence {ev.evidence_id} references unknown attempt_id={ev.attempt_id}"
                )

        # Verdict -> Hypothesis traceability
        for ver in verdicts:
            if ver.hypothesis_id and ver.hypothesis_id not in hyp_ids:
                errors.append(
                    f"verdict {ver.verdict_id} references unknown hypothesis_id={ver.hypothesis_id}"
                )

        # NextAction -> Verdict traceability
        ver_ids = {v.verdict_id for v in verdicts}
        for na in next_actions:
            if na.verdict_id and na.verdict_id not in ver_ids:
                errors.append(
                    f"next_action {na.next_action_id} references unknown verdict_id={na.verdict_id}"
                )

        return errors

    @staticmethod
    def _check_scope_verdicts(attempts: List[AttemptRecord]) -> List[str]:
        errors: List[str] = []
        for att in attempts:
            if not att.scope_verdict or att.scope_verdict.strip() == "":
                errors.append(
                    f"attempt {att.attempt_id} missing scope_verdict"
                )
            elif att.scope_verdict not in (
                "allowed", "out_of_scope", "redirect_out_of_scope", "scope_revalidation_blocked"
            ):
                errors.append(
                    f"attempt {att.attempt_id} has invalid scope_verdict: {att.scope_verdict!r}"
                )
        return errors
