"""
Canonical Evidence Validator — SGK-2026-0422 (engine layer).

This module is the ONLY production signer boundary:

- It holds the Ed25519 PRIVATE signing key (dev/test boundary: explicit
  injection, ``SHIGOKU_VDP_SIGNING_KEY`` env, or ``~/.shigoku/vdp_signing.key``).
- It produces ``EvidenceVerdictV1`` records with ``status="confirmed"`` and a
  canonical v2 proof (``ed25519:v2:<key_id>:<base64url-signature>``).
- It computes evidence content hashes internally from EvidenceRecord dicts;
  caller-supplied hashes are never trusted.
- Reporting / gates / consistency / CLI never import this module and never
  hold the private key. They verify via
  ``src.core.models.vdp_contract.restore_confirmed_from_dict()`` with the
  public verification key only.

Legacy HMAC proofs are NOT handled here — see
``src/core/engine/vdp_legacy_proof_verifier.py`` (verification only, no
generation path).
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.core.models.vdp_contract import (
    VDP_CONTRACT_SCHEMA_VERSION,
    AttemptRecord,
    EvidenceRecordV1,
    EvidenceVerdictV1,
    HypothesisRecord,
    PROOF_ALGORITHM_ED25519,
    PROOF_SCHEMA_VERSION,
    build_confirmation_payload_dict,
    canonical_json_bytes,
)
from src.core.engine.vdp_diagnostic_trace import DiagnosticCollector
from src.core.engine.vdp_key_registry import (
    KeyRegistryError,
    KeyState,
    VdpKeyRegistry,
)

# Real (non-synthetic) evidence types that can support confirmation.
_REAL_EVIDENCE_TYPES = {
    "real_http_response",
    "timing_measurement",
    "browser_execution",
    "dns_lookup",
    "tls_observation",
    "api_observation",
    "out_of_band_callback",
}

# SGK-2026-0422 (audit I-07): required_evidence entries that are NOT concrete
# evidence types are gap/requirement tokens (e.g. the hypothesis generator's
# ``authz_impact_not_proven``). Each such token is satisfied ONLY by an
# explicit structured marker in an evidence record's ``execution_result`` —
# the mere existence of a real response never satisfies it. Unknown tokens
# are unsatisfied (fail-closed): the validator cannot prove what it cannot
# interpret.
_REQUIREMENT_MARKERS: Dict[str, str] = {
    "authz_impact_not_proven": "authz_impact_proven",
    "semantic_diff_owner_permission_sensitive_field": "semantic_diff_observed",
    "untested_no_second_account": "second_account_compared",
    "payload_request_mismatch": "request_fingerprint_matched",
    "state_change_not_verified": "state_change_verified",
    "state_change_readback": "state_change_readback_observed",
    "ssrf_proof_missing": "ssrf_proof_established",
    "unique_oob_callback": "unique_oob_callback_received",
    "insufficient_timing_validation": "timing_difference_observed",
}

VDP_EVIDENCE_VALIDATOR_VERSION = "vdp-evidence-validator-0.1.0"

# Reason codes reused from the public vocabulary (recipe_contracts sets A-E).
REASON_EVIDENCE_MISSING = "evidence_channel_lost"
REASON_SYNTHETIC_ONLY = "synthetic_response_evidence"
REASON_NO_REAL_RESPONSE = "insufficient_response_difference"
REASON_HYPOTHESIS_CONTRACT_INCOMPLETE = "budget_estimate_missing"  # contract gap
REASON_FALSIFICATION_MET = "falsification_condition_met"
REASON_SIGNER_UNAVAILABLE = "signer_unavailable_hold"
REASON_EVIDENCE_TYPE_MISMATCH = "required_evidence_type_not_met"
REASON_SUCCESS_CONDITION_NOT_PROVEN = "success_condition_not_proven"
REASON_EVIDENCE_CONTRACT_SATISFIED = "evidence_contract_satisfied"


class VdpEvidenceValidator:
    """Canonical Evidence Validator (engine layer, SGK-2026-0422).

    Sole authority for ``confirmed`` verdicts at engine time. Evaluates a
    hypothesis against its attempts and evidence records using the plan's
    evidence contract:

    - EvidenceRecord present with a REAL evidence type and non-empty raw_hash.
    - Attempt linkage: evidence.attempt_id must belong to the hypothesis.
    - Payload/request consistency: the attempt's request fingerprint is the
      recorded send (exact-replay executor already guarantees fingerprint
      match at send time).
    - Hypothesis contract: success_condition and falsification_condition are
      non-empty (evaluable), required_evidence is non-empty.
    - Refuted ONLY when an explicit falsification marker exists; timeout /
      auth loss / WAF / dependency stop / scope block / budget exhaustion are
      NEVER converted to refuted (candidate/untested with reason codes).
    - Confirmed only when all evidence requirements are satisfied; a single
      EvidenceRecord alone is NOT sufficient (hypothesis contract must be
      complete and the record must be a real response).
    - When the signer is unavailable, confirmed is NOT produced — the verdict
      stays candidate/untested and an operational Hold reason is recorded.
    """

    def __init__(
        self,
        signer: Optional["Ed25519EvidenceSigner"] = None,
        *,
        validator_version: str = VDP_EVIDENCE_VALIDATOR_VERSION,
        diagnostic_collector: Optional[DiagnosticCollector] = None,
    ) -> None:
        self._signer = signer
        self._validator_version = validator_version
        # SGK-2026-0425 M1: optional diagnostic telemetry collector (None
        # when diagnostics disabled → every emission is a no-op).
        self.diagnostic_collector = diagnostic_collector

    @property
    def signer(self) -> Optional["Ed25519EvidenceSigner"]:
        return self._signer

    @property
    def validator_version(self) -> str:
        return self._validator_version

    def public_key_provider(self) -> Optional[Dict[str, bytes]]:
        """Public-key-only provider for downstream verification, or None."""
        if self._signer is None:
            return None
        return self._signer.public_key_provider()

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        hypothesis: HypothesisRecord,
        attempts: List[AttemptRecord],
        evidence_records: List[EvidenceRecordV1],
        *,
        verdict_id: Optional[str] = None,
    ) -> EvidenceVerdictV1:
        """Evaluate one hypothesis → EvidenceVerdictV1 (confirmed only via
        the signer; otherwise candidate/refuted/untested).

        SGK-2026-0425 M1: emits the S11 diagnostic event AFTER the verdict
        is produced (read-only facts; the signing/proof boundaries are
        never touched). ``verdict_id`` may be supplied by the caller to
        reuse an existing verdict's ID (e.g. the 0420 shadow candidate ID)
        so the ID series and NextAction back-references stay intact when a
        candidate is replaced by a confirmed verdict. When omitted, a
        deterministic ``ver-<hypothesis_id>`` ID is used.
        """
        verdict = self._evaluate_impl(
            hypothesis, attempts, evidence_records, verdict_id=verdict_id
        )
        self._diag_emit_verdict(verdict)
        return verdict

    def _evaluate_impl(
        self,
        hypothesis: HypothesisRecord,
        attempts: List[AttemptRecord],
        evidence_records: List[EvidenceRecordV1],
        *,
        verdict_id: Optional[str] = None,
    ) -> EvidenceVerdictV1:
        """Evaluation core (verdict production only; see ``evaluate``)."""
        hypothesis_attempts = [
            a for a in attempts if a.hypothesis_id == hypothesis.hypothesis_id
        ]
        attempt_ids = {a.attempt_id for a in hypothesis_attempts}
        hypothesis_evidence = [
            e for e in evidence_records if e.attempt_id in attempt_ids
        ]

        verdict_id = verdict_id or f"ver-{hypothesis.hypothesis_id}"

        # --- Refuted: ONLY explicit falsification evidence (never timeout /
        # auth loss / WAF / dependency / scope / budget). ---
        falsified = [
            e
            for e in hypothesis_evidence
            if str((e.execution_result or {}).get("falsification_met", "")).lower()
            in {"true", "1", "yes"}
        ]
        if falsified:
            return self._verdict(
                verdict_id,
                hypothesis,
                status="refuted",
                reason_codes=[REASON_FALSIFICATION_MET],
            )

        # --- Untested: no evidence at all (dependency/channel gaps). ---
        if not hypothesis_evidence:
            return self._verdict(
                verdict_id,
                hypothesis,
                status="untested",
                reason_codes=[REASON_EVIDENCE_MISSING],
            )

        # --- Candidate: contract not evaluable or evidence not real. ---
        if not hypothesis.success_condition or not hypothesis.falsification_condition:
            return self._verdict(
                verdict_id,
                hypothesis,
                status="candidate",
                reason_codes=[REASON_HYPOTHESIS_CONTRACT_INCOMPLETE],
            )
        if not hypothesis.required_evidence:
            return self._verdict(
                verdict_id,
                hypothesis,
                status="candidate",
                reason_codes=[REASON_HYPOTHESIS_CONTRACT_INCOMPLETE],
            )

        real_evidence = [
            e for e in hypothesis_evidence if e.evidence_type in _REAL_EVIDENCE_TYPES
        ]
        if not real_evidence:
            return self._verdict(
                verdict_id,
                hypothesis,
                status="candidate",
                reason_codes=[REASON_NO_REAL_RESPONSE],
            )
        if any(not (e.raw_hash or "").strip() for e in real_evidence):
            return self._verdict(
                verdict_id,
                hypothesis,
                status="candidate",
                reason_codes=[REASON_NO_REAL_RESPONSE],
            )

        # SGK-2026-0422 (audit I-01): required_evidence must MATCH the real
        # evidence types — a real_http_response alone does not satisfy a
        # hypothesis that requires browser_execution.
        unsatisfied_required = self._unsatisfied_required_evidence(
            hypothesis, real_evidence
        )
        if unsatisfied_required:
            # Distinguish type gaps from success-condition proof gaps so the
            # report shows the honest reason (audit I-07).
            type_gaps = [
                token
                for token in unsatisfied_required
                if str(token or "").strip().lower() in _REAL_EVIDENCE_TYPES
            ]
            reason = (
                REASON_EVIDENCE_TYPE_MISMATCH
                if type_gaps
                else REASON_SUCCESS_CONDITION_NOT_PROVEN
            )
            return self._verdict(
                verdict_id,
                hypothesis,
                status="candidate",
                reason_codes=[reason],
            )

        # SGK-2026-0422 (audit I-07): the success condition is proven ONLY by
        # explicit structured markers (privilege difference, state change,
        # cross-account comparison, ...) — a raw response alone is never
        # enough, and the blanket ``success_condition_met`` field is no
        # longer accepted as proof.
        if not self._has_structured_success_marker(real_evidence):
            return self._verdict(
                verdict_id,
                hypothesis,
                status="candidate",
                reason_codes=[REASON_SUCCESS_CONDITION_NOT_PROVEN],
            )

        # --- Confirmed: only when the signer is available (fail-closed). ---
        if self._signer is None:
            return self._verdict(
                verdict_id,
                hypothesis,
                status="candidate",
                reason_codes=[REASON_SIGNER_UNAVAILABLE],
            )

        # The hypothesis must be at least "attempted" before a confirmed
        # transition is legal (observed -> hypothesized -> admitted ->
        # attempted -> candidate|confirmed|refuted|untested). Hypotheses
        # generated in 0420 start at "hypothesized"; the existence of saved
        # AttemptRecords means execution already happened. Walk the valid
        # path stepwise because the state machine only allows one hop per
        # transition (hypothesized -> admitted -> attempted).
        if hypothesis.state == "hypothesized":
            hypothesis.transition_to("admitted")
        if hypothesis.state == "admitted":
            hypothesis.transition_to("attempted")

        # Confirmed verdicts MUST carry a non-empty canonical reason code
        # (audit I-01 / completion D6: no unexplained confirmed).
        try:
            return self._signer.create_confirmed_verdict(
                verdict_id=verdict_id,
                hypothesis_id=hypothesis.hypothesis_id,
                reason_codes=[REASON_EVIDENCE_CONTRACT_SATISFIED],
                validator_version=self._validator_version,
                evidence_records=[e.to_dict() for e in real_evidence],
                hypothesis=hypothesis,
            )
        except KeyRegistryError:
            # SGK-2026-0423: the registered signing key is not ACTIVE
            # (rotated/revoked) — fail closed to candidate + Hold.
            return self._verdict(
                verdict_id,
                hypothesis,
                status="candidate",
                reason_codes=[REASON_SIGNER_UNAVAILABLE, "signing_key_not_active"],
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _unsatisfied_required_evidence(
        hypothesis: HypothesisRecord,
        real_evidence: List[EvidenceRecordV1],
    ) -> List[str]:
        """Return required_evidence entries that are NOT satisfied.

        Each required_evidence entry is matched against the evidence records:
        - An entry that names a concrete evidence type (e.g.
          ``browser_execution``, ``real_http_response``) MUST be matched by a
          real evidence record of that type — a real_http_response does NOT
          satisfy a hypothesis requiring browser_execution (audit I-01).
        - An entry that is a gap/requirement token (e.g.
          ``authz_impact_not_proven``) MUST be satisfied by the structured
          marker mapped in ``_REQUIREMENT_MARKERS`` being truthy in at least
          one real evidence record's ``execution_result``. The mere
          existence of a real response NEVER satisfies a gap token (audit
          I-07: production 200 responses must not be promoted).
        - Unknown tokens are unsatisfied (fail-closed).
        """
        real_types = {e.evidence_type for e in real_evidence}
        marker_keys = set()
        for evidence in real_evidence:
            result = evidence.execution_result or {}
            for key, value in result.items():
                if str(value).lower() in {"true", "1", "yes"}:
                    marker_keys.add(key)
        unsatisfied: List[str] = []
        for required in (hypothesis.required_evidence or []):
            token = str(required or "").strip().lower()
            if not token:
                continue
            if token in _REAL_EVIDENCE_TYPES:
                if token not in real_types:
                    unsatisfied.append(required)
                continue
            required_marker = _REQUIREMENT_MARKERS.get(token)
            if required_marker is None or required_marker not in marker_keys:
                unsatisfied.append(required)
        return unsatisfied

    @staticmethod
    def _has_structured_success_marker(real_evidence: List[EvidenceRecordV1]) -> bool:
        """True when at least one real evidence record carries a truthy
        structured success marker (any of the ``_REQUIREMENT_MARKERS``
        vocabulary). The blanket ``execution_result.success_condition_met``
        field is NOT part of this vocabulary and is never accepted as proof
        (audit I-07)."""
        marker_vocabulary = set(_REQUIREMENT_MARKERS.values())
        for evidence in real_evidence:
            result = evidence.execution_result or {}
            for key, value in result.items():
                if key in marker_vocabulary and str(value).lower() in {"true", "1", "yes"}:
                    return True
        return False

    # ------------------------------------------------------------------
    # Diagnostic telemetry (SGK-2026-0425 M1, additive)
    # ------------------------------------------------------------------

    def _diag_emit(
        self,
        *,
        stage_id: str,
        outcome: str,
        reason_codes: Tuple[str, ...] = (),
        source_refs: Tuple[str, ...] = (),
    ) -> None:
        """Emit one diagnostic event (no-op without a collector).

        Hook exceptions NEVER break evaluation: the failure is recorded on
        the collector (fail-closed kill-switch signal) and the verdict is
        still returned. Events carry no secrets — vocabulary codes and
        source references only.
        """
        collector = self.diagnostic_collector
        if collector is None:
            return
        try:
            collector.emit(
                stage_id=stage_id,
                outcome=outcome,
                reason_codes=tuple(reason_codes or ()),
                source_refs=tuple(source_refs or ()),
                producer_id="vdp_evidence_validator",
            )
        except Exception as exc:
            collector.mark_hook_failed(f"{type(exc).__name__}: {exc}"[:200])

    def _diag_emit_verdict(self, verdict: EvidenceVerdictV1) -> None:
        """Emit the single S11 event from a produced verdict.

        Normal verdicts (candidate/confirmed/refuted/untested) emit S11
        reached with the status in source_refs; the two operational hold
        paths emit S11 blocked with the precise cause:
        - signer unavailable (the proof boundary could not be reached)
          → dependency_unavailable;
        - KeyRegistryError (the registered key was rotated/revoked, the
          proof cannot be produced) → proof_unverifiable.
        """
        if self.diagnostic_collector is None:
            return
        codes = set(verdict.reason_codes or [])
        if "signing_key_not_active" in codes:
            self._diag_emit(
                stage_id="S11", outcome="blocked",
                reason_codes=("proof_unverifiable",),
                source_refs=("signing_key_not_active",),
            )
        elif REASON_SIGNER_UNAVAILABLE in codes:
            self._diag_emit(
                stage_id="S11", outcome="blocked",
                reason_codes=("dependency_unavailable",),
                source_refs=("signer_unavailable",),
            )
        else:
            self._diag_emit(
                stage_id="S11", outcome="reached",
                source_refs=(f"status={verdict.status}",),
            )

    def _verdict(
        self,
        verdict_id: str,
        hypothesis: HypothesisRecord,
        *,
        status: str,
        reason_codes: List[str],
    ) -> EvidenceVerdictV1:
        return EvidenceVerdictV1(
            verdict_id=verdict_id,
            hypothesis_id=hypothesis.hypothesis_id,
            _status=status,
            reason_codes=list(reason_codes),
            evaluated_evidence_ids=[],
            validator_version=self._validator_version,
            schema_version=VDP_CONTRACT_SCHEMA_VERSION,
        )

_SIGNING_KEY_ENV = "SHIGOKU_VDP_SIGNING_KEY"
_SIGNING_KEY_FILE = Path.home() / ".shigoku" / "vdp_signing.key"


def resolve_signing_key() -> Optional[bytes]:
    """Resolve the dev/test Ed25519 private key (32 bytes).

    Sources (priority order):
      1. SHIGOKU_VDP_SIGNING_KEY env (hex, 64 chars)
      2. ~/.shigoku/vdp_signing.key file (hex, 64 chars)

    Returns None when unavailable → fail-closed: no confirmed verdicts are
    produced (the caller records candidate/untested + operational Hold).
    """
    env_val = os.environ.get(_SIGNING_KEY_ENV)
    if env_val:
        try:
            raw = env_val.strip()
            if len(raw) != 64:
                return None
            return bytes.fromhex(raw)
        except ValueError:
            return None
    try:
        if _SIGNING_KEY_FILE.exists():
            raw = _SIGNING_KEY_FILE.read_text(encoding="utf-8").strip()
            if len(raw) != 64:
                return None
            return bytes.fromhex(raw)
    except (OSError, ValueError):
        return None
    return None


def default_signer() -> Optional["Ed25519EvidenceSigner"]:
    """Return a signer from the dev/test key sources, or None (fail-closed)."""
    private_key = resolve_signing_key()
    if private_key is None:
        return None
    return Ed25519EvidenceSigner(private_key=private_key)


class Ed25519EvidenceSigner:
    """Ed25519 signer for canonical confirmed verdicts.

    Construction is explicit: ``private_key`` is the raw 32-byte seed and
    ``key_id`` defaults to ``sha256(public_key)[:16]`` (deterministic, and
    identical to what verifiers derive from the public key).
    """

    def __init__(
        self,
        private_key: bytes,
        key_id: Optional[str] = None,
        *,
        registry: Optional[VdpKeyRegistry] = None,
    ) -> None:
        if not isinstance(private_key, (bytes, bytearray)) or len(private_key) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 bytes")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self._private_key = Ed25519PrivateKey.from_private_bytes(bytes(private_key))
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        self._public_key = self._private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self._key_id = key_id or hashlib.sha256(self._public_key).hexdigest()[:16]
        # SGK-2026-0423: optional versioned key registry (public keys only).
        # When attached, signing requires the key to be ACTIVE and the
        # public-key provider is derived from the registry.
        self._registry = registry

    @property
    def key_id(self) -> str:
        return self._key_id

    def public_key_bytes(self) -> bytes:
        """Raw 32-byte Ed25519 public key (safe to share with verifiers)."""
        return self._public_key

    def public_key_provider(self) -> Dict[str, bytes]:
        """Public-key-only provider dict for verifiers: {key_id: pub_bytes}.

        When a key registry is attached, the provider is derived from the
        registry (ACTIVE + in-expiry VERIFY_ONLY keys only); otherwise the
        signer's own key is offered (legacy dev behavior).
        """
        if self._registry is not None:
            return self._registry.public_key_provider()
        return {self._key_id: self._public_key}

    def create_confirmed_verdict(
        self,
        *,
        verdict_id: str,
        hypothesis_id: str,
        reason_codes: List[str],
        validator_version: str,
        evidence_records: List[Dict[str, Any]],
        hypothesis: Optional[HypothesisRecord] = None,
    ) -> EvidenceVerdictV1:
        """Create a confirmed verdict with a canonical v2 Ed25519 proof.

        Evidence content hashes are computed INTERNALLY from the evidence
        record dicts (via ``build_confirmation_payload_dict``) — caller-
        supplied hashes are never trusted. ``status`` is hard-coded to
        "confirmed"; callers cannot request a different status or pass an
        arbitrary validator name.
        """
        # SGK-2026-0423: when a key registry is attached, the signing key
        # MUST be in ACTIVE state (rotated/revoked keys fail closed).
        if self._registry is not None:
            state = self._registry.get_state(self._key_id)
            if state != KeyState.ACTIVE:
                raise KeyRegistryError("signing_key_not_active")
        if not evidence_records:
            raise ValueError("evidence_records must be non-empty for confirmed status")
        if not validator_version or not validator_version.strip():
            raise ValueError("validator_version must be non-empty for confirmed status")
        if not reason_codes:
            # D6: no unexplained confirmed — every confirmed verdict MUST
            # carry a non-empty canonical reason code (audit I-01).
            raise ValueError(
                "reason_codes must be non-empty for confirmed status "
                "(use the canonical evidence_contract_satisfied code)"
            )

        payload = build_confirmation_payload_dict(
            proof_schema_version=PROOF_SCHEMA_VERSION,
            algorithm=PROOF_ALGORITHM_ED25519,
            key_id=self._key_id,
            verdict_id=verdict_id,
            hypothesis_id=hypothesis_id,
            status="confirmed",
            reason_codes=list(reason_codes or []),
            validator_version=validator_version,
            evidence_records=evidence_records,
        )
        signature = self._private_key.sign(canonical_json_bytes(payload))

        import base64 as _base64

        # Canonical proof format fixed by the plan §4.4.1: three parts
        # ed25519:<key_id>:<base64url-signature> (no version segment — the
        # proof schema version lives inside the signed payload AND in the
        # verdict's proof_schema_version field).
        proof = (
            f"ed25519:{self._key_id}:"
            f"{_base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')}"
        )

        evidence_content_sha256 = {
            str(entry["evidence_id"]): str(entry["content_hash"])
            for entry in payload["evidence"]
        }

        verdict = EvidenceVerdictV1(
            verdict_id=verdict_id,
            hypothesis_id=hypothesis_id,
            _status="candidate",  # bypass __post_init__ rejection
            reason_codes=list(reason_codes or []),
            evaluated_evidence_ids=list(evidence_content_sha256.keys()),
            validator_version=validator_version,
            validation_proof=proof,
            schema_version=VDP_CONTRACT_SCHEMA_VERSION,
            proof_schema_version=PROOF_SCHEMA_VERSION,
            proof_key_id=self._key_id,
            evidence_content_sha256=evidence_content_sha256,
        )
        object.__setattr__(verdict, "_status", "confirmed")

        if hypothesis is not None:
            hypothesis._set_confirmed_by_verdict()

        return verdict
