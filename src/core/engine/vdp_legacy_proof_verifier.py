"""
Legacy HMAC proof verifier — SGK-2026-0422 (engine layer, verification ONLY).

Reads legacy ``hmac-sha256:<key_id>:<tag>`` proofs from pre-0422 sessions.
This module never GENERATES new HMAC proofs; it only verifies the legacy
format so old artifacts can be read explicitly as ``legacy``.

Fail-closed contract:
- No legacy verification key available → ``legacy_proof_unverifiable`` and
  the confirmed verdict is NOT restored (never silently kept as confirmed,
  never silently converted to candidate).
- Key changed / tag mismatch / malformed proof → same fail-closed outcome
  with a compatibility/tamper reason.

Reporting / gates / CLI must NOT import this module (it is engine-layer).
They receive verification RESULTS only; the HMAC secret never leaves this
module's key resolution.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.models.vdp_contract import (
    EvidenceVerdictV1,
    LEGACY_HMAC_PREFIX,
)

_CONFIRMATION_KEY_ENV = "SHIGOKU_VDP_CONFIRMATION_KEY"
_CONFIRMATION_KEY_FILE = Path.home() / ".shigoku" / "vdp_confirmation.key"


def resolve_legacy_confirmation_key() -> Optional[bytes]:
    """Resolve the legacy stable HMAC key. Returns None if unavailable."""
    env_val = os.environ.get(_CONFIRMATION_KEY_ENV)
    if env_val:
        try:
            raw = env_val.strip()
            if len(raw) != 64:
                return None
            return bytes.fromhex(raw)
        except ValueError:
            return None
    try:
        if _CONFIRMATION_KEY_FILE.exists():
            raw = _CONFIRMATION_KEY_FILE.read_text(encoding="utf-8").strip()
            if len(raw) != 64:
                return None
            return bytes.fromhex(raw)
    except (OSError, ValueError):
        return None
    return None


def _current_legacy_key_id() -> str:
    key = resolve_legacy_confirmation_key()
    if key is None:
        return "unavailable"
    return hashlib.sha256(key).hexdigest()[:8]


def _compute_legacy_tag(
    verdict_id: str,
    hypothesis_id: str,
    evidence_ids: List[str],
    validator_version: str,
    key: bytes,
) -> str:
    """Recompute the FULL legacy proof string for comparison (verify only).

    Mirrors the pre-0422 signer output ``hmac-sha256:<key_id>:<tag>`` so
    ``hmac.compare_digest(expected, proof)`` compares like-for-like.
    """
    payload = "|".join(
        [
            verdict_id,
            hypothesis_id,
            ",".join(sorted(evidence_ids)),
            validator_version,
        ]
    )
    tag = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    key_id = hashlib.sha256(key).hexdigest()[:8]
    return f"{LEGACY_HMAC_PREFIX}:{key_id}:{tag}"


def verify_legacy_proof(
    verdict_id: str,
    hypothesis_id: str,
    evidence_ids: List[str],
    validator_version: str,
    proof: str,
) -> Dict[str, Any]:
    """Verify a legacy HMAC proof. Returns a result dict (never raises).

    Result keys: ``verified`` (bool), ``reason_code`` (str),
    ``detail`` (str). Reason codes:
    - ``legacy_proof_unverifiable`` — no legacy key available.
    - ``legacy_proof_malformed`` — not hmac-sha256 / wrong part count.
    - ``legacy_proof_key_changed`` — key_id mismatch.
    - ``legacy_proof_tampered`` — tag mismatch.
    - ``legacy_proof_verified`` — legacy proof accepted (compat).
    """
    if not proof:
        return {
            "verified": False,
            "reason_code": "legacy_proof_unverifiable",
            "detail": "legacy proof missing",
        }
    parts = proof.split(":")
    if len(parts) != 3 or parts[0] != LEGACY_HMAC_PREFIX:
        return {
            "verified": False,
            "reason_code": "legacy_proof_malformed",
            "detail": f"proof format is not {LEGACY_HMAC_PREFIX}:<key_id>:<tag>",
        }
    key = resolve_legacy_confirmation_key()
    if key is None:
        return {
            "verified": False,
            "reason_code": "legacy_proof_unverifiable",
            "detail": "legacy confirmation key unavailable "
            "(set SHIGOKU_VDP_CONFIRMATION_KEY or create "
            "~/.shigoku/vdp_confirmation.key)",
        }
    if parts[1] != _current_legacy_key_id():
        return {
            "verified": False,
            "reason_code": "legacy_proof_key_changed",
            "detail": "legacy key_id mismatch: confirmation key changed since signing",
        }
    expected = _compute_legacy_tag(
        verdict_id, hypothesis_id, evidence_ids, validator_version, key
    )
    if not hmac.compare_digest(expected, proof):
        return {
            "verified": False,
            "reason_code": "legacy_proof_tampered",
            "detail": "legacy tag mismatch — data was not produced by the legacy signer",
        }
    return {
        "verified": True,
        "reason_code": "legacy_proof_verified",
        "detail": "legacy HMAC proof accepted (compatibility mode)",
    }


def restore_legacy_confirmed_verdict(d: Dict[str, Any]) -> EvidenceVerdictV1:
    """Restore a confirmed verdict guarded by a legacy HMAC proof.

    Raises ValueError with the reason code when the legacy proof cannot be
    verified (fail-closed). Only used for pre-0422 artifacts; this path never
    produces a new proof.
    """
    raw_status = d.get("status", "untested")
    if raw_status != "confirmed":
        return EvidenceVerdictV1.from_dict(d)

    evidence_ids = [str(e) for e in (d.get("evaluated_evidence_ids") or [])]
    validator_version = str(d.get("validator_version") or "")
    proof = str(d.get("validation_proof") or "")

    if not evidence_ids:
        raise ValueError("legacy confirmed verdict requires non-empty evaluated_evidence_ids")
    if not validator_version or not validator_version.strip():
        raise ValueError("legacy confirmed verdict requires non-empty validator_version")

    result = verify_legacy_proof(
        str(d.get("verdict_id") or ""),
        str(d.get("hypothesis_id") or ""),
        evidence_ids,
        validator_version,
        proof,
    )
    if not result["verified"]:
        raise ValueError(
            f"legacy confirmed verdict {d.get('verdict_id', 'unknown')} cannot be "
            f"restored: {result['reason_code']}: {result['detail']}"
        )

    instance = EvidenceVerdictV1(
        schema_version=d.get("schema_version", 0),
        verdict_id=d.get("verdict_id", ""),
        hypothesis_id=d.get("hypothesis_id", ""),
        _status="candidate",
        reason_codes=list(d.get("reason_codes", [])),
        evaluated_evidence_ids=evidence_ids,
        validator_version=validator_version,
        validation_proof=proof,
        notes=list(d.get("notes", [])),
        proof_schema_version="",
        proof_key_id="",
        evidence_content_sha256={},
    )
    object.__setattr__(instance, "_status", "confirmed")
    return instance
