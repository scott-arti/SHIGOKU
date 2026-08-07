"""
SGK-2026-0422 — canonical proof v2 (Ed25519) tests.

Covers the plan §4.4 / §4.4.1 byte spec and §7 required proof tests:
- canonical payload determinism (delimiter IDs, Unicode, array order, type
  differences must not collide)
- duplicate evidence_id rejection
- evidence body / raw_hash / reason code / status / validator version
  tamper detection
- missing proof / unknown proof schema version / unknown key ID / garbage
  signature rejection
- evaluated_evidence_ids <-> evidence_content_sha256 key-set equality
  (missing and extra EvidenceRecord both fail)
- signer boundary: no arbitrary validator-name API, no public verifier
  signing, no private-key material in serialized output
- cross-process restore using only the public verification key
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from src.core.models.vdp_contract import (
    VDP_CONTRACT_SCHEMA_VERSION,
    EvidenceRecordV1,
    EvidenceVerdictV1,
    HypothesisRecord,
    canonical_json_bytes,
    canonical_evidence_content_hash,
    verify_confirmed_verdict,
    restore_confirmed_from_dict,
    build_confirmation_payload_dict,
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    PublicFormat,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_keypair(seed: bytes | None = None) -> tuple[Ed25519PrivateKey, bytes, bytes, str]:
    """Return (priv, priv_raw, pub_raw, key_id)."""
    if seed is not None:
        priv = Ed25519PrivateKey.from_private_bytes(seed)
    else:
        priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = hashlib.sha256(pub_raw).hexdigest()[:16]
    return priv, priv_raw, pub_raw, key_id


def _evidence_dict(
    evidence_id: str = "ev-001",
    *,
    raw_hash: str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    excerpt: str = "HTTP/1.1 200 OK\n\n{\"ok\":true}",
    evidence_type: str = "real_http_response",
    attempt_id: str = "att-001",
) -> dict:
    return EvidenceRecordV1(
        evidence_id=evidence_id,
        attempt_id=attempt_id,
        evidence_type=evidence_type,
        raw_hash=raw_hash,
        redacted_excerpt=excerpt,
        normalization_rule_version="v1",
        auth_context_version="none",
        captured_at="2026-08-03T00:00:00Z",
        original_size=len(excerpt.encode("utf-8")),
        truncated=False,
        truncation_reason="",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
    ).to_dict()


def _hypothesis(hypothesis_id: str = "hyp-001") -> HypothesisRecord:
    return HypothesisRecord(
        hypothesis_id=hypothesis_id,
        observation_id="obs-001",
        asset="https://example.com/",
        capability="test",
        hypothesis_text="test",
        trust_boundary="b",
        actors=["unauth"],
        success_condition="s",
        falsification_condition="f",
        required_evidence=["real_http_response"],
        state="attempted",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
    )


def _sign_verdict(
    priv_raw: bytes,
    key_id: str,
    *,
    verdict_id: str = "ver-001",
    hypothesis_id: str = "hyp-001",
    reason_codes: list[str] | None = None,
    validator_version: str = "vdp-evidence-validator-0.1.0",
    evidence_records: list[dict] | None = None,
    status: str = "confirmed",
) -> dict:
    """Produce a serialized confirmed verdict dict via the real signer path.

    Uses src.core.engine.vdp_evidence_validator.Ed25519EvidenceSigner — the
    canonical signer boundary — so tests exercise the production signer.
    Confirmed verdicts require a non-empty canonical reason code (D6).
    """
    from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner

    signer = Ed25519EvidenceSigner(private_key=priv_raw, key_id=key_id)
    verdict = signer.create_confirmed_verdict(
        verdict_id=verdict_id,
        hypothesis_id=hypothesis_id,
        reason_codes=list(reason_codes or ["evidence_contract_satisfied"]),
        validator_version=validator_version,
        evidence_records=list(evidence_records or [_evidence_dict()]),
        hypothesis=_hypothesis(hypothesis_id),
    )
    d = verdict.to_dict()
    if status != "confirmed":
        d["status"] = status
    return d


# ---------------------------------------------------------------------------
# Canonical payload determinism
# ---------------------------------------------------------------------------


class TestCanonicalPayloadDeterminism:
    def test_delimiter_ids_do_not_collide(self):
        """IDs containing '|' must not collide with structurally different ones."""
        ev_a = _evidence_dict("a|b")
        ev_b = _evidence_dict("a", raw_hash="b")
        payload_a = build_confirmation_payload_dict(
            proof_schema_version="2",
            algorithm="ed25519",
            key_id="k1",
            verdict_id="v1",
            hypothesis_id="h1",
            status="confirmed",
            reason_codes=["a", "b"],
            validator_version="1.0.0",
            evidence_records=[ev_a],
        )
        payload_b = build_confirmation_payload_dict(
            proof_schema_version="2",
            algorithm="ed25519",
            key_id="k1",
            verdict_id="v1",
            hypothesis_id="h1",
            status="confirmed",
            reason_codes=["a", "b"],
            validator_version="1.0.0",
            evidence_records=[ev_b],
        )
        assert canonical_json_bytes(payload_a) != canonical_json_bytes(payload_b)

    def test_unicode_and_type_differences_do_not_collide(self):
        ev_unicode = _evidence_dict("ev-ｕ", excerpt="日本語エビデンス|区切り")
        ev_ascii = _evidence_dict("ev-u", excerpt="日本語エビデンス/区切り")
        p1 = build_confirmation_payload_dict(
            "2", "ed25519", "k1", "v1", "h1", "confirmed", ["a"], "1.0.0", [ev_unicode]
        )
        p2 = build_confirmation_payload_dict(
            "2", "ed25519", "k1", "v1", "h1", "confirmed", ["a"], "1.0.0", [ev_ascii]
        )
        assert canonical_json_bytes(p1) != canonical_json_bytes(p2)

    def test_array_order_normalized_deterministically(self):
        ev1 = _evidence_dict("ev-a")
        ev2 = _evidence_dict("ev-b")
        kwargs = dict(
            proof_schema_version="2",
            algorithm="ed25519",
            key_id="k1",
            verdict_id="v1",
            hypothesis_id="h1",
            status="confirmed",
            reason_codes=["b", "a"],  # intentionally unsorted
            validator_version="1.0.0",
        )
        p_ab = build_confirmation_payload_dict(**kwargs, evidence_records=[ev1, ev2])
        p_ba = build_confirmation_payload_dict(**kwargs, evidence_records=[ev2, ev1])
        assert canonical_json_bytes(p_ab) == canonical_json_bytes(p_ba)
        assert p_ab["reason_codes"] == ["a", "b"]

    def test_identical_inputs_produce_identical_bytes(self):
        ev = _evidence_dict()
        kwargs = dict(
            proof_schema_version="2",
            algorithm="ed25519",
            key_id="k1",
            verdict_id="v1",
            hypothesis_id="h1",
            status="confirmed",
            reason_codes=["a"],
            validator_version="1.0.0",
            evidence_records=[ev],
        )
        assert canonical_json_bytes(
            build_confirmation_payload_dict(**kwargs)
        ) == canonical_json_bytes(build_confirmation_payload_dict(**kwargs))

    def test_duplicate_evidence_id_rejected(self):
        ev = _evidence_dict("ev-dup")
        with pytest.raises(ValueError, match="duplicate"):
            build_confirmation_payload_dict(
                proof_schema_version="2",
                algorithm="ed25519",
                key_id="k1",
                verdict_id="v1",
                hypothesis_id="h1",
                status="confirmed",
                reason_codes=[],
                validator_version="1.0.0",
                evidence_records=[ev, dict(ev)],
            )

    def test_content_hash_covers_full_record(self):
        ev = _evidence_dict("ev-hash")
        h = canonical_evidence_content_hash(ev)
        assert h.startswith("sha256:")
        # Redacting the excerpt must change the hash (body protection).
        tampered = dict(ev)
        tampered["redacted_excerpt"] = "HTTP/1.1 200 OK\n\n{\"ok\":false}"
        assert canonical_evidence_content_hash(tampered) != h


# ---------------------------------------------------------------------------
# Sign / verify roundtrip (production signer boundary)
# ---------------------------------------------------------------------------


class TestSignVerifyRoundtrip:
    def test_signed_confirmed_verdict_restores_with_public_key(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        verdict_dict = _sign_verdict(priv_raw, key_id)
        result = verify_confirmed_verdict(
            verdict_dict,
            [_evidence_dict()],
            public_key_provider={key_id: pub_raw},
        )
        assert result.verified is True
        assert result.reason_code == "verified"

    def test_restore_confirmed_returns_frozen_verdict(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        verdict_dict = _sign_verdict(priv_raw, key_id)
        restored = restore_confirmed_from_dict(
            verdict_dict,
            [_evidence_dict()],
            public_key_provider={key_id: pub_raw},
        )
        assert isinstance(restored, EvidenceVerdictV1)
        assert restored.status == "confirmed"
        assert restored.verdict_id == "ver-001"
        assert restored.validation_proof.startswith("ed25519:")
        # Verdict metadata must be populated for proof version/key checks.
        assert restored.proof_schema_version == "v2"
        assert restored.proof_key_id == key_id

    def test_proof_format_ed25519_key_id_base64url(self):
        """Canonical proof format is fixed as ed25519:<key_id>:<base64url>
        (3 parts, plan §4.4.1) — no version segment in the token."""
        _, priv_raw, pub_raw, key_id = _make_keypair()
        verdict_dict = _sign_verdict(priv_raw, key_id)
        parts = verdict_dict["validation_proof"].split(":")
        assert parts[0] == "ed25519"
        assert parts[1] == key_id
        # Signature part: base64url without padding, 64 bytes decoded.
        sig = parts[2]
        assert len(parts) == 3
        assert "=" not in sig
        assert len(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))) == 64

    def test_private_key_never_in_serialized_output(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        verdict_dict = _sign_verdict(priv_raw, key_id)
        blob = json.dumps(verdict_dict, ensure_ascii=False)
        assert base64.b64encode(priv_raw).decode() not in blob
        assert priv_raw.hex() not in blob
        # Full session-like payload also clean.
        session = {"vdp_contract": {"verdicts": [verdict_dict]}}
        assert priv_raw.hex() not in json.dumps(session)


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


class TestTamperDetection:
    def _verify(self, verdict_dict, evidence_records, key_id, pub_raw):
        return verify_confirmed_verdict(
            verdict_dict, evidence_records, public_key_provider={key_id: pub_raw}
        )

    def test_evidence_body_tamper_fails(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id)
        ev = _evidence_dict()
        ev["redacted_excerpt"] = "HTTP/1.1 200 OK\n\n{\"ok\":false}"  # body change
        result = self._verify(v, [ev], key_id, pub_raw)
        assert result.verified is False
        assert "tamper" in result.reason_code or "hash" in result.reason_code

    def test_evidence_raw_hash_tamper_fails(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id)
        ev = _evidence_dict()
        ev["raw_hash"] = "sha256:" + "b" * 64
        result = self._verify(v, [ev], key_id, pub_raw)
        assert result.verified is False

    def test_evidence_type_tamper_fails(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id)
        ev = _evidence_dict()
        ev["evidence_type"] = "timing_measurement"
        result = self._verify(v, [ev], key_id, pub_raw)
        assert result.verified is False

    def test_reason_code_tamper_fails(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id, reason_codes=["payload_request_mismatch"])
        v["reason_codes"] = []  # attacker removes the gap
        result = self._verify(v, [_evidence_dict()], key_id, pub_raw)
        assert result.verified is False

    def test_validator_version_tamper_fails(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id)
        v["validator_version"] = "attacker-version"
        result = self._verify(v, [_evidence_dict()], key_id, pub_raw)
        assert result.verified is False

    def test_status_tamper_fails(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id)
        v["status"] = "candidate"
        result = self._verify(v, [_evidence_dict()], key_id, pub_raw)
        assert result.verified is False

    def test_evidence_content_sha256_tamper_fails(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id)
        v["evidence_content_sha256"]["ev-001"] = "sha256:" + "c" * 64
        result = self._verify(v, [_evidence_dict()], key_id, pub_raw)
        assert result.verified is False


# ---------------------------------------------------------------------------
# Proof / key failures (fail-closed)
# ---------------------------------------------------------------------------


class TestProofFailClosed:
    def test_missing_proof_fails(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id)
        v["validation_proof"] = ""
        result = verify_confirmed_verdict(
            v, [_evidence_dict()], public_key_provider={key_id: pub_raw}
        )
        assert result.verified is False
        assert "proof" in result.reason_code

    def test_unknown_proof_schema_version_fails(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id)
        # 4-part token (ed25519:<key>:<sig>:extra) is not the canonical
        # 3-part form → unknown_proof_version.
        v["validation_proof"] = "ed25519:" + key_id + ":AA:extra"
        result = verify_confirmed_verdict(
            v, [_evidence_dict()], public_key_provider={key_id: pub_raw}
        )
        assert result.verified is False
        assert "version" in result.reason_code

    def test_verdict_proof_schema_version_mismatch_fails(self):
        """Tampering the verdict's proof_schema_version field must fail even
        when the token and signature are intact (audit I-02)."""
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id)
        v["proof_schema_version"] = "v99"
        result = verify_confirmed_verdict(
            v, [_evidence_dict()], public_key_provider={key_id: pub_raw}
        )
        assert result.verified is False
        assert result.reason_code == "proof_schema_version_mismatch"

    def test_verdict_proof_key_id_mismatch_fails(self):
        """Tampering the verdict's proof_key_id field must fail even when the
        token and signature are intact (audit I-02)."""
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id)
        v["proof_key_id"] = "deadbeef" * 2  # different key_id
        result = verify_confirmed_verdict(
            v, [_evidence_dict()], public_key_provider={key_id: pub_raw}
        )
        assert result.verified is False
        assert result.reason_code == "proof_key_id_mismatch"

    def test_unknown_key_id_fails(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id)
        result = verify_confirmed_verdict(
            v, [_evidence_dict()], public_key_provider={}
        )
        assert result.verified is False
        assert "key" in result.reason_code

    def test_garbage_signature_fails(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id)
        parts = v["validation_proof"].split(":")
        parts[2] = base64.urlsafe_b64encode(b"x" * 64).decode().rstrip("=")
        v["validation_proof"] = ":".join(parts)
        result = verify_confirmed_verdict(
            v, [_evidence_dict()], public_key_provider={key_id: pub_raw}
        )
        assert result.verified is False
        assert "signature" in result.reason_code or "tamper" in result.reason_code

    def test_key_unavailable_fails_closed(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id)
        result = verify_confirmed_verdict(
            v, [_evidence_dict()], public_key_provider=None
        )
        assert result.verified is False
        assert result.reason_code == "key_unavailable"

    def test_missing_evidence_record_fails(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id, evidence_records=[_evidence_dict("ev-001")])
        # evaluated_evidence_ids=["ev-001"], hash map has ev-001, but no record supplied
        result = verify_confirmed_verdict(
            v, [], public_key_provider={key_id: pub_raw}
        )
        assert result.verified is False
        assert "evidence" in result.reason_code

    def test_extra_evidence_record_fails(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id, evidence_records=[_evidence_dict("ev-001")])
        result = verify_confirmed_verdict(
            v,
            [_evidence_dict("ev-001"), _evidence_dict("ev-999")],
            public_key_provider={key_id: pub_raw},
        )
        assert result.verified is False
        assert "evidence" in result.reason_code

    def test_evaluated_evidence_ids_hash_key_set_mismatch_fails(self):
        _, priv_raw, pub_raw, key_id = _make_keypair()
        v = _sign_verdict(priv_raw, key_id)
        # attacker adds a hash-map entry without re-signing
        v["evidence_content_sha256"]["ev-extra"] = "sha256:" + "d" * 64
        result = verify_confirmed_verdict(
            v, [_evidence_dict()], public_key_provider={key_id: pub_raw}
        )
        assert result.verified is False


# ---------------------------------------------------------------------------
# Signer boundary
# ---------------------------------------------------------------------------


class TestSignerBoundary:
    def test_no_arbitrary_validator_name_api(self):
        """The signer must not accept a caller-supplied validator name."""
        import inspect

        from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
        sig = inspect.signature(Ed25519EvidenceSigner.create_confirmed_verdict)
        params = list(sig.parameters)
        for forbidden in ("validator_name", "authority", "signed_by"):
            assert forbidden not in params, f"{forbidden} must not be a signer parameter"

    def test_public_verifier_cannot_generate_proof(self):
        """vdp_contract must expose no signing function (scan module symbols)."""
        import src.core.models.vdp_contract as vc
        public_names = [n for n in dir(vc) if not n.startswith("__")]
        for forbidden in (
            "sign",
            "create_confirmed_verdict",
            "compute_validation_proof",
            "sign_confirmed",
        ):
            assert not any(forbidden in n for n in public_names), (
                f"vdp_contract must not expose a signer-like symbol containing {forbidden}"
            )

    def test_reporting_gate_cli_do_not_import_engine_validator_modules(self):
        """production import scan: reporting/gate/CLI must not import the
        engine signer or legacy verifier modules."""
        import re as _re

        banned = (
            "vdp_evidence_validator",
            "vdp_legacy_proof_verifier",
        )
        offenders = []
        roots = [
            Path("src/reporting"),
            Path("scripts"),
        ]
        for root in roots:
            for path in sorted(root.rglob("*.py")):
                try:
                    text = path.read_text(encoding="utf-8")
                except OSError:
                    continue
                for token in banned:
                    if _re.search(rf"(?:import|from)\s+.*\b{token}\b", text):
                        offenders.append(f"{path} imports {token}")
        assert offenders == [], f"engine modules leaked into reporting/CLI: {offenders}"


# ---------------------------------------------------------------------------
# Cross-process restore with public key only
# ---------------------------------------------------------------------------


class TestCrossProcessRestore:
    def test_subprocess_sign_parent_verify_with_public_key(self, tmp_path):
        """Process A signs (holds private key); this process verifies with
        the public key only — proving the verifier never needs the secret."""
        key_path = tmp_path / "signing.key"
        _, priv_raw, pub_raw, key_id = _make_keypair()
        key_path.write_bytes(priv_raw)

        script = (
            "import json, sys\n"
            "from pathlib import Path\n"
            "from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner\n"
            "from src.core.models.vdp_contract import EvidenceRecordV1, VDP_CONTRACT_SCHEMA_VERSION\n"
            "import hashlib\n"
            "priv_raw = Path(sys.argv[1]).read_bytes()\n"
            "pub_raw = __import__('cryptography.hazmat.primitives.asymmetric.ed25519', fromlist=['Ed25519PrivateKey']).Ed25519PrivateKey.from_private_bytes(priv_raw)\n"
            "key_id = hashlib.sha256(pub_raw.public_key().public_bytes(__import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.Raw, __import__('cryptography.hazmat.primitives.serialization', fromlist=['PublicFormat']).PublicFormat.Raw)).hexdigest()[:16]\n"
            "ev = EvidenceRecordV1(evidence_id='ev-xp', attempt_id='att-xp', evidence_type='real_http_response', raw_hash='sha256:'+'e'*64, redacted_excerpt='ok', normalization_rule_version='v1', auth_context_version='none', captured_at='', original_size=2, truncated=False, truncation_reason='', schema_version=VDP_CONTRACT_SCHEMA_VERSION).to_dict()\n"
            "signer = Ed25519EvidenceSigner(private_key=priv_raw, key_id=key_id)\n"
            "ver = signer.create_confirmed_verdict(verdict_id='ver-xp', hypothesis_id='hyp-xp', reason_codes=['evidence_contract_satisfied'], validator_version='1.0.0', evidence_records=[ev])\n"
            "print(json.dumps({'verdict': ver.to_dict(), 'evidence': ev, 'key_id': key_id, 'public_key': pub_raw.public_key().public_bytes(__import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.Raw, __import__('cryptography.hazmat.primitives.serialization', fromlist=['PublicFormat']).PublicFormat.Raw).hex()}))\n"
        )
        env = dict(os.environ)
        result = subprocess.run(
            [sys.executable, "-c", script, str(key_path)],
            capture_output=True,
            text=True,
            env=env,
            cwd="/home/bbb/Documents/App/Shigoku",
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout.strip())

        # This process only has the PUBLIC key.
        public_key_hex = payload["public_key"]
        result_check = verify_confirmed_verdict(
            payload["verdict"],
            [payload["evidence"]],
            public_key_provider={payload["key_id"]: bytes.fromhex(public_key_hex)},
        )
        assert result_check.verified is True
        restored = restore_confirmed_from_dict(
            payload["verdict"],
            [payload["evidence"]],
            public_key_provider={payload["key_id"]: bytes.fromhex(public_key_hex)},
        )
        assert restored.status == "confirmed"
