"""
SGK-2026-0444 T2 — candidate parked store (candidate_ledger.py).

Persisted, fail-safe, secret-safe store for candidate records.

- Atomic writes (recon_state pattern): tempfile.mkstemp in the same dir +
  os.write + fsync + os.close + os.rename; temp file cleaned up on failure.
- Fail-safe load: missing file -> empty ledger; JSON/UTF-8 corruption ->
  warning + QUARANTINE (rename to ``<path>.corrupt-<utc-timestamp>``);
  unknown schema version -> warning + best-effort parse; malformed
  individual record -> warning + skip that record. OSError propagates
  (fail loud).
- MASKING BOUNDARY (lowest write API — defensive, idempotent): in
  ``_to_dict``, every string value is masked recursively through
  dict/list. URL-like values (startswith http:// or https://) get
  ``mask_url_query_values`` first (0439 deny-by-default), then
  ``masker.mask(value).masked``. Already-tokenized ``[PII:...]`` values are
  skipped by the masker (idempotent — reload/save-again never double-masks
  or drifts). The run-scoped token_map is NEVER written to disk and values
  are NOT unmasked on load — tokens persist as stable placeholders across
  runs.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from src.core.security.pii_masker import get_pii_masker
from src.core.validation.candidate_lifecycle import CandidateRecord, LifecycleState

logger = logging.getLogger(__name__)

LEDGER_SCHEMA_VERSION = 1

_QUARANTINE_TIME_FORMAT = "%Y%m%dT%H%M%S%f"

# SGK-2026-0444 (masking hardening): the PIIMasker only masks pattern-matched
# secrets and mask_url_query_values only touches http(s) URLs, so an arbitrary
# secret (an opaque session cookie / bearer / password) sitting in a free-text
# field (reason / title / evidence_summary) would persist raw. Add a
# key-aware, deny-by-default mask over the canonical secret-bearing key
# vocabulary (mirrors vdp_observation_adapter): the VALUE after a secret key is
# masked regardless of its pattern. Over-masking a non-secret word is a safe
# trade for never persisting a raw credential in the cross-run ledger.
_SECRET_HEADER_KEYS = (
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token",
)
_SECRET_KV_KEYS = (
    "token", "access_token", "refresh_token", "auth_token", "session_token",
    "session", "sessionid", "jsessionid", "password", "passwd", "pwd",
    "secret", "credential", "credentials", "api_key", "apikey", "private_key",
    "ssh_key", "jwt",
)
# header form: mask the whole value up to end-of-line / cookie ';' separator.
_SECRET_HEADER_RE = re.compile(
    r"(?i)\b(" + "|".join(re.escape(k) for k in _SECRET_HEADER_KEYS)
    + r")\b\s*[:=]\s*([^\r\n;]+)"
)
# key=value / key: value form: mask the single value token.
_SECRET_KV_RE = re.compile(
    r"(?i)\b(" + "|".join(re.escape(k) for k in _SECRET_KV_KEYS)
    + r")\b\s*[:=]\s*(\"?)([^\s&;\"']+)"
)
# space-separated bearer token: ``Bearer <token>``.
_SECRET_BEARER_RE = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._\-]{6,})")


def _secret_placeholder(raw: str) -> str:
    """Stable, non-reversible mask token for an arbitrary secret value.

    The label is ``REDACTED`` (never a secret-key word) so the key-aware
    regexes below cannot re-match inside a placeholder they just wrote —
    that would nest tokens and break idempotency.
    """
    digest = hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:8]
    return f"[PII:REDACTED:{digest}]"


def _mask_secret_key_values(value: str) -> str:
    """Deny-by-default mask of values following secret-bearing keys.

    Idempotent: values already tokenized as ``[PII:...]`` are left as-is.
    """
    def _skip(v: str) -> bool:
        return v.startswith("[PII:")

    def _hdr(m: "re.Match[str]") -> str:
        v = m.group(2)
        return m.group(0) if _skip(v.strip()) else f"{m.group(1)}={_secret_placeholder(v)}"

    def _kv(m: "re.Match[str]") -> str:
        v = m.group(3)
        return m.group(0) if _skip(v) else f"{m.group(1)}={m.group(2)}{_secret_placeholder(v)}"

    def _bearer(m: "re.Match[str]") -> str:
        v = m.group(1)
        return m.group(0) if _skip(v) else f"bearer {_secret_placeholder(v)}"

    value = _SECRET_HEADER_RE.sub(_hdr, value)
    value = _SECRET_KV_RE.sub(_kv, value)
    value = _SECRET_BEARER_RE.sub(_bearer, value)
    return value


# Secret-bearing dict-key detection: when a secret lives as a dict VALUE under
# a secret key (e.g. {"cookie": "<opaque>"}), the inline key=value regexes above
# cannot see it, so mask by key too (mirrors vdp_observation_adapter).
_SECRET_KEY_SUBSTRINGS = (
    "password", "passwd", "pwd", "secret", "token", "cookie", "authorization",
    "credential", "api_key", "apikey", "bearer", "session", "jwt", "private_key",
)


def _is_secret_key(key: Any) -> bool:
    k = str(key).lower()
    return any(sub in k for sub in _SECRET_KEY_SUBSTRINGS)


class CandidateLedger:
    """In-memory candidate store persisted to ``path`` (empty until load())."""

    def __init__(self, path: Union[str, Path]):
        self.path = Path(path)
        self._records: dict = {}

    @classmethod
    def open(cls, path: Union[str, Path]) -> "CandidateLedger":
        """Create + load(). Missing/corrupt files resolve to an empty
        ledger (fail-safe)."""
        ledger = cls(path)
        ledger.load()
        return ledger

    # ------------------------------------------------------------------
    # load
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Read disk into memory. Missing file -> empty (no error).
        Corrupt JSON / non-UTF-8 -> warn + quarantine + empty ledger.
        Schema mismatch -> warn + best-effort. Malformed record -> warn +
        skip. OSError propagates (fail loud)."""
        self._records = {}
        if not self.path.exists():
            return
        try:
            raw = self.path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            logger.warning(
                "CandidateLedger: file is not valid UTF-8, quarantining: %s", self.path
            )
            self._quarantine()
            return
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning(
                "CandidateLedger: corrupt JSON (%s), quarantining: %s", exc, self.path
            )
            self._quarantine()
            return
        if not isinstance(data, dict):
            logger.warning(
                "CandidateLedger: top-level payload is not an object, quarantining: %s",
                self.path,
            )
            self._quarantine()
            return
        version = data.get("ledger_schema_version")
        if version != LEDGER_SCHEMA_VERSION:
            logger.warning(
                "CandidateLedger: unsupported schema version %r (expected %d); "
                "best-effort load: %s",
                version,
                LEDGER_SCHEMA_VERSION,
                self.path,
            )
        candidates = data.get("candidates")
        if not isinstance(candidates, dict):
            logger.warning(
                "CandidateLedger: missing candidates object; loading empty ledger: %s",
                self.path,
            )
            return
        for finding_id, record_data in candidates.items():
            if not isinstance(record_data, dict):
                logger.warning(
                    "CandidateLedger: skipping malformed record %r (not an object): %s",
                    finding_id,
                    self.path,
                )
                continue
            try:
                record = self._from_dict(record_data)
            except (TypeError, ValueError) as exc:
                logger.warning(
                    "CandidateLedger: skipping malformed record %r (%s): %s",
                    finding_id,
                    exc,
                    self.path,
                )
                continue
            record.finding_id = str(finding_id)
            self._records[str(finding_id)] = record

    def _quarantine(self) -> None:
        """Rename the corrupt file aside; on failure log and continue
        (fail-safe — the ledger stays empty either way)."""
        timestamp = datetime.now(timezone.utc).strftime(_QUARANTINE_TIME_FORMAT)
        target = Path(f"{self.path}.corrupt-{timestamp}")
        try:
            os.rename(str(self.path), str(target))
        except OSError as exc:
            logger.warning(
                "CandidateLedger: failed to quarantine corrupt file %s -> %s (%s); "
                "leaving it in place",
                self.path,
                target,
                exc,
            )

    @staticmethod
    def _from_dict(data: dict) -> CandidateRecord:
        """Record reconstruction (raises ValueError/TypeError when the
        record is malformed — the caller skips it)."""
        state = LifecycleState(data.get("state"))  # ValueError on unknown value
        return CandidateRecord(
            finding_id=str(data.get("finding_id") or ""),
            state=state,
            reason=str(data.get("reason") or ""),
            vuln_type=str(data.get("vuln_type") or ""),
            title=str(data.get("title") or ""),
            target_url_masked=str(data.get("target_url_masked") or ""),
            evidence_summary=dict(data.get("evidence_summary") or {}),
            first_seen=str(data.get("first_seen") or ""),
            last_investigated=str(data.get("last_investigated") or ""),
            budget_used=int(data.get("budget_used") or 0),
            resurrection_count=int(data.get("resurrection_count") or 0),
            promise_score=float(data.get("promise_score") or 0.0),
            revisit_triggers=CandidateLedger._to_tuples(data.get("revisit_triggers") or []),
            resurrection_history=CandidateLedger._to_tuples(
                data.get("resurrection_history") or []
            ),
        )

    @staticmethod
    def _to_tuples(items: Any) -> list:
        """[[type, value], ...] -> [(type, value), ...]; malformed pair -> ValueError."""
        out = []
        for item in items:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise ValueError(f"malformed trigger pair: {item!r}")
            out.append((str(item[0]), str(item[1])))
        return out

    # ------------------------------------------------------------------
    # in-memory API
    # ------------------------------------------------------------------

    def get(self, finding_id: str) -> Optional[CandidateRecord]:
        return self._records.get(finding_id)

    def put(self, record: CandidateRecord) -> None:
        """Upsert by ``record.finding_id``."""
        self._records[record.finding_id] = record

    def list_by_state(self, state: Union[LifecycleState, str]) -> list:
        """Records in the given state (LifecycleState or its string value)."""
        target = state.value if isinstance(state, LifecycleState) else LifecycleState(state)
        return [record for record in self._records.values() if record.state == target]

    def all(self) -> list:
        """All records in insertion order."""
        return list(self._records.values())

    # ------------------------------------------------------------------
    # save (atomic) + masking boundary
    # ------------------------------------------------------------------

    def save(self) -> None:
        """Atomic write (recon_state pattern). Creates parent dirs."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._to_dict(), indent=2, ensure_ascii=False)
        tmp_fd, tmp_path = tempfile.mkstemp(
            prefix=".candidate_ledger_", suffix=".json", dir=str(self.path.parent)
        )
        try:
            os.write(tmp_fd, payload.encode("utf-8"))
            os.fsync(tmp_fd)
            os.close(tmp_fd)
            tmp_fd = -1
            os.rename(tmp_path, str(self.path))
        except Exception:
            if tmp_fd >= 0:
                os.close(tmp_fd)
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _to_dict(self) -> dict:
        return {
            "ledger_schema_version": LEDGER_SCHEMA_VERSION,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "candidates": {
                finding_id: self._to_record_dict(record)
                for finding_id, record in self._records.items()
            },
        }

    def _to_record_dict(self, record: CandidateRecord) -> dict:
        """Record projection; revisit_triggers / resurrection_history are
        serialized as lists (not tuples). Masking is applied to every string
        value recursively (lowest write API)."""
        return self._mask_value(
            {
                "finding_id": record.finding_id,
                "state": record.state.value,
                "reason": record.reason,
                "vuln_type": record.vuln_type,
                "title": record.title,
                "target_url_masked": record.target_url_masked,
                "evidence_summary": record.evidence_summary,
                "first_seen": record.first_seen,
                "last_investigated": record.last_investigated,
                "budget_used": record.budget_used,
                "resurrection_count": record.resurrection_count,
                "promise_score": record.promise_score,
                "revisit_triggers": [[t, v] for t, v in record.revisit_triggers],
                "resurrection_history": [[t, v] for t, v in record.resurrection_history],
            }
        )

    def _mask_value(self, value: Any, key: Any = None) -> Any:
        """Recurse through dict/list; mask every string value. A string whose
        owning dict key is secret-bearing is masked whole (deny-by-default),
        regardless of pattern. Non-strings pass through untouched."""
        if isinstance(value, str):
            masked = self._mask_string(value)
            if key is not None and _is_secret_key(key) and not masked.startswith("[PII:"):
                masked = _secret_placeholder(value)
            return masked
        if isinstance(value, dict):
            return {k: self._mask_value(item, key=k) for k, item in value.items()}
        if isinstance(value, list):
            return [self._mask_value(item, key=key) for item in value]
        return value

    def _mask_string(self, value: str) -> str:
        """Defensive, idempotent string masking: URL-like strings get
        mask_url_query_values first (0439), then mask().masked. Already
        tokenized [PII:...] values are skipped by the masker, so
        reload/save-again never double-masks or drifts. The run-scoped
        token_map is never written to disk."""
        if not value:
            return value
        masker = get_pii_masker()
        if value.startswith(("http://", "https://")):
            value = masker.mask_url_query_values(value)
        # SGK-2026-0444 hardening: key-aware deny-by-default mask for arbitrary
        # secrets in free text, applied on every string (not just URLs).
        value = _mask_secret_key_values(value)
        return masker.mask(value).masked
