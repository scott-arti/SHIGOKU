from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from src.core.utils.json_utils import safe_json_loads

OPS_TARGET_BUNDLE_SCHEMA_VERSION = "shigoku.ops.target_bundle.v1"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_manifest_datetime(raw: str) -> datetime | None:
    token = str(raw or "").strip()
    if not token:
        return None
    try:
        parsed = datetime.fromisoformat(token.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_string_list(values: list[str] | tuple[str, ...] | None) -> list[str]:
    seen: set[str] = set()
    normalized: list[str] = []
    for raw in values or []:
        token = str(raw or "").strip()
        if not token or token in seen:
            continue
        seen.add(token)
        normalized.append(token)
    return normalized


def _normalize_url(raw: str) -> str:
    candidate = str(raw or "").strip()
    if not candidate:
        return ""
    if candidate.startswith("http:/") and not candidate.startswith("http://"):
        candidate = candidate.replace("http:/", "http://", 1)
    if candidate.startswith("https:/") and not candidate.startswith("https://"):
        candidate = candidate.replace("https:/", "https://", 1)
    return candidate


def extract_host_from_url(raw: str) -> str:
    candidate = _normalize_url(raw)
    if not candidate:
        return ""
    if "://" not in candidate and "/" not in candidate:
        return candidate.split(":", 1)[0].strip().lower()
    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    return str(parsed.hostname or parsed.netloc or "").strip().lower()


def _host_matches_allowed(host: str, allowed_host: str) -> bool:
    normalized_host = str(host or "").strip().lower()
    normalized_allowed = str(allowed_host or "").strip().lower()
    if not normalized_host or not normalized_allowed:
        return False
    if normalized_allowed.startswith("*."):
        suffix = normalized_allowed[2:]
        return normalized_host == suffix or normalized_host.endswith(f".{suffix}")
    return normalized_host == normalized_allowed


class IntentCommand(str, Enum):
    REPORT_CONSISTENCY = "report.consistency"
    REPORT_LOOP = "report.loop"
    REPORT_EXPORT_TARGETS = "report.export-targets"
    SESSION_FINDINGS = "session.findings"
    SESSION_EXPORT_TARGETS = "session.export-targets"
    MAIN_ATTACK_TARGETS = "main.attack-targets"
    MAIN_RECON_RESUME = "main.recon-resume"

    @classmethod
    def allowlist(cls) -> list[str]:
        return [item.value for item in cls]


@dataclass
class AttackTargetSpec:
    url: str
    method: str = "GET"
    host: str = ""
    category: str = "api_endpoint"
    tags: list[str] = field(default_factory=list)
    source_kind: str = ""
    source_path: str = ""
    detection_class: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)
    reason_codes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.url = _normalize_url(self.url)
        self.method = str(self.method or "GET").strip().upper() or "GET"
        self.host = extract_host_from_url(self.host or self.url)
        self.category = str(self.category or "api_endpoint").strip() or "api_endpoint"
        self.tags = _normalize_string_list(self.tags)
        self.reason_codes = _normalize_string_list(self.reason_codes)
        if self.category not in self.tags:
            self.tags = [self.category, *self.tags]

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "host": self.host,
            "category": self.category,
            "tags": list(self.tags),
            "source_kind": self.source_kind,
            "source_path": self.source_path,
            "detection_class": self.detection_class,
            "provenance": dict(self.provenance),
            "reason_codes": list(self.reason_codes),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AttackTargetSpec":
        return cls(
            url=str(payload.get("url", "") or ""),
            method=str(payload.get("method", "GET") or "GET"),
            host=str(payload.get("host", "") or ""),
            category=str(payload.get("category", "api_endpoint") or "api_endpoint"),
            tags=list(payload.get("tags", []) or []),
            source_kind=str(payload.get("source_kind", "") or ""),
            source_path=str(payload.get("source_path", "") or ""),
            detection_class=str(payload.get("detection_class", "") or ""),
            provenance=dict(payload.get("provenance", {}) or {}),
            reason_codes=list(payload.get("reason_codes", []) or []),
        )

    def to_signal(self) -> dict[str, Any]:
        primary_label = self.category if self.category.startswith("tagged_") else f"tagged_{self.category}"
        signal_seed = f"{self.method}|{self.url}|{self.category}|{self.source_kind}"
        signal_id = hashlib.sha256(signal_seed.encode("utf-8")).hexdigest()[:16]
        return {
            "signal_id": signal_id,
            "entity_type": "endpoint",
            "primary_label": primary_label,
            "candidate_labels": list(self.tags),
            "url": self.url,
            "method": self.method,
            "seen_count": 1,
            "source_kind": self.source_kind,
            "source_path": self.source_path,
            "detection_class": self.detection_class,
            "reason_codes": list(self.reason_codes),
        }


@dataclass
class ExportManifest:
    schema_version: str = OPS_TARGET_BUNDLE_SCHEMA_VERSION
    correlation_id: str = field(default_factory=lambda: f"ops-{uuid.uuid4().hex[:12]}")
    generated_at: str = field(default_factory=_utc_now_iso)
    ttl_days: int = 7
    manifest_hash: str = ""
    source_session: str | None = None
    source_report: str | None = None
    allowed_hosts: list[str] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    item_count: int = 0
    max_export_records: int = 0

    def __post_init__(self) -> None:
        self.schema_version = str(self.schema_version or OPS_TARGET_BUNDLE_SCHEMA_VERSION).strip()
        self.correlation_id = str(self.correlation_id or f"ops-{uuid.uuid4().hex[:12]}").strip()
        self.generated_at = str(self.generated_at or _utc_now_iso()).strip()
        self.ttl_days = max(0, int(self.ttl_days))
        self.allowed_hosts = sorted(
            {
                str(host or "").strip().lower()
                for host in self.allowed_hosts
                if str(host or "").strip()
            }
        )
        self.reason_codes = _normalize_string_list(self.reason_codes)
        self.item_count = max(0, int(self.item_count))
        self.max_export_records = max(0, int(self.max_export_records))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "correlation_id": self.correlation_id,
            "generated_at": self.generated_at,
            "ttl_days": self.ttl_days,
            "manifest_hash": self.manifest_hash,
            "source_session": self.source_session,
            "source_report": self.source_report,
            "allowed_hosts": list(self.allowed_hosts),
            "reason_codes": list(self.reason_codes),
            "provenance": dict(self.provenance),
            "item_count": self.item_count,
            "max_export_records": self.max_export_records,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ExportManifest":
        return cls(
            schema_version=str(payload.get("schema_version", OPS_TARGET_BUNDLE_SCHEMA_VERSION) or OPS_TARGET_BUNDLE_SCHEMA_VERSION),
            correlation_id=str(payload.get("correlation_id", "") or ""),
            generated_at=str(payload.get("generated_at", "") or ""),
            ttl_days=int(payload.get("ttl_days", 7) or 7),
            manifest_hash=str(payload.get("manifest_hash", "") or ""),
            source_session=str(payload.get("source_session", "") or "") or None,
            source_report=str(payload.get("source_report", "") or "") or None,
            allowed_hosts=list(payload.get("allowed_hosts", []) or []),
            reason_codes=list(payload.get("reason_codes", []) or []),
            provenance=dict(payload.get("provenance", {}) or {}),
            item_count=int(payload.get("item_count", 0) or 0),
            max_export_records=int(payload.get("max_export_records", 0) or 0),
        )


@dataclass
class AttackTargetBundle:
    manifest: ExportManifest
    targets: list[AttackTargetSpec] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.targets = [
            item if isinstance(item, AttackTargetSpec) else AttackTargetSpec.from_dict(item)
            for item in self.targets
        ]
        self.manifest.item_count = len(self.targets)
        if not self.manifest.allowed_hosts:
            self.manifest.allowed_hosts = sorted(
                {
                    target.host
                    for target in self.targets
                    if str(target.host or "").strip()
                }
            )
        if not self.manifest.manifest_hash:
            self.manifest.manifest_hash = self.compute_manifest_hash()

    def _payload_without_hash(self) -> dict[str, Any]:
        manifest_payload = self.manifest.to_dict()
        manifest_payload["manifest_hash"] = ""
        return {
            "manifest": manifest_payload,
            "targets": [target.to_dict() for target in self.targets],
        }

    def compute_manifest_hash(self) -> str:
        canonical = json.dumps(
            self._payload_without_hash(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def ensure_manifest_hash(self) -> str:
        self.manifest.manifest_hash = self.compute_manifest_hash()
        return self.manifest.manifest_hash

    def validate_integrity(self) -> bool:
        expected = self.compute_manifest_hash()
        return str(self.manifest.manifest_hash or "").strip() == expected

    def validate_freshness(self, *, now: datetime | None = None) -> tuple[bool, str | None]:
        generated_at = _parse_manifest_datetime(self.manifest.generated_at)
        if generated_at is None:
            return False, "invalid generated_at"
        ttl_days = int(self.manifest.ttl_days)
        if ttl_days <= 0:
            return True, None
        reference = now.astimezone(timezone.utc) if now is not None else datetime.now(timezone.utc)
        expires_at = generated_at + timedelta(days=ttl_days)
        if reference > expires_at:
            return False, "attack target bundle expired"
        return True, None

    def validate_allowed_hosts(self) -> list[str]:
        violations: list[str] = []
        for target in self.targets:
            if not target.host:
                violations.append(target.url)
                continue
            if not any(_host_matches_allowed(target.host, allowed) for allowed in self.manifest.allowed_hosts):
                violations.append(target.url)
        return violations

    def to_dict(self) -> dict[str, Any]:
        self.ensure_manifest_hash()
        return {
            "manifest": self.manifest.to_dict(),
            "targets": [target.to_dict() for target in self.targets],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AttackTargetBundle":
        manifest_payload = payload.get("manifest", {})
        targets_payload = payload.get("targets", [])
        if not isinstance(manifest_payload, dict):
            raise ValueError("manifest must be an object")
        if not isinstance(targets_payload, list):
            raise ValueError("targets must be a list")
        return cls(
            manifest=ExportManifest.from_dict(manifest_payload),
            targets=[
                item if isinstance(item, AttackTargetSpec) else AttackTargetSpec.from_dict(item)
                for item in targets_payload
                if isinstance(item, dict)
            ],
        )


def load_attack_target_bundle(path: str | Path, *, validate_hash: bool = True) -> AttackTargetBundle:
    raw_path = Path(path).expanduser().resolve()
    payload = safe_json_loads(
        raw_path.read_text(encoding="utf-8"),
        context=f"attack_target_bundle:{raw_path.name}",
    )
    if not isinstance(payload, dict):
        raise ValueError("attack target bundle must be a JSON object")
    manifest_payload = payload.get("manifest", {})
    if not isinstance(manifest_payload, dict):
        raise ValueError("manifest must be an object")
    if not str(manifest_payload.get("generated_at", "") or "").strip():
        raise ValueError("missing generated_at")
    provenance_payload = manifest_payload.get("provenance", {})
    if not isinstance(provenance_payload, dict):
        raise ValueError("provenance must be an object")
    scope_snapshot = provenance_payload.get("scope_snapshot", {})
    if not isinstance(scope_snapshot, dict) or not scope_snapshot:
        raise ValueError("missing scope_snapshot provenance")
    if provenance_payload.get("single_session") and not any(
        str(manifest_payload.get(field, "") or "").strip()
        for field in ("source_session", "source_report")
    ):
        raise ValueError("missing single-session source provenance")
    if provenance_payload.get("cross_session") and not str(provenance_payload.get("db_path", "") or "").strip():
        raise ValueError("missing cross-session source provenance")
    bundle = AttackTargetBundle.from_dict(payload)
    if validate_hash and not bundle.validate_integrity():
        raise ValueError("manifest_hash mismatch")
    freshness_ok, freshness_error = bundle.validate_freshness()
    if not freshness_ok and freshness_error:
        raise ValueError(freshness_error)
    violations = bundle.validate_allowed_hosts()
    if violations:
        raise ValueError(f"allowed_hosts mismatch: {violations[0]}")
    return bundle


def write_attack_target_bundle(bundle: AttackTargetBundle, path: str | Path) -> Path:
    output_path = Path(path).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = bundle.to_dict()
    tmp_path = output_path.with_suffix(f"{output_path.suffix}.tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.flush()
            import os

            os.fsync(fh.fileno())
        tmp_path.replace(output_path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise
    return output_path
