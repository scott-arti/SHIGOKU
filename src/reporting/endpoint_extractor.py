from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from src.core.models.ops_artifacts import (
    AttackTargetBundle,
    AttackTargetSpec,
    ExportManifest,
    write_attack_target_bundle,
)
from src.core.utils.json_utils import safe_json_loads, stream_jsonl
from src.reporting.haddix_evidence_quality import redact_raw_request
from src.reporting.session_finding_inspector import inspect_session_findings


def _resolve_artifact_path(session_path: Path, artifact_ref: str) -> Path:
    candidate = Path(str(artifact_ref or "").strip())
    if candidate.is_absolute():
        return candidate

    for parent in session_path.parents:
        if parent.name == "workspace":
            workspace_candidate = (parent / candidate).resolve()
            if workspace_candidate.exists():
                return workspace_candidate

    return (session_path.parent / candidate).resolve()


def _normalize_category(raw: str) -> str:
    category = str(raw or "").strip()
    if category.startswith("tagged_"):
        category = category[7:]
    return category or "api_endpoint"


def _map_detection_class_to_category(detection_class: str) -> str:
    token = str(detection_class or "").strip().lower()
    mapping = {
        "idor_bola": "id_param",
        "xss": "xss_candidate",
        "csrf": "csrf_candidate",
        "open_redirect": "redirect_param",
        "ssrf": "redirect_param",
    }
    return mapping.get(token, "api_endpoint")


def extract_attack_targets_from_session(
    session_path: str | Path,
    *,
    max_records: int | None = None,
) -> list[AttackTargetSpec]:
    path = Path(session_path).expanduser().resolve()
    session_data = safe_json_loads(
        path.read_text(encoding="utf-8"),
        context=f"endpoint_extractor:{path.name}",
    )
    completed_tasks = session_data.get("completed_tasks", []) if isinstance(session_data, dict) else []

    dedup: dict[str, AttackTargetSpec] = {}

    for task in completed_tasks:
        if not isinstance(task, dict):
            continue
        result = task.get("result", {})
        data = result.get("data", {}) if isinstance(result, dict) else {}
        results = data.get("results", {}) if isinstance(data, dict) else {}
        if not isinstance(results, dict):
            continue

        for category_name, descriptor in results.items():
            if not isinstance(descriptor, dict):
                continue
            artifact_ref = str(descriptor.get("file", "") or "").strip()
            if not artifact_ref.endswith(".jsonl"):
                continue
            artifact_path = _resolve_artifact_path(path, artifact_ref)
            if not artifact_path.exists():
                continue

            category = _normalize_category(category_name)
            descriptor_tags = descriptor.get("tags", []) if isinstance(descriptor.get("tags", []), list) else []
            for entry in stream_jsonl(str(artifact_path)):
                if not isinstance(entry, dict):
                    continue
                url = str(entry.get("url", "") or "").strip()
                if not url:
                    continue
                method = str(entry.get("method", "GET") or "GET")
                tags = entry.get("tags", []) if isinstance(entry.get("tags", []), list) else descriptor_tags
                target = AttackTargetSpec(
                    url=url,
                    method=method,
                    category=category,
                    tags=list(tags or descriptor_tags or [category]),
                    source_kind="tagged_url",
                    source_path=str(artifact_path),
                    provenance={"task_id": str(task.get("id", "") or "")},
                )
                dedup[f"{target.method}|{target.url}"] = target

    finding_summary = inspect_session_findings(path)
    for finding in finding_summary.get("findings", []):
        if not isinstance(finding, dict):
            continue
        url = str(finding.get("target_url", "") or "").strip()
        if not url:
            continue
        category = _map_detection_class_to_category(str(finding.get("detection_class", "") or ""))
        target = AttackTargetSpec(
            url=url,
            method="GET",
            category=category,
            tags=[category],
            source_kind="finding",
            source_path=str(path),
            detection_class=str(finding.get("detection_class", "") or ""),
            provenance={"task_id": str(finding.get("task_id", "") or "")},
        )
        dedup.setdefault(f"{target.method}|{target.url}", target)

    targets = list(dedup.values())
    if max_records is not None:
        targets = targets[: max(0, int(max_records))]
    return targets


def extract_attack_targets_from_findings(
    findings: list[Any],
    *,
    source_path: str,
    max_records: int | None = None,
) -> list[AttackTargetSpec]:
    dedup: dict[str, AttackTargetSpec] = {}

    for finding in findings:
        payload = finding.to_dict() if hasattr(finding, "to_dict") else finding
        if not isinstance(payload, dict):
            continue

        url = str(
            payload.get("target_url")
            or payload.get("url")
            or payload.get("target")
            or ""
        ).strip()
        if not url:
            continue

        evidence = payload.get("evidence", {})
        evidence_dict = evidence if isinstance(evidence, dict) else {}
        detection_class = str(
            payload.get("vuln_type")
            or payload.get("type")
            or payload.get("detection_class")
            or ""
        ).strip()
        category = _map_detection_class_to_category(detection_class)
        method = str(evidence_dict.get("request_method", "GET") or "GET").strip().upper() or "GET"
        target = AttackTargetSpec(
            url=url,
            method=method,
            category=category,
            tags=[category, "finding_repository"],
            source_kind="findings_repository",
            source_path=source_path,
            detection_class=detection_class,
            provenance={
                "finding_id": str(payload.get("id", "") or ""),
                "source_agent": str(payload.get("source_agent", "") or ""),
            },
            reason_codes=["cross_session_export"],
        )
        dedup.setdefault(f"{target.method}|{target.url}", target)

    targets = list(dedup.values())
    if max_records is not None:
        targets = targets[: max(0, int(max_records))]
    return targets


def build_attack_target_bundle_from_session(
    session_path: str | Path,
    *,
    report_path: str | Path | None = None,
    ttl_days: int = 7,
    max_records: int = 500,
) -> AttackTargetBundle:
    path = Path(session_path).expanduser().resolve()
    targets = extract_attack_targets_from_session(path, max_records=max_records)
    if not targets:
        raise ValueError("empty export")
    allowed_hosts = sorted({target.host for target in targets if str(target.host or "").strip()})

    manifest = ExportManifest(
        source_session=str(path),
        source_report=str(Path(report_path).expanduser().resolve()) if report_path else None,
        ttl_days=ttl_days,
        allowed_hosts=allowed_hosts,
        reason_codes=["single_session_export"],
        provenance={
            "single_session": True,
            "source_kinds": sorted({target.source_kind for target in targets if target.source_kind}),
            "scope_snapshot": {
                "allowed_hosts": allowed_hosts,
                "target_count": len(targets),
            },
        },
        item_count=len(targets),
        max_export_records=max_records,
    )
    return AttackTargetBundle(manifest=manifest, targets=targets)


def build_attack_target_bundle_from_findings(
    findings: list[Any],
    *,
    db_path: str | Path,
    ttl_days: int = 7,
    max_records: int = 500,
    allowed_hosts: list[str] | None = None,
    filters: dict[str, Any] | None = None,
) -> AttackTargetBundle:
    resolved_db = Path(db_path).expanduser().resolve()
    targets = extract_attack_targets_from_findings(
        findings,
        source_path=str(resolved_db),
        max_records=max_records,
    )
    if not targets:
        raise ValueError("empty export")
    normalized_allowed_hosts = list(allowed_hosts or sorted({target.host for target in targets if str(target.host or "").strip()}))

    manifest = ExportManifest(
        ttl_days=ttl_days,
        allowed_hosts=normalized_allowed_hosts,
        reason_codes=["cross_session_export", "findings_repository"],
        provenance={
            "cross_session": True,
            "db_path": str(resolved_db),
            "filters": dict(filters or {}),
            "source_kinds": ["findings_repository"],
            "scope_snapshot": {
                "allowed_hosts": normalized_allowed_hosts,
                "target_count": len(targets),
            },
        },
        item_count=len(targets),
        max_export_records=max_records,
    )
    return AttackTargetBundle(manifest=manifest, targets=targets)


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(f"{path.suffix}.tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
            fh.flush()
            import os

            os.fsync(fh.fileno())
        tmp_path.replace(path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise


def write_attack_target_artifacts(
    bundle: AttackTargetBundle,
    output_dir: str | Path,
    *,
    overwrite: bool = False,
) -> dict[str, str]:
    destination = Path(output_dir).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)

    attack_targets_path = destination / "attack_targets.json"
    endpoints_json_path = destination / "endpoints.json"
    endpoints_csv_path = destination / "endpoints.csv"
    endpoints_md_path = destination / "endpoints.md"

    if not overwrite:
        for path in (attack_targets_path, endpoints_json_path, endpoints_csv_path, endpoints_md_path):
            if path.exists():
                raise FileExistsError(f"artifact already exists: {path}")

    write_attack_target_bundle(bundle, attack_targets_path)

    json_payload = redact_raw_request([target.to_dict() for target in bundle.targets])
    _atomic_write_text(
        endpoints_json_path,
        json.dumps(json_payload, ensure_ascii=False, indent=2),
    )

    csv_lines: list[str] = []
    with open(endpoints_csv_path.with_suffix(".csv.tmp"), "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "url",
                "method",
                "host",
                "category",
                "tags",
                "source_kind",
                "detection_class",
            ],
        )
        writer.writeheader()
        for target in bundle.targets:
            safe_url = str(redact_raw_request(target.url))
            writer.writerow(
                {
                    "url": safe_url,
                    "method": target.method,
                    "host": target.host,
                    "category": target.category,
                    "tags": ",".join(target.tags),
                    "source_kind": target.source_kind,
                    "detection_class": target.detection_class,
                }
            )
        fh.flush()
        import os

        os.fsync(fh.fileno())
    endpoints_csv_path.with_suffix(".csv.tmp").replace(endpoints_csv_path)

    markdown_lines = ["# Endpoints", ""]
    for target in bundle.targets:
        markdown_lines.append(
            f"- `{target.method}` {redact_raw_request(target.url)} [{target.category}]"
        )
    markdown_lines.append("")
    _atomic_write_text(endpoints_md_path, "\n".join(markdown_lines))

    return {
        "attack_targets": str(attack_targets_path),
        "endpoints_json": str(endpoints_json_path),
        "endpoints_csv": str(endpoints_csv_path),
        "endpoints_md": str(endpoints_md_path),
    }
