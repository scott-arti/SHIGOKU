"""report/haddix evidence artifact helpers extracted from report_haddix.py.

Functions in this module synthesize HTTP request/response artifacts,
build detector signals, replay commands, and materialize evidence files
from finding dictionaries.
"""

import json
import shlex
import re
from pathlib import Path
from typing import Any
import urllib.parse

from src.cli.handlers._shared import dedupe_keep_order


def coerce_finding_dict(entry: Any) -> dict[str, Any] | None:
    if isinstance(entry, dict):
        return dict(entry)
    to_dict = getattr(entry, "to_dict", None)
    if callable(to_dict):
        try:
            payload = to_dict()
            if isinstance(payload, dict):
                return payload
        except Exception:
            return None
    return None


def first_non_empty_string(values: list[Any]) -> str:
    for value in values:
        token = str(value or "").strip()
        if token:
            return token
    return ""


def clip_http_text(raw: Any, *, limit: int = 1200) -> str:
    text = str(raw or "")
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n...[truncated]"


def synthesize_request_raw_from_evidence(
    *,
    evidence_obj: dict[str, Any],
    target_url: str,
) -> str:
    method = str(
        first_non_empty_string(
            [
                evidence_obj.get("request_method"),
                evidence_obj.get("method"),
                "GET",
            ]
        )
    ).upper()
    request_url = first_non_empty_string(
        [
            evidence_obj.get("request_url"),
            evidence_obj.get("url"),
            target_url,
        ]
    )
    if not request_url:
        return ""

    lines = [f"{method} {request_url} HTTP/1.1"]
    request_headers = evidence_obj.get("request_headers")
    if isinstance(request_headers, dict):
        header_count = 0
        for key, value in request_headers.items():
            h_key = str(key or "").strip()
            h_value = str(value or "").strip()
            if not h_key or not h_value:
                continue
            lines.append(f"{h_key}: {h_value}")
            header_count += 1
            if header_count >= 12:
                break

    request_body = evidence_obj.get("request_body")
    if isinstance(request_body, (dict, list)):
        body = json.dumps(request_body, ensure_ascii=False)
    else:
        body = str(request_body or "")
    body = clip_http_text(body, limit=1000).strip()
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines).strip()


def synthesize_response_raw_from_evidence(*, evidence_obj: dict[str, Any]) -> str:
    response_status = 0
    try:
        response_status = int(evidence_obj.get("response_status", 0) or 0)
    except Exception:
        response_status = 0

    lines = [f"HTTP/1.1 {response_status}"]
    response_headers = evidence_obj.get("response_headers")
    if isinstance(response_headers, dict):
        header_count = 0
        for key, value in response_headers.items():
            h_key = str(key or "").strip()
            h_value = str(value or "").strip()
            if not h_key or not h_value:
                continue
            lines.append(f"{h_key}: {h_value}")
            header_count += 1
            if header_count >= 12:
                break

    response_body = evidence_obj.get("response_body")
    if isinstance(response_body, (dict, list)):
        body = json.dumps(response_body, ensure_ascii=False)
    else:
        body = str(response_body or "")
    body = clip_http_text(body, limit=1000).strip()
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines).strip()


def build_replay_command_for_finding(
    *,
    target_url: str,
    request_raw: str,
    request_headers: dict[str, Any] | None = None,
    request_body: str = "",
) -> str:
    method = "GET"
    replay_url = str(target_url or "").strip()

    first_line = str(request_raw or "").splitlines()[0].strip() if str(request_raw or "").strip() else ""
    if first_line:
        parts = first_line.split()
        if len(parts) >= 2:
            if str(parts[0]).isalpha():
                method = str(parts[0]).upper()
            candidate = str(parts[1]).strip()
            if candidate.startswith("http://") or candidate.startswith("https://"):
                replay_url = candidate
            elif candidate.startswith("/") and replay_url:
                from urllib.parse import urlsplit, urlunsplit

                split = urlsplit(replay_url)
                if split.scheme and split.netloc:
                    replay_url = urlunsplit((split.scheme, split.netloc, candidate, "", ""))

    if not replay_url:
        return ""

    cmd_parts = ["curl", "-i", "-X", method, shlex.quote(replay_url)]
    if isinstance(request_headers, dict):
        header_count = 0
        for key, value in request_headers.items():
            h_key = str(key or "").strip()
            h_value = str(value or "").strip()
            if not h_key or not h_value:
                continue
            cmd_parts.extend(["-H", shlex.quote(f"{h_key}: {h_value}")])
            header_count += 1
            if header_count >= 5:
                break
    body = str(request_body or "").strip()
    if body:
        cmd_parts.extend(["--data-raw", shlex.quote(body)])
    return " ".join(cmd_parts)


def build_detector_signals(additional_info: dict[str, Any]) -> list[str]:
    if not isinstance(additional_info, dict):
        return []

    signals: list[str] = []
    authz = additional_info.get("authz_differential", {})
    if isinstance(authz, dict):
        raw_signals = authz.get("signals", [])
        if isinstance(raw_signals, list):
            for signal in raw_signals:
                token = str(signal or "").strip()
                if token:
                    signals.append(token)
        scenario = str(authz.get("scenario", "") or "").strip()
        if scenario:
            signals.append(f"authz_scenario:{scenario}")

    heuristic_reasons = additional_info.get("heuristic_reasons", [])
    if isinstance(heuristic_reasons, list):
        for reason in heuristic_reasons:
            token = str(reason or "").strip()
            if token:
                signals.append(f"heuristic:{token}")

    repeat_signal = additional_info.get("repeat_signal", {})
    if isinstance(repeat_signal, dict):
        for key in ("total", "completed_with_probe", "privilege_probe"):
            if key in repeat_signal:
                signals.append(f"repeat:{key}={repeat_signal.get(key)}")

    probe_skip = str(additional_info.get("probe_skipped_reason", "") or "").strip()
    if probe_skip:
        signals.append(f"probe_skip:{probe_skip}")

    return dedupe_keep_order(signals)


def materialize_haddix_evidence_artifacts(
    *,
    findings: list[Any],
    evidence_dir: Path,
    captured_at: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    normalized_findings: list[dict[str, Any]] = []
    artifact_paths: list[str] = []
    if not isinstance(findings, list) or not findings:
        return normalized_findings, artifact_paths

    for entry in findings:
        normalized = coerce_finding_dict(entry)
        if normalized is None:
            continue
        normalized_findings.append(normalized)

    if not normalized_findings:
        return normalized_findings, artifact_paths

    evidence_dir.mkdir(parents=True, exist_ok=True)

    for index, finding in enumerate(normalized_findings, 1):
        additional_info = finding.get("additional_info", {})
        if not isinstance(additional_info, dict):
            additional_info = {}
        finding["additional_info"] = additional_info

        evidence_obj = finding.get("evidence", {})
        if not isinstance(evidence_obj, dict):
            evidence_obj = {}

        request_raw = first_non_empty_string(
            [
                finding.get("poc_request"),
                finding.get("request"),
                finding.get("raw_request"),
                additional_info.get("poc_request"),
                additional_info.get("request"),
                additional_info.get("request_raw"),
                additional_info.get("raw_request"),
                evidence_obj.get("request"),
                evidence_obj.get("request_raw"),
                evidence_obj.get("raw_request"),
            ]
        )
        response_raw = first_non_empty_string(
            [
                finding.get("poc_response"),
                finding.get("response"),
                finding.get("raw_response"),
                additional_info.get("poc_response"),
                additional_info.get("response"),
                additional_info.get("response_raw"),
                additional_info.get("raw_response"),
                evidence_obj.get("response"),
                evidence_obj.get("response_raw"),
                evidence_obj.get("raw_response"),
            ]
        )

        if not request_raw:
            request_raw = synthesize_request_raw_from_evidence(
                evidence_obj=evidence_obj,
                target_url=str(
                    finding.get("target_url", finding.get("target", finding.get("url", ""))) or ""
                ).strip(),
            )
        if not response_raw:
            response_raw = synthesize_response_raw_from_evidence(evidence_obj=evidence_obj)

        if not str(finding.get("poc_request", "") or "").strip() and request_raw:
            finding["poc_request"] = request_raw
        if not str(finding.get("poc_response", "") or "").strip() and response_raw:
            finding["poc_response"] = response_raw

        target_url = str(
            finding.get("target_url", finding.get("target", finding.get("url", ""))) or ""
        ).strip()
        replay_command = build_replay_command_for_finding(
            target_url=target_url,
            request_raw=request_raw,
            request_headers=evidence_obj.get("request_headers") if isinstance(evidence_obj, dict) else None,
            request_body=str(evidence_obj.get("request_body", "") or "") if isinstance(evidence_obj, dict) else "",
        )

        vuln_token = re.sub(r"[^A-Z0-9_]+", "_", str(finding.get("vuln_type", "unknown") or "unknown").upper())
        vuln_token = vuln_token.strip("_") or "UNKNOWN"
        artifact_path = evidence_dir / f"EV-{index:03d}-{vuln_token}.json"
        detector_verdict = {
            "detection_mode": str(additional_info.get("detection_mode", "") or "").strip() or "-",
            "heuristic_candidate": bool(additional_info.get("heuristic_candidate", False)),
            "verification_required": bool(additional_info.get("verification_required", False)),
            "authz_differential": additional_info.get("authz_differential", {})
            if isinstance(additional_info.get("authz_differential"), dict)
            else {},
            "blind_correlation": additional_info.get("blind_correlation", {})
            if isinstance(additional_info.get("blind_correlation"), dict)
            else {},
        }
        key_signals = build_detector_signals(additional_info)

        artifact_payload = {
            "captured_at": captured_at,
            "finding_index": index,
            "title": str(finding.get("title", "") or ""),
            "vuln_type": str(finding.get("vuln_type", finding.get("type", "")) or ""),
            "severity": str(finding.get("severity", "") or ""),
            "target_url": target_url,
            "raw_request": request_raw,
            "raw_response": response_raw,
            "replay_command": replay_command,
            "detector_verdict": detector_verdict,
            "key_signals": key_signals,
        }
        artifact_path.write_text(
            json.dumps(artifact_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        artifact_paths.append(str(artifact_path.resolve()))

        capture_status = "missing"
        if request_raw and response_raw:
            capture_status = "full"
        elif request_raw or response_raw:
            capture_status = "partial"

        additional_info["evidence_artifact_path"] = str(artifact_path.resolve())
        additional_info["replay_command"] = replay_command
        additional_info["evidence_capture_status"] = capture_status

    return normalized_findings, artifact_paths
