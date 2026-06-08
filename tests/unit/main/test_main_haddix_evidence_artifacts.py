import json
from datetime import datetime

from src import main as main_module


def test_materialize_haddix_evidence_artifacts_writes_required_fields(tmp_path):
    findings = [
        {
            "title": "Potential Unauthenticated API Access",
            "severity": "medium",
            "vuln_type": "broken_access_control",
            "target_url": "http://example.com/api/state",
            "additional_info": {
                "detection_mode": "phase1",
                "authz_differential": {
                    "scenario": "unauthenticated_api_access",
                    "signals": ["auth_success", "unauth_success"],
                },
            },
            "poc_request": "GET /api/state HTTP/1.1",
            "poc_response": "HTTP/1.1 200 OK",
        }
    ]

    evidence_dir = tmp_path / "reports" / "haddix_evidence_20260422_010101"
    normalized, artifact_paths = main_module._materialize_haddix_evidence_artifacts(
        findings=findings,
        evidence_dir=evidence_dir,
        captured_at=datetime.now().isoformat(timespec="seconds"),
    )

    assert len(normalized) == 1
    assert len(artifact_paths) == 1

    payload = json.loads((evidence_dir / "EV-001-BROKEN_ACCESS_CONTROL.json").read_text(encoding="utf-8"))
    assert payload["raw_request"].startswith("GET /api/state")
    assert payload["raw_response"].startswith("HTTP/1.1 200")
    assert payload["replay_command"].startswith("curl -i -X GET")
    assert payload["detector_verdict"]["detection_mode"] == "phase1"
    assert "authz_scenario:unauthenticated_api_access" in payload["key_signals"]

    additional = normalized[0].get("additional_info", {})
    assert additional.get("evidence_capture_status") == "full"
    assert additional.get("evidence_artifact_path")
    assert additional.get("replay_command")
