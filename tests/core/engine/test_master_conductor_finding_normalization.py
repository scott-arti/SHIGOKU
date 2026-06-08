from src.core.engine.master_conductor import MasterConductor


def test_extract_findings_from_nested_payload_and_deduplicate():
    conductor = MasterConductor()
    payload = {
        "success": True,
        "data": {
            "finding": {"id": "f-1", "title": "A", "vuln_type": "broken_access_control"},
            "findings": [
                {"id": "f-1", "title": "A", "vuln_type": "broken_access_control"},
                {"id": "f-2", "title": "B", "vuln_type": "idor"},
            ],
        },
        "finding": {"id": "f-2", "title": "B", "vuln_type": "idor"},
    }

    findings = conductor._extract_findings_from_result_payload(payload)
    assert {f["id"] for f in findings} == {"f-1", "f-2"}


def test_augment_payload_with_findings_injects_findings_list():
    conductor = MasterConductor()
    payload = {
        "result": "success",
        "finding": {"id": "f-authz-1", "title": "AuthZ Differential", "vuln_type": "broken_access_control"},
    }

    augmented, findings = conductor._augment_payload_with_findings(payload)

    assert len(findings) == 1
    assert findings[0]["id"] == "f-authz-1"
    assert augmented["findings"][0]["id"] == "f-authz-1"
