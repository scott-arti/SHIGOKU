import json

from src.reporting.haddix_evidence_quality import HaddixEvidenceQualityValidator
from src.reporting.haddix_formatter import HaddixFormatter


def test_formatter_sorts_findings_by_quality_score_within_same_severity():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")

    formatter.add_finding_from_dict(
        {
            "title": "Weak high severity candidate",
            "severity": "high",
            "vuln_type": "xss",
            "target_url": "http://example.com/search?q=1",
            "confidence": 0.55,
            "summary": "No strong verification signal.",
            "additional_info": {},
        }
    )
    formatter.add_finding_from_dict(
        {
            "title": "Verified high severity candidate",
            "severity": "high",
            "vuln_type": "xss",
            "target_url": "http://example.com/search?q=2",
            "confidence": 0.92,
            "summary": "Reflection and payload confirmed.",
            "additional_info": {
                "tested_params": ["q"],
                "reflection_observed": True,
                "payloads_used": ["<script>alert(1)</script>"],
            },
        }
    )

    report = json.loads(formatter.format_json())
    titles = [item.get("title") for item in report.get("findings", [])]
    assert titles[:2] == [
        "Verified high severity candidate",
        "Weak high severity candidate",
    ]


def test_formatter_filters_low_signal_low_confidence_injection_finding():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")

    formatter.add_finding_from_dict(
        {
            "title": "Likely noise",
            "severity": "medium",
            "vuln_type": "xss",
            "target_url": "http://example.com/profile",
            "confidence": 0.2,
            "summary": "No verification signal.",
            "additional_info": {},
        }
    )
    formatter.add_finding_from_dict(
        {
            "title": "AuthZ differential",
            "severity": "medium",
            "vuln_type": "idor",
            "target_url": "http://example.com/api/user/1",
            "confidence": 0.2,
            "summary": "Non-injection finding should remain.",
            "additional_info": {},
        }
    )

    report = json.loads(formatter.format_json())
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["suppressed_low_signal"] == 1
    assert report["findings"][0]["title"] == "AuthZ differential"


def test_formatter_keeps_critical_injection_even_when_signal_is_thin():
    formatter = HaddixFormatter()
    formatter.set_target("http://example.com")

    formatter.add_finding_from_dict(
        {
            "title": "Critical XSS candidate",
            "severity": "critical",
            "vuln_type": "xss",
            "target_url": "http://example.com/",
            "confidence": 0.1,
            "summary": "Critical severity should not be auto-suppressed.",
            "additional_info": {},
        }
    )

    report = json.loads(formatter.format_json())
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["suppressed_low_signal"] == 0
    assert report["findings"][0]["title"] == "Critical XSS candidate"


# ---------------------------------------------------------------------------
# CORS Finding → レポーター出力テスト (A-2)
# ---------------------------------------------------------------------------

def _cors_finding_dict(**overrides) -> dict:
    base = {
        "title": "CORS Misconfiguration: origin_reflection_with_credentials",
        "severity": "high",
        "vuln_type": "cors_misconfiguration",
        "target_url": "http://api.example.com/data",
        "confidence": 0.95,
        "summary": "Origin https://evil.com was reflected in ACAO with ACAC: true",
        "additional_info": {
            "test_origin": "https://evil.com",
            "acao": "https://evil.com",
            "acac": "true",
            "misconfiguration": "origin_reflection_with_credentials",
            "tested_params": [],
            "poc_request": "GET /data HTTP/1.1\nOrigin: https://evil.com\n",
            "poc_response": "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://evil.com\nAccess-Control-Allow-Credentials: true\n",
        },
    }
    base.update(overrides)
    return base


def test_formatter_cors_finding_is_included_in_report():
    """CORS Finding がサプレスされずレポートに含まれること"""
    formatter = HaddixFormatter()
    formatter.set_target("http://api.example.com")
    formatter.add_finding_from_dict(_cors_finding_dict())

    report = json.loads(formatter.format_json())
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["suppressed_low_signal"] == 0
    finding = report["findings"][0]
    assert finding["vuln_type"] == "cors_misconfiguration"
    assert finding["severity"] == "high"


def test_formatter_cors_finding_poc_request_populated():
    """additional_info.poc_request が poc_request フィールドに反映されること"""
    formatter = HaddixFormatter()
    formatter.set_target("http://api.example.com")
    formatter.add_finding_from_dict(_cors_finding_dict())

    report = json.loads(formatter.format_json())
    finding = report["findings"][0]
    assert "Origin: https://evil.com" in (finding.get("poc_request") or ""), \
        f"poc_request should contain Origin header, got: {finding.get('poc_request')!r}"


def test_formatter_builds_poc_from_structured_file_upload_evidence():
    """Finding.evidence だけの File Upload でも品質ゲートが実証拠として扱えること"""
    formatter = HaddixFormatter()
    formatter.set_target("http://localhost:4280")

    formatter.add_finding_from_dict(
        {
            "title": "Unrestricted File Upload: Safe Canary Upload Probe",
            "severity": "high",
            "vuln_type": "file_upload",
            "target_url": "http://localhost:4280/vulnerabilities/upload/",
            "description": "Successfully uploaded 'probe_fixed.jpg' using Safe Canary Upload Probe technique.",
            "confidence": 0.9,
            "source_agent": "FileUploadSpecialist",
            "evidence": {
                "request_method": "POST",
                "request_url": "http://localhost:4280/vulnerabilities/upload/",
                "request_body": (
                    "multipart/form-data upload\n"
                    "uploaded=@probe_fixed.jpg; filename=probe_fixed.jpg; content_type=image/jpeg\n"
                    "MAX_FILE_SIZE=100000\n"
                    "Upload=Upload"
                ),
                "response_status": 200,
                "response_body": (
                    "Status: 200\n"
                    "Evidence: Server accepted 'probe_fixed.jpg' using Safe Canary Upload Probe; "
                    "retrieved at http://localhost:4280/hackable/uploads/probe_fixed.jpg"
                ),
            },
            "additional_info": {
                "payload": "probe_fixed.jpg",
                "file_upload_evidence": {
                    "upload_allowed": True,
                    "retrieved": True,
                    "retrieval_url": "http://localhost:4280/hackable/uploads/probe_fixed.jpg",
                    "retrieval_status": 200,
                    "safe_canary": True,
                },
            },
        }
    )

    finding = formatter._findings[0]
    assert "POST /vulnerabilities/upload/ HTTP/1.1" in finding.poc_request
    assert "probe_fixed.jpg" in finding.poc_request
    assert finding.poc_response.startswith("HTTP/1.1 200 OK")
    assert "retrieved at http://localhost:4280/hackable/uploads/probe_fixed.jpg" in finding.poc_response

    verdict = HaddixEvidenceQualityValidator().evaluate_finding(
        finding,
        current_status="candidate",
    )
    assert verdict.shadow_status == "confirmed"
    assert "payload_request_mismatch" not in verdict.reason_codes
    assert "synthetic_response_evidence" not in verdict.reason_codes
    assert "file_upload_impact_not_proven" not in verdict.reason_codes


def test_formatter_cors_cia_and_remediation_not_generic():
    """CORS Finding の CIA評価と修正方針が汎用フォールバックではないこと"""
    formatter = HaddixFormatter()
    formatter.set_target("http://api.example.com")
    formatter.add_finding_from_dict(_cors_finding_dict())

    md = formatter.format_markdown()
    assert "クロスオリジン" in md, "CIA評価に CORS 固有の文言が含まれること"
    assert "ホワイトリスト" in md, "修正方針に Origin ホワイトリストの記述が含まれること"
