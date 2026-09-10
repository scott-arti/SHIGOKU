"""
SGK-2026-0480 — payout_grade file_upload（任意ファイル設置＋Web 取得）確定バー
単体テスト。

PRODUCT-INDEPENDENT fixtures のみ（target.example・汎用良性マーカー）。
- (a) file_upload_evidence 完備（upload_allowed/retrieved/retrieval_marker/
      retrieval_url）＋ impact/repro → payout_grade=True / marker=
      uploaded_file_retrieved
- (b) retrieved 偽 → False（fail-closed）
- (c) retrieval_marker 空 → False（fail-closed）
- (d) 他 vuln_type（sqli/xss）の判定は非回帰
"""
from __future__ import annotations

from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade

UPLOAD_URL = "https://target.example/upload"
RETRIEVAL_URL = "https://target.example/uploads/probe_a1b2c3d4e5f60718.txt"
MARKER = "SHIGOKU_PROBE_a1b2c3d4e5f60718"


def _file_upload_evidence(**overrides) -> dict:
    evidence = {
        "upload_allowed": True,
        "retrieved": True,
        "retrieval_url": RETRIEVAL_URL,
        "retrieval_status": 200,
        "execution_observed": False,
        "safe_canary": True,
        "mime_type": "image/jpeg",
        "technique": "Safe Canary Upload Probe",
        "retrieval_marker": MARKER,
    }
    evidence.update(overrides)
    return evidence


def _file_upload_finding(**overrides) -> dict:
    payload = {
        "vuln_type": "file_upload",
        "evidence": {
            "request_method": "POST",
            "request_url": UPLOAD_URL,
            "response_status": 200,
            "response_body": (
                "Status: 200\nEvidence: retrieved\n\n"
                f"Retrieval Marker: {MARKER}\nRetrieval URL: {RETRIEVAL_URL}"
            ),
        },
        "additional_info": {
            "file_upload_evidence": _file_upload_evidence(),
        },
        "impact": "認証境界内で任意の非実行ファイルをサーバへ設置し Web から取得可能。",
        "reproduction_steps": [
            "Upload a benign file carrying a unique marker.",
            "GET the retrieval URL and observe the same marker.",
        ],
    }
    payload.update(overrides)
    return payload


def _sqli_finding() -> dict:
    return {
        "vuln_type": "sqli",
        "evidence": {
            "request_method": "GET",
            "request_url": "https://target.example/item?id=1'",
            "response_status": 200,
            "response_body": "Fatal error: SQL syntax near '1'",
        },
        "additional_info": {},
        "impact": "Database error disclosure.",
        "reproduction_steps": ["Send the crafted id value."],
    }


def _xss_finding() -> dict:
    return {
        "vuln_type": "xss",
        "evidence": {
            "request_method": "GET",
            "request_url": "https://target.example/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "response_status": 200,
            "response_body": "<html><script>alert(1)</script></html>",
        },
        "additional_info": {},
        "impact": "Session theft via reflected XSS.",
        "reproduction_steps": ["Visit the crafted URL."],
    }


class TestFileUploadPayoutGrade:
    def test_complete_evidence_is_payout_grade(self) -> None:
        """(a) file_upload_evidence 完備＋ impact/repro → True /
        uploaded_file_retrieved."""
        result = evaluate_payout_grade(_file_upload_finding())
        assert result.payout_grade is True
        assert result.marker == "uploaded_file_retrieved"
        assert result.reason == "payout_grade_satisfied"

    def test_retrieved_false_fails_closed(self) -> None:
        """(b) retrieved 偽 → False（no_firing_marker・marker None）。"""
        evidence = _file_upload_evidence(retrieved=False)
        result = evaluate_payout_grade(
            _file_upload_finding(
                additional_info={"file_upload_evidence": evidence}
            )
        )
        assert result.payout_grade is False
        assert result.marker is None
        assert result.reason == "no_firing_marker"

    def test_retrieval_marker_empty_fails_closed(self) -> None:
        """(c) retrieval_marker 空 → False（fail-closed）。"""
        evidence = _file_upload_evidence(retrieval_marker="")
        result = evaluate_payout_grade(
            _file_upload_finding(
                additional_info={"file_upload_evidence": evidence}
            )
        )
        assert result.payout_grade is False
        assert result.marker is None
        assert result.reason == "no_firing_marker"

    def test_retrieval_url_empty_fails_closed(self) -> None:
        evidence = _file_upload_evidence(retrieval_url="")
        result = evaluate_payout_grade(
            _file_upload_finding(
                additional_info={"file_upload_evidence": evidence}
            )
        )
        assert result.payout_grade is False
        assert result.marker is None
        assert result.reason == "no_firing_marker"

    def test_upload_allowed_false_fails_closed(self) -> None:
        evidence = _file_upload_evidence(upload_allowed=False)
        result = evaluate_payout_grade(
            _file_upload_finding(
                additional_info={"file_upload_evidence": evidence}
            )
        )
        assert result.payout_grade is False
        assert result.marker is None
        assert result.reason == "no_firing_marker"

    def test_missing_file_upload_evidence_fails_closed(self) -> None:
        result = evaluate_payout_grade(
            _file_upload_finding(additional_info={})
        )
        assert result.payout_grade is False
        assert result.marker is None
        assert result.reason == "no_firing_marker"

    def test_missing_impact_still_fails_closed(self) -> None:
        """file_upload でも impact/repro 要件は不変（missing_impact・
        マーカー発火後も確定しない）。"""
        result = evaluate_payout_grade(_file_upload_finding(impact=""))
        assert result.payout_grade is False
        assert result.reason == "missing_impact"


class TestOtherCategoriesNonRegression:
    def test_sqli_still_fires(self) -> None:
        result = evaluate_payout_grade(_sqli_finding())
        assert result.payout_grade is True
        assert result.marker == "sql_error"

    def test_xss_still_fires(self) -> None:
        result = evaluate_payout_grade(_xss_finding())
        assert result.payout_grade is True
        assert result.marker == "reflected_payload"
