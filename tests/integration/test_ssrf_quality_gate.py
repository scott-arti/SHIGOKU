import httpx

from src.core.attack.ssrf_tester import SSRFTester, SSRFPayloadType


def _make_response(url: str, status: int, text: str, history=None):
    req = httpx.Request("GET", url)
    return httpx.Response(status, request=req, text=text, history=history or [])


def test_ssrf_quality_gate_kpi_fp_zero_on_open_redirect_only():
    tester = SSRFTester()
    baseline = _make_response("https://target.test/path", 200, "generic 404 page")
    redirect_hop = _make_response("https://redirector.test/jump", 302, "redirect")
    response = _make_response("https://public.example/landing", 200, "generic 404 page", history=[redirect_hop])

    scored = tester._score_confidence(
        vuln_meta={"vulnerable": False, "matched_variant": "", "matched_variant_source": ""},
        payload_type=SSRFPayloadType.LOCALHOST,
        payload="http://127.0.0.1/admin",
        response=response,
        baseline_response=baseline,
    )

    assert scored["score"] < tester.CONFIDENCE_THRESHOLD


def test_ssrf_quality_gate_kpi_detection_kept_for_strong_metadata_signal():
    tester = SSRFTester()
    baseline = _make_response("https://target.test/path", 404, "not found")
    response = _make_response(
        "http://169.254.169.254/latest/meta-data/instance-id",
        200,
        "instance-id i-abc123\nmetadata token required",
    )

    scored = tester._score_confidence(
        vuln_meta={
            "vulnerable": True,
            "matched_variant": "instance-id",
            "matched_variant_source": "indicator",
        },
        payload_type=SSRFPayloadType.CLOUD_METADATA,
        payload="http://169.254.169.254/latest/meta-data/instance-id",
        response=response,
        baseline_response=baseline,
    )

    assert scored["score"] >= tester.CONFIDENCE_THRESHOLD


def test_ssrf_quality_gate_kpi_breakdown_schema_completeness():
    tester = SSRFTester()
    baseline = _make_response("https://target.test/path", 404, "not found")
    response = _make_response("http://metadata.google.internal/computeMetadata/v1/", 401, "metadata token")

    scored = tester._score_confidence(
        vuln_meta={
            "vulnerable": True,
            "matched_variant": "metadata",
            "matched_variant_source": "indicator",
        },
        payload_type=SSRFPayloadType.CLOUD_METADATA,
        payload="http://metadata.google.internal/computeMetadata/v1/",
        response=response,
        baseline_response=baseline,
    )

    for row in scored["breakdown"]:
        assert set(["schema_version", "signal", "weight", "observed", "subtotal", "reason_code"]).issubset(row.keys())
        assert row["schema_version"] == tester.CONFIDENCE_SCHEMA_VERSION
