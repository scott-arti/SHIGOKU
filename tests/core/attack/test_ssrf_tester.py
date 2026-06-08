from src.core.attack.ssrf_tester import SSRFTester, SSRFPayloadType
import httpx
from pathlib import Path


def test_analyze_response_detects_imdsv2_401_token_required():
    tester = SSRFTester()
    body = "401 Unauthorized: X-aws-ec2-metadata-token is required for metadata access"
    result = tester._analyze_response(body, SSRFPayloadType.CLOUD_METADATA)
    assert result["vulnerable"] is True
    assert result["matched_variant_source"] in {"indicator", "heuristic"}


def test_check_final_destination_detects_decimal_localhost_variant():
    tester = SSRFTester()
    body = "Fetched from: http://2130706433/admin"
    matched = tester._check_final_destination(
        body,
        SSRFPayloadType.LOCALHOST,
        "http://127.0.0.1/admin",
    )
    assert matched == "2130706433"


def test_check_final_destination_returns_false_for_unrelated_body():
    tester = SSRFTester()
    body = "safe endpoint response"
    assert tester._check_final_destination(
        body,
        SSRFPayloadType.CLOUD_METADATA,
        "http://169.254.169.254/latest/meta-data/",
    ) == ""


def test_score_confidence_has_fixed_breakdown_schema():
    tester = SSRFTester()
    req = httpx.Request("GET", "https://example.com")
    baseline = httpx.Response(404, request=req, text="not found")
    response = httpx.Response(200, request=req, text="instance-id i-123")
    scored = tester._score_confidence(
        vuln_meta={
            "vulnerable": True,
            "matched_variant": "instance-id",
            "matched_variant_source": "indicator",
        },
        payload_type=SSRFPayloadType.CLOUD_METADATA,
        payload="http://169.254.169.254/latest/meta-data/",
        response=response,
        baseline_response=baseline,
    )
    assert scored["breakdown"]
    for item in scored["breakdown"]:
        assert "schema_version" in item
        assert item["schema_version"] == tester.CONFIDENCE_SCHEMA_VERSION
        assert {"signal", "weight", "observed", "subtotal", "reason_code"} <= set(item.keys())


def test_open_redirect_only_penalty_and_internal_recovery():
    tester = SSRFTester()
    assert (
        tester._is_open_redirect_only(
            payload="http://example.com/a",
            redirect_chain=["http://redirector.test/r"],
            destination_class="public",
            matched_variant="",
        )
        is True
    )
    assert (
        tester._has_internal_recovery_signal(
            payload_type=SSRFPayloadType.CLOUD_METADATA,
            destination_class="internal",
            matched_source="",
            final_url="http://example.com",
        )
        is True
    )


def test_baseline_size_threshold_is_payload_type_specific():
    tester = SSRFTester()
    assert tester._baseline_size_threshold(SSRFPayloadType.CLOUD_METADATA) == 80
    assert tester._baseline_size_threshold(SSRFPayloadType.LOCALHOST) == 200


def test_load_quality_config_from_features_overrides_defaults(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    features_yaml = config_dir / "features.yaml"
    features_yaml.write_text(
        """
features:
  phase3:
    ssrf_quality:
      enabled: true
      confidence_threshold: 4.5
      baseline_probe: "custom_probe"
      baseline_size_diff_threshold_by_type:
        cloud_metadata: 99
      confidence_weights:
        indicator_hit: 9.0
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    tester = SSRFTester()
    assert tester.CONFIDENCE_THRESHOLD == 4.5
    assert tester.BASELINE_PROBE == "custom_probe"
    assert tester._baseline_size_threshold(SSRFPayloadType.CLOUD_METADATA) == 99
    assert tester.CONFIDENCE_WEIGHTS["indicator_hit"] == 9.0
