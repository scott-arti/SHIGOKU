import json

from src.core.waf.detector import WAFDetector


def test_detect_cloudflare_with_signature_file(tmp_path):
    db = tmp_path / "waf_signatures.json"
    db.write_text(
        json.dumps(
            {
                "version": 1,
                "signatures": {
                    "cloudflare": {
                        "header_contains": ["cf-ray"],
                        "body_contains": ["attention required"],
                        "status_codes": [403],
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    detector = WAFDetector(signatures_path=str(db), threshold=0.2)
    result = detector.detect(
        status_code=403,
        headers={"CF-Ray": "abc123"},
        body="Attention Required",
    )

    assert result.waf_name == "cloudflare"
    assert result.is_blocked is True
    assert result.confidence >= 0.5


def test_missing_or_broken_db_uses_fallback(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{invalid json", encoding="utf-8")

    detector = WAFDetector(signatures_path=str(broken), threshold=0.2)
    result = detector.detect(
        status_code=403,
        headers={"x-amzn-requestid": "req"},
        body="request blocked",
    )

    assert result.waf_name in {"aws_waf", None}
    assert result.is_blocked is True


def test_block_status_without_signature():
    detector = WAFDetector(signatures_path="nonexistent.json", threshold=0.9)
    result = detector.detect(
        status_code=403,
        headers={},
        body="forbidden",
    )

    assert result.waf_name is None
    assert result.is_blocked is True
    assert result.reason in {"block_status_without_signature", "no_waf_signal"}


def test_signature_match_without_block_status_is_not_blocked(tmp_path):
    db = tmp_path / "waf_signatures.json"
    db.write_text(
        json.dumps(
            {
                "version": 1,
                "signatures": {
                    "cloudflare": {
                        "header_contains": ["cf-ray"],
                        "body_contains": [],
                        "status_codes": [403],
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    detector = WAFDetector(signatures_path=str(db), threshold=0.2)
    result = detector.detect(
        status_code=200,
        headers={"CF-Ray": "abc123"},
        body="ok",
    )

    assert result.waf_name == "cloudflare"
    assert result.reason == "signature_match"
    assert result.is_blocked is False

