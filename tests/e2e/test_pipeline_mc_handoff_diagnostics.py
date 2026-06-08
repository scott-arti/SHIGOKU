from __future__ import annotations

from tests.e2e.test_pipeline_mc_handoff import summarize_httpx_failures


def test_summarize_httpx_failures_reports_timeout_summary() -> None:
    diagnostics = summarize_httpx_failures(
        [
            {"url": "http://target/a", "failed": True, "error_type": "connect_timeout", "error_message": "connect timeout during request"},
            {"url": "http://target/b", "failed": True, "error_type": "connect_timeout", "error_message": "connect timeout during request"},
        ]
    )

    assert diagnostics["failure_count"] == 2
    assert diagnostics["failure_summary"] == {"connect_timeout": 2}
    assert diagnostics["input_quality_warning"] is None


def test_summarize_httpx_failures_warns_when_invalid_url_dominates() -> None:
    diagnostics = summarize_httpx_failures(
        [
            {"url": f"bad-{index}", "failed": True, "error_type": "invalid_url", "error_message": "input URL is invalid or malformed"}
            for index in range(5)
        ]
        + [
            {"url": "http://target", "failed": True, "error_type": "connect_timeout", "error_message": "connect timeout during request"}
        ]
    )

    assert diagnostics["failure_summary"]["invalid_url"] == 5
    assert diagnostics["input_quality_warning"] is not None
    assert "input URL quality" in diagnostics["input_quality_warning"]
