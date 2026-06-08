"""XCTO-5 (Stage separation) RED tests.

These tests intentionally codify the target behavior described in
`docs/shigoku/plans/2026-05-24_xss-hunter-enhancement_plan.md` section 5.3.
They are expected to fail until XCTO-5 is implemented.
"""

from __future__ import annotations

import pytest

from src.core.detection.dom_xss_detector import DOMXSSDetector, DOMXSSFinding
from src.core.detection.xss_pipeline import XSSDetectionPipeline


class _SplitDetectorStub:
    def __init__(self, static_findings=None, dynamic_findings=None, dynamic_exc: Exception | None = None):
        self._static = static_findings or []
        self._dynamic = dynamic_findings or []
        self._dynamic_exc = dynamic_exc

    async def run_static_only(self, target_url: str):
        return list(self._static)

    async def run_dynamic_only(self, target_url: str, options: dict):
        if self._dynamic_exc:
            raise self._dynamic_exc
        return list(self._dynamic)

    # Current implementation path in xss_pipeline.py (kept for RED demonstration)
    async def detect_dom_xss(self, target_url: str, options: dict):
        return []


class _VerifyRecorder:
    def __init__(self):
        self.calls = []

    async def __call__(self, findings, *, max_tasks: int, dialog_timeout: float):
        self.calls.append({
            "count": len(findings),
            "max_tasks": max_tasks,
            "dialog_timeout": dialog_timeout,
        })
        return [], [f.to_dict() for f in findings]


def _mk_finding(url: str, param: str, payload: str = "<svg/onload=1>", source_tool: str = "dalfox") -> DOMXSSFinding:
    return DOMXSSFinding(
        type="dom_xss",
        target=url,
        parameter=param,
        payload=payload,
        url=url,
        confidence=0.7,
        source_tool=source_tool,
    )


@pytest.mark.asyncio
async def test_xcto5_stage_contract_methods_are_required():
    """5.3.2: run_static_only/run_dynamic_only stage contract must exist."""
    detector = DOMXSSDetector()
    assert hasattr(detector, "run_static_only"), "run_static_only() is required by XCTO-5"
    assert hasattr(detector, "run_dynamic_only"), "run_dynamic_only() is required by XCTO-5"


@pytest.mark.asyncio
async def test_xcto5_static_candidate_normalization_api_is_required():
    """5.3.2: static candidates must be normalized into DOMXSSFinding."""
    assert hasattr(DOMXSSDetector, "from_static_candidate"), "from_static_candidate() is required by XCTO-5"


@pytest.mark.asyncio
async def test_xcto5_keeps_static_candidates_when_dalfox_returns_zero():
    """5.3.1/5.3.3/5.3.4: DalFox 0件でも static は candidate_findings に残る。"""
    static_findings = [_mk_finding("https://app.test/#/search?q=1", "q", payload="", source_tool="static_analysis")]

    pipeline = XSSDetectionPipeline(enable_browser_verify=False)
    pipeline._dom_detector = _SplitDetectorStub(static_findings=static_findings, dynamic_findings=[])

    result = await pipeline.run("https://app.test/#/search?q=1")

    assert len(result.candidate_findings) >= len(static_findings)
    assert result.pipeline_metrics.get("static_candidates_count") == 1
    assert result.pipeline_metrics.get("dynamic_findings_count") == 0


@pytest.mark.asyncio
async def test_xcto5_records_dalfox_timeout_and_preserves_static_candidates():
    """5.3.1: DalFox timeout/error metrics and fail-soft behavior are required."""
    static_findings = [_mk_finding("https://app.test/#/items", "hash_route", payload="", source_tool="static_analysis")]

    pipeline = XSSDetectionPipeline(enable_browser_verify=False)
    pipeline._dom_detector = _SplitDetectorStub(
        static_findings=static_findings,
        dynamic_findings=[],
        dynamic_exc=TimeoutError("dalfox timeout"),
    )

    result = await pipeline.run("https://app.test/#/items")

    assert len(result.candidate_findings) >= 1
    assert result.pipeline_metrics.get("dalfox_timeout_count") == 1
    assert result.pipeline_metrics.get("dalfox_error_count") == 1


@pytest.mark.asyncio
async def test_xcto5_static_candidate_verify_cap_is_required():
    """5.3.1: max_static_candidates_for_verify should cap verification load."""
    static_findings = [_mk_finding(f"https://app.test/#/route/{i}", f"p{i}", source_tool="static_analysis") for i in range(12)]

    recorder = _VerifyRecorder()
    pipeline = XSSDetectionPipeline(enable_browser_verify=True)
    pipeline._dom_detector = _SplitDetectorStub(static_findings=static_findings, dynamic_findings=[])
    pipeline._verify_with_pool = recorder

    await pipeline.run(
        "https://app.test/#/route",
        options={
            "max_static_candidates_for_verify": 5,
            "max_verify_tasks": 50,
        },
    )

    assert recorder.calls, "verification should be invoked for capped static candidates"
    assert recorder.calls[0]["count"] == 5


@pytest.mark.asyncio
async def test_xcto5_case_matrix_static_dynamic_merge_and_metrics():
    """5.3.3: mandatory matrix case (static+dynamic merge with dedupe) and metric checks."""
    static_findings = [
        _mk_finding("https://app.test/#/search?q=1", "q", payload="", source_tool="static_analysis"),
    ]
    dynamic_findings = [
        _mk_finding("https://app.test/#/search?q=1", "q", payload="<img src=x onerror=alert(1)>", source_tool="dalfox"),
    ]

    pipeline = XSSDetectionPipeline(enable_browser_verify=False)
    pipeline._dom_detector = _SplitDetectorStub(static_findings=static_findings, dynamic_findings=dynamic_findings)

    result = await pipeline.run("https://app.test/#/search?q=1")

    assert len(result.candidate_findings) == 1, "duplicate URL should be merged into one candidate"
    assert result.pipeline_metrics.get("candidate_findings_count") == 1


@pytest.mark.asyncio
async def test_xcto5_case_matrix_dalfox_exception_fallback_to_static():
    """5.3.3: mandatory matrix case (DalFox exception fallback)."""
    static_findings = [_mk_finding("https://app.test/#/profile", "hash_route", payload="", source_tool="static_analysis")]

    pipeline = XSSDetectionPipeline(enable_browser_verify=False)
    pipeline._dom_detector = _SplitDetectorStub(
        static_findings=static_findings,
        dynamic_findings=[],
        dynamic_exc=RuntimeError("dalfox failed"),
    )

    result = await pipeline.run("https://app.test/#/profile")

    assert len(result.candidate_findings) == 1
    assert result.candidate_findings[0]["source_tool"] == "static_analysis"


@pytest.mark.asyncio
async def test_xcto5_completion_criterion_candidate_ge_static_on_dalfox_zero():
    """5.3.4: completion criterion codified as test."""
    static_findings = [
        _mk_finding("https://app.test/#/r1", "r1", payload="", source_tool="static_analysis"),
        _mk_finding("https://app.test/#/r2", "r2", payload="", source_tool="static_analysis"),
    ]

    pipeline = XSSDetectionPipeline(enable_browser_verify=False)
    pipeline._dom_detector = _SplitDetectorStub(static_findings=static_findings, dynamic_findings=[])

    result = await pipeline.run("https://app.test/#/r")

    assert len(result.candidate_findings) >= 2
