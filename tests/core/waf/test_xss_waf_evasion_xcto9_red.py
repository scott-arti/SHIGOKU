"""XCTO-9 (context-valid encoding filter) RED tests.

These tests codify the target behavior described in:
`docs/shigoku/plans/2026-05-24_sgk-2026-0244_xss-hunter-enhancement_plan.md` section 5.3.5.
They are expected to fail until XCTO-9 is implemented.
"""

from __future__ import annotations

import inspect

from src.core.payloads.xss_waf_evasion import XSSContext, XSSEncodingEngine


def test_xcto9_generate_variants_requires_context_argument():
    """5.3.5-architect: generate_variants must accept context for context-aware filtering."""
    sig = inspect.signature(XSSEncodingEngine.generate_variants)
    assert "context" in sig.parameters, "generate_variants(context=...) is required by XCTO-9"


def test_xcto9_generate_variants_supports_optional_context_for_backward_compatibility():
    """5.3.5-architect: context should be optional during migration phase."""
    sig = inspect.signature(XSSEncodingEngine.generate_variants)
    context_param = sig.parameters["context"]
    assert context_param.default is not inspect._empty, "context must be Optional-compatible in XCTO-9 migration"


def test_xcto9_context_valid_encoding_map_is_required():
    """5.3.5-architect: context × valid encoding mapping table must exist."""
    assert hasattr(XSSEncodingEngine, "_CONTEXT_VALID_ENCODINGS"), "_CONTEXT_VALID_ENCODINGS is required by XCTO-9"


def test_xcto9_context_mapping_covers_all_xss_contexts():
    """5.3.5-architect: every XSSContext must be registered in the mapping table."""
    mapping = getattr(XSSEncodingEngine, "_CONTEXT_VALID_ENCODINGS")
    for ctx in XSSContext:
        assert ctx in mapping, f"{ctx} must be registered in _CONTEXT_VALID_ENCODINGS"


def test_xcto9_script_block_excludes_url_encodings():
    """5.3.5-debugger: SCRIPT_BLOCK must not generate URL encodings."""
    variants = XSSEncodingEngine.generate_variants(
        "<script>alert(1)</script>",
        context=XSSContext.SCRIPT_BLOCK,
        max_variants=20,
    )
    assert "%3C" not in "".join(variants), "url/double_url encodings must be filtered out in SCRIPT_BLOCK"


def test_xcto9_json_value_keeps_unicode_encoding_variant():
    """5.3.5-debugger: JSON_VALUE should keep unicode variant."""
    variants = XSSEncodingEngine.generate_variants(
        "<script>alert(1)</script>",
        context=XSSContext.JSON_VALUE,
        max_variants=20,
    )
    assert any("\\u003c" in v.lower() for v in variants), "unicode encoding must remain for JSON_VALUE"


def test_xcto9_unknown_context_uses_fallback_allowlist():
    """5.3.5-sre: UNKNOWN context fallback must preserve broad encoding coverage."""
    variants = XSSEncodingEngine.generate_variants(
        "<script>alert(1)</script>",
        context=XSSContext.UNKNOWN,
        max_variants=20,
    )
    joined = "\n".join(variants).lower()
    assert "%3c" in joined, "UNKNOWN fallback should allow URL-style encoding"
    assert "&#x3c;" in joined or "&#60;" in joined, "UNKNOWN fallback should allow HTML entity/hex encoding"
    assert "\\u003c" in joined, "UNKNOWN fallback should allow unicode encoding"


def test_xcto9_supports_context_none_compatibility_mode():
    """5.3.5-debugger: context=None compatibility mode is required."""
    variants = XSSEncodingEngine.generate_variants("<svg/onload=alert(1)>", context=None, max_variants=5)
    assert variants, "context=None compatibility mode must work during rollout"


def test_xcto9_strict_context_filter_switch_is_required():
    """5.3.5-sre: strict_context_filter switch must exist for safe fallback/rollback behavior."""
    sig = inspect.signature(XSSEncodingEngine.generate_variants)
    assert "strict_context_filter" in sig.parameters, "strict_context_filter parameter is required by XCTO-9"


def test_xcto9_context_filter_mode_off_shadow_enforce_is_required():
    """5.3.5-sre: context_filter_mode off/shadow/enforce must be configurable."""
    assert hasattr(XSSEncodingEngine, "set_context_filter_mode"), "set_context_filter_mode() is required by XCTO-9"
    XSSEncodingEngine.set_context_filter_mode("shadow")
    mode = XSSEncodingEngine.get_context_filter_mode()
    assert mode == "shadow"


def test_xcto9_shadow_mode_sampling_and_output_cap_controls_are_required():
    """5.3.5-sre: shadow mode should expose sampling and max-output controls."""
    assert hasattr(XSSEncodingEngine, "set_shadow_log_sampling_rate")
    assert hasattr(XSSEncodingEngine, "set_shadow_log_max_records_per_run")


def test_xcto9_debug_diagnostics_fields_are_exposed():
    """5.3.5-debugger: diagnostics must contain filter decision fields."""
    assert hasattr(XSSEncodingEngine, "generate_variants_with_diagnostics")
    result = XSSEncodingEngine.generate_variants_with_diagnostics(
        "<img src=x onerror=alert(1)>",
        context=XSSContext.TAG_ATTRIBUTE,
        max_variants=10,
    )
    assert "before_count" in result
    assert "after_count" in result
    assert "decisions" in result
    assert result["decisions"], "diagnostic decisions are required"
    assert {"context", "candidate_encoding", "filtered_reason"}.issubset(result["decisions"][0].keys())


def test_xcto9_off_vs_enforce_snapshot_diff_api_is_required():
    """5.3.5-debugger: reproducible off/enforce diff snapshot API is required."""
    assert hasattr(XSSEncodingEngine, "build_variant_snapshot_diff")
    diff = XSSEncodingEngine.build_variant_snapshot_diff("<script>alert(1)</script>", context=XSSContext.SCRIPT_BLOCK)
    assert "off" in diff and "enforce" in diff and "removed" in diff


def test_xcto9_encoding_type_enum_is_required():
    """5.3.5-architect: encoding types should be enum-based, not raw strings."""
    assert hasattr(XSSEncodingEngine, "EncodingType"), "EncodingType enum is required by XCTO-9"


def test_xcto9_go_nogo_threshold_contract_is_required():
    """5.3.5-cto: go/no-go threshold contract for detection-rate guard must exist."""
    assert hasattr(XSSEncodingEngine, "evaluate_go_nogo"), "evaluate_go_nogo() contract is required by XCTO-9"
    verdict = XSSEncodingEngine.evaluate_go_nogo(
        baseline_detection_rate=0.80,
        current_detection_rate=0.79,
        allowed_drop_ratio=0.02,
    )
    assert "go" in verdict and "reason" in verdict


def test_xcto9_multi_sample_guard_contract_is_required():
    """5.3.5-cto: multi-sample-set validation contract must exist."""
    assert hasattr(XSSEncodingEngine, "validate_across_sample_sets"), "validate_across_sample_sets() is required by XCTO-9"
    report = XSSEncodingEngine.validate_across_sample_sets(sample_set_ids=["s1", "s2", "s3"])
    assert report.get("sample_sets") == 3

