from src.dashboard.api.main import (
    _calculate_unknown_skip_reason_alert,
    _calculate_skip_reason_other_ratio,
    _extract_low_ssrf_top_missing_feature,
    _aggregate_low_ssrf_score_breakdown,
    _aggregate_skip_reason_unknown_counts,
    _aggregate_skip_reason_counts,
)


def test_aggregate_skip_reason_counts_prefers_summary_counts():
    session_data = {
        "completed_tasks": [
            {
                "result": {
                    "data": {
                        "execution_log": [
                            {"phase": "phase1_summary", "skip_reason_counts": {"low_ssrf_score": 2, "other": 1}}
                        ]
                    }
                }
            }
        ]
    }
    out = _aggregate_skip_reason_counts(session_data)
    assert out["low_ssrf_score"] == 2
    assert out["other"] == 1


def test_aggregate_skip_reason_counts_fallbacks_from_url_results():
    session_data = {
        "completed_tasks": [
            {
                "result": {
                    "data": {
                        "execution_log": [
                            {
                                "phase": "phase1_summary",
                                "url_results": [
                                    {"status": "skipped", "skip_reason": "ssrf_reachability_gate"},
                                    {"status": "skipped", "skip_reason": "dedupe_execution_key"},
                                    {"status": "completed"},
                                ],
                            }
                        ]
                    }
                }
            }
        ]
    }
    out = _aggregate_skip_reason_counts(session_data)
    assert out["ssrf_reachability_gate"] == 1
    assert out["dedupe_execution_key"] == 1


def test_aggregate_low_ssrf_score_breakdown_prefers_summary_breakdown():
    session_data = {
        "completed_tasks": [
            {
                "result": {
                    "data": {
                        "execution_log": [
                            {
                                "phase": "phase1_summary",
                                "low_ssrf_score_breakdown": {
                                    "query_url_param": 3,
                                    "graphql_variables": 2,
                                },
                            }
                        ]
                    }
                }
            }
        ]
    }
    out = _aggregate_low_ssrf_score_breakdown(session_data)
    assert out["query_url_param"] == 3
    assert out["graphql_variables"] == 2


def test_aggregate_low_ssrf_score_breakdown_fallbacks_from_url_results():
    session_data = {
        "completed_tasks": [
            {
                "result": {
                    "data": {
                        "execution_log": [
                            {
                                "phase": "phase1_summary",
                                "url_results": [
                                    {
                                        "status": "skipped",
                                        "skip_reason": "low_ssrf_score",
                                        "score_breakdown": {
                                            "query_url_param": 0,
                                            "header_context": 0,
                                            "path_context": 10,
                                        },
                                    },
                                    {
                                        "status": "skipped",
                                        "skip_reason": "low_ssrf_score",
                                        "score_breakdown": {
                                            "query_url_param": 0,
                                            "header_context": 5,
                                        },
                                    },
                                ],
                            }
                        ]
                    }
                }
            }
        ]
    }
    out = _aggregate_low_ssrf_score_breakdown(session_data)
    assert out["query_url_param"] == 2
    assert out["header_context"] == 1


def test_calculate_skip_reason_other_ratio():
    ratio = _calculate_skip_reason_other_ratio({"other": 2, "low_ssrf_score": 6})
    assert ratio == 0.25


def test_extract_low_ssrf_top_missing_feature():
    top = _extract_low_ssrf_top_missing_feature(
        {"query_url_param": 3, "header_context": 1}
    )
    assert top == "query_url_param"


def test_aggregate_skip_reason_unknown_counts_prefers_summary():
    session_data = {
        "completed_tasks": [
            {
                "result": {
                    "data": {
                        "execution_log": [
                            {
                                "phase": "phase1_summary",
                                "skip_reason_unknown_counts": {
                                    "dns_resolution_failed": 2,
                                    "waf_blocked": 1,
                                },
                            }
                        ]
                    }
                }
            }
        ]
    }
    out = _aggregate_skip_reason_unknown_counts(session_data)
    assert out["dns_resolution_failed"] == 2
    assert out["waf_blocked"] == 1


def test_aggregate_skip_reason_unknown_counts_fallback_from_url_results():
    session_data = {
        "completed_tasks": [
            {
                "result": {
                    "data": {
                        "execution_log": [
                            {
                                "phase": "phase1_summary",
                                "url_results": [
                                    {"status": "skipped", "skip_reason": "dns_resolution_failed"},
                                    {"status": "skipped", "skip_reason": "dns_resolution_failed"},
                                    {"status": "skipped", "skip_reason": "low_ssrf_score"},
                                ],
                            }
                        ]
                    }
                }
            }
        ]
    }
    out = _aggregate_skip_reason_unknown_counts(session_data)
    assert out["dns_resolution_failed"] == 2
    assert "low_ssrf_score" not in out


def test_aggregate_skip_reason_unknown_counts_applies_normalization_alias():
    session_data = {
        "completed_tasks": [
            {
                "result": {
                    "data": {
                        "execution_log": [
                            {
                                "phase": "phase1_summary",
                                "url_results": [
                                    {"status": "skipped", "skip_reason": "timeout_circuit_open"},
                                ],
                            }
                        ]
                    }
                }
            }
        ]
    }
    out = _aggregate_skip_reason_unknown_counts(session_data)
    # alias resolves to known reason, so unknown bucket should be empty
    assert out == {}


def test_calculate_unknown_skip_reason_alert_triggered_on_count_and_ratio():
    out = _calculate_unknown_skip_reason_alert(
        {"low_ssrf_score": 10},
        {"dns_resolution_failed": 5},
    )
    assert out["triggered"] is True
    assert out["unknown_count"] == 5


def test_calculate_unknown_skip_reason_alert_not_triggered_when_ratio_low():
    out = _calculate_unknown_skip_reason_alert(
        {"low_ssrf_score": 95},
        {"dns_resolution_failed": 5},
    )
    assert out["triggered"] is False
