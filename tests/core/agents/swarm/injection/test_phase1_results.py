from src.core.agents.swarm.injection.manager_internal.phase1_results import (
    collect_phase1_vuln_types,
    extract_max_ssrf_score,
    has_actionable_blind_signal,
    summarize_low_ssrf_score_breakdown,
    summarize_skip_reason_counts,
    summarize_skip_reason_unknown_counts,
)


def test_has_actionable_blind_signal_correlated() -> None:
    blind = {
        "correlated": True,
        "time_based": {"confirmed": False},
        "oob": {"confirmed": False},
        "dns": {"confirmed": False},
    }
    assert has_actionable_blind_signal(blind) is True


def test_has_actionable_blind_signal_time_based() -> None:
    blind = {
        "correlated": False,
        "time_based": {"confirmed": True},
        "oob": {},
        "dns": {},
    }
    assert has_actionable_blind_signal(blind) is True


def test_has_actionable_blind_signal_oob_confirmed() -> None:
    blind = {
        "correlated": False,
        "time_based": {},
        "oob": {"confirmed": True},
        "dns": {},
    }
    assert has_actionable_blind_signal(blind) is True


def test_has_actionable_blind_signal_oob_hits() -> None:
    blind = {
        "correlated": False,
        "time_based": {},
        "oob": {"confirmed": False, "hits": ["hit1"]},
        "dns": {},
    }
    assert has_actionable_blind_signal(blind) is True


def test_has_actionable_blind_signal_dns_confirmed() -> None:
    blind = {
        "correlated": False,
        "time_based": {},
        "oob": {},
        "dns": {"confirmed": True},
    }
    assert has_actionable_blind_signal(blind) is True


def test_has_actionable_blind_signal_dns_hits() -> None:
    blind = {
        "correlated": False,
        "time_based": {},
        "oob": {},
        "dns": {"confirmed": False, "hits": ["hit1"]},
    }
    assert has_actionable_blind_signal(blind) is True


def test_has_actionable_blind_signal_none() -> None:
    assert has_actionable_blind_signal(None) is False


def test_has_actionable_blind_signal_empty_dict() -> None:
    assert has_actionable_blind_signal({}) is False


def test_has_actionable_blind_signal_no_signal() -> None:
    assert has_actionable_blind_signal(
        {"correlated": False, "time_based": {}, "oob": {}, "dns": {}}
    ) is False


def test_has_actionable_blind_signal_non_dict() -> None:
    assert has_actionable_blind_signal("not_a_dict") is False
    assert has_actionable_blind_signal(42) is False
    assert has_actionable_blind_signal([]) is False


def test_summarize_skip_reason_counts_known_reasons() -> None:
    results = [
        {"status": "skipped", "skip_reason": "low_ssrf_score"},
        {"status": "skipped", "skip_reason": "low_ssrf_score"},
        {"status": "skipped", "skip_reason": "ssrf_reachability_gate"},
        {"status": "completed", "vuln_type": "xss"},
    ]
    counts = summarize_skip_reason_counts(results)
    assert counts.get("low_ssrf_score") == 2
    assert counts.get("ssrf_reachability_gate") == 1


def test_summarize_skip_reason_counts_unknown_to_other() -> None:
    results = [{"status": "skipped", "skip_reason": "random_unknown_reason_xyz"}]
    counts = summarize_skip_reason_counts(results)
    assert "other" in counts
    assert counts["other"] == 1


def test_summarize_skip_reason_counts_ignores_non_skipped() -> None:
    results = [
        {"status": "completed", "skip_reason": "low_ssrf_score"},
        {"status": "error"},
        None,
    ]
    counts = summarize_skip_reason_counts(results)
    assert counts == {}


def test_summarize_skip_reason_counts_empty() -> None:
    assert summarize_skip_reason_counts([]) == {}


def test_summarize_skip_reason_unknown_counts_basic() -> None:
    results = [
        {"status": "skipped", "skip_reason": "low_ssrf_score"},
        {"status": "skipped", "skip_reason": "random_unknown_reason_xyz"},
        {"status": "skipped", "skip_reason": "another_unknown"},
        {"status": "skipped", "skip_reason": "no_injection_point"},
        {"status": "completed"},
    ]
    counts = summarize_skip_reason_unknown_counts(results)
    assert "low_ssrf_score" not in counts
    assert counts.get("random_unknown_reason_xyz") == 1
    assert counts.get("another_unknown") == 1
    assert counts.get("no_injection_point") == 1


def test_summarize_skip_reason_unknown_counts_all_known() -> None:
    results = [
        {"status": "skipped", "skip_reason": "low_ssrf_score"},
        {"status": "skipped", "skip_reason": "ssrf_reachability_gate"},
    ]
    counts = summarize_skip_reason_unknown_counts(results)
    assert counts == {}


def test_summarize_skip_reason_unknown_counts_empty() -> None:
    assert summarize_skip_reason_unknown_counts([]) == {}


def test_summarize_low_ssrf_score_breakdown_missing_features() -> None:
    results = [
        {
            "status": "skipped",
            "skip_reason": "low_ssrf_score",
            "score_breakdown": {"param_count": 0, "url_like_keys": 0},
        },
        {
            "status": "skipped",
            "skip_reason": "low_ssrf_score",
            "score_breakdown": {"param_count": 5, "url_like_keys": 20},
        },
    ]
    breakdown = summarize_low_ssrf_score_breakdown(results)
    assert breakdown.get("param_count") == 1
    assert breakdown.get("url_like_keys") == 1


def test_summarize_low_ssrf_score_breakdown_ignores_non_ssrf() -> None:
    results = [
        {"status": "skipped", "skip_reason": "ssrf_reachability_gate",
         "score_breakdown": {"param_count": 0}},
        {"status": "skipped", "skip_reason": "low_ssrf_score",
         "score_breakdown": {"param_count": 0}},
    ]
    breakdown = summarize_low_ssrf_score_breakdown(results)
    assert breakdown.get("param_count") == 1


def test_summarize_low_ssrf_score_breakdown_empty() -> None:
    assert summarize_low_ssrf_score_breakdown([]) == {}


def test_extract_max_ssrf_score_basic() -> None:
    results = [
        {"ssrf_score": 30},
        {"ssrf_score": 65},
        {"ssrf_score": 20},
        {"no_score": True},
        None,
    ]
    assert extract_max_ssrf_score(results) == 65


def test_extract_max_ssrf_score_empty() -> None:
    assert extract_max_ssrf_score([]) == 0


def test_extract_max_ssrf_score_all_zero() -> None:
    results = [{"ssrf_score": 0}, {"ssrf_score": 0}]
    assert extract_max_ssrf_score(results) == 0


def test_collect_phase1_vuln_types_basic() -> None:
    results = [
        {"vuln_type": "xss"},
        {"vuln_type": "sqli"},
        {"vuln_type": "xss"},
        {"vuln_type": "lfi"},
        {"no_type": True},
        None,
    ]
    vuln_types = collect_phase1_vuln_types(results)
    assert vuln_types == {"xss", "sqli", "lfi"}


def test_collect_phase1_vuln_types_empty() -> None:
    assert collect_phase1_vuln_types([]) == set()


def test_collect_phase1_vuln_types_empty_string_skipped() -> None:
    results = [
        {"vuln_type": ""},
        {"vuln_type": "  "},
        {"other": True},
    ]
    assert collect_phase1_vuln_types(results) == set()
