from src.core.agents.swarm.injection.manager import InjectionManagerAgent


def test_injection_manager_has_actionable_blind_signal_correlated() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    blind = {
        "correlated": True,
        "time_based": {"confirmed": False},
        "oob": {"confirmed": False},
        "dns": {"confirmed": False},
    }
    assert manager._has_actionable_blind_signal(blind) is True


def test_injection_manager_has_actionable_blind_signal_time_based() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    blind = {
        "correlated": False,
        "time_based": {"confirmed": True},
        "oob": {},
        "dns": {},
    }
    assert manager._has_actionable_blind_signal(blind) is True


def test_injection_manager_has_actionable_blind_signal_oob_hits() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    blind = {
        "correlated": False,
        "time_based": {},
        "oob": {"confirmed": False, "hits": ["hit1"]},
        "dns": {},
    }
    assert manager._has_actionable_blind_signal(blind) is True


def test_injection_manager_has_actionable_blind_signal_dns_hits() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    blind = {
        "correlated": False,
        "time_based": {},
        "oob": {},
        "dns": {"confirmed": False, "hits": ["hit1"]},
    }
    assert manager._has_actionable_blind_signal(blind) is True


def test_injection_manager_has_actionable_blind_signal_none() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    assert manager._has_actionable_blind_signal(None) is False
    assert manager._has_actionable_blind_signal({}) is False
    assert manager._has_actionable_blind_signal(
        {"correlated": False, "time_based": {}, "oob": {}, "dns": {}}
    ) is False


def test_injection_manager_summarize_skip_reason_counts_basic() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    results = [
        {"status": "skipped", "skip_reason": "low_ssrf_score"},
        {"status": "skipped", "skip_reason": "low_ssrf_score"},
        {"status": "skipped", "skip_reason": "ssrf_reachability_gate"},
        {"status": "completed", "vuln_type": "xss"},
        {"status": "error"},
        None,
    ]
    counts = manager._summarize_skip_reason_counts(results)
    assert counts.get("low_ssrf_score") == 2
    assert counts.get("ssrf_reachability_gate") == 1


def test_injection_manager_summarize_skip_reason_counts_unknown_to_other() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    results = [{"status": "skipped", "skip_reason": "random_unknown_reason_xyz"}]
    counts = manager._summarize_skip_reason_counts(results)
    assert "other" in counts
    assert counts["other"] == 1


def test_injection_manager_summarize_skip_reason_unknown_counts_basic() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    results = [
        {"status": "skipped", "skip_reason": "no_injection_point"},
        {"status": "skipped", "skip_reason": "random_unknown_reason_xyz"},
        {"status": "skipped", "skip_reason": "another_unknown"},
        {"status": "completed"},
    ]
    counts = manager._summarize_skip_reason_unknown_counts(results)
    assert "low_ssrf_score" not in counts
    assert counts.get("random_unknown_reason_xyz") == 1
    assert counts.get("another_unknown") == 1
    assert counts.get("no_injection_point") == 1


def test_injection_manager_summarize_low_ssrf_score_breakdown_basic() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
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
        {"status": "completed"},
    ]
    breakdown = manager._summarize_low_ssrf_score_breakdown(results)
    assert breakdown.get("param_count") == 1
    assert breakdown.get("url_like_keys") == 1


def test_injection_manager_extract_max_ssrf_score_basic() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    results = [
        {"ssrf_score": 30},
        {"ssrf_score": 65},
        {"ssrf_score": 20},
        {"no_score": True},
        None,
    ]
    assert manager._extract_max_ssrf_score(results) == 65


def test_injection_manager_extract_max_ssrf_score_empty() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    assert manager._extract_max_ssrf_score([]) == 0


def test_injection_manager_collect_phase1_vuln_types_basic() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    results = [
        {"vuln_type": "xss"},
        {"vuln_type": "sqli"},
        {"vuln_type": "xss"},
        {"vuln_type": "lfi"},
        {"no_type": True},
        None,
    ]
    vuln_types = manager._collect_phase1_vuln_types(results)
    assert vuln_types == {"xss", "sqli", "lfi"}


def test_injection_manager_collect_phase1_vuln_types_empty() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    assert manager._collect_phase1_vuln_types([]) == set()
