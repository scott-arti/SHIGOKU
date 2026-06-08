from types import SimpleNamespace

from src.core.agents.swarm.injection.manager_internal.result_normalizer import (
    infer_detection_class_for_finding,
    normalize_blind_correlation,
    normalize_detection_class_token,
    normalize_findings_additional_info,
    sanitize_tested_params,
)

EXCLUDED_PARAMS = {
    "scan_profile",
    "profile",
    "forms",
    "url_evidence",
    "detection_mode",
    "_auth",
    "_context",
    "method",
    "tags",
    "category",
    "count",
    "source_file",
    "targets",
    "extra_targets",
    "auth_headers",
    "headers",
    "cookies",
}


# ── sanitize_tested_params ──

def test_sanitize_tested_params_filters_excluded() -> None:
    result = sanitize_tested_params(
        ["user", "scan_profile", "category", "method", "legit"],
        excluded_params=EXCLUDED_PARAMS,
    )
    assert result == ["user", "legit"]


def test_sanitize_tested_params_removes_duplicates() -> None:
    result = sanitize_tested_params(
        ["user", "user", "role", "role"],
        excluded_params=EXCLUDED_PARAMS,
    )
    assert result == ["user", "role"]


def test_sanitize_tested_params_empty() -> None:
    assert sanitize_tested_params([], excluded_params=EXCLUDED_PARAMS) == []
    assert sanitize_tested_params(None, excluded_params=EXCLUDED_PARAMS) == []


def test_sanitize_tested_params_skips_empty_strings() -> None:
    result = sanitize_tested_params(
        ["", "  ", "user"],
        excluded_params=EXCLUDED_PARAMS,
    )
    assert result == ["user"]


# ── normalize_detection_class_token ──

def test_normalize_detection_class_token_lower_and_underscore() -> None:
    assert normalize_detection_class_token("UnAuth API Access") == "unauth_api_access"
    assert normalize_detection_class_token("IDOR-BOLA") == "idor_bola"


def test_normalize_detection_class_token_enum_like() -> None:
    class DummyEnum:
        value = "Mass_Assignment"
    assert normalize_detection_class_token(DummyEnum()) == "mass_assignment"


def test_normalize_detection_class_token_empty() -> None:
    assert normalize_detection_class_token("") == ""
    assert normalize_detection_class_token(None) == ""


# ── normalize_blind_correlation ──

def test_normalize_blind_correlation_confirmed() -> None:
    blind = {
        "time_based": {"confirmed": True, "delay": 2.5},
        "oob": {"confirmed": True, "target": "http://collab.example"},
        "dns": {"confirmed": False},
    }
    result = normalize_blind_correlation(blind)
    assert result["time_based"]["confirmed"] is True
    assert result["time_based"]["delay"] == 2.5
    assert result["oob"]["confirmed"] is True
    assert result["dns"]["confirmed"] is False
    assert result["correlated"] is True
    assert result["verdict"] == "confirmed"


def test_normalize_blind_correlation_confirmed_false_positives() -> None:
    blind = {
        "time_based": {"confirmed": "yes"},
        "oob": {"confirmed": 1},
        "dns": {"confirmed": True},
    }
    result = normalize_blind_correlation(blind)
    assert result["correlated"] is True
    assert result["verdict"] == "confirmed"


def test_normalize_blind_correlation_tentative() -> None:
    blind = {
        "time_based": {"confirmed": True},
        "oob": {},
        "dns": {},
    }
    result = normalize_blind_correlation(blind)
    assert result["correlated"] is False
    assert result["verdict"] == "tentative"


def test_normalize_blind_correlation_none() -> None:
    result = normalize_blind_correlation({})
    assert result["time_based"]["confirmed"] is False
    assert result["oob"]["confirmed"] is False
    assert result["dns"]["confirmed"] is False
    assert result["correlated"] is False
    assert result["verdict"] == "none"


def test_normalize_blind_correlation_non_dict() -> None:
    result = normalize_blind_correlation(None)
    assert result["correlated"] is False
    assert result["verdict"] == "none"

    result2 = normalize_blind_correlation([])
    assert result2["correlated"] is False
    assert result2["verdict"] == "none"


def test_normalize_blind_correlation_sub_key_preserved() -> None:
    blind = {
        "time_based": {"confirmed": False, "avg_delay": 0.5, "extra": "keep"},
        "oob": {"confirmed": False},
        "dns": {"confirmed": False},
    }
    result = normalize_blind_correlation(blind)
    assert result["time_based"]["avg_delay"] == 0.5
    assert result["time_based"]["extra"] == "keep"


# ── infer_detection_class_for_finding ──

def test_infer_detection_class_mass_assignment() -> None:
    finding = SimpleNamespace(vuln_type="mass_assignment", tags=[])
    result = infer_detection_class_for_finding(finding, {})
    assert result == "mass_assignment"


def test_infer_detection_class_idor_direct() -> None:
    finding = SimpleNamespace(vuln_type="idor", tags=[])
    assert infer_detection_class_for_finding(finding, {}) == "idor_bola"


def test_infer_detection_class_idor_tagged() -> None:
    finding = SimpleNamespace(vuln_type="other", tags=["idor"])
    assert infer_detection_class_for_finding(finding, {}) == "idor_bola"


def test_infer_detection_class_bac_unauthenticated_api() -> None:
    finding = SimpleNamespace(vuln_type="broken_access_control", tags=[])
    info = {"authz_differential": {"scenario": "unauthenticated_api_access"}}
    assert infer_detection_class_for_finding(finding, info) == "endpoint_bfla"


def test_infer_detection_class_bac_unauthenticated_discovered() -> None:
    finding = SimpleNamespace(vuln_type="broken_access_control", tags=[])
    info = {"authz_differential": {"scenario": "unauthenticated_discovered_api_access"}}
    assert infer_detection_class_for_finding(finding, info) == "endpoint_bfla"


def test_infer_detection_class_bac_api_candidate_tag() -> None:
    finding = SimpleNamespace(vuln_type="broken_access_control", tags=["api_candidate"])
    assert infer_detection_class_for_finding(finding, {}) == "endpoint_bfla"


def test_infer_detection_class_api_vuln_type() -> None:
    finding = SimpleNamespace(vuln_type="api", tags=[])
    assert infer_detection_class_for_finding(finding, {}) == "endpoint_bfla"


def test_infer_detection_class_bac_default() -> None:
    finding = SimpleNamespace(vuln_type="broken_access_control", tags=[])
    assert infer_detection_class_for_finding(finding, {}) == "access_control"


def test_infer_detection_class_existing_in_info() -> None:
    finding = SimpleNamespace(vuln_type="api", tags=[])
    info = {"detection_class": "custom_class"}
    assert infer_detection_class_for_finding(finding, info) == "custom_class"


def test_infer_detection_class_unknown() -> None:
    finding = SimpleNamespace(vuln_type="unknown", tags=[])
    assert infer_detection_class_for_finding(finding, {}) == ""


def test_infer_detection_class_info_no_authz_differential() -> None:
    finding = SimpleNamespace(vuln_type="broken_access_control", tags=[])
    result = infer_detection_class_for_finding(finding, {"other": "data"})
    assert result == "access_control"


# ── normalize_findings_additional_info ──

def test_normalize_findings_additional_info_basic() -> None:
    finding = SimpleNamespace(additional_info={"payload": "test=1"})

    normalize_findings_additional_info(
        findings=[finding],
        tested_params=["user", "role"],
        detection_mode="phase1",
        excluded_params=EXCLUDED_PARAMS,
    )

    info = finding.additional_info
    assert info["payloads_used"] == ["test=1"]
    assert info["tested_params"] == ["user", "role"]
    assert info["detection_mode"] == "phase1"
    assert "detection_class" not in info


def test_normalize_findings_additional_info_payloads_used_from_list() -> None:
    finding = SimpleNamespace(additional_info={"payloads_used": ["x=1", "y=2"]})

    normalize_findings_additional_info(
        findings=[finding],
        tested_params=["x", "y"],
        detection_mode="phase2",
        excluded_params=EXCLUDED_PARAMS,
    )

    info = finding.additional_info
    assert info["payloads_used"] == ["x=1", "y=2"]
    assert info["payload"] == "y=2"


def test_normalize_findings_additional_info_excluded_params() -> None:
    finding = SimpleNamespace(additional_info={})

    normalize_findings_additional_info(
        findings=[finding],
        tested_params=["user", "scan_profile", "category", "legit"],
        detection_mode="phase1",
        excluded_params=EXCLUDED_PARAMS,
    )

    info = finding.additional_info
    assert "scan_profile" not in info["tested_params"]
    assert "category" not in info["tested_params"]
    assert "user" in info["tested_params"]
    assert "legit" in info["tested_params"]


def test_normalize_findings_additional_info_empty() -> None:
    normalize_findings_additional_info(
        findings=[],
        tested_params=["a"],
        detection_mode="phase1",
        excluded_params=EXCLUDED_PARAMS,
    )


def test_normalize_findings_additional_info_inferred_detection_class() -> None:
    finding = SimpleNamespace(vuln_type="mass_assignment", tags=[], additional_info={})

    normalize_findings_additional_info(
        findings=[finding],
        tested_params=["role"],
        detection_mode="phase2",
        excluded_params=EXCLUDED_PARAMS,
    )

    assert finding.additional_info["detection_class"] == "mass_assignment"


def test_normalize_findings_additional_info_multiple_findings() -> None:
    f1 = SimpleNamespace(additional_info={"payload": "a=1"})
    f2 = SimpleNamespace(additional_info={"payload": "b=2", "detection_mode": "override"})

    normalize_findings_additional_info(
        findings=[f1, f2],
        tested_params=["a"],
        detection_mode="phase1",
        excluded_params=EXCLUDED_PARAMS,
    )

    assert f1.additional_info["detection_mode"] == "phase1"
    assert f2.additional_info["detection_mode"] == "override"


def test_normalize_findings_additional_info_dedupe_payloads() -> None:
    finding = SimpleNamespace(additional_info={
        "payloads_used": ["a=1", "b=2", "a=1", "c=3"]
    })

    normalize_findings_additional_info(
        findings=[finding],
        tested_params=[],
        detection_mode="phase1",
        excluded_params=EXCLUDED_PARAMS,
    )

    assert finding.additional_info["payloads_used"] == ["a=1", "b=2", "c=3"]


def test_normalize_findings_additional_info_tested_params_dedupe() -> None:
    finding = SimpleNamespace(
        additional_info={"payload": "x=1", "tested_params": ["a", "b", "a"]}
    )

    normalize_findings_additional_info(
        findings=[finding],
        tested_params=["c"],
        detection_mode="phase1",
        excluded_params=EXCLUDED_PARAMS,
    )

    assert finding.additional_info["tested_params"] == ["a", "b"]
