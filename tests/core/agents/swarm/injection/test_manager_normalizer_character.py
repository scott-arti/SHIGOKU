from types import SimpleNamespace

from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.agents.swarm.injection.manager_internal.result_normalizer import (
    infer_detection_class_for_finding,
    normalize_blind_correlation,
    normalize_detection_class_token,
    normalize_findings_additional_info,
    sanitize_tested_params,
)


# ── normalize_blind_correlation ──

def test_manager_normalize_blind_correlation_confirmed() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
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


def test_manager_normalize_blind_correlation_tentative() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    blind = {
        "time_based": {"confirmed": True},
        "oob": {},
        "dns": {},
    }
    result = normalize_blind_correlation(blind)
    assert result["correlated"] is False
    assert result["verdict"] == "tentative"


def test_manager_normalize_blind_correlation_none() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    result = normalize_blind_correlation({})
    assert result["correlated"] is False
    assert result["verdict"] == "none"


def test_manager_normalize_blind_correlation_non_dict() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    result = normalize_blind_correlation(None)
    assert result["correlated"] is False
    assert result["verdict"] == "none"


# ── normalize_detection_class_token ──

def test_manager_normalize_detection_class_token_basic() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    assert normalize_detection_class_token("UnAuth API Access") == "unauth_api_access"
    assert normalize_detection_class_token("  idor_BOLA  ") == "idor_bola"
    assert normalize_detection_class_token("") == ""


# ── infer_detection_class_for_finding ──

def test_manager_infer_detection_class_mass_assignment() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    finding = SimpleNamespace(vuln_type="mass_assignment", tags=[])
    result = infer_detection_class_for_finding(finding, {})
    assert result == "mass_assignment"


def test_manager_infer_detection_class_idor() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    finding = SimpleNamespace(vuln_type="idor", tags=[])
    result = infer_detection_class_for_finding(finding, {})
    assert result == "idor_bola"


def test_manager_infer_detection_class_bac_unauthenticated_api() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    finding = SimpleNamespace(vuln_type="broken_access_control", tags=[])
    info = {"authz_differential": {"scenario": "unauthenticated_api_access"}}
    result = infer_detection_class_for_finding(finding, info)
    assert result == "endpoint_bfla"


def test_manager_infer_detection_class_bac_api_candidate_tag() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    finding = SimpleNamespace(vuln_type="broken_access_control", tags=["api_candidate"])
    result = infer_detection_class_for_finding(finding, {})
    assert result == "endpoint_bfla"


def test_manager_infer_detection_class_api_vuln_type() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    finding = SimpleNamespace(vuln_type="api", tags=[])
    result = infer_detection_class_for_finding(finding, {})
    assert result == "endpoint_bfla"


def test_manager_infer_detection_class_bac_default() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    finding = SimpleNamespace(vuln_type="broken_access_control", tags=[])
    result = infer_detection_class_for_finding(finding, {})
    assert result == "access_control"


def test_manager_infer_detection_class_existing_in_info() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    finding = SimpleNamespace(vuln_type="api", tags=[])
    info = {"detection_class": "custom_class"}
    result = infer_detection_class_for_finding(finding, info)
    assert result == "custom_class"


def test_manager_infer_detection_class_unknown_vuln_type() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    finding = SimpleNamespace(vuln_type="unknown", tags=[])
    result = infer_detection_class_for_finding(finding, {})
    assert result == ""


# ── normalize_findings_additional_info ──

def test_manager_normalize_findings_additional_info_basic() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    finding = SimpleNamespace(additional_info={"payload": "test=1"})

    normalize_findings_additional_info(
        findings=[finding],
        tested_params=["user", "role"],
        detection_mode="phase1",
        excluded_params=agent.EXCLUDED_TESTED_PARAMS,
    )

    info = finding.additional_info
    assert "payloads_used" in info
    assert "test=1" in info["payloads_used"]
    assert info["tested_params"] == ["user", "role"]
    assert info["detection_mode"] == "phase1"


def test_manager_normalize_findings_additional_info_payload_from_payloads_used() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    finding = SimpleNamespace(additional_info={"payloads_used": ["x=1", "y=2"]})

    normalize_findings_additional_info(
        findings=[finding],
        tested_params=["x", "y"],
        detection_mode="phase2",
        excluded_params=agent.EXCLUDED_TESTED_PARAMS,
    )

    info = finding.additional_info
    assert info["payloads_used"] == ["x=1", "y=2"]
    assert info["payload"] == "y=2"


def test_manager_normalize_findings_additional_info_excluded_params_filtered() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    finding = SimpleNamespace(additional_info={})

    normalize_findings_additional_info(
        findings=[finding],
        tested_params=["user", "scan_profile", "category", "legit"],
        detection_mode="phase1",
        excluded_params=agent.EXCLUDED_TESTED_PARAMS,
    )

    info = finding.additional_info
    assert "scan_profile" not in info["tested_params"]
    assert "category" not in info["tested_params"]
    assert "user" in info["tested_params"]
    assert "legit" in info["tested_params"]


def test_manager_normalize_findings_additional_info_empty_findings() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    normalize_findings_additional_info(
        findings=[],
        tested_params=["a"],
        detection_mode="phase1",
        excluded_params=agent.EXCLUDED_TESTED_PARAMS,
    )


def test_manager_normalize_findings_additional_info_inferred_detection_class() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    finding = SimpleNamespace(vuln_type="mass_assignment", tags=[], additional_info={})

    normalize_findings_additional_info(
        findings=[finding],
        tested_params=["role"],
        detection_mode="phase2",
        excluded_params=agent.EXCLUDED_TESTED_PARAMS,
    )

    assert finding.additional_info["detection_class"] == "mass_assignment"


def test_manager_normalize_findings_additional_info_multiple_findings() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    f1 = SimpleNamespace(additional_info={"payload": "a=1"})
    f2 = SimpleNamespace(additional_info={"payload": "b=2", "detection_mode": "override"})

    normalize_findings_additional_info(
        findings=[f1, f2],
        tested_params=["a"],
        detection_mode="phase1",
        excluded_params=agent.EXCLUDED_TESTED_PARAMS,
    )

    assert f1.additional_info["detection_mode"] == "phase1"
    assert f2.additional_info["detection_mode"] == "override"


# ── sanitize_tested_params ──

def test_manager_sanitize_tested_params_filters_excluded() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    result = sanitize_tested_params(
        ["user", "scan_profile", "category", "method", "legit"],
        excluded_params=agent.EXCLUDED_TESTED_PARAMS,
    )
    assert "scan_profile" not in result
    assert "category" not in result
    assert "method" not in result
    assert "user" in result
    assert "legit" in result


def test_manager_sanitize_tested_params_empty() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    assert sanitize_tested_params([], excluded_params=agent.EXCLUDED_TESTED_PARAMS) == []
    assert sanitize_tested_params(None, excluded_params=agent.EXCLUDED_TESTED_PARAMS) == []
