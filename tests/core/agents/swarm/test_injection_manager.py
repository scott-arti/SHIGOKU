import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from types import SimpleNamespace
from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.manager_internal.target_classifier import classify_target_url
from src.core.agents.swarm.injection.manager_internal.target_selection import prioritize_targets
from src.core.agents.swarm.injection.manager_internal.unknown_hypotheses import build_unknown_hypotheses
from src.core.agents.swarm.injection.manager_internal.api_probe_payload import (
    extract_mass_assignment_schema_candidates,
)
from src.config import settings

@pytest.mark.asyncio
async def test_injection_manager_delegation():
    """
    InjectionManagerAgentがSmartSQLiHunterを正しく呼び出すかテスト
    """
    # 1. Mocking
    mock_llm_response = MagicMock()
    mock_llm_response.choices = [MagicMock()]
    mock_llm_response.choices[0].message.content = "Thought: Suspect SQLi.\nAction: run_sqli_hunter(url=\"http://example.com\", params={\"id\": \"1\"})"
    
    mock_llm_response_2 = MagicMock()
    mock_llm_response_2.choices = [MagicMock()]
    mock_llm_response_2.choices[0].message.content = "Thought: Done.\nFinal Answer: Vulnerable"

    # 2. Setup Manager
    manager = InjectionManagerAgent(config={"model": "test-model"})
    mock_llm = MagicMock()
    mock_llm.agenerate = AsyncMock(side_effect=[mock_llm_response, mock_llm_response_2])
    manager.set_llm_client(mock_llm)

    # 3. Running
    with patch("src.core.agents.swarm.injection.smart_sqli.SmartSQLiHunter.run_as_tool", new_callable=AsyncMock) as mock_worker:
        mock_worker.return_value = {"vulnerable": True, "description": "Mock SQLi"}
        
        task = Task(id="test-inj", name="Test Injection", target="http://example.com/vulnerabilities/sqli/?id=1")
        result = await manager.dispatch(task)

        # 4. Verification
        assert result.status == "success"
        
        # Worker呼び出し確認
        mock_worker.assert_called_once()
        args, _kwargs = mock_worker.call_args
        assert args[0] == "http://example.com/vulnerabilities/sqli/?id=1"
        assert isinstance(args[1], dict)
        assert "_auth" in args[1]
        assert args[1].get("method") == "GET"
        assert "forms" in args[1]
        assert "method" in args[1]
        assert "scan_profile" in args[1]
        
        # 履歴確認
        assert result.execution_log
        assert any("phase" in l for l in result.execution_log if isinstance(l, dict))


@pytest.mark.asyncio
async def test_process_single_url_unknown_classification_only_does_not_bruteforce():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}

    manager.run_sqli_hunter = AsyncMock(return_value={
        "findings_count": 0,
        "tested_params": ["id"],
        "blind_correlation": {},
    })
    manager.run_xss_hunter = AsyncMock(return_value={
        "findings_count": 0,
        "tested_params": ["q"],
        "reflection_observed": True,
        "evidence": "reflected",
    })
    manager.run_lfi_check = AsyncMock(return_value={
        "findings_count": 0,
        "tested_params": ["page"],
    })
    manager.run_open_redirect_check = AsyncMock(return_value={
        "findings_count": 0,
        "tested_params": ["next"],
    })
    manager.run_cmd_ssrf_hunter = AsyncMock(return_value={
        "findings_count": 1,
        "tested_params": ["ip"],
        "blind_correlation": {"time_based": {"confirmed": True}},
    })

    result = await manager._process_single_url(
        url="http://example.com/unknown",
        vuln_type="unknown",
        base_params={"_auth": {"auth_headers": {}, "cookies": ""}},
        quick_mode=True,
    )

    manager.run_sqli_hunter.assert_not_called()
    manager.run_xss_hunter.assert_not_called()
    manager.run_lfi_check.assert_not_called()
    manager.run_open_redirect_check.assert_not_called()
    manager.run_cmd_ssrf_hunter.assert_not_called()

    assert result["findings_count"] == 0
    assert result["tested_params"] == []
    assert result["reflection_observed"] is False
    assert result["xss_evidence"] == ""
    assert result["blind_correlation"] == {}


@pytest.mark.asyncio
async def test_process_single_url_unknown_executes_hypothesis_scan_when_opted_in():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    mock_finding = SimpleNamespace(additional_info={})
    manager.current_context = {"findings": [], "params": {"unknown_classification_only": False}}

    manager._run_unknown_hypothesis_scans = AsyncMock(
        return_value={
            "findings_count": 1,
            "findings": [mock_finding],
            "tested_params": ["q"],
            "reflection_observed": True,
            "xss_evidence": "reflected",
            "blind_correlation": {"time_based": {"confirmed": True}},
            "unknown_profile": {"hypotheses": ["xss"]},
        }
    )

    result = await manager._process_single_url(
        url="http://example.com/unknown",
        vuln_type="unknown",
        base_params={"_auth": {"auth_headers": {}, "cookies": ""}},
        quick_mode=True,
    )

    manager._run_unknown_hypothesis_scans.assert_called_once()
    assert result["findings_count"] == 1
    assert result["tested_params"] == ["q"]
    assert result["reflection_observed"] is True
    assert result["xss_evidence"] == "reflected"
    assert result["blind_correlation"] == {"time_based": {"confirmed": True}}
    assert result["unknown_profile"] == {"hypotheses": ["xss"]}


@pytest.mark.asyncio
async def test_process_single_url_unknown_classification_only_emits_idor_bola_candidate() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}

    with patch("src.core.agents.swarm.injection.manager.build_unknown_hypotheses",
               MagicMock(
                   return_value={
                       "path": "/account/settings",
                       "query_keys": ["user_id"],
                       "form_fields": [],
                       "source": "path+params",
                       "response_status": 0,
                       "content_type": "",
                       "csp_present": False,
                       "has_form_tag": False,
                       "hypotheses": ["idor"],
                       "signals": ["idor_signal"],
                       "selected_specialists": ["sqli"],
                   }
               )):
        result = await manager._process_single_url(
            url="http://example.com/account/settings?user_id=1",
            vuln_type="unknown",
            base_params={"_auth": {"auth_headers": {}, "cookies": ""}},
            quick_mode=True,
        )

    assert result["findings_count"] == 1
    assert len(manager.current_context["findings"]) == 1
    finding = manager.current_context["findings"][0]
    assert finding.title == "Potential IDOR/BOLA Object Access Surface"
    assert finding.target_url == "http://example.com/account/settings?user_id=1"
    assert finding.additional_info.get("detection_class") == "idor_bola"
    assert finding.additional_info.get("heuristic_candidate") is True
    assert finding.additional_info.get("verification_required") is True
    assert finding.additional_info.get("unknown_profile", {}).get("signals") == ["idor_signal"]
    assert "idor" in (finding.tags or [])


@pytest.mark.asyncio
async def test_process_single_url_unknown_opted_in_emits_idor_bola_candidate_when_scans_are_empty() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": [], "params": {"unknown_classification_only": False}}

    manager._run_unknown_hypothesis_scans = AsyncMock(
        return_value={
            "findings_count": 0,
            "findings": [],
            "tested_params": ["user_id"],
            "reflection_observed": False,
            "xss_evidence": "",
            "blind_correlation": {},
            "unknown_profile": {
                "path": "/account/settings",
                "query_keys": ["user_id"],
                "form_fields": [],
                "source": "path+params",
                "response_status": 0,
                "content_type": "",
                "csp_present": False,
                "has_form_tag": False,
                "hypotheses": ["idor"],
                "signals": ["idor_signal"],
                "selected_specialists": ["sqli"],
            },
        }
    )

    result = await manager._process_single_url(
        url="http://example.com/account/settings?user_id=1",
        vuln_type="unknown",
        base_params={"_auth": {"auth_headers": {}, "cookies": ""}},
        quick_mode=True,
    )

    assert result["findings_count"] == 1
    assert len(manager.current_context["findings"]) == 1
    finding = manager.current_context["findings"][0]
    assert finding.title == "Potential IDOR/BOLA Object Access Surface"
    assert finding.additional_info.get("detection_class") == "idor_bola"
    assert finding.additional_info.get("heuristic_candidate") is True
    assert finding.additional_info.get("verification_required") is True
    assert result["unknown_profile"].get("signals") == ["idor_signal"]


@pytest.mark.asyncio
async def test_open_redirect_check_returns_normalized_shape():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"auth_headers": {}, "params": {}, "findings": []}
    if "redirect" not in manager.specialists:
        pytest.skip("OpenRedirectSpecialist not available in this environment")

    mock_finding = MagicMock()
    mock_finding.additional_info = {
        "parameter": "next",
        "payload": "//evil.test",
    }
    mock_finding.description = "Open redirect confirmed"
    mock_finding.severity = MagicMock()
    mock_finding.severity.name = "MEDIUM"

    manager.specialists["redirect"].execute_with_retry = AsyncMock(return_value=[mock_finding])

    result = await manager.run_open_redirect_check("http://example.com/?next=/home", params={})

    assert result["success"] is True
    assert result["findings_count"] == 1
    assert result["parameter"] == "next"
    assert result["tested_params"] == ["next"]


@pytest.mark.asyncio
async def test_run_xss_hunter_normalizes_param_payload_and_discovered_hints():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"auth_headers": {}, "params": {"cookies": ""}, "findings": []}

    captured = {}

    async def _capture_task(task, quick_mode=False):
        captured["task"] = task
        captured["quick_mode"] = quick_mode
        return []

    manager.specialists["xss"].execute_with_retry = AsyncMock(side_effect=_capture_task)
    manager.specialists["xss"].last_tested_params = []
    manager.specialists["xss"].reflection_observed = False
    manager.specialists["xss"].evidence = ""

    result = await manager.run_xss_hunter(
        url="http://example.com/chatbot/genai/state",
        params={"discovered_params": ["state", "user_id"]},
        quick_mode=True,
        param="test",
        payload="<script>alert(1)</script>",
    )

    sent_params = captured["task"].params
    assert sent_params["test"] == "<script>alert(1)</script>"
    assert sent_params["state"] == "1"
    assert sent_params["user_id"] == "1"
    assert "param" not in sent_params
    assert "payload" not in sent_params
    assert "discovered_params" not in sent_params
    assert captured["quick_mode"] is True
    assert result["success"] is False
    assert result["findings_count"] == 0


@pytest.mark.asyncio
async def test_api_minimal_check_promotes_reproducible_privileged_acceptance_without_reflection():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}

    request_client = MagicMock()
    request_client.request = AsyncMock(
        side_effect=[
            SimpleNamespace(status=200, body='{"user":"demo"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=204, body="", headers={"Allow": "GET,POST,PATCH,OPTIONS"}),
            SimpleNamespace(status=200, body='{"ok":true}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"ok":true}', headers={"Content-Type": "application/json"}),
        ]
    )
    manager._resolve_request_client = MagicMock(return_value=request_client)

    result = await manager._run_api_minimal_check(
        url="http://example.com/vulnerabilities/api/v2/user/",
        base_params={"_auth": {"auth_headers": {"Authorization": "Bearer token"}, "cookies": ""}},
    )

    assert result["findings_count"] >= 1
    assert result["probe_sent"] is True
    assert result["probe_skipped_reason"] == ""
    assert request_client.request.await_count == 5
    finding = next(f for f in manager.current_context["findings"] if f.title == "Reproducible Privileged Parameter Acceptance")
    assert finding.title == "Reproducible Privileged Parameter Acceptance"
    assert "auto_reverified" in finding.tags
    auto_reverification = finding.additional_info.get("auto_reverification", {})
    assert auto_reverification.get("performed") is True
    assert auto_reverification.get("reproduced") is True


@pytest.mark.asyncio
async def test_api_minimal_check_promotes_authenticated_overposting_when_unauth_probe_fails():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}

    request_client = MagicMock()
    request_client.request = AsyncMock(
        side_effect=[
            SimpleNamespace(status=200, body='{"profile":"ok"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=204, body="", headers={"Allow": "GET,OPTIONS"}),
            SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"ok":true}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"ok":true}', headers={"Content-Type": "application/json"}),
        ]
    )
    manager._resolve_request_client = MagicMock(return_value=request_client)

    result = await manager._run_api_minimal_check(
        url="http://example.com/vulnerabilities/api/v2/user/",
        base_params={"_auth": {"auth_headers": {"Authorization": "Bearer token"}, "cookies": ""}},
    )

    assert result["findings_count"] == 1
    assert result["probe_sent"] is True
    assert result["probe_skipped_reason"] == ""
    finding = manager.current_context["findings"][0]
    assert finding.title == "Potential Authenticated API Mass Assignment / Over-Posting"
    assert "auth_context" in finding.tags


@pytest.mark.asyncio
async def test_api_minimal_check_adds_authz_differential_metadata_for_unauthenticated_api_access():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}

    request_client = MagicMock()
    request_client.request = AsyncMock(
        side_effect=[
            SimpleNamespace(status=200, body='{"user":"demo"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"user":"demo"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=204, body="", headers={"Allow": "GET,OPTIONS"}),
            SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"}),
        ]
    )
    manager._resolve_request_client = MagicMock(return_value=request_client)

    result = await manager._run_api_minimal_check(
        url="http://example.com/vulnerabilities/api/v2/user/",
        base_params={"_auth": {"auth_headers": {"Authorization": "Bearer token"}, "cookies": ""}},
    )

    assert result["findings_count"] == 1
    finding = manager.current_context["findings"][0]
    assert finding.title == "Potential Unauthenticated API Access"
    assert finding.additional_info.get("detection_class") == "endpoint_bfla"

    differential = finding.additional_info.get("authz_differential", {})
    assert differential.get("scenario") == "unauthenticated_api_access"
    assert differential.get("baseline_status") == 200
    assert differential.get("test_status") == 200
    assert differential.get("body_length_delta") == 0
    assert differential.get("confidence", 0.0) >= 0.6

    signals = differential.get("signals", [])
    assert "auth_success" in signals
    assert "unauth_success" in signals
    assert "auth_json_like" in signals
    assert "unauth_json_like" in signals
    assert "body_length_close" in signals


@pytest.mark.asyncio
async def test_api_minimal_check_uses_read_probe_when_write_method_cannot_be_discovered():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}

    async def _request(method, url, headers=None, **_kwargs):
        headers = headers or {}
        has_auth = bool(str(headers.get("Authorization", "") or "").strip() or str(headers.get("Cookie", "") or "").strip())

        if method == "GET" and has_auth:
            return SimpleNamespace(status=200, body='{"profile":"ok"}', headers={"Content-Type": "application/json"})
        if method == "GET" and "__shigoku_probe=mass_assignment_read_probe" in str(url):
            return SimpleNamespace(
                status=200,
                body='{"echo":"mass_assignment_read_probe","role":"admin","is_admin":"true"}',
                headers={"Content-Type": "application/json"},
            )
        if method == "GET":
            return SimpleNamespace(status=200, body='{"user_id":1,"role":"guest"}', headers={"Content-Type": "application/json"})
        if method == "OPTIONS":
            return SimpleNamespace(status=204, body="", headers={"Allow": "GET,OPTIONS"})
        return SimpleNamespace(status=405, body='{"error":"method_not_allowed"}', headers={"Content-Type": "application/json"})

    request_client = MagicMock()
    request_client.request = AsyncMock(side_effect=_request)
    manager._resolve_request_client = MagicMock(return_value=request_client)

    result = await manager._run_api_minimal_check(
        url="http://example.com/account/settings",
        base_params={"_auth": {"auth_headers": {"Authorization": "Bearer token"}, "cookies": ""}},
    )

    assert result["probe_sent"] is True
    assert result["probe_skipped_reason"] == ""
    assert "role" in result["tested_params"]
    assert "is_admin" in result["tested_params"]
    finding = next(
        (
            f
            for f in manager.current_context["findings"]
            if f.title == "Potential Unauthenticated Input Reflection on API-like Endpoint"
        ),
        None,
    )
    assert finding is not None
    assert "read_probe" in finding.tags


@pytest.mark.asyncio
async def test_api_minimal_check_marks_probe_skipped_without_write_methods_on_non_api_path():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}

    seen_calls = []

    async def _mock_request(method, url, headers=None, **_kwargs):
        method_upper = str(method or "").upper()
        seen_calls.append((method_upper, url))
        headers = headers or {}
        if method_upper == "GET":
            if headers.get("Authorization"):
                return SimpleNamespace(status=200, body="<html>ok</html>", headers={"Content-Type": "text/html"})
            return SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"})
        if method_upper == "OPTIONS":
            return SimpleNamespace(status=204, body="", headers={"Allow": "GET,HEAD,OPTIONS"})
        return SimpleNamespace(status=405, body="", headers={})

    request_client = MagicMock()
    request_client.request = AsyncMock(side_effect=_mock_request)
    manager._resolve_request_client = MagicMock(return_value=request_client)

    result = await manager._run_api_minimal_check(
        url="http://example.com/account/settings",
        base_params={"_auth": {"auth_headers": {"Authorization": "Bearer token"}, "cookies": ""}},
    )

    assert result["findings_count"] == 0
    assert "role" in result["tested_params"]
    assert "is_admin" in result["tested_params"]
    assert result["probe_sent"] is True
    assert result["probe_skipped_reason"] == ""
    assert request_client.request.await_count >= 9
    assert any("/api/account/settings" in url for _method, url in seen_calls)


@pytest.mark.asyncio
async def test_api_minimal_check_uses_fallback_method_discovery_and_then_finds_authenticated_overposting():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}

    request_client = MagicMock()
    request_client.request = AsyncMock(
        side_effect=[
            SimpleNamespace(status=200, body='{"profile":"ok"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=204, body="", headers={"Allow": "GET,OPTIONS"}),
            SimpleNamespace(status=405, body="", headers={}),
            SimpleNamespace(status=405, body="", headers={}),
            SimpleNamespace(status=415, body='{"error":"unsupported media type"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"ok":true}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"ok":true}', headers={"Content-Type": "application/json"}),
        ]
    )
    manager._resolve_request_client = MagicMock(return_value=request_client)

    result = await manager._run_api_minimal_check(
        url="http://example.com/account/settings",
        base_params={"_auth": {"auth_headers": {"Authorization": "Bearer token"}, "cookies": ""}},
    )

    assert result["findings_count"] == 1
    assert result["probe_sent"] is True
    assert result["probe_skipped_reason"] == ""
    finding = manager.current_context["findings"][0]
    assert finding.title == "Potential Authenticated API Mass Assignment / Over-Posting"
    assert "auth_context" in finding.tags
    assert "auto_reverified" in finding.tags
    assert request_client.request.await_count == 9


@pytest.mark.asyncio
async def test_api_minimal_check_discovers_nearby_api_candidate_target():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}

    discovered_target = "http://example.com/api/account/settings"
    seen_calls = []

    async def _mock_request(method, url, headers=None, json=None, **_kwargs):
        method_upper = str(method or "").upper()
        seen_calls.append((method_upper, url, json or {}))
        headers = headers or {}

        if method_upper == "GET":
            if headers.get("Authorization"):
                return SimpleNamespace(status=200, body="<html>settings</html>", headers={"Content-Type": "text/html"})
            return SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"})

        if method_upper == "OPTIONS":
            return SimpleNamespace(status=204, body="", headers={"Allow": "GET,OPTIONS"})

        if method_upper in {"PATCH", "PUT", "POST"} and (json or {}).get("__shigoku_probe") == "method_discovery":
            if url == discovered_target and method_upper == "POST":
                return SimpleNamespace(status=415, body='{"error":"unsupported"}', headers={"Content-Type": "application/json"})
            return SimpleNamespace(status=405, body="", headers={})

        if method_upper == "POST" and url == discovered_target and (json or {}).get("__shigoku_probe") == "mass_assignment":
            return SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"})

        if method_upper == "POST" and url == discovered_target and (json or {}).get("__shigoku_probe") == "mass_assignment_auth":
            return SimpleNamespace(status=200, body='{"ok":true}', headers={"Content-Type": "application/json"})

        if method_upper == "POST" and url == discovered_target and (json or {}).get("__shigoku_probe") == "mass_assignment_auth_recheck":
            return SimpleNamespace(status=200, body='{"ok":true}', headers={"Content-Type": "application/json"})

        return SimpleNamespace(status=405, body="", headers={})

    request_client = MagicMock()
    request_client.request = AsyncMock(side_effect=_mock_request)
    manager._resolve_request_client = MagicMock(return_value=request_client)

    result = await manager._run_api_minimal_check(
        url="http://example.com/account/settings",
        base_params={"_auth": {"auth_headers": {"Authorization": "Bearer token"}, "cookies": ""}},
    )

    assert result["findings_count"] == 1
    assert result["probe_sent"] is True
    finding = manager.current_context["findings"][0]
    assert finding.title == "Potential Authenticated API Mass Assignment / Over-Posting"
    assert finding.evidence.request_url == "http://example.com/account/settings"
    differential = finding.additional_info.get("authz_differential", {})
    assert differential.get("scenario") == "authenticated_overposting_requires_auth_context"
    assert differential.get("baseline_status") == 401
    assert differential.get("test_status") == 200
    assert "status_improved_with_auth" in differential.get("signals", [])
    assert any(call[1] == discovered_target and call[0] == "POST" and (call[2] or {}).get("__shigoku_probe") == "method_discovery" for call in seen_calls)
    assert any(call[1] == discovered_target and call[0] == "POST" and (call[2] or {}).get("__shigoku_probe") == "mass_assignment_auth" for call in seen_calls)


def test_extract_mass_assignment_schema_candidates_infers_fields_from_response_schema():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    candidates = extract_mass_assignment_schema_candidates(
        response_bodies=[
            '{"user":{"role":"user","quota":10,"status":"inactive"},"is_admin":false,"display_name":"demo"}',
            '{"profile":{"permission":"read","tier":"free"}}',
        ],
        excluded_params=manager.EXCLUDED_TESTED_PARAMS,
    )

    assert candidates.get("role") == "admin"
    assert candidates.get("is_admin") is True
    assert "quota" in candidates
    assert "status" in candidates
    assert "permission" in candidates or "tier" in candidates


@pytest.mark.asyncio
async def test_api_minimal_check_records_auth_three_way_and_object_ab_comparison():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}

    seen_post_payloads = []

    async def _mock_request(method, url, headers=None, json=None, **_kwargs):
        method_upper = str(method or "").upper()
        headers = headers or {}
        auth_header = str(headers.get("Authorization", headers.get("authorization", "")) or "").strip()

        if method_upper == "GET":
            if auth_header == "Bearer token" and "id=2" in str(url):
                return SimpleNamespace(status=200, body='{"user_id":2,"role":"user"}', headers={"Content-Type": "application/json"})
            if auth_header == "Bearer token":
                return SimpleNamespace(status=200, body='{"user_id":1,"role":"user","quota":10}', headers={"Content-Type": "application/json"})
            if auth_header == "Bearer alt":
                return SimpleNamespace(status=200, body='{"user_id":1,"role":"guest"}', headers={"Content-Type": "application/json"})
            return SimpleNamespace(status=200, body='{"user_id":1,"role":"guest"}', headers={"Content-Type": "application/json"})

        if method_upper == "OPTIONS":
            return SimpleNamespace(status=204, body="", headers={"Allow": "GET,POST,OPTIONS"})

        if method_upper == "POST":
            seen_post_payloads.append(dict(json or {}))
            probe = str((json or {}).get("__shigoku_probe", "") or "")
            if probe in {"mass_assignment", "mass_assignment_auth"}:
                return SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"})
            return SimpleNamespace(status=405, body="", headers={})

        return SimpleNamespace(status=405, body="", headers={})

    request_client = MagicMock()
    request_client.request = AsyncMock(side_effect=_mock_request)
    manager._resolve_request_client = MagicMock(return_value=request_client)

    fake_msm = MagicMock()
    fake_msm.get_all_alternative_sessions.return_value = {
        "user_b": {"headers": {"authorization": "Bearer alt"}, "metadata": {"user_id": "2"}},
    }

    with patch("src.core.session.multi_session_manager.get_multi_session_manager", return_value=fake_msm):
        result = await manager._run_api_minimal_check(
            url="http://example.com/vulnerabilities/api/v2/user/?id=1",
            base_params={
                "_auth": {
                    "auth_headers": {"Authorization": "Bearer token"},
                    "cookies": "",
                    "auth_matrix_from_multi_session": True,
                }
            },
        )

    matrix = result.get("auth_context_matrix", {})
    rows = matrix.get("rows", [])
    assert matrix.get("available") is True
    assert {str(row.get("actor", "")) for row in rows} >= {"unauth", "authA", "authB"}
    assert any(str(signal) == "authA_authB_both_success" for signal in matrix.get("signals", []))

    object_ab = result.get("object_ab_comparison", {})
    assert object_ab.get("performed") is True
    assert object_ab.get("param") == "id"
    assert object_ab.get("resource_a") == "1"
    assert object_ab.get("resource_b") == "2"

    checks = result.get("comparison_checks", [])
    kinds = {str(item.get("kind", "")) for item in checks if isinstance(item, dict)}
    assert "auth_context_three_way" in kinds
    assert "object_ab" in kinds
    assert result.get("single_request_validation") is False
    assert "quota" in result.get("schema_candidate_params", [])
    assert any(payload.get("quota") is not None for payload in seen_post_payloads)


@pytest.mark.asyncio
async def test_api_minimal_check_emits_idor_companion_finding_on_object_ab_success():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}

    async def _mock_request(method, url, headers=None, json=None, **_kwargs):
        method_upper = str(method or "").upper()
        headers = headers or {}
        auth_header = str(headers.get("Authorization", headers.get("authorization", "")) or "").strip()

        if method_upper == "GET":
            if auth_header == "Bearer token" and "id=2" in str(url):
                return SimpleNamespace(status=200, body='{"user_id":2,"role":"user"}', headers={"Content-Type": "application/json"})
            if auth_header == "Bearer token":
                return SimpleNamespace(status=200, body='{"user_id":1,"role":"user","quota":10}', headers={"Content-Type": "application/json"})
            if auth_header == "Bearer alt":
                return SimpleNamespace(status=200, body='{"user_id":1,"role":"guest"}', headers={"Content-Type": "application/json"})
            return SimpleNamespace(status=200, body='{"user_id":1,"role":"guest"}', headers={"Content-Type": "application/json"})

        if method_upper == "OPTIONS":
            return SimpleNamespace(status=204, body="", headers={"Allow": "GET,POST,OPTIONS"})

        if method_upper == "POST":
            probe = str((json or {}).get("__shigoku_probe", "") or "")
            if probe in {"mass_assignment", "mass_assignment_auth"}:
                return SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"})
            return SimpleNamespace(status=405, body="", headers={})

        return SimpleNamespace(status=405, body="", headers={})

    request_client = MagicMock()
    request_client.request = AsyncMock(side_effect=_mock_request)
    manager._resolve_request_client = MagicMock(return_value=request_client)

    fake_msm = MagicMock()
    fake_msm.get_all_alternative_sessions.return_value = {
        "user_b": {"headers": {"authorization": "Bearer alt"}, "metadata": {"user_id": "2"}},
    }

    with patch("src.core.session.multi_session_manager.get_multi_session_manager", return_value=fake_msm):
        result = await manager._run_api_minimal_check(
            url="http://example.com/vulnerabilities/api/v2/user/?id=1",
            base_params={
                "_auth": {
                    "auth_headers": {"Authorization": "Bearer token"},
                    "cookies": "",
                    "auth_matrix_from_multi_session": True,
                }
            },
        )

    assert result["findings_count"] == 2
    idor_findings = [
        finding
        for finding in manager.current_context["findings"]
        if str(getattr(finding, "vuln_type", "")) == "VulnType.IDOR"
    ]
    assert idor_findings
    idor_finding = idor_findings[0]
    assert idor_finding.additional_info.get("detection_class") == "idor_bola"
    assert idor_finding.additional_info.get("object_ab_comparison", {}).get("performed") is True

def test_prioritize_targets_scores_method_json_params_and_auth_boundary():
    manager = InjectionManagerAgent(config={"model": "test-model"})

    targets = [
        "http://example.com/healthz",
        "http://example.com/api/account/update?id=1&role=user",
    ]
    forms_by_url = {
        "http://example.com/api/account/update?id=1&role=user": [
            {"fields": [{"name": "is_admin"}]},
        ]
    }
    url_evidence_by_url = {
        "http://example.com/api/account/update?id=1&role=user": {
            "method": "PATCH",
            "response_headers": {"Content-Type": "application/json"},
            "response_body_snippet": '{"role":"user","is_admin":false}',
        }
    }

    prioritized = prioritize_targets(
        targets,
        forms_by_url=forms_by_url,
        url_evidence_by_url=url_evidence_by_url,
        category="api_candidate",
    )

    assert prioritized
    top_url, top_score, top_signals = prioritized[0]
    assert top_url == "http://example.com/api/account/update?id=1&role=user"
    assert top_score > prioritized[-1][1]
    assert "method:PATCH" in top_signals
    assert "json_surface" in top_signals
    assert "high_signal_param" in top_signals
    assert "auth_boundary_surface" in top_signals


@pytest.mark.asyncio
async def test_dispatch_records_priority_score_in_url_results_and_execution_log():
    manager = InjectionManagerAgent(config={"model": "test-model"})

    manager._process_single_url = AsyncMock(
        return_value={
            "findings_count": 0,
            "vuln_type": "api",
            "findings": [],
            "tested_params": [],
            "reflection_observed": False,
            "xss_evidence": "",
            "blind_correlation": {},
            "unknown_profile": {},
            "probe_sent": True,
            "probe_skipped_reason": "",
            "comparison_checks": [],
            "auth_context_matrix": {},
            "object_ab_comparison": {},
            "schema_candidate_params": [],
            "single_request_validation": True,
            "detection_mode": "phase1",
        }
    )

    high_url = "http://example.com/api/account/update?id=1&role=user"
    low_url = "http://example.com/healthz"
    task = Task(
        id="inj-priority-1",
        name="Priority score propagation",
        target=high_url,
        params={
            "targets": [low_url, high_url],
            "category": "api_candidate",
            "manager_timeout_seconds": 30,
            "per_url_timeout_seconds": 5,
            "phase1_force_full_coverage": True,
            "phase1_stop_on_first_hit": False,
            "phase2_on_empty_phase1": False,
            "_context": {
                "forms_by_url": {
                    high_url: [{"fields": [{"name": "is_admin"}]}],
                },
                "url_evidence_by_url": {
                    high_url: {
                        "method": "PATCH",
                        "response_headers": {"Content-Type": "application/json"},
                        "response_body_snippet": '{"role":"user"}',
                    }
                },
            },
        },
    )

    with patch("src.core.agents.swarm.injection.manager.resolve_risk_force_allowlist", return_value=set()):
        result = await manager.dispatch(task)

    assert result.status == "success"
    assert manager.current_context["url_results"]
    first_entry = manager.current_context["url_results"][0]
    assert first_entry["url"] == high_url
    assert isinstance(first_entry.get("priority_score"), int)
    assert first_entry.get("priority_score", 0) > 0
    assert isinstance(first_entry.get("priority_signals"), list)
    assert "method:PATCH" in first_entry.get("priority_signals", [])

    phase1_summary = next(
        (item for item in result.execution_log if isinstance(item, dict) and item.get("phase") == "phase1_summary"),
        {},
    )
    prioritized_targets = phase1_summary.get("prioritized_targets", [])
    assert prioritized_targets
    assert prioritized_targets[0].get("url") == high_url
    assert isinstance(prioritized_targets[0].get("priority_score"), int)
    assert isinstance(phase1_summary.get("skip_reason_counts", {}), dict)


@pytest.mark.asyncio
async def test_dispatch_timeout_retry_guard_suppresses_same_cause_retries_for_low_priority() -> None:
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager._summarize_phase1_signals = MagicMock(
        return_value={"tool_error": False, "weak_signal": False, "high_risk_endpoint": False}
    )

    async def _always_timeout(*_args, **_kwargs):
        raise asyncio.TimeoutError()

    manager._process_single_url = AsyncMock(side_effect=_always_timeout)

    old_guard = bool(getattr(settings, "phase1_timeout_retry_same_cause_guard", False))
    old_min_priority = int(getattr(settings, "phase1_timeout_retry_guard_min_priority", 70) or 70)

    settings.phase1_timeout_retry_same_cause_guard = True
    settings.phase1_timeout_retry_guard_min_priority = 10_000
    try:
        task = Task(
            id="inj-timeout-guard-1",
            name="Timeout retry guard",
            target="http://example.com/vulnerabilities/sqli/?id=1",
            params={
                "targets": [
                    "http://example.com/vulnerabilities/sqli/?id=1",
                    "http://example.com/vulnerabilities/sqli/?id=2",
                ],
                "manager_timeout_seconds": 30,
                "per_url_timeout_seconds": 1,
                "phase1_timeout_retries": 1,
                "phase1_force_full_coverage": True,
                "phase1_stop_on_first_hit": False,
                "phase2_on_empty_phase1": False,
            },
        )

        with patch("src.core.agents.swarm.injection.manager.resolve_risk_force_allowlist", return_value=set()):
            result = await manager.dispatch(task)
    finally:
        settings.phase1_timeout_retry_same_cause_guard = old_guard
        settings.phase1_timeout_retry_guard_min_priority = old_min_priority

    assert result.status == "success"
    # 1st URL: default escalationで retry 2 回まで実施 (=3 calls)
    # 2nd URL: guard により retry 抑制 (=1 call)
    assert manager._process_single_url.await_count == 4

    timeout_rows = [
        row for row in manager.current_context.get("url_results", [])
        if isinstance(row, dict) and row.get("status") == "timeout"
    ]
    assert len(timeout_rows) == 2
    assert int(timeout_rows[0].get("retry_count", -1)) == 2
    assert int(timeout_rows[1].get("retry_count", -1)) == 0


# ---------------------------------------------------------------------------
# classify_target_url: SSTI 分類テスト (A1-3)
# ---------------------------------------------------------------------------

def test_classify_url_ssti_candidate_category():
    result = classify_target_url("http://example.com/greet", "ssti_candidate")
    assert result == "ssti"


def test_classify_url_render_path():
    result = classify_target_url("http://example.com/render/page", "")
    assert result == "ssti"


def test_classify_url_tpl_path():
    result = classify_target_url("http://example.com/tpl/view", "")
    assert result == "ssti"


def test_classify_url_template_param_ssti_candidate_not_lfi():
    result = classify_target_url(
        "http://example.com/page?template=foo", "ssti_candidate"
    )
    assert result == "ssti"
    assert result != "lfi"


def test_classify_url_file_param_still_lfi():
    result = classify_target_url(
        "http://example.com/view?file=doc.pdf", "file_param"
    )
    assert result == "lfi"


# classify_target_url: CORS 分類テスト (A-2)
# ---------------------------------------------------------------------------

def test_classify_url_cors_candidate_category():
    result = classify_target_url("http://example.com/api/data", "cors_candidate")
    assert result == "cors"


def test_classify_url_cors_candidate_takes_priority_over_api():
    result = classify_target_url("http://example.com/api/v1/users", "cors_candidate")
    assert result == "cors"
    assert result != "api"


def test_classify_url_cors_candidate_not_triggered_by_api_hint():
    result = classify_target_url("http://example.com/api/v1/users", "api_candidate")
    assert result == "api"
    assert result != "cors"


# ---------------------------------------------------------------------------
# build_unknown_hypotheses: SSTI 仮説テスト (A1-4)
# ---------------------------------------------------------------------------

def test_hypotheses_ssti_signal_from_template_param():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    profile = build_unknown_hypotheses(
        "http://example.com/page?template=foo",
        {"template": "foo"},
        available_specialists=set(manager.specialists.keys()),
    )
    assert "ssti" in profile.get("hypotheses", [])


def test_hypotheses_ssti_signal_from_render_path():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    profile = build_unknown_hypotheses(
        "http://example.com/render?name=test",
        {"name": "test"},
        available_specialists=set(manager.specialists.keys()),
    )
    assert "ssti" in profile.get("hypotheses", [])


def test_specialist_map_ssti_maps_to_ssti():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    profile = build_unknown_hypotheses(
        "http://example.com/render?name=test",
        {"name": "test"},
        available_specialists=set(manager.specialists.keys()),
    )
    assert "ssti" in profile.get("selected_specialists", [])


# ---------------------------------------------------------------------------
# E2E スモーク: _process_single_url で ssti → run_ssti_hunter 委譲 (A1-6)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_process_single_url_ssti_routes_to_ssti_hunter():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}
    manager.run_ssti_hunter = AsyncMock(return_value={
        "findings_count": 1,
        "tested_params": ["name"],
        "vulnerable": True,
        "engine": "jinja2",
        "success": True,
    })

    result = await manager._process_single_url(
        url="http://example.com/render?name=test",
        vuln_type="ssti",
        base_params={"_auth": {"auth_headers": {}, "cookies": ""}},
        quick_mode=False,
    )

    manager.run_ssti_hunter.assert_called_once()
    assert result["findings_count"] == 1
