from unittest.mock import AsyncMock, patch

import pytest

from src.core.agents.swarm.injection.smart_cmd_ssrf import SmartCmdSSRFHunter
from src.core.agents.swarm.injection.smart_xss import SmartXSSHunter


def test_cmd_ssrf_manager_metadata_is_not_treated_as_attack_params():
    for name in (
        "forms",
        "url_evidence",
        "scan_profile",
        "detection_mode",
        "candidate_params",
        "discovered_params",
        "params_list",
        "selection_origin",
        "source_category",
    ):
        assert not SmartCmdSSRFHunter._is_attack_param(name)


def test_cmd_ssrf_exec_target_prefers_dvwa_command_parameter():
    hints = SmartCmdSSRFHunter._target_specific_candidate_params(
        "http://localhost:4280/vulnerabilities/exec/"
    )

    assert hints[:3] == ["ip", "host", "cmd"]


def test_xss_stored_target_prioritizes_dvwa_post_fields():
    hunter = SmartXSSHunter.__new__(SmartXSSHunter)
    payload_params = {
        "page": "1",
        "redirect": "1",
        "id": "1",
        "name": "1",
        "txtName": "1",
        "mtxMessage": "1",
    }

    ordered = hunter._prioritize_candidate_params(
        payload_params=payload_params,
        url_params_flat={},
        target="http://localhost:4280/vulnerabilities/xss_s/",
        scan_profile="bbpt",
    )

    assert ordered[:2] == ["txtName", "mtxMessage"]


def test_xss_stored_target_hints_include_dvwa_form_fields():
    hints = SmartXSSHunter._target_specific_candidate_params(
        "http://localhost:4280/vulnerabilities/xss_s/"
    )

    assert hints[:2] == ["txtName", "mtxMessage"]


@pytest.mark.asyncio
async def test_cmd_ssrf_run_as_tool_prioritizes_exec_hint_before_global_params():
    hunter = SmartCmdSSRFHunter(config={"model": "test-model"})

    with (
        patch(
            "src.core.agents.swarm.injection.smart_cmd_ssrf._fetch_and_parse_form",
            new=AsyncMock(return_value=[]),
        ),
        patch.object(
            SmartCmdSSRFHunter,
            "_run_cmd_deterministic_precheck",
            new=AsyncMock(return_value={"confirmed": False}),
        ),
        patch.object(
            SmartCmdSSRFHunter,
            "run_loop",
            new=AsyncMock(return_value={"status": "safe"}),
        ),
    ):
        result = await hunter.run_as_tool(
            "http://localhost:4280/vulnerabilities/exec/",
            {
                "forms": [],
                "url_evidence": {"source": "recon"},
                "scan_profile": "bbpt",
                "discovered_params": ["page", "redirect", "id"],
            },
        )

    assert result["tested_params"][:3] == ["ip", "host", "cmd"]


@pytest.mark.asyncio
async def test_cmd_ssrf_run_as_tool_filters_task_metadata_before_exec_hints():
    hunter = SmartCmdSSRFHunter(config={"model": "test-model"})

    with (
        patch(
            "src.core.agents.swarm.injection.smart_cmd_ssrf._fetch_and_parse_form",
            new=AsyncMock(return_value=[]),
        ),
        patch.object(
            SmartCmdSSRFHunter,
            "_run_cmd_deterministic_precheck",
            new=AsyncMock(return_value={"confirmed": False}),
        ),
        patch.object(
            SmartCmdSSRFHunter,
            "run_loop",
            new=AsyncMock(return_value={"status": "safe"}),
        ),
    ):
        result = await hunter.run_as_tool(
            "http://localhost:4280/vulnerabilities/exec/",
            {
                "target": "http://localhost:4280/vulnerabilities/exec/",
                "targets": ["http://localhost:4280/vulnerabilities/exec/"],
                "task_name": "Command Injection Focused Scan",
                "category": "command_injection",
                "swarm_type": "injection",
                "signal_count": 1,
                "_source": "signal_bundle",
                "_run_id": "test-run",
                "_strategy": {"name": "focused"},
                "_intervention": {"mode": "auto"},
                "alternative_sessions": [],
                "recipe_to_swarm_reason": "no_recipe_match",
                "recipe_to_swarm_reasons": ["no_recipe_match"],
                "_context": {
                    "discovered_params": ["redirect", "id", "page", "doc", "data", "cmd"],
                },
            },
        )

    assert result["tested_params"][:4] == ["ip", "host", "cmd", "command"]
    assert "_strategy" not in result["tested_params"]
    assert "_intervention" not in result["tested_params"]


@pytest.mark.asyncio
async def test_cmd_ssrf_run_as_tool_preserves_submit_control_for_post_forms():
    hunter = SmartCmdSSRFHunter(config={"model": "test-model"})
    captured_context = {}

    async def fake_precheck(_tested_params):
        captured_context["method"] = hunter.context.get("method")
        captured_context["params"] = dict(hunter.context.get("params", {}))
        return {"confirmed": False}

    with (
        patch(
            "src.core.agents.swarm.injection.smart_cmd_ssrf._fetch_and_parse_form",
            new=AsyncMock(
                return_value=[
                    {
                        "method": "POST",
                        "inputs": [
                            {"name": "ip", "value": "", "type": "text"},
                            {"name": "Submit", "value": "Submit", "type": "submit"},
                        ],
                    }
                ]
            ),
        ),
        patch.object(
            hunter,
            "_run_cmd_deterministic_precheck",
            new=fake_precheck,
        ),
        patch.object(
            SmartCmdSSRFHunter,
            "run_loop",
            new=AsyncMock(return_value={"status": "safe"}),
        ),
    ):
        result = await hunter.run_as_tool(
            "http://localhost:4280/vulnerabilities/exec/",
            {
                "_context": {
                    "discovered_params": ["page", "redirect", "id", "doc"],
                },
            },
        )

    assert captured_context["method"] == "POST"
    assert captured_context["params"]["Submit"] == "Submit"
    assert result["tested_params"] == ["ip"]
    assert "Submit" not in result["tested_params"]


@pytest.mark.asyncio
async def test_cmd_ssrf_finish_safe_json_with_not_vulnerable_text_stays_safe():
    hunter = SmartCmdSSRFHunter(config={"model": "test-model"})
    hunter.vulnerable = False
    hunter.evidence = ""

    await hunter.act(
        "finish",
        '{"status": "Safe", "reason": "Parameter does not appear to be processed or vulnerable."}',
    )

    assert hunter.vulnerable is False
    assert hunter.evidence == ""


@pytest.mark.asyncio
async def test_xss_run_as_tool_prioritizes_stored_hints_before_context_params():
    hunter = SmartXSSHunter(config={"model": "test-model"})

    with (
        patch(
            "src.core.agents.swarm.injection.smart_xss._fetch_and_parse_form",
            new=AsyncMock(return_value=[]),
        ),
        patch.object(
            SmartXSSHunter,
            "_send_request",
            new=AsyncMock(return_value={"status": 200, "diff": "normal", "body_snippet": ""}),
        ),
        patch.object(
            SmartXSSHunter,
            "run_loop",
            new=AsyncMock(return_value={"status": "safe"}),
        ),
    ):
        result = await hunter.run_as_tool(
            "http://localhost:4280/vulnerabilities/xss_s/",
            {
                "forms": [],
                "url_evidence": {"source": "recon"},
                "scan_profile": "bbpt",
                "_context": {
                    "discovered_params": ["page", "redirect", "id", "name"],
                },
            },
        )

    assert result["tested_params"][:2] == ["txtName", "mtxMessage"]
    assert hunter.context["method"] == "POST"
