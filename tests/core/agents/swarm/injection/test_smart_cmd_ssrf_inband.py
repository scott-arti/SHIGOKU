"""
SmartCmdSSRFHunter in-band コマンド実行 artifacts テスト — SGK-2026-0478 (B)

POST フォームへの読み取り専用コマンド注入（;id 等）の in-band 出力（応答本文
の uid= 等）が確認できた Finding に、impact / reproduction_steps /
command_replay 記述子（method/url/body_params/readonly_command/content_type）
が付与されることを検証する。

- (a) POST in-band 確定 → impact・repro・command_replay（readonly_command は
      許可リスト内 id/whoami/uname/pwd/hostname/groups）・evidence uid=
- (b) in-band 指標が出ない（ブラインド等）→ impact/repro/記述子なし（False）
- (c) command_replay の readonly_command は許可リスト内のみ（sleep/cat 等は
      記述子なし・fail-closed）
- GET-based in-band は従来どおり impact/repro/記述子なし（byte-identical）

PRODUCT-INDEPENDENT fixtures のみ（target.test・汎用コマンド）。
"""
import pytest
from unittest.mock import AsyncMock, patch

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.smart_cmd_ssrf import (
    READONLY_COMMAND_ALLOWLIST,
    SmartCmdSSRFHunter,
    _extract_readonly_command,
)

EXEC_URL = "http://target.test/exec/"
CMD_BODY = (
    "PING 127.0.0.1 (127.0.0.1): 56 data bytes\n"
    "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
    "--- 127.0.0.1 ping statistics ---"
)
NORMAL_BODY = "<html><body>host appears to be down</body></html>"


def _inband_cmd_result(*, payload: str = "127.0.0.1;id") -> dict:
    """deterministic precheck 確定時の run_as_tool 結果形状（delivery_evidence
    は _delivery_evidence_from_observation の出力）。"""
    return {
        "vulnerable": True,
        "evidence": "Deterministic command injection signal on 'ip'",
        "param": "ip",
        "tested_params": ["ip"],
        "payloads_used": [payload],
        "description": "Command Injection/SSRF detected.",
        "loop_result": {"status": "deterministic_precheck_confirmed"},
        "vuln_type": "cmd",
        "blind_correlation": {
            "time_based": {"confirmed": False},
            "oob": {"confirmed": False, "hits": []},
            "dns": {"confirmed": False, "hits": []},
            "correlated": False,
        },
        "execution_profile": {},
        "command_execution_evidence": {
            "output_observed": True,
            "timing_confirmed": False,
            "payload": payload,
            "command_output": CMD_BODY,
            "response_status": 200,
        },
        "delivery_evidence": {
            "request_method": "POST",
            "request_url": EXEC_URL,
            "request_headers": {"Cookie": "session=abc123"},
            "body_params": {"ip": payload, "Submit": "Submit"},
            "response_status": 200,
            "response_body": CMD_BODY,
            "poc_request": f"POST /exec/ HTTP/1.1\nHost: target.test\n\nip={payload}&Submit=Submit",
            "poc_response": f"HTTP/1.1 200\n\n{CMD_BODY}",
            "content_type": "text/html",
            "body_length": len(CMD_BODY),
            "delivered": True,
        },
        "reason_code": "",
    }


def _task() -> Task:
    return Task(
        id="cmd-inband",
        name="cmd-inband",
        target=EXEC_URL,
        params={},
    )


def _hunter() -> SmartCmdSSRFHunter:
    return SmartCmdSSRFHunter(config={"model": "test-model"})


class TestInbandCmdArtifacts:
    @pytest.mark.asyncio
    async def test_execute_inband_post_sets_impact_repro_and_command_replay(self) -> None:
        """(a) POST in-band 確定 → impact / reproduction_steps /
        command_replay（POST・body_params・readonly_command=id・
        form-urlencoded）が Finding に付与される。"""
        hunter = _hunter()
        with patch.object(
            SmartCmdSSRFHunter,
            "run_as_tool",
            new=AsyncMock(return_value=_inband_cmd_result()),
        ):
            findings = await hunter.execute(_task())

        assert len(findings) == 1
        finding = findings[0]
        # evidence は in-band 出力（uid=）を保持する
        assert "uid=" in finding.evidence.response_body
        assert finding.evidence.request_method == "POST"
        assert finding.evidence.request_headers.get("Cookie") == "session=abc123"
        # impact / reproduction_steps（payout_grade の impact 条件を満たす）
        assert "RCE" in finding.impact
        assert len(finding.reproduction_steps) == 3
        assert all(str(step).strip() for step in finding.reproduction_steps)
        assert "127.0.0.1;id" in finding.reproduction_steps[1]
        # command_replay 記述子
        replay = finding.additional_info.get("command_replay")
        assert isinstance(replay, dict)
        assert replay["method"] == "POST"
        assert replay["url"] == EXEC_URL
        assert replay["body_params"] == {"ip": "127.0.0.1;id", "Submit": "Submit"}
        assert replay["readonly_command"] == "id"
        assert replay["content_type"] == "application/x-www-form-urlencoded"

    @pytest.mark.asyncio
    async def test_execute_inband_whoami_replay_readonly_command_allowlisted(self) -> None:
        """(c) whoami 注入でも readonly_command は許可リスト内 whoami。"""
        hunter = _hunter()
        with patch.object(
            SmartCmdSSRFHunter,
            "run_as_tool",
            new=AsyncMock(return_value=_inband_cmd_result(payload="127.0.0.1;whoami")),
        ):
            findings = await hunter.execute(_task())
        replay = findings[0].additional_info.get("command_replay")
        assert isinstance(replay, dict)
        assert replay["readonly_command"] == "whoami"
        assert replay["readonly_command"] in READONLY_COMMAND_ALLOWLIST

    @pytest.mark.asyncio
    async def test_execute_no_inband_output_no_artifacts(self) -> None:
        """(b) 応答に指標なし（ブラインド等）→ impact/repro/記述子なし
        （従来どおり・vulnerable=True でも本物証拠を補わない）。"""
        result = _inband_cmd_result()
        result["delivery_evidence"]["response_body"] = NORMAL_BODY
        result["command_execution_evidence"] = {
            "output_observed": False,
            "timing_confirmed": True,
            "payload": "127.0.0.1;sleep 3",
        }
        hunter = _hunter()
        with patch.object(
            SmartCmdSSRFHunter,
            "run_as_tool",
            new=AsyncMock(return_value=result),
        ):
            findings = await hunter.execute(_task())

        assert len(findings) == 1
        finding = findings[0]
        assert finding.impact == ""
        assert finding.reproduction_steps == []
        assert "command_replay" not in finding.additional_info

    @pytest.mark.asyncio
    async def test_execute_get_inband_stays_byte_identical(self) -> None:
        """GET-based in-band は従来どおり impact/repro/記述子なし
        （GET 再送経路を変えない・byte-identical）。"""
        result = _inband_cmd_result()
        delivery = result["delivery_evidence"]
        delivery["request_method"] = "GET"
        delivery["request_url"] = f"{EXEC_URL}?ip=127.0.0.1%3Bid"
        delivery["body_params"] = {}
        result["command_execution_evidence"]["payload"] = "127.0.0.1;id"
        hunter = _hunter()
        with patch.object(
            SmartCmdSSRFHunter,
            "run_as_tool",
            new=AsyncMock(return_value=result),
        ):
            findings = await hunter.execute(_task())

        assert len(findings) == 1
        finding = findings[0]
        assert finding.impact == ""
        assert finding.reproduction_steps == []
        assert "command_replay" not in finding.additional_info


class TestExtractReadonlyCommand:
    def test_allowlisted_commands_extracted_from_joined_payloads(self) -> None:
        assert _extract_readonly_command("127.0.0.1;id") == "id"
        assert _extract_readonly_command("127.0.0.1&&id") == "id"
        assert _extract_readonly_command("127.0.0.1|id") == "id"
        assert _extract_readonly_command("127.0.0.1;whoami") == "whoami"
        assert _extract_readonly_command("127.0.0.1;uname -a") == "uname"
        assert _extract_readonly_command("127.0.0.1;hostname") == "hostname"
        assert _extract_readonly_command("127.0.0.1;pwd") == "pwd"
        assert _extract_readonly_command("127.0.0.1;groups") == "groups"

    def test_non_allowlisted_commands_rejected(self) -> None:
        # 破壊的/出力なしコマンドは記述子対象外（fail-closed）
        assert _extract_readonly_command("127.0.0.1;sleep 3") is None
        assert _extract_readonly_command("127.0.0.1;cat /etc/passwd") is None
        assert _extract_readonly_command("127.0.0.1;rm -rf /tmp/x") is None
        assert _extract_readonly_command("") is None
        assert _extract_readonly_command(None) is None
        # 単語境界: username 内の id に誤反応しない
        assert _extract_readonly_command("127.0.0.1;echo username") is None


class TestSendRequestRecordsReplayMaterial:
    @pytest.mark.asyncio
    async def test_post_observation_records_body_params_and_request_headers(self) -> None:
        """POST 送信の observation に body_params（注入値入りフォーム値一式）と
        request_headers（認証）が記録される（command_replay の材料）。"""
        hunter = _hunter()
        hunter.context = {
            "target": EXEC_URL,
            "param": "ip",
            "method": "POST",
            "params": {"ip": "127.0.0.1", "Submit": "Submit"},
            "auth_headers": {"Cookie": "session=abc123"},
            "execution_profile": {},
        }
        hunter.smart_client.request = AsyncMock(
            return_value={"status": 200, "body": CMD_BODY}
        )

        result = await hunter._send_request("127.0.0.1;id")

        assert result["diff"] == "cmd_injection_found"
        assert result["body_params"] == {
            "ip": "127.0.0.1;id",
            "Submit": "Submit",
        }
        assert result["request_headers"] == {"Cookie": "session=abc123"}
        # _delivery_evidence_from_observation も記述子材料を保持する
        delivery = SmartCmdSSRFHunter._delivery_evidence_from_observation(result)
        assert delivery["body_params"] == result["body_params"]
        assert delivery["request_headers"] == result["request_headers"]
