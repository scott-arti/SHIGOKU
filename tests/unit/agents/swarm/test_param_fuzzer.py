import pytest
import os
from unittest.mock import MagicMock, patch, AsyncMock
from src.core.agents.swarm.fuzzing.manager import ParamFuzzerSpecialist, FuzzingSwarm
from src.core.attack.native_param_fuzzer import NativeParamFuzzer
from src.core.agents.swarm.base import Task

@pytest.fixture
def mock_client():
    client = MagicMock()
    client.request = AsyncMock()
    return client

class TestNativeParamFuzzer:
    @pytest.mark.asyncio
    async def test_reflection_detection(self, mock_client):
        fuzzer = NativeParamFuzzer(client=mock_client)
        
        # Dynamic side effect to reflect params
        async def request_side_effect(method, url, params=None, data=None):
            p = params or data or {}
            # Baseline and Random check calls have no 'user' or different values
            if "user" in p:
                return MagicMock(status=200, body=f"reflection {p['user']}")
            return MagicMock(status=200, body="normal page")
            
        mock_client.request.side_effect = request_side_effect
    
        results = await fuzzer.fuzz("http://test.com", "GET", ["user"])
        
        assert len(results) == 1
        assert results[0].parameter == "user"
        assert results[0].evidence["reason"] == "reflection"

    @pytest.mark.asyncio
    async def test_self_correcting_mutation_on_block(self, mock_client):
        fuzzer = NativeParamFuzzer(client=mock_client)
        fuzzer.max_mutation_attempts = 3

        async def request_side_effect(method, url, params=None, data=None, **kwargs):
            p = params or data or {}
            if not p:
                return MagicMock(status=200, body="normal page")
            if "user" not in p:
                return MagicMock(status=200, body="normal page")

            payload = p["user"]
            if "%" in payload:
                return MagicMock(status=200, body=f"reflection {payload}")
            return MagicMock(status=403, body="blocked by waf")

        mock_client.request.side_effect = request_side_effect
        results = await fuzzer.fuzz("http://test.com", "GET", ["user"])

        assert len(results) == 1
        assert results[0].parameter == "user"
        assert results[0].evidence["reason"] == "reflection"
        assert results[0].evidence["attempts"] == 2
        assert results[0].evidence["mutation_history"][0]["strategy"] == "url_encode"
        assert results[0].evidence["mutation_history"][0]["reason"] == "blocked_response_detected"

    @pytest.mark.asyncio
    async def test_mutation_attempts_are_capped(self, mock_client):
        fuzzer = NativeParamFuzzer(client=mock_client)
        fuzzer.max_mutation_attempts = 3

        state = {"param_calls": 0}

        async def request_side_effect(method, url, params=None, data=None, **kwargs):
            p = params or data or {}
            if "user" in p:
                state["param_calls"] += 1
                return MagicMock(status=403, body="blocked by waf")
            return MagicMock(status=200, body="normal page")

        mock_client.request.side_effect = request_side_effect
        results = await fuzzer.fuzz("http://test.com", "GET", ["user"])

        # 非検知時は結果を返さない既存仕様を維持
        assert results == []
        # 暴走防止: 試行回数は上限を超えない
        assert state["param_calls"] == 3

    @pytest.mark.asyncio
    async def test_send_request_propagates_timeout_and_retries(self, mock_client):
        fuzzer = NativeParamFuzzer(client=mock_client)
        fuzzer.request_timeout_seconds = 7
        fuzzer.request_retries = 4

        mock_client.request.return_value = MagicMock(status=200, body="ok")

        await fuzzer._send_request("http://test.com", "GET", {"user": "alice"})

        mock_client.request.assert_awaited_once_with(
            "GET",
            "http://test.com",
            params={"user": "alice"},
            timeout=7,
            retries=4,
        )

class TestParamFuzzerSpecialist:
    @pytest.mark.asyncio
    async def test_fallback_logic(self):
        # Mock adapter provider to force fallback path
        with patch("src.core.attack.native_param_fuzzer.NativeParamFuzzer") as MockNative:
            mock_native = MockNative.return_value
            result_obj = MagicMock()
            result_obj.parameter = "hidden_param"
            mock_native.fuzz = AsyncMock(return_value=[result_obj])

            specialist = ParamFuzzerSpecialist()
            specialist.param_wordlist_path = "/tmp/wordlist_dummy"
            specialist._external_tools.has = MagicMock(return_value=False)
            specialist._observability.metrics.inc_counter = AsyncMock()

            # Mock create_default_wordlist
            with patch.object(specialist, "_create_default_wordlist"):
                with patch("builtins.open"):
                    task = Task(id="1", name="test", params={"target_url": "http://test.com", "tags": ["has_params"]})

                    findings = await specialist.execute(task)

                    assert len(findings) == 1
                    assert "Hidden Parameters Discovered" in findings[0].title
                    assert "hidden_param" in findings[0].additional_info.get("params", {})
                    mock_native.fuzz.assert_called_once()
                    specialist._observability.metrics.inc_counter.assert_any_await("native_fallback_total")
                    specialist._observability.metrics.inc_counter.assert_any_await(
                        "native_fallback_total.trigger_reason.arjun_unavailable"
                    )

    @pytest.mark.asyncio
    async def test_arjun_adapter_path(self):
        specialist = ParamFuzzerSpecialist()
        specialist._external_tools.has = MagicMock(return_value=True)
        specialist._observability.metrics.inc_counter = AsyncMock()
        specialist._external_tools.execute = AsyncMock(
            return_value=MagicMock(
                status=MagicMock(value="success"),
                data=[{"param": "debug"}, {"param": "token"}],
                error_message=None,
            )
        )

        task = Task(id="1", name="test", params={"target_url": "http://test.com", "tags": ["has_params"]})
        findings = await specialist.execute(task)

        assert len(findings) == 1
        assert "debug" in findings[0].additional_info.get("params", {})
        assert "token" in findings[0].additional_info.get("params", {})
        specialist._observability.metrics.inc_counter.assert_any_await("arjun_scan_total")

    @pytest.mark.asyncio
    async def test_arjun_failure_records_reason_and_fallback(self):
        specialist = ParamFuzzerSpecialist()
        specialist._external_tools.has = MagicMock(return_value=True)
        specialist._observability.metrics.inc_counter = AsyncMock()
        specialist._external_tools.execute = AsyncMock(
            return_value=MagicMock(
                status=MagicMock(value="failure"),
                data=[],
                error_message="execution timeout",
            )
        )
        specialist.native.fuzz = AsyncMock(return_value=[])
        specialist.param_wordlist_path = "/tmp/wordlist_dummy"

        with patch("builtins.open", new_callable=MagicMock):
            task = Task(id="1", name="test", params={"target_url": "http://test.com", "tags": ["has_params"]})
            await specialist.execute(task)

        specialist._observability.metrics.inc_counter.assert_any_await("arjun_scan_failure_total.reason.timeout")
        specialist._observability.metrics.inc_counter.assert_any_await("native_fallback_total")
        specialist._observability.metrics.inc_counter.assert_any_await(
            "native_fallback_total.trigger_reason.arjun_failure"
        )

    @pytest.mark.asyncio
    async def test_arjun_empty_success_records_empty_and_single_fallback(self):
        specialist = ParamFuzzerSpecialist()
        specialist._external_tools.has = MagicMock(return_value=True)
        specialist._observability.metrics.inc_counter = AsyncMock()
        specialist._external_tools.execute = AsyncMock(
            return_value=MagicMock(
                status=MagicMock(value="success"),
                data=[],
                error_message=None,
            )
        )
        specialist.native.fuzz = AsyncMock(return_value=[])
        specialist.param_wordlist_path = "/tmp/wordlist_dummy"

        with patch("builtins.open", new_callable=MagicMock):
            task = Task(id="1", name="test", params={"target_url": "http://test.com", "tags": ["has_params"]})
            await specialist.execute(task)

        calls = [c.args[0] for c in specialist._observability.metrics.inc_counter.await_args_list]
        assert calls.count("native_fallback_total") == 1
        assert "arjun_scan_empty_success_total" in calls


class TestFuzzingSwarmSelection:
    def test_get_specialists_includes_param_fuzzer_for_param_tags(self):
        swarm = FuzzingSwarm()

        specialists = swarm.get_specialists(["param_fuzz"])
        names = [s.name for s in specialists]

        assert "DirBruteSpecialist" in names
        assert "ParamFuzzerSpecialist" in names
