import pytest

from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter


@pytest.mark.asyncio
async def test_time_based_blind_precheck_records_three_series_timing_samples():
    hunter = SmartSQLiHunter(config={"model": "test-model", "mode": "ctf"})
    hunter.context = {
        "target": "http://example.com/vulnerabilities/sqli_blind/?id=1",
        "param": "id",
        "method": "GET",
        "params": {"id": "1"},
        "auth_headers": {},
    }

    async def fake_send(payload: str):
        if "sleep" in payload.lower():
            return {
                "status": 200,
                "diff": "normal",
                "body_snippet": "User ID exists",
                "elapsed_seconds": 3.2,
                "poc_request": "GET /vulnerabilities/sqli_blind/?id=1%27+AND+SLEEP%283%29--+- HTTP/1.1\nHost: example.com",
                "poc_response": "HTTP/1.1 200\n\nUser ID exists",
            }
        return {
            "status": 200,
            "diff": "normal",
            "body_snippet": "User ID exists",
            "elapsed_seconds": 0.1,
            "poc_request": "GET /vulnerabilities/sqli_blind/?id=1 HTTP/1.1\nHost: example.com",
            "poc_response": "HTTP/1.1 200\n\nUser ID exists",
        }

    hunter._send_request = fake_send

    result = await hunter._run_time_based_blind_precheck("id", "1")

    assert result["confirmed"] is True
    timing_samples = result["timing_samples"]
    assert len(timing_samples["baseline"]) == 3
    assert len(timing_samples["sleep"]) == 3
    assert len(timing_samples["inverse_condition"]) == 1
    assert hunter._time_signal_timing_samples == timing_samples
    assert "SLEEP" in hunter._last_poc_request


@pytest.mark.asyncio
async def test_sqli_request_action_records_sql_error_evidence_and_poc():
    hunter = SmartSQLiHunter(config={"model": "test-model", "mode": "ctf"})
    hunter.context = {
        "target": "http://example.com/vulnerabilities/sqli/?id=1",
        "param": "id",
        "method": "GET",
        "params": {"id": "1"},
        "auth_headers": {},
    }
    hunter.used_payloads = []

    async def fake_send(payload: str):
        return {
            "status": 200,
            "diff": "syntax",
            "body_snippet": "You have an error in your SQL syntax near '''",
            "elapsed_seconds": 0.05,
            "db_detection": {"type": "mysql", "confidence": 0.9},
            "error_classification": {"type": "syntax", "details": "SQL syntax"},
            "poc_request": "GET /vulnerabilities/sqli/?id=1%27 HTTP/1.1\nHost: example.com",
            "poc_response": "HTTP/1.1 200\n\nYou have an error in your SQL syntax",
        }

    hunter._send_request = fake_send

    observation = await hunter.act("request", "id=1'")

    assert "Diff=syntax" in observation
    assert hunter._sql_error_observed is True
    assert hunter._sql_error_evidence["error_type"] == "syntax"
    assert hunter._response_differential["diff_type"] == "syntax"
    assert hunter._last_poc_request.endswith("Host: example.com")


@pytest.mark.asyncio
async def test_sqli_request_action_promotes_mariadb_sql_syntax_error_from_basic_diff():
    hunter = SmartSQLiHunter(config={"model": "test-model", "mode": "ctf"})
    hunter.context = {
        "target": "http://example.com/vulnerabilities/sqli/?id=1",
        "param": "id",
        "method": "GET",
        "params": {"id": "1"},
        "auth_headers": {},
    }
    hunter.used_payloads = []

    async def fake_send(payload: str):
        return {
            "status": 200,
            "diff": "error",
            "body_snippet": (
                "Uncaught mysqli_sql_exception: You have an error in your SQL syntax; "
                "check the manual that corresponds to your MariaDB server version"
            ),
            "elapsed_seconds": 0.05,
            "db_detection": {"type": "mysql", "confidence": 0.9},
            "error_classification": {"type": "none", "details": ""},
            "poc_request": "GET /vulnerabilities/sqli/?id=1%27 HTTP/1.1\nHost: example.com",
            "poc_response": "HTTP/1.1 200\n\nFatal error: mysqli_sql_exception SQL syntax",
        }

    hunter._send_request = fake_send

    observation = await hunter.act("request", "id=1'")

    assert "Diff=error" in observation
    assert hunter._sql_error_observed is True
    assert hunter._sql_error_evidence["error_type"] == "sql_error"
    assert hunter._response_differential["diff_type"] == "error"
