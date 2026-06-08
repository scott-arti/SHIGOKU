from src.commands.report import ExecutionSummary


class DummyTask:
    def __init__(self, result):
        self.result = result


class DummyResultObject:
    def __init__(self, data, findings):
        self.data = data
        self.findings = findings


def test_extract_injection_notes_includes_tested_blind_and_authz():
    summary = ExecutionSummary(completed_tasks=[], context=None)
    task = DummyTask(
        result={
            "data": {
                "execution_log": [
                    {
                        "url_results": [
                            {
                                "url": "http://example.com/vuln?id=1",
                                "tested_params": ["id"],
                                "status": "completed",
                                "retry_count": 1,
                                "blind_correlation": {
                                    "time_based": {"confirmed": True, "observed_latency_seconds": 5.1},
                                    "oob": {"confirmed": True, "hits": [{"token": "t1"}]},
                                    "correlated": True,
                                },
                            }
                        ]
                    }
                ],
                "findings": [
                    {
                        "additional_info": {
                            "authz_differential": {
                                "scenario": "id_manipulation",
                                "confidence": 0.91,
                                "signals": ["id_reflected", {"name": "secret_keyword"}],
                                "original_id": "1",
                                "test_id": "2",
                                "baseline_status": 200,
                                "test_status": 200,
                            }
                        }
                    }
                ],
            }
        }
    )

    notes = summary._extract_injection_notes(task)

    assert "tested_params:" in notes
    assert "blind:" in notes
    assert "authz_diff:" in notes
    assert "id_manipulation" in notes
    assert "id=1->2" in notes
    assert "status=200->200" in notes
    assert "signals=id_reflected,secret_keyword" in notes
    assert "timeout_kpi:" in notes


def test_extract_injection_notes_empty_when_no_data():
    summary = ExecutionSummary(completed_tasks=[], context=None)
    task = DummyTask(result={"data": {"execution_log": []}})

    notes = summary._extract_injection_notes(task)

    assert notes == ""


def test_extract_injection_notes_reads_top_level_result_findings():
    summary = ExecutionSummary(completed_tasks=[], context=None)
    result_obj = DummyResultObject(
        data={"execution_log": []},
        findings=[
            {
                "additional_info": {
                    "authz_differential": {
                        "scenario": "cross_session_access",
                        "confidence": 0.77,
                        "signals": ["id_reflected", "id_reflected"],
                        "original_id": "11",
                        "test_id": "22",
                        "baseline_status": 200,
                        "test_status": 403,
                    }
                }
            }
        ],
    )
    task = DummyTask(result=result_obj)

    notes = summary._extract_injection_notes(task)

    assert "authz_diff:" in notes
    assert "cross_session_access" in notes
    assert "id=11->22" in notes
    assert "status=200->403" in notes
    assert "signals=id_reflected" in notes


def test_extract_injection_notes_timeout_kpi_counts_statuses():
    summary = ExecutionSummary(completed_tasks=[], context=None)
    task = DummyTask(
        result={
            "data": {
                "execution_log": [
                    {
                        "url_results": [
                            {"url": "u1", "status": "completed", "retry_count": 0},
                            {"url": "u2", "status": "timeout", "retry_count": 2},
                            {"url": "u3", "status": "error", "retry_count": 1},
                            {"url": "u4", "status": "cache_hit", "retry_count": 0},
                        ]
                    }
                ]
            }
        }
    )

    notes = summary._extract_injection_notes(task)

    assert "timeout_kpi:" in notes
    assert "total=4" in notes
    assert "completed=2" in notes
    assert "timeout=1" in notes
    assert "error=1" in notes
