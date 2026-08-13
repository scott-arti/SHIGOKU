"""
SGK-2026-0449 Scope B tests: observed-request evidence + impact/repro fill
for error-based SQLi findings.

Fixture: observed facts from the SGK-2026-0448 run, written as literals
(0448 candidate: GET /rest/products/search?q=... -> HTTP 500 with a
SQLITE_ERROR body marker). Only ALREADY-OBSERVED facts are asserted;
nothing here claims data extraction.
"""
from urllib.parse import parse_qsl, urlsplit

from src.core.agents.swarm.injection.manager_internal.injection_evidence_fields import (
    build_sqli_impact_and_reproduction_steps,
    build_sqli_observed_evidence,
)
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.agents.swarm.injection.smart_sqli import _build_sqli_evidence_and_impact
from src.core.engine.vdp_follow_up_executor import build_request_fingerprint

# ---------------------------------------------------------------------------
# 0448 run observed facts (literals)
# ---------------------------------------------------------------------------

POC_REQUEST = (
    "GET /rest/products/search?q=%27+OR+%271%27%3D%271%27+--&method=GET HTTP/1.1\n"
    "Host: localhost:3000"
)
POC_RESPONSE = (
    "HTTP/1.1 500\nContent-Type: text/html; charset=utf-8\n\n"
    "<html><title>Error: SQLITE_ERROR: incomplete input</title></html>"
)
PAYLOAD = "q=' OR '1'='1' --"
PARAMETER = "q"
ATTACK_STATUS = 500
BODY_SNIPPET = (
    "<html>\n  <head>\n    <meta charset='utf-8'> \n"
    "    <title>Error: SQLITE_ERROR: incomplete input</title>"
)
PAYLOAD_URL = "http://localhost:3000/rest/products/search?q=%27+OR+%271%27%3D%271%27+--&method=GET"


def _base_kwargs(**overrides):
    kwargs = dict(
        parameter=PARAMETER,
        payload=PAYLOAD,
        method="GET",
        request_url=PAYLOAD_URL,
        response_status=ATTACK_STATUS,
        sql_error_observed=True,
        marker_excerpt=BODY_SNIPPET,
    )
    kwargs.update(overrides)
    return kwargs


def test_impact_and_steps_fire_with_complete_observation():
    impact, steps = build_sqli_impact_and_reproduction_steps(**_base_kwargs())
    assert impact is not None
    assert steps is not None
    assert PARAMETER in impact
    assert PAYLOAD in impact
    assert "500" in impact
    assert "not proof of data extraction" in impact
    assert len(steps) == 3
    assert any(step.startswith("Send GET ") for step in steps)


def test_fail_closed_when_sql_error_not_observed():
    impact, steps = build_sqli_impact_and_reproduction_steps(
        **_base_kwargs(sql_error_observed=False)
    )
    assert impact is None
    assert steps is None


def test_fail_closed_when_payload_missing():
    impact, steps = build_sqli_impact_and_reproduction_steps(
        **_base_kwargs(payload="")
    )
    assert impact is None
    assert steps is None


def test_fail_closed_when_parameter_missing():
    impact, steps = build_sqli_impact_and_reproduction_steps(
        **_base_kwargs(parameter="")
    )
    assert impact is None
    assert steps is None


def test_fail_closed_when_status_zero():
    impact, steps = build_sqli_impact_and_reproduction_steps(
        **_base_kwargs(response_status=0)
    )
    assert impact is None
    assert steps is None


def test_fail_closed_when_url_invalid():
    impact, steps = build_sqli_impact_and_reproduction_steps(
        **_base_kwargs(request_url="not-a-url")
    )
    assert impact is None
    assert steps is None

    impact, steps = build_sqli_impact_and_reproduction_steps(
        **_base_kwargs(request_url="ftp://x/y")
    )
    assert impact is None
    assert steps is None


def test_fail_closed_when_method_non_read_only():
    impact, steps = build_sqli_impact_and_reproduction_steps(
        **_base_kwargs(method="POST")
    )
    assert impact is None
    assert steps is None


def test_observed_evidence_records_request_identity():
    observed = build_sqli_observed_evidence(
        target_url="http://localhost:3000/rest/products/search",
        poc_request=POC_REQUEST,
        poc_response=POC_RESPONSE,
        attack_status=ATTACK_STATUS,
        sql_error_observed=True,
    )
    assert observed["request_method"] == "GET"
    assert observed["request_url"] == PAYLOAD_URL
    assert observed["response_status"] == 500


def test_observed_evidence_fail_closed():
    # sql_error not observed -> {}
    observed = build_sqli_observed_evidence(
        target_url="http://localhost:3000/rest/products/search",
        poc_request=POC_REQUEST,
        poc_response=POC_RESPONSE,
        attack_status=ATTACK_STATUS,
        sql_error_observed=False,
    )
    assert observed == {}

    # empty poc_request -> {}
    observed = build_sqli_observed_evidence(
        target_url="http://localhost:3000/rest/products/search",
        poc_request="",
        poc_response=POC_RESPONSE,
        attack_status=ATTACK_STATUS,
        sql_error_observed=True,
    )
    assert observed == {}

    # attack_status 0 and no status line in poc_response -> {}
    observed = build_sqli_observed_evidence(
        target_url="http://localhost:3000/rest/products/search",
        poc_request=POC_REQUEST,
        poc_response="no status line here",
        attack_status=0,
        sql_error_observed=True,
    )
    assert observed == {}


def test_evidence_fingerprint_matches_replay():
    observed = build_sqli_observed_evidence(
        target_url="http://localhost:3000/rest/products/search",
        poc_request=POC_REQUEST,
        poc_response=POC_RESPONSE,
        attack_status=ATTACK_STATUS,
        sql_error_observed=True,
    )
    query = urlsplit(observed["request_url"]).query
    param_names = tuple(sorted(key for key, _ in parse_qsl(query)))
    assert build_request_fingerprint(
        observed["request_method"], observed["request_url"], param_names
    ) == build_request_fingerprint("GET", observed["request_url"], param_names)


def test_filled_finding_passes_payout_grade_and_empty_fails():
    evidence = {
        "request_method": "GET",
        "request_url": PAYLOAD_URL,
        "response_status": 500,
        "response_body": BODY_SNIPPET,
    }
    additional_info = {
        "parameter": PARAMETER,
        "payload": PAYLOAD,
        "payloads_used": [PAYLOAD],
        "sql_error_observed": True,
        "sql_error_evidence": {"body_snippet": BODY_SNIPPET},
        "poc_request": POC_REQUEST,
        "poc_response": POC_RESPONSE,
        "response_differential": {"attack_status": ATTACK_STATUS},
    }

    impact, steps = build_sqli_impact_and_reproduction_steps(**_base_kwargs())
    filled = {
        "vuln_type": "sqli",
        "evidence": evidence,
        "additional_info": additional_info,
        "impact": impact,
        "reproduction_steps": steps,
    }
    result = evaluate_payout_grade(filled)
    assert result.payout_grade is True
    assert result.reason == "payout_grade_satisfied"
    assert result.marker == "sql_error"

    unfilled = {
        "vuln_type": "sqli",
        "evidence": evidence,
        "additional_info": additional_info,
    }
    result = evaluate_payout_grade(unfilled)
    assert result.payout_grade is False
    assert result.reason == "missing_impact"


def test_wiring_0448_candidate_shape():
    result = {
        "param": PARAMETER,
        "payloads_used": [PAYLOAD],
        "sql_error_observed": True,
        "sql_error_evidence": {"body_snippet": BODY_SNIPPET},
        "response_differential": {"attack_status": ATTACK_STATUS},
        "poc_request": POC_REQUEST,
        "poc_response": POC_RESPONSE,
    }
    observed, impact, steps = _build_sqli_evidence_and_impact(
        result, "http://localhost:3000/rest/products/search"
    )
    assert observed["request_method"] == "GET"
    assert observed["request_url"] == PAYLOAD_URL
    assert observed["response_status"] == 500
    assert impact is not None
    assert steps is not None
