"""
SGK-2026-0452 STEP 2: additive extensions of the 0449 evidence-field helpers.

- ``impact_probe_records=None`` (or both observed flags False) -> byte-identical
  0449 impact/steps wording (fail-closed; existing tests keep passing).
- boolean-only observation -> boolean clause in impact, no extraction clause,
  steps = error / true / false (3).
- extraction-only observation -> extraction clause, no boolean clause.
- both observed -> both clauses, steps = error / true / false / extraction (4).
- ``build_sqli_observed_evidence``: explicit ``evidence_request_url`` /
  ``evidence_status`` win over derivation; None keeps the legacy derivation.
- settings flag ``sqli_impact_probe_enabled``: default False, env
  ``SHIGOKU_SQLI_IMPACT_PROBE_ENABLED`` turns it on.

Only ALREADY-OBSERVED facts are asserted; nothing here claims extraction
beyond the single non-sensitive token the caller observed.
"""
from typing import Any, Dict

from src.core.agents.swarm.injection.manager_internal.injection_evidence_fields import (
    build_sqli_impact_and_reproduction_steps,
    build_sqli_observed_evidence,
)
from src.core.config.settings import Settings

# ---------------------------------------------------------------------------
# 0448 run observed facts (literals, same as the 0449 existing tests)
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
# BODY_SNIPPET を _WS_RE と同じ規則で空白圧縮した観測事実（120 文字未満・切詰めなし）
COLLAPSED_EXCERPT = (
    "<html> <head> <meta charset='utf-8'> "
    "<title>Error: SQLITE_ERROR: incomplete input</title>"
)

# ---------------------------------------------------------------------------
# SGK-2026-0452 probe records (observed facts only)
# ---------------------------------------------------------------------------

BOOLEAN_RECORDS = {
    "boolean_differential": {
        "observed": True,
        "true_probe": "q=1' AND 1=1 --",
        "true_result": "HTTP 200, rows=8, body_len=1234",
        "false_probe": "q=1' AND 1=2 --",
        "false_result": "HTTP 200, rows=0, body_len=60",
    },
}

EXTRACTION_RECORDS = {
    "extraction": {
        "observed": True,
        "expr": "sqlite_version()",
        "value": "3.45.1",
        "probe": "q=-1' UNION SELECT sqlite_version(),2,3,4,5,6,7,8,9--",
        "response_excerpt": "3.45.1",
    },
}

BOTH_RECORDS = {
    "boolean_differential": BOOLEAN_RECORDS["boolean_differential"],
    "extraction": EXTRACTION_RECORDS["extraction"],
}

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _base_kwargs(**overrides: Any) -> Dict[str, Any]:
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


def _error_observation_step():
    """Probe-observed branch: the error-observation probe step (base step)."""
    return (
        f"Send GET {PAYLOAD_URL} with parameter '{PARAMETER}' set to '{PAYLOAD}'; "
        f"observed HTTP {ATTACK_STATUS} with a SQL error marker in the response body "
        f"(response excerpt: '{COLLAPSED_EXCERPT}')."
    )


# ---------------------------------------------------------------------------
# 1) byte-identical 0449 wording when no probe is observed
# ---------------------------------------------------------------------------

EXPECTED_IMPACT_0449 = (
    f"Error-based SQL injection indicator on GET parameter '{PARAMETER}': "
    f"the payload '{PAYLOAD}' sent to {PAYLOAD_URL} returned HTTP {ATTACK_STATUS} "
    f"with a SQL error marker observed in the response body "
    f"(response excerpt: '{COLLAPSED_EXCERPT}'). "
    "The sql_error marker is an indicator of error-based injection, "
    "not proof of data extraction."
)
EXPECTED_STEPS_0449 = [
    f"Send GET {PAYLOAD_URL} with parameter '{PARAMETER}' set to the payload '{PAYLOAD}'.",
    f"Observed HTTP status {ATTACK_STATUS} in the response.",
    "The response body contains a SQL error marker (sql_error firing marker) "
    f"(response excerpt: '{COLLAPSED_EXCERPT}').",
]


def test_impact_probe_records_none_is_byte_identical_to_0449():
    impact, steps = build_sqli_impact_and_reproduction_steps(
        **_base_kwargs(impact_probe_records=None)
    )
    assert impact == EXPECTED_IMPACT_0449
    assert steps == EXPECTED_STEPS_0449


def test_impact_probe_records_unobserved_is_byte_identical_to_0449():
    records = {
        "boolean_differential": {"observed": False},
        "extraction": {"observed": False},
    }
    impact, steps = build_sqli_impact_and_reproduction_steps(
        **_base_kwargs(impact_probe_records=records)
    )
    assert impact == EXPECTED_IMPACT_0449
    assert steps == EXPECTED_STEPS_0449


def test_impact_probe_records_empty_dict_is_byte_identical_to_0449():
    impact, steps = build_sqli_impact_and_reproduction_steps(
        **_base_kwargs(impact_probe_records={})
    )
    assert impact == EXPECTED_IMPACT_0449
    assert steps == EXPECTED_STEPS_0449


# ---------------------------------------------------------------------------
# 2) boolean-only observation
# ---------------------------------------------------------------------------


def test_boolean_only_observation_adds_boolean_clause_and_three_steps():
    impact, steps = build_sqli_impact_and_reproduction_steps(
        **_base_kwargs(impact_probe_records=BOOLEAN_RECORDS)
    )
    assert impact is not None
    assert steps is not None
    assert (
        "Boolean differential oracle: 'q=1' AND 1=1 --' returned "
        "HTTP 200, rows=8, body_len=1234 while 'q=1' AND 1=2 --' returned "
        "HTTP 200, rows=0, body_len=60, a deterministic differential "
        "demonstrating the injected condition controls the query logic."
    ) in impact
    # extraction clause must NOT appear (not observed)
    assert "Non-sensitive token extraction" not in impact
    assert len(steps) == 3
    assert steps[0] == _error_observation_step()
    assert steps[1] == (
        f"Send GET {PAYLOAD_URL} with parameter '{PARAMETER}' set to "
        "'q=1' AND 1=1 --'; observed HTTP 200, rows=8, body_len=1234."
    )
    assert steps[2] == (
        f"Send GET {PAYLOAD_URL} with parameter '{PARAMETER}' set to "
        "'q=1' AND 1=2 --'; observed HTTP 200, rows=0, body_len=60."
    )


# ---------------------------------------------------------------------------
# 3) extraction-only observation
# ---------------------------------------------------------------------------


def test_extraction_only_observation_adds_extraction_clause_no_boolean():
    impact, steps = build_sqli_impact_and_reproduction_steps(
        **_base_kwargs(impact_probe_records=EXTRACTION_RECORDS)
    )
    assert impact is not None
    assert steps is not None
    assert (
        "Non-sensitive token extraction: sqlite_version() evaluated to '3.45.1' "
        "and was observed in the response body, demonstrating information "
        "disclosure of server metadata."
    ) in impact
    # boolean clause must NOT appear (not observed)
    assert "Boolean differential oracle" not in impact
    assert len(steps) == 2
    assert steps[0] == _error_observation_step()
    assert steps[1] == (
        f"Send GET {PAYLOAD_URL} with parameter '{PARAMETER}' set to "
        "'q=-1' UNION SELECT sqlite_version(),2,3,4,5,6,7,8,9--'; "
        "observed 'sqlite_version()' evaluated to '3.45.1' in the response body "
        "(response excerpt: '3.45.1')."
    )


# ---------------------------------------------------------------------------
# 4) both observations
# ---------------------------------------------------------------------------


def test_both_observations_add_both_clauses_and_four_steps():
    impact, steps = build_sqli_impact_and_reproduction_steps(
        **_base_kwargs(impact_probe_records=BOTH_RECORDS)
    )
    assert impact is not None
    assert steps is not None
    assert "Boolean differential oracle: 'q=1' AND 1=1 --'" in impact
    assert (
        "Non-sensitive token extraction: sqlite_version() evaluated to '3.45.1'"
    ) in impact
    assert len(steps) == 4
    assert steps[0] == _error_observation_step()
    assert steps[3] == (
        f"Send GET {PAYLOAD_URL} with parameter '{PARAMETER}' set to "
        "'q=-1' UNION SELECT sqlite_version(),2,3,4,5,6,7,8,9--'; "
        "observed 'sqlite_version()' evaluated to '3.45.1' in the response body "
        "(response excerpt: '3.45.1')."
    )


def test_incomplete_boolean_record_omits_boolean_claims():
    """observed=True だが観測値が欠けている record は文言を捏造しない
    （節を省略し、観測済み事実のみで構成）。"""
    records = {
        "boolean_differential": {"observed": True, "true_probe": ""},
    }
    impact, steps = build_sqli_impact_and_reproduction_steps(
        **_base_kwargs(impact_probe_records=records)
    )
    assert impact is not None
    assert steps is not None
    assert "Boolean differential oracle" not in impact
    assert len(steps) == 1  # error observation step only


# ---------------------------------------------------------------------------
# 5) build_sqli_observed_evidence: explicit URL/status win over derivation
# ---------------------------------------------------------------------------


def test_observed_evidence_explicit_url_and_status_win():
    observed = build_sqli_observed_evidence(
        target_url="http://localhost:3000/rest/products/search",
        poc_request=POC_REQUEST,
        poc_response="HTTP/1.1 200\n\nok",
        attack_status=200,
        sql_error_observed=True,
        evidence_request_url="http://localhost:3000/rest/products/search?q=1%27",
        evidence_status=500,
    )
    assert observed["request_method"] == "GET"
    assert observed["request_url"] == "http://localhost:3000/rest/products/search?q=1%27"
    assert observed["response_status"] == 500


def test_observed_evidence_explicit_none_keeps_legacy_derivation():
    observed = build_sqli_observed_evidence(
        target_url="http://localhost:3000/rest/products/search",
        poc_request=POC_REQUEST,
        poc_response=POC_RESPONSE,
        attack_status=ATTACK_STATUS,
        sql_error_observed=True,
        evidence_request_url=None,
        evidence_status=None,
    )
    assert observed["request_method"] == "GET"
    assert observed["request_url"] == PAYLOAD_URL
    assert observed["response_status"] == 500


def test_observed_evidence_explicit_invalid_status_fails_closed():
    observed = build_sqli_observed_evidence(
        target_url="http://localhost:3000/rest/products/search",
        poc_request=POC_REQUEST,
        poc_response=POC_RESPONSE,
        attack_status=ATTACK_STATUS,
        sql_error_observed=True,
        evidence_request_url="http://localhost:3000/rest/products/search?q=1%27",
        evidence_status=0,
    )
    assert observed == {}


# ---------------------------------------------------------------------------
# 6) settings flag: default False, env turns it on
# ---------------------------------------------------------------------------


def test_sqli_impact_probe_enabled_default_off(monkeypatch):
    monkeypatch.delenv("SHIGOKU_SQLI_IMPACT_PROBE_ENABLED", raising=False)
    assert Settings().sqli_impact_probe_enabled is False


def test_sqli_impact_probe_enabled_env_on(monkeypatch):
    monkeypatch.setenv("SHIGOKU_SQLI_IMPACT_PROBE_ENABLED", "true")
    assert Settings().sqli_impact_probe_enabled is True
