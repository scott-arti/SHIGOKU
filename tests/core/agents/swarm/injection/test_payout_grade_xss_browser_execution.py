"""
SGK-2026-0477 — payout_grade: real-browser DOM-XSS firing evidence.

Covers the ``_match_firing_marker`` xss branch extension: a finding whose
``additional_info.browser_execution.dialog_observed`` is true (the payload
actually executed in a real browser, e.g. DOM XSS via a URL fragment that
never appears in the HTTP body) fires the existing ``reflected_payload``
marker.

- (a) dialog_observed=True without any body XSS marker -> marker
       "reflected_payload" / payout_grade=True (evidence.response_status>0
       + impact + reproduction_steps).
- (b) dialog_observed=False (DOM-mutation-only weak evidence) and no body
       reflection -> marker None / payout_grade=False (weak evidence never
       fires).
- (c) body carries an _XSS_MARKERS token -> "reflected_payload" as before
       (non-regression).
- (d) reflection_observed=True -> "reflected_payload" as before
       (non-regression).
- (e) browser_execution not a dict / empty dict / missing -> no firing when
       the body reflects nothing (fail-closed).
"""
from __future__ import annotations

import pytest

from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade

# Product-independent fixture only: generic XSS payload in a URL fragment.
_DOM_TEST_URL = "http://example.com/#/search?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E"
_XSS_PAYLOAD = "<svg/onload=alert(1)>"


def _xss_finding(**overrides) -> dict:
    """Full structured-evidence XSS finding (impact + reproduction_steps,
    evidence.response_status=200) so every verdict below is decided by the
    firing-marker stage, not by missing evidence/impact."""
    payload = {
        "vuln_type": "xss",
        "evidence": {
            "request_method": "GET",
            "request_url": _DOM_TEST_URL,
            "response_status": 200,
            "response_body": "<html><body>no payload in this body</body></html>",
        },
        "additional_info": {},
        "impact": "Attacker-controlled script executes in the victim's browser.",
        "reproduction_steps": [
            "Send the victim the crafted fragment URL",
            "Observe the browser dialog fire on page load",
        ],
    }
    payload.update(overrides)
    return payload


def _browser_execution(**overrides) -> dict:
    execution = {
        "dialog_observed": True,
        "variant": "dom",
        "event": "dom_runtime_execution",
        "test_url": _DOM_TEST_URL,
        "payload": _XSS_PAYLOAD,
    }
    execution.update(overrides)
    return execution


class TestXssBrowserExecutionMarker:
    def test_dialog_observed_fires_without_body_marker(self) -> None:
        # (a) DOM XSS: payload lives in the URL fragment, the HTTP body never
        # carries a marker — the real-browser dialog is the only firing signal.
        finding = _xss_finding(
            additional_info={"browser_execution": _browser_execution()}
        )
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "reflected_payload"
        assert result.reason == "payout_grade_satisfied"

    def test_dialog_observed_fires_via_poc_pair_without_body_marker(self) -> None:
        # Same firing via the additional_info poc_request/poc_response
        # reproducibility path (evidence-free shape).
        finding = {
            "vuln_type": "xss",
            "additional_info": {
                "poc_request": "GET /#/search?q=canary HTTP/1.1\nHost: example.com",
                "poc_response": "HTTP/1.1 200\n\nno payload in this body",
                "browser_execution": _browser_execution(),
            },
            "impact": "Attacker-controlled script executes in the victim's browser.",
            "reproduction_steps": ["Send the crafted fragment URL"],
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "reflected_payload"

    def test_dom_mutation_only_weak_evidence_never_fires(self) -> None:
        # (b) dialog not observed: even with dom_mutation_observed + variant,
        # the evidence stays below the real-execution bar -> fail-closed.
        finding = _xss_finding(
            additional_info={
                "browser_execution": _browser_execution(
                    dialog_observed=False, dom_mutation_observed=True
                )
            }
        )
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.marker is None
        assert result.reason == "no_firing_marker"

    def test_body_marker_still_fires(self) -> None:
        # (c) non-regression: classic reflected marker in the body fires as
        # before, with no browser evidence at all.
        finding = _xss_finding()
        finding["evidence"]["response_body"] = "<html><script>alert(1)</script></html>"
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "reflected_payload"

    def test_reflection_observed_still_fires(self) -> None:
        # (d) non-regression: reflection_observed alone fires as before.
        finding = _xss_finding(additional_info={"reflection_observed": True})
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "reflected_payload"

    @pytest.mark.parametrize(
        "browser_execution",
        [
            pytest.param("garbage", id="non-dict-string"),
            pytest.param(["dialog_observed", True], id="non-dict-list"),
            pytest.param({}, id="empty-dict"),
            pytest.param({"dialog_observed": False}, id="dialog-false"),
        ],
    )
    def test_missing_or_non_firing_browser_execution_never_fires(
        self, browser_execution
    ) -> None:
        # (e) not a dict / empty dict / dialog false -> no firing when the
        # body reflects nothing.
        finding = _xss_finding(additional_info={"browser_execution": browser_execution})
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.marker is None
        assert result.reason == "no_firing_marker"

    def test_absent_browser_execution_never_fires(self) -> None:
        # (e) key entirely absent -> fail-closed, unchanged behavior.
        result = evaluate_payout_grade(_xss_finding())
        assert result.payout_grade is False
        assert result.marker is None
        assert result.reason == "no_firing_marker"
