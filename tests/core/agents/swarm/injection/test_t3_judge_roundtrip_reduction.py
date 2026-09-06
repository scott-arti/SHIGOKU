"""
SGK-2026-0470 — poc_judge round-trip reduction (caller side only).

Proves (both levers additive, OFF by default -> existing runs unchanged):
- Lever 2 (``t3_skip_unchanged_rejudge_enabled``): a needs_more record whose
  judged-evidence fingerprint is unchanged since the last judge is NOT
  re-judged on the next pass (zero additional judge calls, record kept
  as-is); when the evidence changes the judge runs again and the
  fingerprint is restamped; flag OFF re-judges every pass (existing
  behaviour).
- Lever 1 (``t3_prejudge_dedup_enabled``): within one T3 pass the strongest
  representative per root-cause signature is judged first; same-signature
  findings are skipped ONLY once a member CONFIRMS (redundant). A signature
  that does not confirm is judged member by member — a confirmed is never
  dropped because a needs_more twin sat in front of it (discard-based
  suppression regressed this on control A/B, run 04f64975). Findings
  without a signature are each judged; flag OFF judges every finding.
- The ``judge_fingerprint`` key survives a CandidateLedger save -> load
  round trip (dict projection + recursive masking must not corrupt the
  digest token).

All fixtures are product-independent (target.example style URLs).
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.config.settings import settings
from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.validation import (
    AiJudgement,
    CandidateLedger,
    CandidateLifecycleManager,
    CandidateRecord,
    LifecycleState,
    ReproductionOutcome,
)

SEARCH_URL = "http://target.example/search"
API_URL = "http://target.example/api/account"

FLAG_PREJUDGE_DEDUP = "t3_prejudge_dedup_enabled"
FLAG_SKIP_UNCHANGED = "t3_skip_unchanged_rejudge_enabled"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class _CountingPoCJudge:
    """Scripted poc_judge stand-in recording every judged finding."""

    def __init__(self, outcome: str = "positive"):
        self.outcome = outcome
        self.calls = 0
        self.called_finding_ids: list = []

    def judge(self, finding):
        self.calls += 1
        self.called_finding_ids.append(str(getattr(finding, "id", "") or ""))
        if self.outcome == "inconclusive":
            return AiJudgement(
                payout_grade=False,
                is_real=True,
                has_actual_impact=False,
                counter_evidence=False,
                needs_human=False,
                reason_masked="ai_no_prize_grade (test)",
            )
        return AiJudgement(
            payout_grade=True,
            is_real=True,
            has_actual_impact=True,
            counter_evidence=False,
            needs_human=False,
            reason_masked="hybrid_confirmed (test)",
        )


class _DictPoCJudge:
    """Scripted per-finding verdicts (finding_id -> 'confirmed' |
    'needs_more'; anything else -> confirmed). Deterministic mix inside one
    pass is exactly what the confirm gate must react to."""

    def __init__(self, verdicts: dict):
        self.verdicts = verdicts
        self.calls = 0
        self.called_finding_ids: list = []

    def judge(self, finding):
        self.calls += 1
        fid = str(getattr(finding, "id", "") or "")
        self.called_finding_ids.append(fid)
        if self.verdicts.get(fid) == "needs_more":
            return AiJudgement(
                payout_grade=False,
                is_real=True,
                has_actual_impact=False,
                counter_evidence=False,
                needs_human=False,
                reason_masked="ai_no_prize_grade (test)",
            )
        return AiJudgement(
            payout_grade=True,
            is_real=True,
            has_actual_impact=True,
            counter_evidence=False,
            needs_human=False,
            reason_masked="hybrid_confirmed (test)",
        )


class _FakeReproductionChecker:
    def __init__(self, status: str = "not_run"):
        self.status = status

    def check(self, finding):
        if self.status == "matched":
            return ReproductionOutcome("matched", "reproduction_marker_matched:xss")
        return ReproductionOutcome("not_run", "reproduction_pending")


def _xss_finding(
    *,
    severity: Severity = Severity.MEDIUM,
    body: str = "<script>alert(1)</script>",
    url: str = SEARCH_URL,
    title: str = "Reflected XSS in search",
) -> Finding:
    """A payout-grade reflected-XSS finding (mechanical floor passes)."""
    return Finding(
        vuln_type=VulnType.XSS,
        severity=severity,
        title=title,
        description="d",
        target_url=url,
        evidence=Evidence(
            request_method="GET",
            request_url=f"{url}?q=1",
            response_status=200,
            response_body=body,
        ),
        impact="Reflected XSS in the search result page",
        reproduction_steps=[f"GET {url}?q=1"],
        confidence=0.5,
        additional_info={
            "parameter": "q",
            "poc_request": f"GET {url}?q=1",
            "poc_response": "HTTP/1.1 200 OK",
        },
    )


def _no_signature_finding(vuln_type: VulnType = VulnType.SECRET_LEAK) -> Finding:
    """A finding with no 0470 dedup signature (kept individually)."""
    return Finding(
        vuln_type=vuln_type,
        severity=Severity.LOW,
        title="Plain candidate",
        description="d",
        target_url=API_URL,
        additional_info={},
    )


def _seed_needs_more(finding: Finding, *, budget_used: int = 0) -> CandidateRecord:
    return CandidateRecord(
        finding_id=finding.id,
        state=LifecycleState.NEEDS_MORE,
        reason="seeded",
        vuln_type="xss",
        title=finding.title,
        target_url_masked="",
        evidence_summary={},
        first_seen="2026-09-04T00:00:00+00:00",
        last_investigated="2026-09-04T00:00:00+00:00",
        budget_used=budget_used,
        resurrection_count=0,
        promise_score=0.33,
    )


def _flag_on(monkeypatch, flag: str) -> None:
    """Flip one 0470 settings flag on the lazy settings proxy instance (the
    manager reads the very same proxy object). monkeypatch restores the
    original (False) attribute afterwards, so the model default stays
    authoritative for every later test."""
    monkeypatch.setattr(settings, flag, True)


def _manager(*, judge, checker, ledger, hybrid: bool = True) -> InjectionManagerAgent:
    return InjectionManagerAgent(
        config={"model": "test-model"},
        hybrid_enabled=hybrid,
        poc_judge=judge,
        reproduction_checker=checker,
        candidate_ledger=ledger,
    )


def _apply_verdict(manager, finding, judge, ledger) -> bool:
    return manager._t3_apply_hybrid_verdict(
        finding,
        judge=judge,
        checker=_FakeReproductionChecker("not_run"),
        lifecycle=CandidateLifecycleManager(),
        ledger=ledger,
    )


# ---------------------------------------------------------------------------
# Lever 2 — unchanged-evidence re-judge suppression (cross-pass)
# ---------------------------------------------------------------------------


class TestLever2SkipUnchangedRejudge:
    def test_unchanged_evidence_skips_second_judge(self, monkeypatch, tmp_path):
        """Same judged evidence on two passes -> the judge runs once."""
        _flag_on(monkeypatch, FLAG_SKIP_UNCHANGED)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _xss_finding()
        ledger.put(_seed_needs_more(finding))
        judge = _CountingPoCJudge("positive")
        manager = _manager(
            judge=judge, checker=_FakeReproductionChecker("not_run"), ledger=ledger
        )
        expected_fp = manager._judge_evidence_fingerprint(finding)

        changed1 = _apply_verdict(manager, finding, judge, ledger)
        record = ledger.get(finding.id)
        assert changed1 is True
        assert judge.calls == 1
        assert record is not None
        assert record.state == LifecycleState.NEEDS_MORE
        assert record.evidence_summary.get("judge_fingerprint") == expected_fp

        changed2 = _apply_verdict(manager, finding, judge, ledger)
        assert changed2 is False  # no ledger mutation (record kept as-is)
        assert judge.calls == 1  # judge NOT called again
        after = ledger.get(finding.id)
        assert after is not None
        assert after.evidence_summary.get("judge_fingerprint") == expected_fp

    def test_changed_evidence_rejudges_and_restamps(self, monkeypatch, tmp_path):
        """A changed judged-evidence fingerprint -> judge runs again."""
        _flag_on(monkeypatch, FLAG_SKIP_UNCHANGED)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _xss_finding()
        ledger.put(_seed_needs_more(finding))
        judge = _CountingPoCJudge("positive")
        manager = _manager(
            judge=judge, checker=_FakeReproductionChecker("not_run"), ledger=ledger
        )

        _apply_verdict(manager, finding, judge, ledger)
        record_after_pass1 = ledger.get(finding.id)
        assert record_after_pass1 is not None
        old_fp = record_after_pass1.evidence_summary.get("judge_fingerprint")

        # evidence change (the AI judge's response_body input differs)
        finding.evidence.response_body = "<script>alert(2)</script>"
        changed = _apply_verdict(manager, finding, judge, ledger)
        assert changed is True
        assert judge.calls == 2
        record_after_pass2 = ledger.get(finding.id)
        assert record_after_pass2 is not None
        new_fp = record_after_pass2.evidence_summary.get("judge_fingerprint")
        assert new_fp is not None
        assert new_fp != old_fp

        # unchanged again after the restamp -> skip
        changed = _apply_verdict(manager, finding, judge, ledger)
        assert changed is False
        assert judge.calls == 2

    def test_flag_off_judges_every_pass(self, tmp_path):
        """Flag OFF -> existing behaviour: every pass re-judges (and no
        fingerprint is stamped)."""
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _xss_finding()
        ledger.put(_seed_needs_more(finding))
        judge = _CountingPoCJudge("positive")
        manager = _manager(
            judge=judge, checker=_FakeReproductionChecker("not_run"), ledger=ledger
        )

        assert _apply_verdict(manager, finding, judge, ledger) is True
        assert _apply_verdict(manager, finding, judge, ledger) is True
        assert judge.calls == 2
        record = ledger.get(finding.id)
        assert record is not None
        assert "judge_fingerprint" not in record.evidence_summary


# ---------------------------------------------------------------------------
# Lever 1 — confirm-gated intra-pass suppression (judge until confirmed,
# never discard)
# ---------------------------------------------------------------------------


class TestLever1ConfirmGated:
    """SGK-2026-0470 (Lever 1): representatives are judged first and
    same-signature members are skipped only AFTER one member CONFIRMS.
    A signature that never confirms is judged member by member."""

    def _run_pass(self, manager, findings) -> bool:
        task = SimpleNamespace(target=SEARCH_URL)
        return manager._t3_run_hybrid_pass(task, findings)

    def test_representative_confirmed_then_remaining_same_signature_skipped(
        self, monkeypatch, tmp_path
    ):
        """(a) The representative CONFIRMS -> the remaining same-signature
        findings are NOT judged (judge calls stop at the confirmation)."""
        _flag_on(monkeypatch, FLAG_PREJUDGE_DEDUP)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        # same root-cause signature (title/severity differ -> distinct ids
        # and strengths); the strongest (HIGH) is NOT first in the input,
        # so the reorder must move it to the front for it to confirm first.
        dup_low = _xss_finding(severity=Severity.LOW, title="Reflected XSS in search (p1)")
        dup_high = _xss_finding(severity=Severity.HIGH, title="Reflected XSS in search (p2)")
        dup_med = _xss_finding(severity=Severity.MEDIUM, title="Reflected XSS in search (p3)")
        judge = _DictPoCJudge({})  # every verdict confirms
        manager = _manager(
            judge=judge, checker=_FakeReproductionChecker("matched"), ledger=ledger
        )

        changed = self._run_pass(manager, [dup_low, dup_high, dup_med])

        assert changed is True
        assert judge.calls == 1  # judged until confirmation only
        assert judge.called_finding_ids == [dup_high.id]
        record = ledger.get(dup_high.id)
        assert record is not None
        assert record.state == LifecycleState.CONFIRMED
        assert ledger.get(dup_low.id) is None  # redundant once the sig is confirmed
        assert ledger.get(dup_med.id) is None

    def test_no_member_confirms_then_every_member_is_judged(
        self, monkeypatch, tmp_path
    ):
        """(b) A signature that never confirms is judged member by member —
        NOTHING is discarded (confirm-safety core of the gate)."""
        _flag_on(monkeypatch, FLAG_PREJUDGE_DEDUP)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        a = _xss_finding(title="Reflected XSS in search (n1)")
        b = _xss_finding(title="Reflected XSS in search (n2)")
        c = _xss_finding(title="Reflected XSS in search (n3)")
        judge = _DictPoCJudge(
            {a.id: "needs_more", b.id: "needs_more", c.id: "needs_more"}
        )
        manager = _manager(
            judge=judge, checker=_FakeReproductionChecker("matched"), ledger=ledger
        )

        changed = self._run_pass(manager, [a, b, c])

        assert changed is True
        assert judge.calls == 3
        assert judge.called_finding_ids == [a.id, b.id, c.id]
        for finding in (a, b, c):
            record = ledger.get(finding.id)
            assert record is not None
            assert record.state == LifecycleState.NEEDS_MORE

    def test_confirmed_not_representative_still_judged_and_confirms(
        self, monkeypatch, tmp_path
    ):
        """(b) Regression (control A/B, run 04f64975): a same-strength tie
        where the needs_more twin comes first and becomes the representative.
        The old discard path judged the representative only and silently
        dropped the confirmed member; the confirm gate must judge the second
        member too and reach CONFIRMED."""
        _flag_on(monkeypatch, FLAG_PREJUDGE_DEDUP)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        nm = _xss_finding(title="Reflected XSS in search (tie-needs-more)")
        conf = _xss_finding(title="Reflected XSS in search (tie-confirmed)")
        # Preconditions: identical root-cause signature AND identical
        # strength (severity rank / has_poc / confidence), so the stable
        # reorder keeps input order -> nm is the representative.
        assert InjectionManagerAgent._prejudge_dedup_key(nm) == (
            InjectionManagerAgent._prejudge_dedup_key(conf)
        )
        assert InjectionManagerAgent._prejudge_strength(nm) == (
            InjectionManagerAgent._prejudge_strength(conf)
        )
        assert InjectionManagerAgent._prejudge_order_rep_first([nm, conf])[0].id == nm.id
        judge = _DictPoCJudge({nm.id: "needs_more", conf.id: "confirmed"})
        manager = _manager(
            judge=judge, checker=_FakeReproductionChecker("matched"), ledger=ledger
        )

        changed = self._run_pass(manager, [nm, conf])

        assert changed is True
        assert judge.calls == 2  # needs_more rep does NOT gate the confirmed twin
        assert judge.called_finding_ids == [nm.id, conf.id]
        conf_record = ledger.get(conf.id)
        assert conf_record is not None
        assert conf_record.state == LifecycleState.CONFIRMED
        nm_record = ledger.get(nm.id)
        assert nm_record is not None
        assert nm_record.state == LifecycleState.NEEDS_MORE

    def test_signature_less_findings_kept_and_judged_individually(
        self, monkeypatch, tmp_path
    ):
        """(c) Signature-less findings are judged individually and keep their
        relative order — reordering drops nothing, and a non-confirming
        signature group next to them does not hide them."""
        _flag_on(monkeypatch, FLAG_PREJUDGE_DEDUP)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        dup_a = _xss_finding(title="Reflected XSS in search (g1)")
        dup_b = _xss_finding(title="Reflected XSS in search (g2)")
        none_1 = _no_signature_finding()
        none_2 = _no_signature_finding(VulnType.HOST_HEADER_INJECTION)
        judge = _DictPoCJudge({dup_a.id: "needs_more", dup_b.id: "needs_more"})
        manager = _manager(
            judge=judge, checker=_FakeReproductionChecker("matched"), ledger=ledger
        )

        changed = self._run_pass(manager, [none_1, dup_a, dup_b, none_2])

        assert changed is True
        assert judge.calls == 4  # every finding judged exactly once
        judged = judge.called_finding_ids
        assert set(judged) == {dup_a.id, dup_b.id, none_1.id, none_2.id}
        assert judged.index(none_1.id) < judged.index(none_2.id)
        for finding in (dup_a, dup_b, none_1, none_2):
            assert ledger.get(finding.id) is not None

    def test_prejudge_order_rep_first_reorders_only(self, tmp_path):
        """The reorder helper moves the strongest representative to the front
        of each group (groups in first-appearance order, signature-less
        findings in place) and drops NOTHING."""
        g1_weak = _xss_finding(
            severity=Severity.MEDIUM, title="Reflected XSS in search (g1-weak)"
        )
        g1_med = _xss_finding(
            severity=Severity.MEDIUM, title="Reflected XSS in search (g1-med)"
        )
        g1_strong = _xss_finding(
            severity=Severity.HIGH, title="Reflected XSS in search (g1-strong)"
        )
        g2 = _xss_finding(
            severity=Severity.HIGH,
            title="Reflected XSS in admin search",
            url=API_URL,
        )
        none_1 = _no_signature_finding()
        assert len({InjectionManagerAgent._prejudge_dedup_key(f) for f in (g1_weak, g1_med, g1_strong)}) == 1
        assert InjectionManagerAgent._prejudge_dedup_key(g2) not in (
            InjectionManagerAgent._prejudge_dedup_key(g1_weak),
            None,
        )

        ordered = InjectionManagerAgent._prejudge_order_rep_first(
            [g1_weak, none_1, g2, g1_med, g1_strong]
        )

        # nothing dropped, representative first, groups in first-appearance
        # order, g1 tie (weak before med in input) stays stable, none in place
        assert [f.id for f in ordered] == [
            g1_strong.id, g1_weak.id, g1_med.id, none_1.id, g2.id,
        ]

    def test_flag_off_judges_every_finding(self, tmp_path):
        """(d) Flag OFF -> every finding is judged (byte-identical to today)."""
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        findings = [
            _xss_finding(severity=Severity.LOW, title="Reflected XSS in search (p1)"),
            _xss_finding(severity=Severity.HIGH, title="Reflected XSS in search (p2)"),
            _xss_finding(severity=Severity.MEDIUM, title="Reflected XSS in search (p3)"),
            _no_signature_finding(),
            _no_signature_finding(VulnType.HOST_HEADER_INJECTION),
        ]
        judge = _CountingPoCJudge("positive")
        manager = _manager(
            judge=judge, checker=_FakeReproductionChecker("matched"), ledger=ledger
        )

        changed = self._run_pass(manager, findings)

        assert changed is True
        assert judge.calls == 5
        assert len(set(judge.called_finding_ids)) == 5


# ---------------------------------------------------------------------------
# Fingerprint: stability, coverage of judge inputs, ledger round trip
# ---------------------------------------------------------------------------


class TestJudgeEvidenceFingerprint:
    def test_same_evidence_same_fingerprint(self):
        manager = _manager(
            judge=_CountingPoCJudge(),
            checker=_FakeReproductionChecker("not_run"),
            ledger=CandidateLedger("/tmp/nonexistent_ledger_sgk0470.json"),
        )
        a = _xss_finding()
        b = _xss_finding()  # identical payload
        assert manager._judge_evidence_fingerprint(a) == manager._judge_evidence_fingerprint(b)
        assert len(manager._judge_evidence_fingerprint(a)) == 55

    def test_browser_execution_input_changes_fingerprint(self):
        manager = _manager(
            judge=_CountingPoCJudge(),
            checker=_FakeReproductionChecker("not_run"),
            ledger=CandidateLedger("/tmp/nonexistent_ledger_sgk0470.json"),
        )
        finding = _xss_finding()
        fp_before = manager._judge_evidence_fingerprint(finding)
        finding.additional_info["browser_execution"] = {
            "executor": "playwright",
            "event": "dialog_fired",
            "variant": "stored",
            "dom_mutation_observed": True,
            "dialog_observed": True,
            "test_url": SEARCH_URL,
        }
        fp_after = manager._judge_evidence_fingerprint(finding)
        assert fp_after != fp_before

    def test_fingerprint_survives_ledger_save_load_round_trip(
        self, monkeypatch, tmp_path
    ):
        """The digest survives the CandidateLedger _to_dict/_from_dict
        projection and its recursive masking (stable letters-only token, no re-mask)."""
        _flag_on(monkeypatch, FLAG_SKIP_UNCHANGED)
        ledger_path = tmp_path / "candidate_ledger.json"
        ledger = CandidateLedger(ledger_path)
        finding = _xss_finding()
        ledger.put(_seed_needs_more(finding))
        judge = _CountingPoCJudge("positive")
        manager = _manager(
            judge=judge, checker=_FakeReproductionChecker("not_run"), ledger=ledger
        )

        assert _apply_verdict(manager, finding, judge, ledger) is True
        judged_record = ledger.get(finding.id)
        assert judged_record is not None
        fp_raw = judged_record.evidence_summary["judge_fingerprint"]
        assert len(fp_raw) == 55

        ledger.save()
        reloaded = CandidateLedger.open(ledger_path)
        record = reloaded.get(finding.id)
        assert record is not None
        assert record.evidence_summary.get("judge_fingerprint") == fp_raw
        assert record.evidence_summary.get("judge_fingerprint") == (
            manager._judge_evidence_fingerprint(finding)
        )
