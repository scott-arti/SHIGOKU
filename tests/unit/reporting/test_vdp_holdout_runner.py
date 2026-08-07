"""
SGK-2026-0423 Lane B — offline holdout runner tests.

Covers requirements 14-22:
14. run with pass-level records -> outcome pass, leakage 0
15. metric below threshold -> hold
16. leakage hit -> fail
17. eval_version mismatch with thresholds -> EvalVersionMismatch
18. assert_thresholds_frozen_for_eval_version: same eval_version + different
    fingerprint -> EvalVersionMismatch
19. save/load result roundtrip with artifact_hash match
20. runner consumes ONLY canonical records — summary/records constructed via
    vdp_contract models (generic fixtures, no target names)
21. metrics separate (no single composite) — metrics dict has per-class /
    per-actor / per-trust_boundary keys
22. result never contains secret markers (no Authorization/Cookie/token
    values in saved JSON)

All fixtures are GENERIC (example.com-style hosts) — no product names,
known URLs or known payloads of a specific target.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
from src.core.models.vdp_contract import (
    VDP_CONTRACT_SCHEMA_VERSION,
    AttemptRecord,
    EvidenceRecordV1,
    EvidenceVerdictV1,
    HypothesisRecord,
    NextActionRecord,
    canonical_json_bytes,
)
from src.reporting.vdp_canonical import VdpCanonicalSummary
from src.reporting.vdp_dataset import (
    ThresholdArtifact,
    ThresholdMetric,
    freeze_thresholds,
    thresholds_fingerprint,
)
from src.reporting.vdp_holdout_runner import (
    EvalVersionMismatch,
    HoldoutEvaluationResult,
    assert_thresholds_frozen_for_eval_version,
    run_holdout_evaluation,
    save_evaluation_result,
    verify_no_runtime_leakage,
)

_GENERIC_HYPOTHESIS_TEXT = "cross-actor object read at example.com"
_GENERIC_PRODUCT = "acme-web-store"
_GENERIC_CAPABILITY = "authz_detector"
_GENERIC_GT_CLASS = "authz"


def _hypothesis(hypothesis_id: str, observation_id: str,
                capability: str = _GENERIC_CAPABILITY,
                text: str = _GENERIC_HYPOTHESIS_TEXT,
                asset: str = "https://example.com/items") -> HypothesisRecord:
    return HypothesisRecord(
        hypothesis_id=hypothesis_id,
        observation_id=observation_id,
        asset=asset,
        capability=capability,
        hypothesis_text=text,
        trust_boundary="api_endpoint",
        actors=["actor-a", "actor-b"],
        state="attempted",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
        observation_ids=[observation_id],
    )


def _gt(*, cls: str = _GENERIC_GT_CLASS, capability: str = _GENERIC_CAPABILITY,
        method: str = "get", endpoint: str) -> dict:
    """One product-independent ground-truth entry (generic capability
    vocabulary + normalized endpoint structure — never product names)."""
    return {"class": cls, "capability": capability,
            "method": method, "endpoint": endpoint}


def _labels(ground_truth: list) -> dict:
    """Holdout labels dict: leakage lists plus the optional ground_truth."""
    return {"urls": [], "payloads": [], "product_names": [],
            "ground_truth": ground_truth}


def _attempt(attempt_id: str, hypothesis_id: str) -> AttemptRecord:
    return AttemptRecord(
        attempt_id=attempt_id,
        hypothesis_id=hypothesis_id,
        actor="actor-b",
        request_fingerprint="fp-" + attempt_id,
        scope_verdict="allowed",
        state="evidence_saved",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
    )


def _evidence(evidence_id: str, attempt_id: str) -> EvidenceRecordV1:
    return EvidenceRecordV1(
        evidence_id=evidence_id,
        attempt_id=attempt_id,
        evidence_type="real_http_response",
        redacted_excerpt="HTTP/1.1 200 OK",
        raw_hash="sha256:" + "a" * 64,
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
    )


def _next_action(next_action_id: str, verdict_id: str) -> NextActionRecord:
    return NextActionRecord(
        next_action_id=next_action_id,
        verdict_id=verdict_id,
        action_class="follow_up_probe",
        risk_class="read_only",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
    )


def _summary(signer=None, hypothesis_count: int = 2) -> VdpCanonicalSummary:
    """Build a canonical summary purely from vdp_contract records.

    When ``signer`` is given the verdicts are confirmed (engine signer used
    only in tests); otherwise they are candidates. The runner itself never
    imports engine modules.
    """
    hypotheses, attempts, evidence_records, verdicts, next_actions = [], [], [], [], []
    for i in range(1, hypothesis_count + 1):
        hid, aid, eid = f"hyp-{i:03d}", f"att-{i:03d}", f"ev-{i:03d}"
        hypotheses.append(_hypothesis(hid, f"obs-{i:03d}"))
        attempts.append(_attempt(aid, hid))
        evidence_records.append(_evidence(eid, aid))
        if signer is not None:
            verdicts.append(signer.create_confirmed_verdict(
                verdict_id=f"ver-{i:03d}",
                hypothesis_id=hid,
                reason_codes=["evidence_contract_satisfied"],
                validator_version="test-validator-0.1",
                evidence_records=[evidence_records[-1].to_dict()],
            ))
        else:
            verdicts.append(EvidenceVerdictV1(
                verdict_id=f"ver-{i:03d}",
                hypothesis_id=hid,
                _status="candidate",
                schema_version=VDP_CONTRACT_SCHEMA_VERSION,
            ))
        next_actions.append(_next_action(f"nxt-{i:03d}", f"ver-{i:03d}"))
    return VdpCanonicalSummary(
        source_kind="canonical_vdp",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
        hypotheses=tuple(hypotheses),
        attempts=tuple(attempts),
        evidence_records=tuple(evidence_records),
        verdicts=tuple(verdicts),
        next_actions=tuple(next_actions),
    )


def _confirmed_summary(assets: list, capabilities=None) -> VdpCanonicalSummary:
    """A canonical summary where every hypothesis carries a CONFIRMED
    verdict (engine signer used only in tests). ``assets`` and
    ``capabilities`` map positionally to hypotheses."""
    signer = _signer()
    hypotheses, attempts, evidence_records, verdicts, next_actions = [], [], [], [], []
    for i, asset in enumerate(assets, start=1):
        cap = capabilities[i - 1] if capabilities else _GENERIC_CAPABILITY
        hid, aid, eid = f"hyp-{i:03d}", f"att-{i:03d}", f"ev-{i:03d}"
        hypotheses.append(_hypothesis(hid, f"obs-{i:03d}", capability=cap, asset=asset))
        attempts.append(_attempt(aid, hid))
        evidence_records.append(_evidence(eid, aid))
        verdicts.append(signer.create_confirmed_verdict(
            verdict_id=f"ver-{i:03d}",
            hypothesis_id=hid,
            reason_codes=["evidence_contract_satisfied"],
            validator_version="test-validator-0.1",
            evidence_records=[evidence_records[-1].to_dict()],
        ))
        next_actions.append(_next_action(f"nxt-{i:03d}", f"ver-{i:03d}"))
    return VdpCanonicalSummary(
        source_kind="canonical_vdp",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
        hypotheses=tuple(hypotheses),
        attempts=tuple(attempts),
        evidence_records=tuple(evidence_records),
        verdicts=tuple(verdicts),
        next_actions=tuple(next_actions),
    )


def _thresholds(eval_version: str = "ev-1", metrics=None):
    if metrics is None:
        metrics = [ThresholdMetric(
            name=f"recall:{_GENERIC_GT_CLASS}", value=0.5,
            formula="matched_ground_truth / ground_truth",
            target_set="hidden_holdout")]
    return freeze_thresholds(eval_version=eval_version,
                             decided_at="2026-08-04T00:00:00Z",
                             metrics=metrics)


def _signer(seed: str = "d1") -> Ed25519EvidenceSigner:
    return Ed25519EvidenceSigner(private_key=bytes.fromhex(seed * 32))


class TestHoldoutOutcome:
    def test_pass_outcome_with_healthy_records(self):
        summary = _summary(signer=_signer())
        thresholds = _thresholds()
        # ground truth: one entry matching the confirmed hypotheses'
        # capability + normalized endpoint -> label-based recall 1.0
        labels = _labels([_gt(endpoint="/items")])
        result = run_holdout_evaluation(
            summary, labels=labels, thresholds=thresholds,
            eval_version="ev-1", runner_version="runner-test-1",
            session_ref="sess-1")
        assert result.outcome == "pass"
        assert result.leakage_hits == []
        assert verify_no_runtime_leakage(result) is True
        assert result.schema_version == 1
        assert result.eval_version == "ev-1"
        assert result.input_session_ref == "sess-1"
        assert result.threshold_fingerprint == thresholds_fingerprint(thresholds)
        assert result.started_at and result.finished_at
        assert result.metrics[f"recall:{_GENERIC_GT_CLASS}"]["value"] == pytest.approx(1.0)

    def test_metric_below_threshold_hold(self):
        summary = _summary(signer=_signer("d2"))
        # ground truth: only one of two entries matches a confirmed
        # hypothesis -> label-based recall 0.5
        labels = _labels([_gt(endpoint="/items"), _gt(endpoint="/users/7")])
        thresholds = _thresholds()
        thresholds.metrics[0].value = 0.9
        result = run_holdout_evaluation(
            summary, labels=labels, thresholds=thresholds,
            eval_version="ev-1", runner_version="runner-test-1")
        assert result.outcome == "hold"
        assert result.leakage_hits == []
        entry = result.metrics[f"recall:{_GENERIC_GT_CLASS}"]
        assert entry["value"] == pytest.approx(0.5)
        assert entry["met"] is False
        assert entry["threshold"] == 0.9

    def test_leakage_hit_fails(self):
        summary = _summary(signer=_signer("d3"))
        summary = replace(
            summary,
            hypotheses=tuple([
                replace(summary.hypotheses[0],
                        hypothesis_text=f"session handling of {_GENERIC_PRODUCT}"),
            ] + list(summary.hypotheses[1:])),
        )
        labels = {"urls": [], "payloads": [], "product_names": [_GENERIC_PRODUCT]}
        result = run_holdout_evaluation(
            summary, labels=labels, thresholds=_thresholds(),
            eval_version="ev-1", runner_version="runner-test-1")
        assert result.outcome == "fail"
        assert result.leakage_hits
        assert verify_no_runtime_leakage(result) is False
        assert any(h.kind == "product_name" and h.matched == _GENERIC_PRODUCT
                   for h in result.leakage_hits)

    def test_eval_version_mismatch_raises(self):
        summary = _summary()
        thresholds = _thresholds(eval_version="ev-2")
        with pytest.raises(EvalVersionMismatch):
            run_holdout_evaluation(summary, labels={}, thresholds=thresholds,
                                   eval_version="ev-1", runner_version="runner-test-1")


# ---------------------------------------------------------------------------
# Label-based quality metrics (Lane G): recall against product-independent
# ground truth, false promotion of confirmed verdicts without a gt match.
# ---------------------------------------------------------------------------


class TestLabelBasedRecall:
    def test_recall_matches_ground_truth(self):
        # Confirmed hypotheses match gt entries by capability + normalized
        # endpoint. A DIFFERENT host still matches (host-agnostic); an
        # unmatched class scores 0.0.
        summary = _confirmed_summary(
            assets=[
                "https://alpha.example.com/items/42",
                "https://beta.example.com/users/7",
                "https://alpha.example.com/search/1",
            ],
            capabilities=["authz_detector", "authz_detector", "sqli_detector"],
        )
        labels = _labels([
            _gt(endpoint="/items/42"),
            _gt(endpoint="https://gamma.example.com/users/7"),
            _gt(cls="sqli", capability="sqli_detector", method="post",
                endpoint="/search/1"),
            _gt(cls="xss", capability="xss_detector", method="get",
                endpoint="/profile/3"),
        ])
        result = run_holdout_evaluation(
            summary, labels=labels, thresholds=_thresholds(),
            eval_version="ev-1", runner_version="runner-test-1")
        assert result.metrics["recall"]["value"] == pytest.approx(0.75)
        assert result.metrics["recall:authz"]["value"] == pytest.approx(1.0)
        assert result.metrics["recall:sqli"]["value"] == pytest.approx(1.0)
        assert result.metrics["recall:xss"]["value"] == pytest.approx(0.0)

    def test_target_name_substitution_does_not_fake_match(self):
        # Same capability + host-substituted endpoint -> match (target-name
        # substitution is still detected, never faked).
        gt = [{"class": "authz", "capability": "authz_detector",
               "method": "get", "endpoint": "https://gamma.example.com/items/42"}]
        matched = run_holdout_evaluation(
            _confirmed_summary(["https://beta.example.com/items/42"]),
            labels=_labels(gt), thresholds=_thresholds(),
            eval_version="ev-1", runner_version="runner-test-1")
        assert matched.metrics["recall"]["value"] == pytest.approx(1.0)
        assert matched.metrics["false_promotion_rate"]["value"] == pytest.approx(0.0)

        # Different capability -> NO match, even on the same endpoint.
        unmatched = run_holdout_evaluation(
            _confirmed_summary(["https://beta.example.com/items/42"],
                               capabilities=["sqli_detector"]),
            labels=_labels(gt), thresholds=_thresholds(),
            eval_version="ev-1", runner_version="runner-test-1")
        assert unmatched.metrics["recall"]["value"] == pytest.approx(0.0)
        assert unmatched.metrics["false_promotion_rate"]["value"] == pytest.approx(1.0)


class TestFalsePromotionRate:
    def test_false_promotion_rate_matches_confirmed_without_gt(self):
        # One of two confirmed hypotheses has no gt match -> 0.5.
        mixed = run_holdout_evaluation(
            _confirmed_summary([
                "https://alpha.example.com/items/42",
                "https://alpha.example.com/other/9",
            ]),
            labels=_labels([_gt(endpoint="/items/42")]),
            thresholds=_thresholds(),
            eval_version="ev-1", runner_version="runner-test-1")
        assert mixed.metrics["false_promotion_rate"]["value"] == pytest.approx(0.5)
        assert mixed.metrics["false_promotion_rate:authz"]["value"] == pytest.approx(0.5)

        # Every confirmed hypothesis matched -> 0.0.
        all_matched = run_holdout_evaluation(
            _confirmed_summary(["https://alpha.example.com/items/42"]),
            labels=_labels([_gt(endpoint="/items/42")]),
            thresholds=_thresholds(),
            eval_version="ev-1", runner_version="runner-test-1")
        assert all_matched.metrics["false_promotion_rate"]["value"] == pytest.approx(0.0)
        assert all_matched.metrics["false_promotion_rate:authz"]["value"] == pytest.approx(0.0)


class TestLabelBasedThresholds:
    def test_threshold_on_label_based_metrics(self):
        # 1 of 4 gt entries matched (recall 0.25); 1 of 2 confirmed has no
        # gt match (false_promotion_rate 0.5).
        summary = _confirmed_summary([
            "https://alpha.example.com/items/42",
            "https://alpha.example.com/other/9",
        ])
        labels = _labels([
            _gt(endpoint="/items/42"),
            _gt(endpoint="/users/7"),
            _gt(cls="sqli", capability="sqli_detector", endpoint="/search/1"),
            _gt(cls="xss", capability="xss_detector", endpoint="/profile/3"),
        ])

        def _run(recall_value: float, fp_value: float):
            thresholds = freeze_thresholds(
                eval_version="ev-1", decided_at="2026-08-04T00:00:00Z",
                metrics=[
                    ThresholdMetric(name="recall", value=recall_value,
                                    formula="matched / total",
                                    target_set="hidden_holdout"),
                    ThresholdMetric(name="false_promotion_rate", value=fp_value,
                                    formula="confirmed_without_gt / confirmed",
                                    target_set="hidden_holdout"),
                ],
            )
            return run_holdout_evaluation(
                summary, labels=labels, thresholds=thresholds,
                eval_version="ev-1", runner_version="runner-test-1")

        held = _run(recall_value=0.5, fp_value=0.1)
        assert held.outcome == "hold"
        assert held.metrics["recall"]["value"] == pytest.approx(0.25)
        assert held.metrics["recall"]["met"] is False
        assert held.metrics["false_promotion_rate"]["value"] == pytest.approx(0.5)
        assert held.metrics["false_promotion_rate"]["met"] is False

        passed = _run(recall_value=0.25, fp_value=0.5)
        assert passed.outcome == "pass"
        assert passed.metrics["recall"]["met"] is True
        assert passed.metrics["false_promotion_rate"]["met"] is True

    def test_no_ground_truth_adds_gap_and_zero_recall(self):
        summary = _confirmed_summary(["https://alpha.example.com/items/42"])
        labels = {"urls": [], "payloads": [], "product_names": []}
        result = run_holdout_evaluation(
            summary, labels=labels, thresholds=_thresholds(),
            eval_version="ev-1", runner_version="runner-test-1")
        assert result.metrics["recall"]["value"] == pytest.approx(0.0)
        assert result.gaps == ["no_ground_truth"]
        # the frozen recall threshold is unmet (fail-closed) -> hold
        assert result.outcome == "hold"


class TestGapsRoundtrip:
    def test_result_roundtrip_includes_gaps(self, tmp_path):
        summary = _confirmed_summary(["https://alpha.example.com/items/42"])
        result = run_holdout_evaluation(
            summary, labels={}, thresholds=_thresholds(),
            eval_version="ev-1", runner_version="runner-test-1")
        assert result.gaps == ["no_ground_truth"]
        assert result.to_dict()["gaps"] == ["no_ground_truth"]

        path = tmp_path / "result.json"
        save_evaluation_result(result, path)
        data = json.loads(path.read_text(encoding="utf-8"))
        loaded = HoldoutEvaluationResult.from_dict(data)
        assert loaded.gaps == ["no_ground_truth"]
        # gaps participate in the artifact hash
        recomputed = hashlib.sha256(canonical_json_bytes(
            {k: v for k, v in data.items() if k != "artifact_hash"}
        )).hexdigest()
        assert loaded.artifact_hash == recomputed


class TestFrozenThresholdsGuard:
    def test_frozen_thresholds_for_eval_version(self, tmp_path):
        summary = _summary()
        t1 = _thresholds(eval_version="ev-9")
        result = run_holdout_evaluation(
            summary, labels={}, thresholds=t1,
            eval_version="ev-9", runner_version="runner-test-1")
        path = tmp_path / "result.json"
        save_evaluation_result(result, path)

        # same thresholds -> no raise
        assert_thresholds_frozen_for_eval_version(path, t1)

        # same eval_version, different threshold artifact -> EvalVersionMismatch
        t2 = _thresholds(eval_version="ev-9")
        t2.metrics[0].value = 0.99
        with pytest.raises(EvalVersionMismatch):
            assert_thresholds_frozen_for_eval_version(path, t2)

        # different eval_version -> no claim, no raise
        t3 = _thresholds(eval_version="ev-10")
        assert_thresholds_frozen_for_eval_version(path, t3)

        # missing result file -> first run, no raise
        assert_thresholds_frozen_for_eval_version(tmp_path / "missing.json", t1)


class TestResultArtifact:
    def test_save_load_roundtrip_artifact_hash(self, tmp_path):
        summary = _summary()
        result = run_holdout_evaluation(
            summary, labels={}, thresholds=_thresholds(),
            eval_version="ev-1", runner_version="runner-test-1")
        path = tmp_path / "result.json"
        save_evaluation_result(result, path)
        assert path.exists()

        data = json.loads(path.read_text(encoding="utf-8"))
        loaded = HoldoutEvaluationResult.from_dict(data)
        assert loaded.outcome == result.outcome
        assert loaded.eval_version == result.eval_version
        assert loaded.runner_version == "runner-test-1"
        assert loaded.artifact_hash == result.artifact_hash
        assert loaded.artifact_hash

        recomputed = hashlib.sha256(canonical_json_bytes(
            {k: v for k, v in data.items() if k != "artifact_hash"}
        )).hexdigest()
        assert loaded.artifact_hash == recomputed

    def test_runner_consumes_only_canonical_records(self):
        # No signer, no session dict: records built via vdp_contract models.
        summary = _summary()
        thresholds = freeze_thresholds(eval_version="ev-1",
                                       decided_at="2026-08-04T00:00:00Z",
                                       metrics=[])
        result = run_holdout_evaluation(
            summary, labels={}, thresholds=thresholds,
            eval_version="ev-1", runner_version="runner-test-1")
        assert result.outcome == "pass"
        assert result.metrics["funnel:observation_to_hypothesis"]["value"] == 1.0
        assert result.metrics["funnel:hypothesis_to_attempt"]["value"] == 1.0

        # Fixture hygiene (structural): record text carries no URLs, and the
        # only host referenced anywhere is the generic example.com.
        for h in summary.hypotheses:
            assert "://" not in h.hypothesis_text
            assert "example.com" in h.asset
        for a in summary.attempts:
            assert "://" not in a.request_fingerprint
        assert "://" not in _GENERIC_PRODUCT

    def test_metrics_are_separate_no_composite_score(self):
        summary = _summary(signer=_signer("d4"))
        labels = _labels([_gt(endpoint="/items")])
        result = run_holdout_evaluation(
            summary, labels=labels, thresholds=_thresholds(),
            eval_version="ev-1", runner_version="runner-test-1")
        keys = set(result.metrics)
        assert any(k.startswith("coverage:class:") for k in keys)
        assert any(k.startswith("coverage:actor:") for k in keys)
        assert any(k.startswith("coverage:trust_boundary:") for k in keys)
        # recall:* holds ONLY label-based values now: overall recall plus a
        # per-ground-truth-class recall; no self-referential actor/boundary
        # recall variants remain.
        assert "recall" in keys
        assert any(k.startswith("recall:") for k in keys)
        assert not any(k.startswith("recall:actor:") for k in keys)
        assert not any(k.startswith("recall:trust_boundary:") for k in keys)
        assert not any(k.startswith("recall:class:") for k in keys)
        assert "false_promotion_rate" in keys
        assert any(k.startswith("false_promotion_rate:") for k in keys)
        assert "evidence_completeness" in keys
        assert "untested_rate" in keys
        assert "budget_compliance" in keys
        assert "funnel:observation_to_hypothesis" in keys
        assert "funnel:hypothesis_to_attempt" in keys
        assert "funnel:attempt_to_follow_up" in keys
        assert "funnel:follow_up_to_verdict" in keys
        assert not any(("composite" in k or "overall" in k or "score" in k)
                       for k in keys)
        for k in (f"recall:{_GENERIC_GT_CLASS}",
                  "evidence_completeness", "false_promotion_rate"):
            assert {"value", "formula", "target_set"}.issubset(result.metrics[k])

    def test_result_never_contains_secret_markers(self, tmp_path):
        summary = _summary(signer=_signer("d5"))
        secret_value = "sekret-token-987654"
        summary = replace(
            summary,
            hypotheses=tuple([
                replace(summary.hypotheses[0],
                        hypothesis_text="Authorization: Bearer " + secret_value),
            ] + list(summary.hypotheses[1:])),
        )
        result = run_holdout_evaluation(
            summary, labels={}, thresholds=_thresholds(),
            eval_version="ev-1", runner_version="runner-test-1")
        path = tmp_path / "result.json"
        save_evaluation_result(result, path)

        raw = path.read_text(encoding="utf-8").lower()
        assert secret_value not in raw
        assert "bearer" not in raw
        assert "authorization" not in raw

        data = json.loads(path.read_text(encoding="utf-8"))
        assert "authorization" not in data
        assert "cookie" not in data
        assert "token" not in data


# ---------------------------------------------------------------------------
# Lane J-1 (audit wave 3): explicit threshold comparison direction
# (minimum | maximum) and additive result metadata.
# ---------------------------------------------------------------------------


class TestThresholdDirection:
    """Lane J-1: thresholds bind by their explicit ``direction`` —
    "minimum" requires value >= bound, "maximum" requires value <= bound.
    Legacy artifacts without the field keep historical upper-bound semantics
    for ``false_promotion_rate:*`` and ``untested_rate``."""

    @staticmethod
    def _thresholds(*metrics) -> ThresholdArtifact:
        return freeze_thresholds(
            eval_version="ev-1", decided_at="2026-08-04T00:00:00Z",
            metrics=list(metrics),
        )

    @staticmethod
    def _verdict_summary(*statuses: str) -> VdpCanonicalSummary:
        """A canonical summary whose verdicts carry exactly the given
        statuses (untested verdicts use a valid budget_* reason code)."""
        base = _summary(hypothesis_count=len(statuses))
        verdicts = []
        for i, status in enumerate(statuses, start=1):
            verdicts.append(EvidenceVerdictV1(
                verdict_id=f"ver-{i:03d}",
                hypothesis_id=f"hyp-{i:03d}",
                _status=status,
                reason_codes=(["budget_exhausted"] if status == "untested"
                              else ["evidence_contract_satisfied"]),
                schema_version=VDP_CONTRACT_SCHEMA_VERSION,
            ))
        return VdpCanonicalSummary(
            source_kind="canonical_vdp",
            schema_version=VDP_CONTRACT_SCHEMA_VERSION,
            hypotheses=base.hypotheses,
            attempts=base.attempts,
            evidence_records=base.evidence_records,
            verdicts=tuple(verdicts),
            next_actions=base.next_actions,
        )

    def test_untested_rate_maximum_audit_case(self):
        """The audit's exact case: untested_rate 0.0 vs bound 0.5 must be
        met under maximum semantics (0.8 vs 0.5 unmet)."""
        thresholds = self._thresholds(ThresholdMetric(
            name="untested_rate", value=0.5,
            formula="untested_verdicts / verdicts",
            target_set="hidden_holdout", direction="maximum",
        ))
        ok = run_holdout_evaluation(
            self._verdict_summary("candidate"), labels={}, thresholds=thresholds,
            eval_version="ev-1", runner_version="runner-test-1")
        assert ok.metrics["untested_rate"]["value"] == pytest.approx(0.0)
        assert ok.metrics["untested_rate"]["met"] is True
        assert ok.outcome == "pass"

        bad = run_holdout_evaluation(
            self._verdict_summary("untested", "untested", "untested",
                                  "untested", "candidate"),
            labels={}, thresholds=thresholds,
            eval_version="ev-1", runner_version="runner-test-1")
        assert bad.metrics["untested_rate"]["value"] == pytest.approx(0.8)
        assert bad.metrics["untested_rate"]["met"] is False
        assert bad.outcome == "hold"

    def test_legacy_artifact_without_direction_uses_maximum_for_upper_bounds(self):
        """Old artifacts (no direction field) keep historical semantics:
        ``false_promotion_rate:*`` and ``untested_rate`` bind as maximums."""
        thresholds = self._thresholds(
            ThresholdMetric(name="untested_rate", value=0.5,
                            formula="untested_verdicts / verdicts",
                            target_set="hidden_holdout"),
            ThresholdMetric(name="false_promotion_rate", value=0.1,
                            formula="confirmed_without_gt / confirmed",
                            target_set="hidden_holdout"),
        )
        result = run_holdout_evaluation(
            self._verdict_summary("candidate"), labels={}, thresholds=thresholds,
            eval_version="ev-1", runner_version="runner-test-1")
        # 0.0 <= 0.5 and 0.0 <= 0.1 -> met (maximum preserved for old shape)
        assert result.metrics["untested_rate"]["met"] is True
        assert result.metrics["false_promotion_rate"]["met"] is True

        # the same semantics hold when the artifact is loaded from an
        # old-shape JSON dict (no direction key)
        loaded = ThresholdArtifact.from_dict({
            "schema_version": 1,
            "eval_version": "ev-1",
            "decided_at": "2026-08-04T00:00:00Z",
            "metrics": [
                {"name": "untested_rate", "value": 0.5,
                 "formula": "untested_verdicts / verdicts",
                 "target_set": "hidden_holdout"},
            ],
        })
        result2 = run_holdout_evaluation(
            self._verdict_summary("candidate"), labels={}, thresholds=loaded,
            eval_version="ev-1", runner_version="runner-test-1")
        assert result2.metrics["untested_rate"]["met"] is True

    def test_minimum_direction_below_bound_unmet(self):
        thresholds = self._thresholds(ThresholdMetric(
            name="recall", value=0.9,
            formula="matched_ground_truth / ground_truth",
            target_set="hidden_holdout", direction="minimum",
        ))
        unmatched = run_holdout_evaluation(
            _confirmed_summary(["https://alpha.example.com/items/42"]),
            labels=_labels([_gt(endpoint="/nope")]),
            thresholds=thresholds,
            eval_version="ev-1", runner_version="runner-test-1")
        assert unmatched.metrics["recall"]["value"] == pytest.approx(0.0)
        assert unmatched.metrics["recall"]["met"] is False
        assert unmatched.outcome == "hold"

        matched = run_holdout_evaluation(
            _confirmed_summary(["https://alpha.example.com/items/42"]),
            labels=_labels([_gt(endpoint="/items/42")]),
            thresholds=thresholds,
            eval_version="ev-1", runner_version="runner-test-1")
        assert matched.metrics["recall"]["value"] == pytest.approx(1.0)
        assert matched.metrics["recall"]["met"] is True


class TestResultMetadata:
    """Lane J-1: HoldoutEvaluationResult carries additive metadata
    (code_version / config_version / feature_flags / input_hash /
    termination_state) that roundtrips through save/load and participates in
    the artifact hash."""

    def test_metadata_roundtrip_and_hash_sensitivity(self, tmp_path):
        summary = _summary()
        thresholds = _thresholds()
        metadata = dict(
            code_version="shigoku-1.2.3",
            config_version="vdp-config-7",
            feature_flags={"enforce_m4": True, "retries": 3},
            input_hash="sha256:" + "b" * 64,
            termination_state="succeeded",
        )
        result = run_holdout_evaluation(
            summary, labels={}, thresholds=thresholds,
            eval_version="ev-1", runner_version="runner-test-1",
            **metadata,
        )
        for key, value in metadata.items():
            assert getattr(result, key) == value

        path = tmp_path / "result.json"
        save_evaluation_result(result, path)
        data = json.loads(path.read_text(encoding="utf-8"))
        loaded = HoldoutEvaluationResult.from_dict(data)
        for key, value in metadata.items():
            assert getattr(loaded, key) == value

        # metadata participates in the artifact hash: the same eval run with
        # different metadata yields a different hash
        bare = run_holdout_evaluation(
            summary, labels={}, thresholds=thresholds,
            eval_version="ev-1", runner_version="runner-test-1")
        bare_path = tmp_path / "bare.json"
        save_evaluation_result(bare, bare_path)
        assert json.loads(bare_path.read_text(encoding="utf-8"))["artifact_hash"] \
            != data["artifact_hash"]

        # defaults: no metadata supplied -> empty/unknown, still serialized
        assert bare.code_version == ""
        assert bare.config_version == ""
        assert bare.feature_flags == {}
        assert bare.input_hash == ""
        assert bare.termination_state == "unknown"
        assert bare.to_dict()["termination_state"] == "unknown"
        assert "feature_flags" in bare.to_dict()
