"""
SGK-2026-0425 M0: vdp_diagnostics_v1 session section fail-closed validation.

Covers §11 required test 11: DiagnosticEvent non-dict / unknown version /
unknown stage / unknown reason / broken ID reference must be rejected by the
M0 contract validation — and a valid section (including an EMPTY event list,
which must stay legal so that Hypothesis-0 runs can still carry S00..S03
events) passes. Also guards code-vocabulary drift against the frozen
``config/diagnostics/taxonomy_v1.json`` artifact.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from src.core.engine.vdp_diagnostic_trace import (
    ALL_MECHANISM_CODES,
    CAUSE_FAMILIES,
    DIAGNOSTIC_SECTION_VERSION,
    DIAGNOSTIC_TAXONOMY_VERSION,
    DiagnosticCollector,
    DiagnosticEventV1,
    MECHANISM_CODES,
    OUTCOMES,
    STAGE_IDS,
    validate_diagnostic_section,
)


def _event(**overrides) -> dict:
    ev = {
        "event_id": "evt-0000000000000000000000000000000000000001",
        "run_id": "run-1",
        "stage_id": "S02",
        "outcome": "skipped",
        "reason_codes": ["parse_rejected"],
        "predecessor_ids": [],
        "successor_ids": [],
        "opaque_asset_fingerprint": "fp:abc123",
        "source_refs": ["adapter:adapt_endpoint_signal"],
        "schema_version": DIAGNOSTIC_SECTION_VERSION,
        "taxonomy_version": DIAGNOSTIC_TAXONOMY_VERSION,
    }
    ev.update(overrides)
    return ev


def _section(**overrides) -> dict:
    sec = {
        "schema_version": DIAGNOSTIC_SECTION_VERSION,
        "taxonomy_version": DIAGNOSTIC_TAXONOMY_VERSION,
        "diagnostic_active": True,
        "run_id": "run-1",
        "events": [_event()],
    }
    sec.update(overrides)
    return sec


class TestDiagnosticSectionFailClosed:
    """§11 test 11: malformed diagnostic sections are rejected (fail-closed)."""

    def test_valid_section_passes(self):
        result = validate_diagnostic_section(_section())
        assert result.passed is True
        assert result.reason_codes == []

    def test_empty_events_list_passes(self):
        # Hypothesis-0 runs must still be able to carry S00..S03 events.
        result = validate_diagnostic_section(_section(events=[]))
        assert result.passed is True

    def test_section_not_dict_rejected(self):
        result = validate_diagnostic_section("not-a-dict")
        assert result.passed is False
        assert "diagnostic_section_not_dict" in result.reason_codes

    def test_section_none_rejected(self):
        result = validate_diagnostic_section(None)
        assert result.passed is False
        assert "diagnostic_section_not_dict" in result.reason_codes

    def test_unknown_schema_version_rejected(self):
        result = validate_diagnostic_section(_section(schema_version=99))
        assert result.passed is False
        assert "diagnostic_schema_version_unknown" in result.reason_codes

    def test_non_int_schema_version_rejected(self):
        result = validate_diagnostic_section(_section(schema_version="1"))
        assert result.passed is False
        assert "diagnostic_schema_version_unknown" in result.reason_codes

    def test_unknown_taxonomy_version_rejected(self):
        result = validate_diagnostic_section(_section(taxonomy_version="v3"))
        assert result.passed is False
        assert "diagnostic_taxonomy_version_unknown" in result.reason_codes

    def test_diagnostic_active_not_strict_bool_rejected(self):
        result = validate_diagnostic_section(_section(diagnostic_active=1))
        assert result.passed is False
        assert "diagnostic_active_not_bool" in result.reason_codes

    def test_missing_run_id_rejected(self):
        sec = _section()
        del sec["run_id"]
        result = validate_diagnostic_section(sec)
        assert result.passed is False
        assert "diagnostic_run_id_missing" in result.reason_codes

    def test_events_not_list_rejected(self):
        result = validate_diagnostic_section(_section(events={"event_id": "x"}))
        assert result.passed is False
        assert "diagnostic_events_not_list" in result.reason_codes

    def test_non_dict_event_rejected(self):
        result = validate_diagnostic_section(_section(events=["not-a-dict"]))
        assert result.passed is False
        assert "diagnostic_event_not_dict" in result.reason_codes

    def test_event_id_missing_rejected(self):
        ev = _event()
        del ev["event_id"]
        result = validate_diagnostic_section(_section(events=[ev]))
        assert result.passed is False
        assert "diagnostic_event_id_invalid" in result.reason_codes

    def test_duplicate_event_id_rejected(self):
        result = validate_diagnostic_section(
            _section(events=[_event(), _event(stage_id="S03")])
        )
        assert result.passed is False
        assert "diagnostic_event_id_duplicate" in result.reason_codes

    def test_unknown_stage_rejected(self):
        result = validate_diagnostic_section(_section(events=[_event(stage_id="S99")]))
        assert result.passed is False
        assert "diagnostic_stage_unknown" in result.reason_codes

    def test_u00_stage_accepted(self):
        result = validate_diagnostic_section(_section(events=[_event(stage_id="U00")]))
        assert result.passed is True

    def test_unknown_outcome_rejected(self):
        result = validate_diagnostic_section(_section(events=[_event(outcome="maybe")]))
        assert result.passed is False
        assert "diagnostic_outcome_unknown" in result.reason_codes

    def test_unknown_reason_code_rejected(self):
        result = validate_diagnostic_section(
            _section(events=[_event(reason_codes=["not_a_known_mechanism"])])
        )
        assert result.passed is False
        assert "diagnostic_reason_code_unknown" in result.reason_codes

    def test_reason_codes_not_list_rejected(self):
        result = validate_diagnostic_section(
            _section(events=[_event(reason_codes="parse_rejected")])
        )
        assert result.passed is False
        assert "diagnostic_reason_code_unknown" in result.reason_codes

    def test_empty_reason_codes_accepted(self):
        result = validate_diagnostic_section(_section(events=[_event(reason_codes=[])]))
        assert result.passed is True

    def test_broken_predecessor_reference_rejected(self):
        result = validate_diagnostic_section(
            _section(events=[_event(predecessor_ids=["evt-missing"])])
        )
        assert result.passed is False
        assert "diagnostic_reference_broken" in result.reason_codes

    def test_broken_successor_reference_rejected(self):
        result = validate_diagnostic_section(
            _section(events=[_event(successor_ids=["evt-missing"])])
        )
        assert result.passed is False
        assert "diagnostic_reference_broken" in result.reason_codes

    def test_valid_cross_reference_accepted(self):
        first = _event()
        second = _event(
            event_id="evt-0000000000000000000000000000000000000002",
            stage_id="S03",
            predecessor_ids=[first["event_id"]],
        )
        result = validate_diagnostic_section(_section(events=[first, second]))
        assert result.passed is True

    def test_unknown_event_schema_version_rejected(self):
        result = validate_diagnostic_section(
            _section(events=[_event(schema_version=2)])
        )
        assert result.passed is False
        assert "diagnostic_event_version_unknown" in result.reason_codes

    def test_non_str_fingerprint_rejected(self):
        result = validate_diagnostic_section(
            _section(events=[_event(opaque_asset_fingerprint=123)])
        )
        assert result.passed is False
        assert "diagnostic_event_fingerprint_invalid" in result.reason_codes

    def test_events_absent_rejected(self):
        sec = _section()
        del sec["events"]
        result = validate_diagnostic_section(sec)
        assert result.passed is False
        assert "diagnostic_events_not_list" in result.reason_codes


class TestTaxonomyArtifactConsistency:
    """Guard against drift between code vocabulary and the frozen artifact."""

    @staticmethod
    def _artifact() -> dict:
        return json.loads(
            Path("config/diagnostics/taxonomy_v1.json").read_text(encoding="utf-8")
        )

    def test_versions_match_artifact(self):
        artifact = self._artifact()
        assert artifact["schema_version"] == DIAGNOSTIC_SECTION_VERSION
        assert artifact["taxonomy_version"] == DIAGNOSTIC_TAXONOMY_VERSION

    def test_stage_vocabulary_matches_artifact(self):
        artifact = self._artifact()
        assert artifact["stages"] == list(STAGE_IDS)
        assert set(artifact["outcomes"]) == set(OUTCOMES)

    def test_cause_and_mechanism_vocabulary_matches_artifact(self):
        artifact = self._artifact()
        assert artifact["causes"] == list(CAUSE_FAMILIES)
        assert artifact["mechanism_codes"] == MECHANISM_CODES
        assert "c13_unclassified_hold" in ALL_MECHANISM_CODES

    def test_artifact_content_hash_self_consistent(self):
        artifact = self._artifact()
        body = {k: v for k, v in artifact.items() if k != "content_hash"}
        expected = hashlib.sha256(
            json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        assert artifact["content_hash"] == f"sha256:{expected}"


class TestDiagnosticCollectorM1:
    """§11 M1: deterministic bounded DiagnosticEventV1 collector (SGK-2026-0425)."""

    @staticmethod
    def _collector(**kwargs) -> DiagnosticCollector:
        kwargs.setdefault("enabled", True)
        kwargs.setdefault("run_id", "run-1")
        return DiagnosticCollector(**kwargs)

    # --- Deterministic event IDs ---------------------------------------------

    def test_emit_deterministic_across_collectors(self):
        # Identical inputs must give identical IDs across collectors; the ID
        # must not depend on wall clock or UUID.
        c1 = self._collector()
        c2 = self._collector()
        eid1 = c1.emit(
            stage_id="S02",
            outcome="skipped",
            reason_codes=["parse_rejected"],
            source_refs=["adapter:adapt_endpoint_signal"],
        )
        eid2 = c2.emit(
            stage_id="S02",
            outcome="skipped",
            reason_codes=["parse_rejected"],
            source_refs=["adapter:adapt_endpoint_signal"],
        )
        assert eid1 == eid2
        assert isinstance(eid1, str) and eid1.startswith("dgev-")

    def test_emit_id_stable_across_argument_order(self):
        c1 = self._collector()
        c2 = self._collector()
        eid1 = c1.emit(
            stage_id="S02", outcome="skipped",
            reason_codes=["parse_rejected"], source_refs=["a", "b"],
        )
        eid2 = c2.emit(
            source_refs=["a", "b"], reason_codes=["parse_rejected"],
            outcome="skipped", stage_id="S02",
        )
        assert eid1 == eid2

    def test_emit_id_distinguishes_run_id(self):
        c1 = DiagnosticCollector(enabled=True, run_id="run-1")
        c2 = DiagnosticCollector(enabled=True, run_id="run-2")
        assert (
            c1.emit(stage_id="S02", outcome="skipped")
            != c2.emit(stage_id="S02", outcome="skipped")
        )

    def test_event_to_dict_from_dict_roundtrip(self):
        ev = DiagnosticEventV1(
            event_id="dgev-abc",
            run_id="run-1",
            stage_id="S02",
            outcome="skipped",
            reason_codes=("parse_rejected",),
            source_refs=("a", "b"),
        )
        d = ev.to_dict()
        assert d["reason_codes"] == ["parse_rejected"]
        assert d["source_refs"] == ["a", "b"]
        assert d["schema_version"] == DIAGNOSTIC_SECTION_VERSION
        assert d["taxonomy_version"] == DIAGNOSTIC_TAXONOMY_VERSION
        assert DiagnosticEventV1.from_dict(d) == ev

    def test_event_from_dict_strict_type_errors(self):
        with pytest.raises(TypeError):
            DiagnosticEventV1.from_dict("not-a-dict")
        with pytest.raises(TypeError):
            DiagnosticEventV1.from_dict({"event_id": 123})
        with pytest.raises(TypeError):
            DiagnosticEventV1.from_dict(
                {
                    "event_id": "x", "run_id": "r", "stage_id": "S01",
                    "outcome": "reached", "reason_codes": "not-a-list",
                }
            )

    # --- Disabled collector ---------------------------------------------------

    def test_disabled_collector_emits_nothing(self):
        c = DiagnosticCollector(enabled=False, run_id="run-1")
        assert c.is_enabled() is False
        assert c.emit(stage_id="S02", outcome="skipped") is None
        assert c.event_count() == 0
        assert c.to_section() is None
        assert c.backpressure_reasons == []
        assert c.duplicate_event_counts == {}

    # --- Dedupe / vocabulary --------------------------------------------------

    def test_dedupe_identical_event_emitted_twice(self):
        c = self._collector()
        eid = c.emit(stage_id="S02", outcome="skipped", reason_codes=["parse_rejected"])
        again = c.emit(stage_id="S02", outcome="skipped", reason_codes=["parse_rejected"])
        assert again == eid
        assert c.event_count() == 1
        assert c.duplicate_event_counts[eid] == 1
        sec = c.to_section()
        assert len(sec["events"]) == 1
        assert validate_diagnostic_section(sec).passed

    def test_vocabulary_enforcement_raises_valueerror(self):
        c = self._collector()
        with pytest.raises(ValueError):
            c.emit(stage_id="S99", outcome="skipped")
        with pytest.raises(ValueError):
            c.emit(stage_id="S02", outcome="maybe")
        with pytest.raises(ValueError):
            c.emit(stage_id="S02", outcome="skipped", reason_codes=["bogus"])
        assert c.event_count() == 0

    # --- Bounded queue / artifact limits --------------------------------------

    def test_bounded_queue_records_queue_full_backpressure(self):
        c = DiagnosticCollector(enabled=True, run_id="run-1", event_queue_capacity=2)
        assert c.emit(stage_id="S01", outcome="reached") is not None
        assert c.emit(stage_id="S02", outcome="skipped") is not None
        # third unique event exceeds the pending queue -> backpressure, not drop
        assert c.emit(stage_id="S03", outcome="blocked") is None
        assert c.event_count() == 2
        reasons = c.backpressure_reasons
        assert len(reasons) == 1
        assert reasons[0]["reason"] == "queue_full"
        assert reasons[0]["event_count"] == 2
        assert reasons[0]["stage_id"] == "S03"
        sec = c.to_section()
        assert len(sec["events"]) == 2
        assert validate_diagnostic_section(sec).passed

    def test_max_events_records_artifact_limit_backpressure(self):
        c = DiagnosticCollector(enabled=True, run_id="run-1", max_events=3)
        for i in (1, 2, 3):
            assert c.emit(stage_id=f"S0{i}", outcome="reached") is not None
        assert c.emit(stage_id="S04", outcome="failed") is None
        assert c.event_count() == 3
        reasons = c.backpressure_reasons
        assert reasons[0]["reason"] == "artifact_limit_exceeded"
        assert reasons[0]["event_count"] == 3
        assert reasons[0]["stage_id"] == "S04"
        assert validate_diagnostic_section(c.to_section()).passed

    def test_queue_drains_after_checkpoint(self, tmp_path):
        c = DiagnosticCollector(
            enabled=True, run_id="run-1",
            event_queue_capacity=2, max_events=10,
        )
        c.emit(stage_id="S01", outcome="reached")
        c.emit(stage_id="S02", outcome="skipped")
        assert c.emit(stage_id="S03", outcome="blocked") is None
        c.checkpoint(str(tmp_path / "diag.json"))
        # pending queue is drained by the checkpoint -> S03 accepted now
        assert c.emit(stage_id="S03", outcome="blocked") is not None
        assert c.event_count() == 3

    # --- Deep redaction at the lowest writer ----------------------------------

    def test_redaction_nested_secrets_never_reach_section_or_checkpoint(
        self, monkeypatch, tmp_path
    ):
        c = self._collector()
        target = c.emit(
            stage_id="S02", outcome="skipped", reason_codes=["parse_rejected"]
        )
        assert target is not None
        # Event fields are flat, so simulate the section being attacked:
        # nested dict/list secrets inside source_refs plus an extra nested key.
        orig_to_dict = DiagnosticEventV1.to_dict

        def poisoned_to_dict(self):
            d = orig_to_dict(self)
            if d["event_id"] == target:
                d["source_refs"] = [
                    "password=hunter2",
                    {"authorization": "Authorization: Bearer xyz"},
                    {"cookie": "Cookie: sid=1"},
                    [{"token": "token=abc123"}],
                    {"private_key": "PRIVATE-KEY"},
                ]
                d["extra_nested"] = {"credentials": {"password": "hunter2"}}
            return d

        monkeypatch.setattr(DiagnosticEventV1, "to_dict", poisoned_to_dict)
        secrets = (
            "Bearer xyz",
            "Authorization",
            "Cookie: sid=1",
            "token=abc123",
            "password=hunter2",
            "PRIVATE-KEY",
            "hunter2",
        )
        sec = c.to_section()
        assert sec is not None
        assert validate_diagnostic_section(sec).passed
        serialized = json.dumps(sec, sort_keys=True)
        for secret in secrets:
            assert secret not in serialized, f"leaked {secret!r} in section"
        out = tmp_path / "checkpoint.json"
        c.checkpoint(str(out))
        blob = out.read_bytes().decode("utf-8")
        for secret in secrets:
            assert secret not in blob, f"leaked {secret!r} in checkpoint"

    # --- Checkpoint / resume --------------------------------------------------

    def test_checkpoint_resume_roundtrip(self, tmp_path):
        c = self._collector()
        ids = [c.emit(stage_id=f"S0{i}", outcome="reached") for i in (1, 2, 3)]
        c.emit(stage_id="S02", outcome="reached")  # duplicate before checkpoint
        assert c.duplicate_event_counts[ids[1]] == 1
        out = tmp_path / "diag.json"
        c.checkpoint(str(out))
        r = DiagnosticCollector(enabled=True, run_id="", max_events=2000)
        assert r.resume(str(out)) is True
        assert r.event_count() == 3
        assert r.run_id == "run-1"
        assert r.is_enabled() is True
        assert r.duplicate_event_counts.get(ids[1]) == 1
        # re-emitting the same events must not double state (dedupe by event_id)
        for idx in (1, 2, 3):
            r.emit(stage_id=f"S0{idx}", outcome="reached")
        assert r.event_count() == 3
        sec = r.to_section()
        assert len(sec["events"]) == 3
        assert validate_diagnostic_section(sec).passed

    def test_checkpoint_replace_failure_propagates_and_cleans_temp(
        self, tmp_path, monkeypatch
    ):
        c = self._collector()
        c.emit(stage_id="S01", outcome="reached")
        out = tmp_path / "diag.json"

        def boom(src, dst):
            raise PermissionError("directory is read-only")

        monkeypatch.setattr(os, "replace", boom)
        with pytest.raises(PermissionError):
            c.checkpoint(str(out))
        assert not out.exists()
        leftovers = [p for p in tmp_path.iterdir() if p.name.startswith("diag.json.")]
        assert leftovers == []

    def test_checkpoint_oserror_propagates(self, tmp_path, monkeypatch):
        c = self._collector()
        c.emit(stage_id="S01", outcome="reached")

        def boom(src, dst):
            raise OSError("device error")

        monkeypatch.setattr(os, "replace", boom)
        with pytest.raises(OSError):
            c.checkpoint(str(tmp_path / "diag.json"))

    def test_interrupt_resume_emit_checkpoint_all_unique_once(self, tmp_path):
        c = self._collector()
        c.emit(stage_id="S01", outcome="reached")
        c.emit(stage_id="S02", outcome="skipped")
        c.emit(stage_id="S02", outcome="skipped")  # duplicate
        out = tmp_path / "diag.json"
        c.checkpoint(str(out))
        r = DiagnosticCollector(enabled=True, run_id="", max_events=100)
        assert r.resume(str(out)) is True
        r.emit(stage_id="S03", outcome="blocked")
        r.emit(stage_id="S04", outcome="failed")
        r.emit(stage_id="S01", outcome="reached")  # already known -> dedupe
        assert r.event_count() == 4
        out2 = tmp_path / "diag2.json"
        r.checkpoint(str(out2))
        final = r.to_section()
        assert len(final["events"]) == 4
        eids = [ev["event_id"] for ev in final["events"]]
        assert len(set(eids)) == len(eids)
        assert validate_diagnostic_section(final).passed
        # the second checkpoint is resumable as well
        r2 = DiagnosticCollector(enabled=True, run_id="")
        assert r2.resume(str(out2)) is True
        assert r2.event_count() == 4

    def test_resume_missing_file_returns_false(self, tmp_path):
        c = self._collector()
        assert c.resume(str(tmp_path / "nope.json")) is False

    def test_resume_garbage_json_raises(self, tmp_path):
        p = tmp_path / "diag.json"
        p.write_text("not json {{{", encoding="utf-8")
        c = self._collector()
        with pytest.raises(RuntimeError):
            c.resume(str(p))

    def test_resume_non_dict_raises(self, tmp_path):
        p = tmp_path / "diag.json"
        p.write_text("[1, 2, 3]", encoding="utf-8")
        c = self._collector()
        with pytest.raises(RuntimeError):
            c.resume(str(p))

    def test_resume_wrong_schema_version_raises(self, tmp_path):
        p = tmp_path / "diag.json"
        p.write_text(
            json.dumps(
                {
                    "schema_version": 99,
                    "taxonomy_version": "v1",
                    "diagnostic_active": True,
                    "run_id": "run-1",
                    "events": [],
                }
            ),
            encoding="utf-8",
        )
        c = self._collector()
        with pytest.raises(RuntimeError):
            c.resume(str(p))

    # --- Hook failure ---------------------------------------------------------

    def test_hook_failed_sets_flag_and_records_reason(self):
        c = self._collector()
        assert c.hook_failed is False
        c.mark_hook_failed("checkpoint hook crashed")
        assert c.hook_failed is True
        assert any(
            r["reason"] == "hook_failed" and r["detail"] == "checkpoint hook crashed"
            for r in c.backpressure_reasons
        )
        sec = c.to_section()
        assert validate_diagnostic_section(sec).passed
        assert any(r["reason"] == "hook_failed" for r in sec["backpressure_reasons"])

    def test_hook_failed_detail_is_sanitized_and_redacted(self, tmp_path):
        c = self._collector()
        c.mark_hook_failed("hook crashed: password=hunter2 " + "x" * 500)
        details = [
            r["detail"] for r in c.backpressure_reasons if r["reason"] == "hook_failed"
        ]
        assert len(details) == 1
        assert "hunter2" not in details[0]
        assert len(details[0]) <= 200
        out = tmp_path / "diag.json"
        c.checkpoint(str(out))
        blob = out.read_bytes().decode("utf-8")
        assert "hunter2" not in blob

    # --- Section invariants ---------------------------------------------------

    def test_to_section_omits_empty_optional_blocks(self):
        c = self._collector()
        c.emit(stage_id="S01", outcome="reached")
        sec = c.to_section()
        assert "duplicate_event_counts" not in sec
        assert "backpressure_reasons" not in sec

    def test_to_section_always_passes_validation_across_scenarios(self):
        c = DiagnosticCollector(
            enabled=True, run_id="run-1",
            event_queue_capacity=1, max_events=2,
        )
        c.emit(stage_id="S01", outcome="reached")
        c.emit(stage_id="S01", outcome="reached")  # duplicate
        assert c.emit(stage_id="S02", outcome="skipped") is None  # queue full
        c.mark_hook_failed("boom")
        assert c.emit(stage_id="S03", outcome="blocked") is None  # still full
        sec = c.to_section()
        assert sec is not None
        assert sec["schema_version"] == DIAGNOSTIC_SECTION_VERSION
        assert sec["taxonomy_version"] == DIAGNOSTIC_TAXONOMY_VERSION
        assert sec["diagnostic_active"] is True
        assert sec["run_id"] == "run-1"
        assert "duplicate_event_counts" in sec
        assert validate_diagnostic_section(sec).passed

    # --- from_section ---------------------------------------------------------

    def test_from_section_reconstructs_and_continues_without_duplicates(self):
        c = self._collector()
        ids = [c.emit(stage_id=f"S0{i}", outcome="reached") for i in (1, 2)]
        c.emit(stage_id="S01", outcome="reached")  # duplicate
        sec = c.to_section()
        r = DiagnosticCollector.from_section(sec)
        assert r.event_count() == 2
        assert r.run_id == "run-1"
        assert [ev["event_id"] for ev in r.to_section()["events"]] == [
            ev["event_id"] for ev in sec["events"]
        ]
        r.emit(stage_id="S01", outcome="reached")  # duplicate of restored event
        r.emit(stage_id="S03", outcome="blocked")
        assert r.event_count() == 3
        final = r.to_section()
        eids = [ev["event_id"] for ev in final["events"]]
        assert len(set(eids)) == len(eids)
        assert validate_diagnostic_section(final).passed

    def test_from_section_invalid_raises(self):
        with pytest.raises(RuntimeError):
            DiagnosticCollector.from_section(
                {
                    "schema_version": 99,
                    "taxonomy_version": "v1",
                    "diagnostic_active": True,
                    "run_id": "run-1",
                    "events": [],
                }
            )
