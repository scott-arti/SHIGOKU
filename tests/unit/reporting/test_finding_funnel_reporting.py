"""
SGK-2026-0440 Lane B — finding-funnel session carriage + reporting tests.

Covers (measurement-only, additive, default-off):
- session carriage: inject_vdp_section_to_session_payload carries
  ``finding_funnel_v1`` in the vdp_contract section only when provided;
  ``finding_funnel_v1`` survives the redact_and_write_session +
  read_session_compat roundtrip (unknown keys preserved by old readers)
- report machine block: embed_finding_funnel_index is byte-identical when
  the funnel is absent and embeds an opaque machine-readable JSON block
  when present
- per-candidate first-failure: additional_info keys attached by finding_id;
  candidates without an earlier stop in the funnel get F5 /
  evidence_insufficient (data, not assertion)
- extractor output: first_failure_stage/reason included when the funnel is
  present, unchanged otherwise

The funnel recorder module (finding_funnel_trace.py, Lane A) may not exist
yet — tests feed the funnel section dict directly (the contract schema).
"""
from __future__ import annotations

import copy
import datetime
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.core.engine.master_conductor import MasterConductor
from src.core.engine.master_conductor_session_service import (
    inject_vdp_section_to_session_payload,
)
from src.core.engine.vdp_session_reader import (
    inject_vdp_fields,
    read_session_compat,
    redact_and_write_session,
)
from src.reporting.finding_extractor import extract_all_findings
from src.reporting.haddix_formatter import (
    HaddixFinding,
    HaddixFormatter,
    generate_haddix_report,
)
from src.reporting.haddix_submission_internal_formatter import (
    HaddixSubmissionInternalFormatter,
)
from src.reporting.vdp_report_projection import (
    FINDING_FUNNEL_INDEX_VERSION,
    embed_finding_funnel_index,
    extract_finding_funnel_index_from_report,
)

_FIXED_NOW = datetime.datetime(2026, 8, 11, 12, 0, 0)


async def _async_noop(*args, **kwargs):
    pass


def _funnel_section() -> dict:
    """Funnel section per the Lane A/B contract schema."""
    return {
        "schema_version": 1,
        "entries": [
            {
                "finding_id": "F1",
                "first_failure_stage": "F3",
                "first_failure_reason": "phase2_skipped_early_return",
                "block_reasons": ["phase2_skipped_early_return"],
                "max_stage_reached": "F3",
                "stages": {
                    "F0": "reached",
                    "F1": "reached",
                    "F2": "reached",
                    "F3": "skipped",
                },
                "producer": "InjectionManager",
            },
            {
                "finding_id": "F2",
                "first_failure_stage": None,
                "first_failure_reason": None,
                "block_reasons": [],
                "max_stage_reached": "F4",
                "stages": {
                    "F0": "reached",
                    "F1": "reached",
                    "F2": "reached",
                    "F3": "reached",
                    "F4": "reached",
                },
                "producer": "InjectionManager",
            },
        ],
        "summary": {
            "by_stage": {"F0": 16, "F3": 1},
            "by_reason": {"phase2_skipped_early_return": 1},
            "suppressed_tasks": 0,
            "total_candidates": 16,
        },
    }


def _finding_dict(finding_id: str, *, candidate: bool = True) -> dict:
    """Raw finding dict whose id resolves to ``finding_id``."""
    info = {"finding_id": finding_id}
    if not candidate:
        info["hypothesis_id"] = "hyp-001"
    return {
        "title": f"XSS in search ({finding_id})",
        "severity": "high",
        "vuln_type": "xss",
        "target_url": "https://example.com/search",
        "summary": f"reflected payload for {finding_id}",
        "impact": "session theft",
        "poc_request": "",
        "poc_response": "",
        "payloads_used": [],
        "additional_info": info,
    }


@pytest.fixture(autouse=True)
def _freeze_report_time(monkeypatch):
    """Freeze generated_at so with/without funnel reports diff ONLY by the
    additive block (deterministic byte comparison)."""
    monkeypatch.setattr(
        HaddixFormatter, "_now_jst", staticmethod(lambda: _FIXED_NOW)
    )


class TestEmbedFindingFunnelIndex:
    def test_none_returns_markdown_unchanged(self):
        md = "# SHIGOKU\n\n## Findings\n\nbody\n"
        assert embed_finding_funnel_index(md, None) == md

    def test_absent_funnel_leaves_report_byte_identical(self, tmp_path):
        """A report generated without a funnel carries no funnel block and no
        first-failure keys (pre-0440 bytes)."""
        out = tmp_path / "haddix_no_funnel.md"
        generate_haddix_report(
            findings=[_finding_dict("F1")],
            target="https://example.com",
            output_path=out,
        )
        text = out.read_text(encoding="utf-8")
        assert "finding_funnel_v1" not in text
        assert "first_failure_stage" not in text
        assert "first_failure_reason" not in text
        assert extract_finding_funnel_index_from_report(text) is None

    def test_present_embeds_opaque_json_block(self):
        md = "# SHIGOKU\n\nbody\n"
        funnel = _funnel_section()
        embedded = embed_finding_funnel_index(md, funnel)
        assert FINDING_FUNNEL_INDEX_VERSION in embedded
        data = extract_finding_funnel_index_from_report(embedded)
        assert data is not None
        assert data["schema_version"] == 1
        assert len(data["entries"]) == 2
        assert data["summary"]["total_candidates"] == 16
        # opaque: no product tokens inside the block
        block = embedded.split("<!-- finding_funnel_v1:start -->", 1)[1].split(
            "<!-- finding_funnel_v1:end -->", 1
        )[0]
        assert "example.com" not in block
        assert "Authorization" not in block

    def test_only_difference_is_appended_block(self, tmp_path):
        """with/without funnel at the full-report level: the ONLY byte
        difference is the appended machine block."""
        out_a = tmp_path / "haddix_a.md"
        out_b = tmp_path / "haddix_b.md"
        findings = [_finding_dict("F1"), _finding_dict("F2")]
        generate_haddix_report(
            findings=findings,
            target="https://example.com",
            output_path=out_a,
        )
        generate_haddix_report(
            findings=findings,
            target="https://example.com",
            output_path=out_b,
            finding_funnel_section=_funnel_section(),
        )
        text_a = out_a.read_text(encoding="utf-8")
        text_b = out_b.read_text(encoding="utf-8")
        block = (
            f"<!-- finding_funnel_v1:start -->\n"
            f"{json.dumps(_funnel_section(), ensure_ascii=False, sort_keys=True, indent=2)}\n"
            f"<!-- finding_funnel_v1:end -->"
        )
        assert text_b == f"{text_a.rstrip()}\n\n{block}\n"

    def test_replace_existing_block(self):
        """An existing block is replaced (same semantics as the diagnostic
        index embedder): exactly one start/end marker pair survives."""
        funnel = _funnel_section()
        once = embed_finding_funnel_index("# SHIGOKU\n", funnel)
        twice = embed_finding_funnel_index(once, funnel)
        assert twice.count("<!-- finding_funnel_v1:start -->") == 1
        assert twice.count("<!-- finding_funnel_v1:end -->") == 1
        assert extract_finding_funnel_index_from_report(twice) == funnel


class TestPerFindingFirstFailure:
    def test_funnel_absent_adds_no_additional_info_keys(self):
        """No funnel -> split must not add first-failure keys (legacy
        byte-identical behavior)."""
        formatter = HaddixSubmissionInternalFormatter()
        formatter.set_target("https://example.com")
        formatter.add_finding_from_dict(_finding_dict("F1"))
        formatter.add_finding_from_dict(_finding_dict("F2"))
        confirmed, candidates, _ = formatter._get_enforced_split()
        assert confirmed == []
        assert len(candidates) == 2
        for finding in candidates:
            assert "first_failure_stage" not in finding.additional_info
            assert "first_failure_reason" not in finding.additional_info

    def test_entry_with_stop_attached_by_finding_id(self):
        formatter = HaddixSubmissionInternalFormatter()
        formatter.set_target("https://example.com")
        formatter.set_finding_funnel_section(_funnel_section())
        formatter.add_finding_from_dict(_finding_dict("F1"))
        confirmed, candidates, _ = formatter._get_enforced_split()
        assert len(candidates) == 1
        assert candidates[0].additional_info["first_failure_stage"] == "F3"
        assert (
            candidates[0].additional_info["first_failure_reason"]
            == "phase2_skipped_early_return"
        )

    def test_candidate_without_stop_gets_f5(self):
        """F2 reached all funnel stages but is not confirmed -> F5 /
        evidence_insufficient (data, not assertion)."""
        formatter = HaddixSubmissionInternalFormatter()
        formatter.set_target("https://example.com")
        formatter.set_finding_funnel_section(_funnel_section())
        formatter.add_finding_from_dict(_finding_dict("F2"))
        confirmed, candidates, _ = formatter._get_enforced_split()
        assert len(candidates) == 1
        assert candidates[0].additional_info["first_failure_stage"] == "F5"
        assert (
            candidates[0].additional_info["first_failure_reason"]
            == "evidence_insufficient"
        )

    def test_candidate_not_in_funnel_gets_f5(self):
        formatter = HaddixSubmissionInternalFormatter()
        formatter.set_target("https://example.com")
        formatter.set_finding_funnel_section(_funnel_section())
        formatter.add_finding_from_dict(_finding_dict("F9"))
        confirmed, candidates, _ = formatter._get_enforced_split()
        assert len(candidates) == 1
        assert candidates[0].additional_info["first_failure_stage"] == "F5"
        assert (
            candidates[0].additional_info["first_failure_reason"]
            == "evidence_insufficient"
        )

    def test_direct_formatter_path_attaches_too(self):
        """HaddixFormatter._split_findings_by_confirmation (non-enforced
        path) attaches as well."""
        formatter = HaddixFormatter()
        formatter.set_target("https://example.com")
        formatter.set_finding_funnel_section(_funnel_section())
        formatter.add_finding_from_dict(_finding_dict("F1"))
        confirmed, candidates = formatter._split_findings_by_confirmation(
            formatter._findings
        )
        assert confirmed == []
        assert len(candidates) == 1
        assert candidates[0].additional_info["first_failure_stage"] == "F3"

    def test_matching_by_finding_model_id(self):
        """Real path: the funnel recorder keys on ``Finding.id`` (md5), which
        sessions serialize as the finding's top-level ``id``. The formatter
        must match on that raw id even without additional_info.finding_id."""
        finding_id = "4ae4c604e1ea"  # Finding.id-style md5
        raw = _finding_dict("ignored")
        raw["id"] = finding_id
        raw["additional_info"] = {}  # no finding_id key
        funnel = _funnel_section()
        funnel["entries"][0]["finding_id"] = finding_id
        formatter = HaddixSubmissionInternalFormatter()
        formatter.set_target("https://example.com")
        formatter.set_finding_funnel_section(funnel)
        formatter.add_finding_from_dict(raw)
        confirmed, candidates, _ = formatter._get_enforced_split()
        assert len(candidates) == 1
        assert candidates[0].additional_info["first_failure_stage"] == "F3"
        assert (
            candidates[0].additional_info["first_failure_reason"]
            == "phase2_skipped_early_return"
        )

    def test_funnel_block_embedded_in_report_markdown(self, tmp_path):
        out = tmp_path / "haddix_funnel.md"
        generate_haddix_report(
            findings=[_finding_dict("F1")],
            target="https://example.com",
            output_path=out,
            finding_funnel_section=_funnel_section(),
        )
        text = out.read_text(encoding="utf-8")
        data = extract_finding_funnel_index_from_report(text)
        assert data is not None
        assert data["entries"][0]["finding_id"] == "F1"

    def test_json_report_includes_funnel_section(self, tmp_path):
        out = tmp_path / "haddix_funnel.json"
        generate_haddix_report(
            findings=[_finding_dict("F1")],
            target="https://example.com",
            output_path=out,
            format_type="json",
            finding_funnel_section=_funnel_section(),
        )
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["finding_funnel_v1"]["summary"]["total_candidates"] == 16
        assert data["finding_funnel_v1"]["entries"][0]["finding_id"] == "F1"


class TestExtractorFirstFailure:
    def _session(self) -> dict:
        return {
            "completed_tasks": [
                {
                    "id": "task-1",
                    "result": {
                        "findings": [
                            {
                                "title": "XSS in search (F1)",
                                "severity": "high",
                                "vuln_type": "xss",
                                "target_url": "https://example.com/search",
                                "summary": "reflected",
                                "impact": "session theft",
                                "poc_request": "",
                                "poc_response": "",
                                "additional_info": {"finding_id": "F1"},
                            }
                        ]
                    },
                }
            ]
        }

    def test_funnel_present_includes_first_failure(self):
        session = self._session()
        session["finding_funnel_v1"] = _funnel_section()
        findings = extract_all_findings(session)
        assert len(findings) == 1
        assert findings[0]["first_failure_stage"] == "F3"
        assert findings[0]["first_failure_reason"] == "phase2_skipped_early_return"

    def test_matching_by_finding_model_id(self):
        """The funnel recorder keys on ``Finding.id`` (md5), serialized as
        the finding's top-level ``id`` — extraction must match on it."""
        finding_id = "4ae4c604e1ea"
        session = self._session()
        raw = session["completed_tasks"][0]["result"]["findings"][0]
        raw["id"] = finding_id
        del raw["additional_info"]  # no finding_id key
        funnel = _funnel_section()
        funnel["entries"][0]["finding_id"] = finding_id
        session["finding_funnel_v1"] = funnel
        findings = extract_all_findings(session)
        assert findings[0]["first_failure_stage"] == "F3"
        assert findings[0]["first_failure_reason"] == "phase2_skipped_early_return"

    def test_funnel_absent_output_unchanged(self):
        """Same session, no funnel key -> extraction is byte-identical and
        carries no first-failure keys."""
        session = self._session()
        findings = extract_all_findings(session)
        assert len(findings) == 1
        # pre-0440 behavior intact: _source_task_id still injected
        assert findings[0]["_source_task_id"] == "task-1"
        assert "first_failure_stage" not in findings[0]
        assert "first_failure_reason" not in findings[0]
        baseline = extract_all_findings(copy.deepcopy(session))
        assert findings == baseline

    def test_session_not_mutated_by_extraction(self):
        session = self._session()
        session["finding_funnel_v1"] = _funnel_section()
        before = copy.deepcopy(session)
        extract_all_findings(session)
        assert session == before


class TestLaneAIntegration:
    """End-to-end reconciliation with Lane A's real recorder
    (src/core/engine/finding_funnel_trace.py). Uses the recorder's actual
    ``to_section()`` output through session injection and the report path."""

    def test_recorder_output_flows_through_inject_and_report(self, tmp_path):
        from src.core.engine.finding_funnel_trace import FindingFunnelRecorder

        finding_id = "4ae4c604e1ea"
        rec = FindingFunnelRecorder(enabled=True)
        rec.record(finding_id, "F0", "reached")
        rec.record(finding_id, "F1", "reached")
        rec.record(finding_id, "F2", "reached")
        rec.record(
            finding_id,
            "F3",
            "skipped",
            reason_code="phase2_skipped_early_return",
        )
        section = rec.to_section()
        assert section is not None
        assert section["entries"][0]["first_failure_stage"] == "F3"
        assert section["summary"]["total_candidates"] == 1

        # session carriage
        payload = inject_vdp_section_to_session_payload(
            {"task_queue": [], "completed_tasks": [], "context": {}},
            {"vdp_active": False, "finding_funnel_section": section},
        )
        assert payload["vdp_contract"]["finding_funnel_v1"] == section

        # report path: block embedded, per-finding attribution attached
        raw = _finding_dict("x")
        raw["id"] = finding_id
        raw["additional_info"] = {}
        out = tmp_path / "haddix_lane_a.md"
        generate_haddix_report(
            findings=[raw],
            target="https://example.com",
            output_path=out,
            finding_funnel_section=section,
        )
        text = out.read_text(encoding="utf-8")
        data = extract_finding_funnel_index_from_report(text)
        assert data is not None
        assert data["entries"][0]["finding_id"] == finding_id
        assert data["entries"][0]["first_failure_stage"] == "F3"
        assert data["summary"]["by_reason"]["phase2_skipped_early_return"] == 1

    def test_disabled_or_empty_recorder_yields_none(self):
        from src.core.engine.finding_funnel_trace import FindingFunnelRecorder

        disabled = FindingFunnelRecorder(enabled=False)
        disabled.record("x", "F0", "reached")
        assert disabled.to_section() is None
        empty = FindingFunnelRecorder(enabled=True)
        assert empty.to_section() is None


class TestMasterConductorFunnelWiring:
    """MasterConductor session-build wiring (Lane B, ~:4038-4050).

    (a) recorder disabled/absent -> saved session has NO finding_funnel_v1
    (top-level or in vdp_contract) — legacy byte-identical.
    (b) recorder present with records -> saved session carries
    ``finding_funnel_v1`` top-level AND inside ``vdp_contract``.
    """

    @staticmethod
    def _new_mc(**overrides) -> "MasterConductor":
        from types import SimpleNamespace as _SN

        import time as _time

        mc = object.__new__(MasterConductor)
        mc.project_manager = _SN(project_dir="/tmp/shigoku-funnel", save_session=_async_noop)
        mc.task_queue = []
        mc.completed_tasks = []
        mc.pending_hitl = []
        mc._vdp_state = {
            "vdp_active": False,
            "hypotheses": [],
            "attempts": [],
            "evidence_records": [],
            "verdicts": [],
            "next_actions": [],
            "budget_snapshot": {},
            "run_health": {},
        }
        mc._current_session = _SN(session_id="test-funnel")
        mc.run_ledger_recorder = _SN(prepare_for_session=lambda spool_dir=None: {}, run_id="run-funnel")
        mc.decision_tracer = None
        mc.execution_log = _SN(to_list=lambda: [])
        mc.context = _SN(
            _total_attempts=0,
            _successful_attempts=0,
            bypass_methods=[],
            discovered_assets=[],
            target_info={"start_time": _time.time()},
        )
        mc._ensure_task_reason_code = lambda task: None
        mc._evaluate_vuln_family_coverage = lambda: {}
        mc._evaluate_intervention_scenario_coverage = lambda: {}
        for key, value in overrides.items():
            setattr(mc, key, value)
        return mc

    @staticmethod
    def _patch_diagnostics(monkeypatch, enabled: bool) -> None:
        from types import SimpleNamespace as _SN

        from src.core.config.settings import DiagnosticsSettings

        monkeypatch.setattr(
            "src.core.config.settings.get_settings",
            lambda: _SN(diagnostics=DiagnosticsSettings(enabled=enabled, required=False)),
        )

    async def test_disabled_recorder_session_has_no_funnel_key(self, monkeypatch):
        from src.core.config.settings import DiagnosticsSettings  # noqa: F401

        self._patch_diagnostics(monkeypatch, enabled=False)
        captured = {}

        async def _capture_save(payload, filename=None):
            captured["payload"] = payload

        mc = self._new_mc()
        mc.project_manager = SimpleNamespace(
            project_dir="/tmp/shigoku-funnel-off", save_session=_capture_save
        )
        await mc.async_save_session("funnel_off.json")
        assert "finding_funnel_v1" not in captured["payload"]
        assert "finding_funnel_v1" not in captured["payload"]["vdp_contract"]

    async def test_enabled_recorder_session_carries_funnel(self, monkeypatch):
        from src.core.engine.finding_funnel_trace import FindingFunnelRecorder

        recorder = FindingFunnelRecorder(enabled=True)
        recorder.record("4ae4c604e1ea", "F0", "reached")
        recorder.record("4ae4c604e1ea", "F3", "skipped", reason_code="phase2_skipped_early_return")
        monkeypatch.setattr(
            "src.core.engine.finding_funnel_trace.get_finding_funnel",
            lambda: recorder,
        )
        captured = {}

        async def _capture_save(payload, filename=None):
            captured["payload"] = payload

        mc = self._new_mc()
        mc.project_manager = SimpleNamespace(
            project_dir="/tmp/shigoku-funnel-on", save_session=_capture_save
        )
        await mc.async_save_session("funnel_on.json")
        payload = captured["payload"]
        assert payload["finding_funnel_v1"]["entries"][0]["finding_id"] == "4ae4c604e1ea"
        assert payload["finding_funnel_v1"]["summary"]["total_candidates"] == 1
        assert (
            payload["vdp_contract"]["finding_funnel_v1"]["entries"][0][
                "first_failure_stage"
            ]
            == "F3"
        )

    async def test_empty_recorder_session_has_no_funnel_key(self, monkeypatch):
        from src.core.engine.finding_funnel_trace import FindingFunnelRecorder

        recorder = FindingFunnelRecorder(enabled=True)  # enabled but no events
        monkeypatch.setattr(
            "src.core.engine.finding_funnel_trace.get_finding_funnel",
            lambda: recorder,
        )
        captured = {}

        async def _capture_save(payload, filename=None):
            captured["payload"] = payload

        mc = self._new_mc()
        mc.project_manager = SimpleNamespace(
            project_dir="/tmp/shigoku-funnel-empty", save_session=_capture_save
        )
        await mc.async_save_session("funnel_empty.json")
        assert "finding_funnel_v1" not in captured["payload"]
        assert "finding_funnel_v1" not in captured["payload"]["vdp_contract"]


class TestSessionCarriage:
    def _payload(self) -> dict:
        return {
            "task_queue": [],
            "completed_tasks": [],
            "context": {"total_attempts": 0, "target_info": {}},
            "timestamp": 1234.0,
        }

    def test_funnel_carried_into_vdp_contract_when_provided(self):
        payload = inject_vdp_section_to_session_payload(
            self._payload(),
            {
                "vdp_active": False,
                "finding_funnel_section": _funnel_section(),
            },
        )
        assert payload["vdp_contract"]["finding_funnel_v1"] == _funnel_section()

    def test_funnel_absent_key_absent(self):
        payload = inject_vdp_section_to_session_payload(
            self._payload(),
            {"vdp_active": False},
        )
        assert "finding_funnel_v1" not in payload["vdp_contract"]

    def test_roundtrip_preserves_finding_funnel_v1(self, tmp_path):
        """inject + redact_and_write_session -> read_session_compat keeps the
        funnel (both the vdp_contract copy and the top-level key)."""
        payload = self._payload()
        payload["finding_funnel_v1"] = _funnel_section()
        payload = inject_vdp_section_to_session_payload(
            payload,
            {
                "vdp_active": False,
                "finding_funnel_section": _funnel_section(),
            },
        )
        session_path = tmp_path / "session_funnel.json"
        redact_and_write_session(payload, session_path)
        restored = read_session_compat(session_path)
        assert restored is not None
        assert restored["finding_funnel_v1"] == _funnel_section()
        assert (
            restored["vdp_contract"]["finding_funnel_v1"] == _funnel_section()
        )

    def test_old_style_reader_ignores_funnel(self, tmp_path):
        """A minimal old-style reader (json.load + inject_vdp_fields) keeps
        the unknown finding_funnel_v1 key untouched."""
        payload = self._payload()
        payload["finding_funnel_v1"] = _funnel_section()
        session_path = tmp_path / "session_old_reader.json"
        redact_and_write_session(payload, session_path)
        raw = json.loads(session_path.read_text(encoding="utf-8"))
        parsed = inject_vdp_fields(raw)
        assert parsed["finding_funnel_v1"] == _funnel_section()
        assert "vdp_contract_version" in parsed
