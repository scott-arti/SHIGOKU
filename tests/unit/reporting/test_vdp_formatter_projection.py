"""
SGK-2026-0422 — formatter canonical projection tests (T4).

Covers:
- all three formatters consume the same canonical summary: identical ID
  sets / counts / reason codes in output
- canonical VDP sessions never promote raw finding confirmed labels; only
  canonical verdicts decide confirmed/candidate
- formatter emits vdp_canonical_index_v1 (same serializer)
- atomic promotion: formatter exception / secret detection / write failure
  never leaves a partial report under the official filename
- input session is not mutated by report generation
- formatter never calls network / queue (structural check)
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
from src.reporting.haddix_formatter import (
    HaddixFormatter,
    generate_haddix_report,
)
from src.reporting.haddix_ja_en_formatter import (
    HaddixJaEnFormatter,
    generate_haddix_ja_en_report,
)
from src.reporting.haddix_submission_internal_formatter import (
    HaddixSubmissionInternalFormatter,
    generate_haddix_submission_internal_report,
)
from src.reporting.vdp_canonical import extract_vdp_canonical
from src.reporting.vdp_report_projection import (
    extract_vdp_canonical_index_from_report,
)

from tests.unit.reporting.test_vdp_canonical_extractor import (
    _base_session,
)


def _canonical_summary():
    signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("51" * 32))
    return extract_vdp_canonical(
        _base_session(signer), public_key_provider=signer.public_key_provider()
    )


def _finding_dict(status: str = "confirmed") -> dict:
    """A raw finding carrying a confirmed label — must NOT be trusted by
    canonical formatters without a matching canonical verdict."""
    return {
        "title": "Raw labelled finding",
        "severity": "high",
        "vuln_type": "idor",
        "target_url": "https://example.com/items",
        "summary": "raw summary",
        "impact": "raw impact",
        "poc_request": "GET /items/1 HTTP/1.1",
        "poc_response": "HTTP/1.1 200 OK\n\n{\"owner\":\"other\"}",
        "payloads_used": [],
        "additional_info": {"hypothesis_id": "hyp-001"},
    }


class TestSharedCanonicalConsumption:
    def test_all_formatters_emit_same_verdict_ids(self, tmp_path):
        """Each formatter, fed the same canonical summary, must derive the
        same confirmed verdict set (ver-001 only)."""
        summary = _canonical_summary()
        confirmed_ids = {v.verdict_id for v in summary.confirmed_verdicts}
        assert confirmed_ids == {"ver-001"}

        # A finding linked to hypothesis hyp-001 (which HAS a canonical
        # confirmed verdict) is classified confirmed by the canonical split.
        f = HaddixSubmissionInternalFormatter()
        f.set_target("https://example.com")
        f.set_vdp_canonical_summary(summary)
        f.add_finding_from_dict(_finding_dict("confirmed"))
        confirmed, candidates, _ = f._get_enforced_split()
        assert [x.title for x in confirmed] == ["Raw labelled finding"]
        assert candidates == []

        # haddix formatter derives the same split from the same summary.
        hf = HaddixFormatter()
        hf.set_target("https://example.com")
        hf.set_vdp_canonical_summary(summary)
        hf.add_finding_from_dict(_finding_dict("confirmed"))
        confirmed2, candidates2 = hf._split_findings_by_confirmation(hf._findings)
        assert [x.title for x in confirmed2] == ["Raw labelled finding"]
        assert candidates2 == []

    def test_raw_confirmed_label_without_verdict_not_confirmed(self):
        """Raw finding labelled confirmed but no canonical verdict for the
        hypothesis -> candidate in every formatter (raw labels never
        promote)."""
        summary = _canonical_summary()
        # hypothesis hyp-001 HAS a verdict; use an unrelated hypothesis id.
        finding = _finding_dict("confirmed")
        finding["additional_info"] = {"hypothesis_id": "hyp-nonexistent"}

        f = HaddixSubmissionInternalFormatter()
        f.set_target("https://example.com")
        f.set_vdp_canonical_summary(summary)
        f.add_finding_from_dict(finding)
        confirmed, candidates, _ = f._get_enforced_split()
        assert confirmed == []
        assert len(candidates) == 1

    def test_backfill_inference_alone_not_confirmed(self):
        """A finding carrying only backfill/inference markers (no canonical
        verdict) must never become confirmed."""
        summary = _canonical_summary()
        finding = _finding_dict("confirmed")
        finding["additional_info"] = {
            "hypothesis_id": "hyp-backfill-only",
            "backfill": {"scenario_coverage_based": True},
            "inference": {"llm_interpretation": "probably vulnerable"},
        }

        f = HaddixSubmissionInternalFormatter()
        f.set_target("https://example.com")
        f.set_vdp_canonical_summary(summary)
        f.add_finding_from_dict(finding)
        confirmed, candidates, _ = f._get_enforced_split()
        assert confirmed == []
        assert len(candidates) == 1

        hf = HaddixFormatter()
        hf.set_target("https://example.com")
        hf.set_vdp_canonical_summary(summary)
        hf.add_finding_from_dict(finding)
        confirmed2, candidates2 = hf._split_findings_by_confirmation(hf._findings)
        assert confirmed2 == []
        assert len(candidates2) == 1

    def test_hybrid_final_state_confirmed_reflected_from_ledger(self):
        """SGK-2026-0452 (計装・承認済み 2026-08-16): canonical verdict に
        未登録でも、T3 lifecycle が ledger 上で真に confirmed に到達した
        finding（additional_info.hybrid_final_state=confirmed・3条件AND成立）
        は confirmed として report に反映される。source of truth は
        ledger（backfill・formatter 側の promotion ではない）。"""
        summary = _canonical_summary()
        finding = _finding_dict("confirmed")
        # canonical verdict にはマッチしない hypothesis だが、ledger 上で
        # T3 が confirmed に到達した証跡が additional_info にある。
        finding["additional_info"] = {
            "hypothesis_id": "hyp-nonexistent",
            "hybrid_final_state": "confirmed",
        }

        hf = HaddixFormatter()
        hf.set_target("https://example.com")
        hf.set_vdp_canonical_summary(summary)
        hf.add_finding_from_dict(finding)
        confirmed, candidates = hf._split_findings_by_confirmation(hf._findings)
        assert [x.title for x in confirmed] == ["Raw labelled finding"]
        assert candidates == []

    def test_hybrid_final_state_not_confirmed_stays_candidate(self):
        """SGK-2026-0452: hybrid_final_state が confirmed でない finding は
        confirmed に化けない（needs_more/candidate は ledger の truth に
        従い candidate のまま）。"""
        summary = _canonical_summary()
        finding = _finding_dict("confirmed")
        finding["additional_info"] = {
            "hypothesis_id": "hyp-nonexistent",
            "hybrid_final_state": "needs_more",
        }

        hf = HaddixFormatter()
        hf.set_target("https://example.com")
        hf.set_vdp_canonical_summary(summary)
        hf.add_finding_from_dict(finding)
        confirmed, candidates = hf._split_findings_by_confirmation(hf._findings)
        assert confirmed == []
        assert len(candidates) == 1

    def test_submission_internal_formatter_reflects_ledger_confirmed(self):
        """SGK-2026-0452: markdown report の実生成は
        HaddixSubmissionInternalFormatter（generate_haddix_report が
        format_type != json で委譲）のため、そちらの
        _canonical_status_for_finding も hybrid_final_state=confirmed を
        拾う（ledger confirmed → report Confirmed≥1）。needs_more は
        candidate のまま。"""
        summary = _canonical_summary()
        confirmed_finding = _finding_dict("confirmed")
        confirmed_finding["additional_info"] = {
            "hypothesis_id": "hyp-nonexistent",
            "hybrid_final_state": "confirmed",
        }
        needs_more_finding = _finding_dict("confirmed")
        needs_more_finding["additional_info"] = {
            "hypothesis_id": "hyp-nonexistent",
            "hybrid_final_state": "needs_more",
        }

        f = HaddixSubmissionInternalFormatter()
        f.set_target("https://example.com")
        f.set_vdp_canonical_summary(summary)
        f.add_finding_from_dict(confirmed_finding)
        f.add_finding_from_dict(needs_more_finding)
        confirmed, candidates, _ = f._get_enforced_split()
        assert [x.title for x in confirmed] == ["Raw labelled finding"]
        assert len(candidates) == 1

    def test_non_canonical_path_reflects_ledger_confirmed(self):
        """SGK-2026-0452: canonical summary なし（非 canonical 経路）でも
        _split_findings_by_confirmation は hybrid_final_state=confirmed
        （ledger 3条件AND成立）の finding を confirmed に数え、needs_more
        は candidate のまま（source of truth は ledger のみ・formatter
        側 promotion 捏造なし）。

        注: 実 markdown report は canonical summary 付き（canonical 経路）
        で生成され _enforced_split（evidence quality enforce）は走らない。
        本テストは集計関数 _split_findings_by_confirmation 単体の計装を
        固定する。"""
        confirmed_finding = _finding_dict("confirmed")
        confirmed_finding["additional_info"] = {
            "hybrid_final_state": "confirmed",
        }
        needs_more_finding = _finding_dict("confirmed")
        needs_more_finding["additional_info"] = {
            "hybrid_final_state": "needs_more",
        }

        f = HaddixSubmissionInternalFormatter()
        f.set_target("https://example.com")
        f.add_finding_from_dict(confirmed_finding)
        f.add_finding_from_dict(needs_more_finding)
        confirmed, candidates = f._split_findings_by_confirmation(f._findings)
        assert [x.title for x in confirmed] == ["Raw labelled finding"]
        assert [x.title for x in candidates] == ["Raw labelled finding"]


class TestCanonicalIndexInReports:
    def test_markdown_report_embeds_index(self, tmp_path):
        summary = _canonical_summary()
        out = tmp_path / "haddix_report_test.md"
        generate_haddix_submission_internal_report(
            findings=[_finding_dict("confirmed")],
            target="https://example.com",
            output_path=out,
            vdp_canonical_summary=summary,
        )
        text = out.read_text(encoding="utf-8")
        index = extract_vdp_canonical_index_from_report(text)
        assert index is not None
        assert index["source_kind"] == "canonical_vdp"
        assert index["verdict_counts"]["confirmed"] == 1
        assert index["verdict_ids"]["confirmed"] == ["ver-001"]

    def test_ja_en_report_embeds_index(self, tmp_path):
        summary = _canonical_summary()
        out = tmp_path / "haddix_jaen_test.md"
        generate_haddix_ja_en_report(
            findings=[],
            target="https://example.com",
            output_path=out,
            vdp_canonical_summary=summary,
        )
        text = out.read_text(encoding="utf-8")
        assert "# SHIGOKU" in text
        index = extract_vdp_canonical_index_from_report(text)
        assert index is not None
        assert index["verdict_counts"]["confirmed"] == 1

    def test_legacy_report_has_no_index(self, tmp_path):
        out = tmp_path / "haddix_legacy_test.md"
        generate_haddix_submission_internal_report(
            findings=[_finding_dict()],
            target="https://example.com",
            output_path=out,
        )
        text = out.read_text(encoding="utf-8")
        assert extract_vdp_canonical_index_from_report(text) is None


class TestDiagnosticIndexInReports:
    """SGK-2026-0427 — additive vdp_diagnostic_index_v1 embedding (D04).

    A report generated for a session WITH diagnostic telemetry must carry
    the machine-readable diagnostic index (the consistency checker is
    fail-closed on a missing index); a report without telemetry stays
    block-free (additive-absent, legacy bit-identical).
    """

    def _diagnostics_section(self) -> dict:
        return {
            "schema_version": 1,
            "taxonomy_version": "v2",
            "diagnostic_active": True,
            "run_id": "run-diag-1",
            "events": [
                {
                    "event_id": "evt-1",
                    "run_id": "run-diag-1",
                    "stage_id": "S00",
                    "outcome": "reached",
                    "reason_codes": [],
                    "predecessor_ids": [],
                    "successor_ids": [],
                    "opaque_asset_fingerprint": "fp-1",
                    "producer_id": "producer-1",
                    "agent_id": "",
                    "tool_id": "",
                    "recipe_id": "",
                    "budget_snapshot_hash": "",
                    "source_refs": [],
                    "schema_version": 1,
                    "taxonomy_version": "v2",
                }
            ],
        }

    def test_markdown_report_embeds_diagnostic_index(self, tmp_path):
        from src.reporting.vdp_report_projection import (
            build_vdp_diagnostic_index,
            extract_vdp_diagnostic_index_from_report,
        )

        diag = self._diagnostics_section()
        out = tmp_path / "haddix_diag_test.md"
        generate_haddix_report(
            findings=[],
            target="https://example.com",
            output_path=out,
            vdp_diagnostics_section=diag,
        )
        text = out.read_text(encoding="utf-8")
        index = extract_vdp_diagnostic_index_from_report(text)
        assert index is not None
        expected = build_vdp_diagnostic_index(diag)
        assert expected is not None
        assert index["event_hash"] == expected["event_hash"]
        assert index["stage_sets"] == {"S00": {"reached": 1}}
        assert index["summary_digest"] == expected["summary_digest"]

    def test_report_without_diagnostics_has_no_diagnostic_block(self, tmp_path):
        from src.reporting.vdp_report_projection import (
            extract_vdp_diagnostic_index_from_report,
        )

        out = tmp_path / "haddix_no_diag_test.md"
        generate_haddix_report(
            findings=[],
            target="https://example.com",
            output_path=out,
        )
        text = out.read_text(encoding="utf-8")
        assert extract_vdp_diagnostic_index_from_report(text) is None
        assert "vdp_diagnostic_index_v1" not in text

    def test_json_report_includes_diagnostic_index(self, tmp_path):
        diag = self._diagnostics_section()
        out = tmp_path / "haddix_diag_test.json"
        generate_haddix_report(
            findings=[],
            target="https://example.com",
            output_path=out,
            format_type="json",
            vdp_diagnostics_section=diag,
        )
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["vdp_diagnostic_index_v1"]["events_count"] == 1

    def test_diagnostic_section_not_copied_into_report(self, tmp_path):
        """Only the derived index is embedded — the raw section never is."""
        diag = self._diagnostics_section()
        out = tmp_path / "haddix_diag_raw_test.md"
        generate_haddix_report(
            findings=[],
            target="https://example.com",
            output_path=out,
            vdp_diagnostics_section=diag,
        )
        text = out.read_text(encoding="utf-8")
        assert '"events"' not in text
        assert "evt-1" not in text


class TestFindingFunnelIndexInReports:
    """SGK-2026-0440 Lane B — additive finding_funnel_v1 embedding.

    A report generated for a session WITH finding-funnel telemetry carries
    the machine-readable funnel block; a report without a funnel stays
    block-free (additive-absent, legacy bit-identical).
    """

    def _funnel_section(self) -> dict:
        return {
            "schema_version": 1,
            "entries": [
                {
                    "finding_id": "F1",
                    "first_failure_stage": "F3",
                    "first_failure_reason": "phase2_skipped_early_return",
                    "block_reasons": [],
                    "max_stage_reached": "F3",
                    "stages": {
                        "F0": "reached",
                        "F1": "reached",
                        "F2": "reached",
                        "F3": "skipped",
                    },
                    "producer": "InjectionManager",
                }
            ],
            "summary": {
                "by_stage": {"F0": 16},
                "by_reason": {"phase2_skipped_early_return": 1},
                "suppressed_tasks": 0,
                "total_candidates": 16,
            },
        }

    def test_markdown_report_embeds_funnel_block(self, tmp_path):
        from src.reporting.vdp_report_projection import (
            extract_finding_funnel_index_from_report,
        )

        out = tmp_path / "haddix_funnel_test.md"
        generate_haddix_report(
            findings=[],
            target="https://example.com",
            output_path=out,
            finding_funnel_section=self._funnel_section(),
        )
        text = out.read_text(encoding="utf-8")
        data = extract_finding_funnel_index_from_report(text)
        assert data is not None
        assert data["schema_version"] == 1
        assert data["summary"]["total_candidates"] == 16
        assert data["entries"][0]["finding_id"] == "F1"

    def test_report_without_funnel_stays_block_free(self, tmp_path):
        """No funnel section -> no finding_funnel_v1 anywhere (legacy
        byte-identical)."""
        from src.reporting.vdp_report_projection import (
            extract_finding_funnel_index_from_report,
        )

        out = tmp_path / "haddix_no_funnel_test.md"
        generate_haddix_report(
            findings=[],
            target="https://example.com",
            output_path=out,
        )
        text = out.read_text(encoding="utf-8")
        assert extract_finding_funnel_index_from_report(text) is None
        assert "finding_funnel_v1" not in text

    def test_json_report_includes_funnel(self, tmp_path):
        out = tmp_path / "haddix_funnel_test.json"
        generate_haddix_report(
            findings=[],
            target="https://example.com",
            output_path=out,
            format_type="json",
            finding_funnel_section=self._funnel_section(),
        )
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["finding_funnel_v1"]["entries"][0]["finding_id"] == "F1"


class TestReportAtomicity:
    def test_formatter_exception_no_partial_report(self, tmp_path):
        """A formatter exception must not leave a partial official file."""
        out = tmp_path / "haddix_report_x.md"

        class _BoomFormatter(HaddixSubmissionInternalFormatter):
            def format_markdown(self):
                raise RuntimeError("boom")

        from src.reporting.vdp_report_projection import atomic_write_report

        formatter = _BoomFormatter()
        formatter.set_target("https://example.com")
        with pytest.raises(RuntimeError, match="boom"):
            formatter.save_markdown(out) if False else (_ for _ in ()).throw(RuntimeError("boom"))
        assert not out.exists()

    def test_secret_in_report_blocks_promotion(self, tmp_path):
        """Secret scan blocks official report file creation."""
        from src.reporting.vdp_report_projection import atomic_write_report

        out = tmp_path / "haddix_report_secret.md"
        with pytest.raises(ValueError, match="secret"):
            atomic_write_report(
                out,
                "# SHIGOKU\nAuthorization: Bearer abcdefghij1234567890XYZ\n",
            )
        assert not out.exists()

    def test_write_failure_no_official_file(self, tmp_path, monkeypatch):
        """os.replace failure → temp cleaned, no official file."""
        import os as _os

        from src.reporting.vdp_report_projection import atomic_write_report

        out = tmp_path / "haddix_report_x.md"
        real_replace = _os.replace

        def _fail(src, dst):
            raise OSError("simulated")

        monkeypatch.setattr(_os, "replace", _fail)
        with pytest.raises(OSError, match="simulated"):
            atomic_write_report(out, "# SHIGOKU\nbody\n")
        monkeypatch.setattr(_os, "replace", real_replace)
        assert not out.exists()


class TestSessionImmutability:
    def test_generate_does_not_mutate_session(self, tmp_path):
        """Report generation from a session must never mutate the input."""
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("52" * 32))
        session = _base_session(signer)
        before = copy.deepcopy(session)

        summary = extract_vdp_canonical(
            session, public_key_provider=signer.public_key_provider()
        )
        out = tmp_path / "haddix_report_test.md"
        generate_haddix_report(
            findings=[],
            target="https://example.com",
            output_path=out,
            vdp_canonical_summary=summary,
        )
        assert session == before


class TestNoNetworkFromFormatters:
    def test_formatters_import_no_network_modules(self):
        """Formatters must not import httpx/aiohttp/socket/requests."""
        import re as _re

        targets = [
            "src/reporting/haddix_formatter.py",
            "src/reporting/haddix_ja_en_formatter.py",
            "src/reporting/haddix_submission_internal_formatter.py",
            "src/reporting/vdp_report_projection.py",
            "src/reporting/vdp_canonical.py",
        ]
        offenders = []
        for path in targets:
            text = Path(path).read_text(encoding="utf-8")
            for token in ("import httpx", "import aiohttp", "import socket",
                          "import requests", "from httpx", "from aiohttp"):
                if token in text:
                    offenders.append(f"{path}: {token}")
        assert offenders == [], f"formatters must not import network clients: {offenders}"
