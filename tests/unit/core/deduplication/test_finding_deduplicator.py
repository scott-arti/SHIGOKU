from src.core.deduplication.finding_deduplicator import deduplicate_findings
from src.core.models.finding import Finding, Severity, VulnType


def _finding(url: str, description: str) -> Finding:
    return Finding(
        vuln_type=VulnType.MASS_ASSIGNMENT,
        severity=Severity.MEDIUM,
        title="Potential privilege parameter tampering surface",
        description=description,
        target_url=url,
        confidence=0.65,
    )


def test_mass_assignment_does_not_merge_across_different_paths() -> None:
    findings = [
        _finding(
            "http://127.0.0.1:8888/chatbot/genai/state",
            "Auto-verified heuristic signal from repeated successful privilege-parameter probes.",
        ),
        _finding(
            "http://127.0.0.1:8888/account/settings",
            "Auto-verified heuristic signal from repeated successful privilege-parameter probes.",
        ),
    ]

    deduped = deduplicate_findings(findings)

    assert len(deduped) == 2
    urls = sorted(f.target_url for f in deduped)
    assert urls == [
        "http://127.0.0.1:8888/account/settings",
        "http://127.0.0.1:8888/chatbot/genai/state",
    ]


def test_mass_assignment_merges_same_path_when_descriptions_are_similar() -> None:
    findings = [
        _finding(
            "http://127.0.0.1:8888/account/settings",
            "Auto-verified heuristic signal from repeated successful privilege-parameter probes. status=completed",
        ),
        _finding(
            "http://127.0.0.1:8888/account/settings?__shigoku_probe=mass_assignment_read_probe&role=admin",
            "Auto-verified heuristic signal from repeated successful privilege-parameter probes. status=completed with probe",
        ),
    ]

    deduped = deduplicate_findings(findings)

    assert len(deduped) == 1
    merged = deduped[0]
    assert merged.additional_info.get("merged_count") == 2


def test_merging_candidates_preserves_all_reason_codes() -> None:
    """A report-time merge must not erase a second candidate's hold-back reason."""
    common = {
        "vuln_type": VulnType.BROKEN_ACCESS_CONTROL,
        "severity": Severity.HIGH,
        "description": "Static session identifier may permit an unauthorized session pivot.",
        "target_url": "http://localhost:4280/vulnerabilities/weak_id/?Submit=Generate",
    }
    first = Finding(
        title="Predictable session identifier candidate",
        confidence=0.8,
        additional_info={"reason_codes": ["untested_no_second_account"]},
        **common,
    )
    second = Finding(
        title="Session fixation candidate",
        confidence=0.7,
        additional_info={"evidence_quality_reason_codes": ["session_takeover_not_verified"]},
        **common,
    )

    deduped = deduplicate_findings([first, second])

    assert len(deduped) == 1
    assert deduped[0].additional_info["reason_codes"] == [
        "untested_no_second_account",
        "session_takeover_not_verified",
    ]
    assert deduped[0].additional_info["evidence_quality_reason_codes"] == [
        "session_takeover_not_verified"
    ]
