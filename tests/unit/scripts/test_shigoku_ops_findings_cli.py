from __future__ import annotations

import json
import subprocess
from pathlib import Path

from src.core.learning.findings_repository import FindingsRepository
from src.core.models.finding import Evidence, Finding, Severity, VulnType


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _seed_finding(
    db_path: Path,
    *,
    url: str,
    title: str,
    vuln_type: VulnType = VulnType.XSS,
    severity: Severity = Severity.HIGH,
    method: str = "GET",
    verified: bool = False,
) -> None:
    repo = FindingsRepository(db_path=str(db_path))
    finding = Finding(
        vuln_type=vuln_type,
        severity=severity,
        title=title,
        description="fixture finding",
        target_url=url,
        evidence=Evidence(
            request_method=method,
            request_url=url,
        ),
        source_agent="test_agent",
        confidence=0.9,
    )
    repo.save(finding)
    if verified:
        assert repo.mark_verified(finding.id, True)


def test_ops_cli_findings_list_returns_saved_records(tmp_path: Path) -> None:
    db_path = tmp_path / "findings.db"
    _seed_finding(db_path, url="http://127.0.0.1:8888/api/users/1", title="XSS fixture")
    _seed_finding(db_path, url="http://127.0.0.1:8888/api/users/2", title="IDOR fixture", vuln_type=VulnType.IDOR)

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "findings",
            "list",
            "--db-path",
            str(db_path),
            "--limit",
            "10",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["finding_count"] == 2


def test_ops_cli_findings_search_filters_verified_records(tmp_path: Path) -> None:
    db_path = tmp_path / "findings.db"
    _seed_finding(
        db_path,
        url="http://127.0.0.1:8888/api/users/1",
        title="verified fixture",
        verified=True,
    )
    _seed_finding(
        db_path,
        url="http://127.0.0.1:8888/api/users/2",
        title="unverified fixture",
        verified=False,
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "findings",
            "search",
            "--db-path",
            str(db_path),
            "--target",
            "127.0.0.1:8888",
            "--verified-only",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["finding_count"] == 1
    assert payload["findings"][0]["title"] == "verified fixture"


def test_ops_cli_findings_stats_reports_counts(tmp_path: Path) -> None:
    db_path = tmp_path / "findings.db"
    _seed_finding(db_path, url="http://127.0.0.1:8888/api/users/1", title="critical fixture", severity=Severity.CRITICAL)
    _seed_finding(db_path, url="http://127.0.0.1:8888/api/users/2", title="low fixture", severity=Severity.LOW)

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "findings",
            "stats",
            "--db-path",
            str(db_path),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["stats"]["total"] == 2
    assert payload["stats"]["by_severity"]["critical"] == 1
    assert payload["stats"]["by_severity"]["low"] == 1


def test_ops_cli_findings_export_targets_blocks_mixed_scope_without_explicit_host(tmp_path: Path) -> None:
    db_path = tmp_path / "findings.db"
    _seed_finding(db_path, url="http://127.0.0.1:8888/api/users/1", title="local fixture")
    _seed_finding(db_path, url="https://api.example.com/v1/users/2", title="remote fixture")

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "findings",
            "export-targets",
            "--db-path",
            str(db_path),
            "--output-dir",
            str(tmp_path / "export"),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert "cross_session_scope_required" in payload["reason_codes"]


def test_ops_cli_findings_export_targets_writes_bundle_when_scope_is_explicit(tmp_path: Path) -> None:
    db_path = tmp_path / "findings.db"
    output_dir = tmp_path / "export"
    _seed_finding(
        db_path,
        url="http://127.0.0.1:8888/api/users/1",
        title="GET fixture",
        method="GET",
    )
    _seed_finding(
        db_path,
        url="http://127.0.0.1:8888/api/users/2",
        title="POST fixture",
        method="POST",
        vuln_type=VulnType.IDOR,
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "findings",
            "export-targets",
            "--db-path",
            str(db_path),
            "--output-dir",
            str(output_dir),
            "--allowed-host",
            "127.0.0.1",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["target_count"] == 2
    assert payload["manifest"]["allowed_hosts"] == ["127.0.0.1"]
    assert "cross_session_export" in payload["reason_codes"]
    assert Path(payload["artifacts"]["attack_targets"]).exists()
    assert Path(payload["artifacts"]["endpoints_json"]).exists()


def test_ops_cli_findings_export_targets_blocks_empty_export(tmp_path: Path) -> None:
    db_path = tmp_path / "findings.db"

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "findings",
            "export-targets",
            "--db-path",
            str(db_path),
            "--target",
            "127.0.0.1:8888",
            "--output-dir",
            str(tmp_path / "export"),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert "empty_export" in payload["reason_codes"]
