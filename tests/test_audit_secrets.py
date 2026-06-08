"""Unit tests for scripts/audit_secrets.py (Task 3 P0)"""

import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scripts.audit_secrets import scan, _parse_timestamp, _resolve_expiry


def test_parse_timestamp_iso():
    dt = _parse_timestamp("2020-01-01T00:00:00Z")
    assert dt is not None
    assert dt.year == 2020


def test_parse_timestamp_unix():
    dt = _parse_timestamp(0)
    assert dt is not None
    assert dt.year == 1970


def test_parse_timestamp_none():
    assert _parse_timestamp(None) is None
    assert _parse_timestamp("not-a-date") is None


def test_resolve_expiry_priority():
    entry = {
        "expires_at": "2020-01-01T00:00:00Z",
        "last_rotated_at": "2019-01-01T00:00:00Z",
        "created_at": "2018-01-01T00:00:00Z",
    }
    dt = _resolve_expiry(entry)
    assert dt is not None
    assert dt.year == 2020


def test_resolve_expiry_fallback_to_created_at():
    entry = {"created_at": "2020-06-01T00:00:00Z"}
    dt = _resolve_expiry(entry)
    assert dt is not None
    assert dt.year == 2020


def test_resolve_expiry_none_when_no_field():
    assert _resolve_expiry({"api_key": "abc123"}) is None


def test_scan_detects_overdue_json(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    old_date = (datetime.now(tz=timezone.utc) - timedelta(days=100)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    data = {"credentials": {"api_key": "secret", "expires_at": old_date}}
    (config_dir / "creds.json").write_text(json.dumps(data))

    findings = scan(config_dirs=["config"], max_age_days=90, project_root=str(tmp_path))
    overdue = [f for f in findings if f.get("overdue")]
    assert len(overdue) >= 1
    assert overdue[0]["age_days"] > 90


def test_scan_no_findings_fresh_credential(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    fresh_date = (datetime.now(tz=timezone.utc) - timedelta(days=10)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    data = {"credentials": {"api_key": "secret", "expires_at": fresh_date}}
    (config_dir / "creds.json").write_text(json.dumps(data))

    findings = scan(config_dirs=["config"], max_age_days=90, project_root=str(tmp_path))
    overdue = [f for f in findings if f.get("overdue")]
    assert len(overdue) == 0


def test_scan_expiry_unknown_flagged(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    data = {"api_key": "no-expiry-field"}
    (config_dir / "keys.json").write_text(json.dumps(data))

    findings = scan(config_dirs=["config"], max_age_days=90, project_root=str(tmp_path))
    unknown = [f for f in findings if f.get("expiry_unknown")]
    assert len(unknown) >= 1


def test_scan_env_file_expiry_unknown(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text('SECRET_KEY="abc123"\n')

    findings = scan(
        config_dirs=[],
        env_patterns=[".env"],
        max_age_days=90,
        project_root=str(tmp_path),
    )
    unknown = [f for f in findings if f.get("expiry_unknown")]
    assert len(unknown) >= 1


def test_scan_empty_dir(tmp_path):
    (tmp_path / "config").mkdir()
    findings = scan(config_dirs=["config"], max_age_days=90, project_root=str(tmp_path))
    assert findings == []
