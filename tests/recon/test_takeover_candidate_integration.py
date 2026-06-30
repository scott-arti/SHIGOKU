"""
Test Step 3: takeover_candidates.json integration with TakeoverCandidate schema (SGK-2026-0283-D02)
"""

import json
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from src.recon.pipeline import ReconPipeline


# ── helpers ──────────────────────────────────────────────────────────────

def _make_dns_json(pipeline: ReconPipeline, cname_map: dict[str, list[str]]) -> Path:
    """Create dns.json with CNAME records at the expected _get_path location."""
    records = []
    for name, targets in cname_map.items():
        for target in targets:
            records.append({
                "name": name,
                "tag": "dns",
                "record_type": "CNAME",
                "record_data": target,
            })
    dns_file = pipeline._get_path("dns", "json")
    dns_file.write_text(json.dumps(records, indent=2, ensure_ascii=False))
    return dns_file


def _make_previous_takeover_json(
    pipeline: ReconPipeline,
    entries: list[dict],
) -> Path:
    """Create a pre-existing takeover_candidates.json with prior session data."""
    takeover_file = pipeline._get_path("takeover_candidates", "json")
    takeover_file.write_text(json.dumps(entries, indent=2, ensure_ascii=False))
    return takeover_file


def _stable_hash(subdomain: str, cname_chain: list[str], provider_guess: str | None) -> str:
    """Reproduce the same hash used in pipeline."""
    chain_str = ":".join([subdomain] + cname_chain)
    hash_input = f"{subdomain}:{chain_str}:{provider_guess or ''}"
    return f"takeover_{hashlib.sha256(hash_input.encode()).hexdigest()[:16]}"


# ── tests ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_takeover_candidates_has_extended_schema(tmp_path):
    """takeover_candidates.json contains candidate_id, observed_at, required_signals, raw_evidence."""
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    pipeline.runner.dev_mode = True

    # Provide dns.json with CNAME records
    _make_dns_json(pipeline, {"dead.example.com": ["dead-target.github.io"]})

    all_subs = ["live.example.com", "dead.example.com"]

    with patch.object(pipeline.runner, "run_json", new=AsyncMock(return_value=[
        {"url": "https://live.example.com", "status_code": 200},
    ])):
        with patch.object(pipeline.runner, "run", new=AsyncMock(return_value="live.example.com\n")):
            await pipeline.step3_live_check(all_subs)

    # Read generated takeover_candidates.json
    takeover_files = list(tmp_path.glob("*_example_com_takeover_candidates.json"))
    assert len(takeover_files) == 1
    content = json.loads(takeover_files[0].read_text())
    assert isinstance(content, list)
    assert len(content) >= 1

    dead_entry = next((item for item in content if item["subdomain"] == "dead.example.com"), None)
    assert dead_entry is not None, f"No entry for dead.example.com in {content}"

    # Mandatory fields
    assert "candidate_id" in dead_entry
    assert dead_entry["candidate_id"].startswith("takeover_")
    assert "observed_at" in dead_entry
    assert "required_signals" in dead_entry
    assert isinstance(dead_entry["required_signals"], dict)
    assert "raw_evidence" in dead_entry
    assert isinstance(dead_entry["raw_evidence"], dict)

    # Status must be "candidate" for NXDOMAIN-only
    assert dead_entry["status"] == "candidate"

    # required_signals must contain dns_dead=True
    assert dead_entry["required_signals"].get("dns_dead") is True


@pytest.mark.asyncio
async def test_candidate_id_is_stable(tmp_path):
    """candidate_id is stable: same subdomain + same cname → same id."""
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    pipeline.runner.dev_mode = True

    # dns.json with CNAME
    _make_dns_json(pipeline, {"dead.example.com": ["dead-target.github.io"]})

    all_subs = ["live.example.com", "dead.example.com"]

    with patch.object(pipeline.runner, "run_json", new=AsyncMock(return_value=[
        {"url": "https://live.example.com", "status_code": 200},
    ])):
        with patch.object(pipeline.runner, "run", new=AsyncMock(return_value="live.example.com\n")):
            await pipeline.step3_live_check(all_subs)

    takeover_files = list(tmp_path.glob("*_example_com_takeover_candidates.json"))
    assert len(takeover_files) == 1
    content = json.loads(takeover_files[0].read_text())
    dead_entry = next((item for item in content if item["subdomain"] == "dead.example.com"), None)
    assert dead_entry is not None

    expected_id = _stable_hash("dead.example.com", ["dead-target.github.io"], "github_pages")
    assert dead_entry["candidate_id"] == expected_id


@pytest.mark.asyncio
async def test_nxdomain_only_candidate_status_is_candidate(tmp_path):
    """NXDOMAIN-only dead subs get status 'candidate' (not 'likely_reclaimable' or 'confirmed')."""
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    pipeline.runner.dev_mode = True

    all_subs = ["live.example.com", "dead.example.com"]

    with patch.object(pipeline.runner, "run_json", new=AsyncMock(return_value=[
        {"url": "https://live.example.com", "status_code": 200},
    ])):
        with patch.object(pipeline.runner, "run", new=AsyncMock(return_value="live.example.com\n")):
            await pipeline.step3_live_check(all_subs)

    takeover_files = list(tmp_path.glob("*_example_com_takeover_candidates.json"))
    assert len(takeover_files) == 1
    content = json.loads(takeover_files[0].read_text())

    for item in content:
        assert item["status"] == "candidate", (
            f"Expected status 'candidate' for {item['subdomain']}, got '{item['status']}'"
        )


@pytest.mark.asyncio
async def test_provider_guess_set_when_cname_matches_provider_matrix(tmp_path):
    """provider_guess is set when CNAME matches a provider in the matrix."""
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    pipeline.runner.dev_mode = True

    # CNAME that matches github.io → github_pages
    _make_dns_json(pipeline, {"dead.example.com": ["dead-target.github.io"]})

    all_subs = ["live.example.com", "dead.example.com"]

    with patch.object(pipeline.runner, "run_json", new=AsyncMock(return_value=[
        {"url": "https://live.example.com", "status_code": 200},
    ])):
        with patch.object(pipeline.runner, "run", new=AsyncMock(return_value="live.example.com\n")):
            await pipeline.step3_live_check(all_subs)

    takeover_files = list(tmp_path.glob("*_example_com_takeover_candidates.json"))
    content = json.loads(takeover_files[0].read_text())
    dead_entry = next((item for item in content if item["subdomain"] == "dead.example.com"), None)
    assert dead_entry is not None

    assert dead_entry["provider_guess"] == "github_pages", (
        f"Expected 'github_pages', got {dead_entry['provider_guess']}"
    )
    assert dead_entry["required_signals"]["provider_match"] is True


@pytest.mark.asyncio
async def test_first_seen_dead_carried_forward(tmp_path):
    """first_seen_dead is carried forward from prior session if available."""
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    pipeline.runner.dev_mode = True

    # Pre-create a prior session's takeover_candidates.json with an older first_seen_dead
    old_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    old_candidates = [
        {
            "candidate_id": "takeover_deadbeef12345678",
            "subdomain": "dead.example.com",
            "status": "candidate",
            "observed_at": old_date,
            "first_seen_dead": old_date,
            "last_seen_dead": old_date,
            "cname_chain": ["dead.example.com", "dead-target.github.io"],
            "provider_guess": "github_pages",
            "required_signals": {"dns_dead": True, "cname_dangling": True, "provider_match": True},
            "blocking_signals": [],
            "raw_evidence": {"dns": {}, "http": {}, "source_files": []},
            "manual_claim_review_required": True,
        }
    ]
    _make_previous_takeover_json(pipeline, old_candidates)

    # Same dns.json
    _make_dns_json(pipeline, {"dead.example.com": ["dead-target.github.io"]})

    all_subs = ["live.example.com", "dead.example.com"]

    with patch.object(pipeline.runner, "run_json", new=AsyncMock(return_value=[
        {"url": "https://live.example.com", "status_code": 200},
    ])):
        with patch.object(pipeline.runner, "run", new=AsyncMock(return_value="live.example.com\n")):
            await pipeline.step3_live_check(all_subs)

    takeover_files = list(tmp_path.glob("*_example_com_takeover_candidates.json"))
    content = json.loads(takeover_files[0].read_text())
    dead_entry = next((item for item in content if item["subdomain"] == "dead.example.com"), None)
    assert dead_entry is not None

    # first_seen_dead should be carried forward (the old date, not today)
    first_seen = dead_entry["first_seen_dead"]
    # Parse both as ISO to compare dates
    first_seen_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
    observed_dt = datetime.fromisoformat(dead_entry["observed_at"].replace("Z", "+00:00"))
    assert first_seen_dt.date() < observed_dt.date(), (
        f"Expected first_seen_dead ({first_seen}) to be older than observed_at ({dead_entry['observed_at']})"
    )


@pytest.mark.asyncio
async def test_no_dns_json_does_not_crash(tmp_path):
    """Missing dns.json gracefully results in null provider_guess and empty cname_chain."""
    pipeline = ReconPipeline(
        config={"recon": {"max_concurrent_tasks": 4}},
        project_manager=None,
        target="*.example.com",
        workspace_root=tmp_path,
    )
    pipeline.runner.dev_mode = True

    # Do NOT create dns.json

    all_subs = ["live.example.com", "dead.example.com"]

    with patch.object(pipeline.runner, "run_json", new=AsyncMock(return_value=[
        {"url": "https://live.example.com", "status_code": 200},
    ])):
        with patch.object(pipeline.runner, "run", new=AsyncMock(return_value="live.example.com\n")):
            await pipeline.step3_live_check(all_subs)

    takeover_files = list(tmp_path.glob("*_example_com_takeover_candidates.json"))
    assert len(takeover_files) == 1
    content = json.loads(takeover_files[0].read_text())
    dead_entry = next((item for item in content if item["subdomain"] == "dead.example.com"), None)
    assert dead_entry is not None

    assert dead_entry["provider_guess"] is None
    assert dead_entry["cname_chain"] == ["dead.example.com"]  # only the subdomain itself
    assert dead_entry["required_signals"]["cname_dangling"] is False
    assert dead_entry["required_signals"]["provider_match"] is False
    assert dead_entry["required_signals"]["dns_dead"] is True
