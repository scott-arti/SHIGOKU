from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from src.recon.pipeline import ReconPipeline


class _DummyProjectManager:
    def __init__(self, project_dir: Path):
        self.project_dir = project_dir


class _DummyMC:
    def __init__(self):
        self.context = SimpleNamespace(target_info={})
        self.added_tasks = []

    def _add_tasks(self, tasks, source=None):  # pragma: no cover - callback shape only
        self.added_tasks.extend(tasks)


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


@pytest.mark.asyncio
async def test_step8_skips_promoted_files_to_avoid_duplicate_categories(tmp_path: Path):
    project_dir = tmp_path / "project"
    tagged_dir = project_dir / "tagged_urls"
    tagged_dir.mkdir(parents=True, exist_ok=True)

    date_str = datetime.now().strftime("%Y%m%d")
    uncategorized_file = tagged_dir / f"{date_str}_target_tagged_uncategorized.jsonl"
    preexisting_promoted_file = tagged_dir / f"{date_str}_target_tagged_uncategorized_promoted_realtime.jsonl"

    _write_jsonl(
        uncategorized_file,
        [
            {"url": "https://app.example.com/ws/events?transport=websocket&t=1&sid=a", "method": "GET", "forms": []},
            {"url": "https://app.example.com/about", "method": "GET", "forms": []},
        ],
    )
    _write_jsonl(
        preexisting_promoted_file,
        [
            {"url": "https://app.example.com/ws/events?transport=websocket&t=10&sid=x", "method": "GET", "forms": []},
            {"url": "https://app.example.com/ws/events?transport=websocket&t=11&sid=y", "method": "GET", "forms": []},
        ],
    )

    pm = _DummyProjectManager(project_dir=project_dir)
    mc = _DummyMC()
    pipeline = ReconPipeline(config={}, project_manager=pm, target="https://app.example.com/", master_conductor=mc)

    result = await pipeline.step8_return_to_mc({})

    assert "tagged_realtime" in result
    assert "tagged_uncategorized" in result
    assert all("_promoted_" not in key for key in result.keys())


@pytest.mark.asyncio
async def test_step8_skips_direct_enqueue_for_realtime_and_meta(tmp_path: Path):
    project_dir = tmp_path / "project"
    tagged_dir = project_dir / "tagged_urls"
    tagged_dir.mkdir(parents=True, exist_ok=True)

    date_str = datetime.now().strftime("%Y%m%d")
    realtime_file = tagged_dir / f"{date_str}_target_tagged_realtime.jsonl"
    meta_file = tagged_dir / f"{date_str}_target_tagged_meta_observability.jsonl"

    _write_jsonl(
        realtime_file,
        [
            {"url": "https://app.example.com/ws/events?transport=websocket&t=1&sid=a", "method": "GET", "forms": []},
        ],
    )
    _write_jsonl(
        meta_file,
        [
            {"url": "https://app.example.com/assets/i18n/en.json", "method": "GET", "forms": []},
        ],
    )

    pm = _DummyProjectManager(project_dir=project_dir)
    mc = _DummyMC()
    pipeline = ReconPipeline(config={}, project_manager=pm, target="https://app.example.com/", master_conductor=mc)

    result = await pipeline.step8_return_to_mc({})

    assert "tagged_realtime" in result
    assert "tagged_meta_observability" in result
    assert mc.added_tasks == []


@pytest.mark.asyncio
async def test_step8_reuses_existing_promoted_files_when_uncategorized_already_pruned(tmp_path: Path):
    project_dir = tmp_path / "project"
    tagged_dir = project_dir / "tagged_urls"
    tagged_dir.mkdir(parents=True, exist_ok=True)

    date_str = datetime.now().strftime("%Y%m%d")
    uncategorized_file = tagged_dir / f"{date_str}_target_tagged_uncategorized.jsonl"
    promoted_auth_file = tagged_dir / f"{date_str}_target_tagged_uncategorized_promoted_auth.jsonl"

    _write_jsonl(
        uncategorized_file,
        [
            {"url": "https://app.example.com/", "method": "GET", "forms": []},
            {"url": "https://app.example.com/manifest.json", "method": "GET", "forms": []},
        ],
    )
    _write_jsonl(
        promoted_auth_file,
        [
            {"url": "https://app.example.com/account", "method": "GET", "forms": []},
            {"url": "https://app.example.com/profile", "method": "GET", "forms": []},
        ],
    )

    pm = _DummyProjectManager(project_dir=project_dir)
    mc = _DummyMC()
    pipeline = ReconPipeline(config={}, project_manager=pm, target="https://app.example.com/", master_conductor=mc)

    result = await pipeline.step8_return_to_mc({})

    assert "tagged_auth" in result
    assert int(result["tagged_auth"]["count"]) == 2
    assert all("_promoted_" not in key for key in result.keys())


@pytest.mark.asyncio
async def test_step8_falls_back_to_latest_tagged_files_when_today_missing(tmp_path: Path):
    project_dir = tmp_path / "project"
    tagged_dir = project_dir / "tagged_urls"
    tagged_dir.mkdir(parents=True, exist_ok=True)

    stale_date = (datetime.now() - timedelta(days=1)).strftime("%Y%m%d")
    stale_file = tagged_dir / f"{stale_date}_target_tagged_auth.jsonl"
    _write_jsonl(
        stale_file,
        [
            {"url": "https://app.example.com/account", "method": "GET", "forms": []},
        ],
    )

    pm = _DummyProjectManager(project_dir=project_dir)
    mc = _DummyMC()
    pipeline = ReconPipeline(config={}, project_manager=pm, target="https://app.example.com/", master_conductor=mc)

    result = await pipeline.step8_return_to_mc({})
    assert "tagged_auth" in result
