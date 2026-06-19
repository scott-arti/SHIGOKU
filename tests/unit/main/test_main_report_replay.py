import asyncio
import json
import sys
from pathlib import Path

from src import main as main_module


def test_main_report_replay_runs_queue_processing(monkeypatch, tmp_path, capsys):
    replay_queue_path = tmp_path / "report_adapter_replay_queue.jsonl"
    replay_queue_path.write_text('{"queue_id":"replay-1","replay_status":"pending"}\n', encoding="utf-8")

    class _FakeManager:
        _platforms = {"hackerone": object()}

        async def replay_pending_submissions(self, platform, *, component_status, replay_queue_path, limit=None):
            return {
                "platform": platform,
                "processed": 1,
                "replayed": 1,
                "failed": 0,
                "queue_path": str(replay_queue_path),
            }

    async def _fake_create_platform_manager(*, hackerone_token=None, hackerone_username=None, bugcrowd_token=None):
        return _FakeManager()

    monkeypatch.setattr("src.core.reporting.platform_integration.create_platform_manager", _fake_create_platform_manager)
    monkeypatch.setattr(sys, "argv", [
        "shigoku",
        "--report-replay",
        "--report-replay-platform",
        "hackerone",
        "--report-replay-queue",
        str(replay_queue_path),
        "--json",
    ])

    main_module.main()

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["platform"] == "hackerone"
    assert payload["replayed"] == 1
    assert payload["processed"] == 1


def test_main_report_replay_requires_configured_platform(monkeypatch, capsys):
    class _FakeManager:
        pass

    async def _fake_create_platform_manager(*, hackerone_token=None, hackerone_username=None, bugcrowd_token=None):
        return _FakeManager()

    monkeypatch.setattr("src.core.reporting.platform_integration.create_platform_manager", _fake_create_platform_manager)
    monkeypatch.setattr(
        sys,
        "argv",
        ["shigoku", "--report-replay", "--report-replay-platform", "hackerone"],
    )

    main_module.main()

    captured = capsys.readouterr()
    assert "does not support replay" in captured.out


def test_main_report_retry_failed_resets_failed_records(monkeypatch, tmp_path, capsys):
    replay_queue_path = tmp_path / "report_adapter_replay_queue.jsonl"
    replay_queue_path.write_text(
        '{"queue_id":"replay-1","platform":"hackerone","replay_status":"failed","replay_error":"boom"}\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "shigoku",
            "--report-retry-failed",
            "--report-replay-platform",
            "hackerone",
            "--report-replay-queue",
            str(replay_queue_path),
            "--json",
        ],
    )

    main_module.main()

    payload = json.loads(capsys.readouterr().out)
    assert payload["reset"] == 1
    record = json.loads(replay_queue_path.read_text(encoding="utf-8").splitlines()[0])
    assert record["replay_status"] == "pending"


def test_main_report_retry_failed_filters_by_queue_id(monkeypatch, tmp_path, capsys):
    replay_queue_path = tmp_path / "report_adapter_replay_queue.jsonl"
    replay_queue_path.write_text(
        "\n".join(
            [
                '{"queue_id":"replay-1","platform":"hackerone","replay_status":"failed","replay_error":"boom-1"}',
                '{"queue_id":"replay-2","platform":"hackerone","replay_status":"failed","replay_error":"boom-2"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "shigoku",
            "--report-retry-failed",
            "--report-replay-platform",
            "hackerone",
            "--report-replay-queue",
            str(replay_queue_path),
            "--report-replay-queue-id",
            "replay-2",
            "--json",
        ],
    )

    main_module.main()

    payload = json.loads(capsys.readouterr().out)
    assert payload["reset"] == 1
    records = [json.loads(line) for line in replay_queue_path.read_text(encoding="utf-8").splitlines()]
    assert records[0]["replay_status"] == "failed"
    assert records[1]["replay_status"] == "pending"


def test_main_report_replay_list_outputs_json(monkeypatch, tmp_path, capsys):
    replay_queue_path = tmp_path / "report_adapter_replay_queue.jsonl"
    replay_queue_path.write_text(
        "\n".join(
            [
                '{"queue_id":"replay-1","platform":"hackerone","replay_status":"failed"}',
                '{"queue_id":"replay-2","platform":"hackerone","replay_status":"pending"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "shigoku",
            "--report-replay-list",
            "--report-replay-platform",
            "hackerone",
            "--report-replay-queue",
            str(replay_queue_path),
            "--report-replay-status",
            "pending",
            "--json",
        ],
    )

    main_module.main()

    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 1
    assert payload["records"][0]["queue_id"] == "replay-2"
