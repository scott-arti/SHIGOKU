from unittest.mock import MagicMock, patch

from src.core.domain.model.task import Task
from src.core.swarm.worker.recon_workers import DiscoveryWorker, LiveCheckWorker


def _task(target: str = "http://localhost:3000/") -> Task:
    return Task(
        id="task_caido_proxy",
        name="caido_proxy_recon",
        target=target,
        params={"target": target},
    )


def test_discovery_worker_passes_configured_proxy_to_katana():
    worker = DiscoveryWorker(MagicMock())
    tool = MagicMock()

    with (
        patch(
            "src.core.swarm.worker.recon_workers.settings.get_proxy_url",
            return_value="http://127.0.0.1:8081",
        ),
        patch("src.tools.custom.katana.KatanaTool", return_value=tool),
    ):
        worker.execute(_task())

    tool.run.assert_called_once_with(
        target="http://localhost:3000/",
        proxy="http://127.0.0.1:8081",
    )


def test_live_check_worker_passes_configured_proxy_to_httpx():
    worker = LiveCheckWorker(MagicMock())
    tool = MagicMock()

    with (
        patch(
            "src.core.swarm.worker.recon_workers.settings.get_proxy_url",
            return_value="http://127.0.0.1:8081",
        ),
        patch("src.tools.custom.httpx.HttpxTool", return_value=tool),
    ):
        worker.execute(_task("https://example.com"))

    tool.run.assert_called_once_with(
        target="https://example.com",
        proxy="http://127.0.0.1:8081",
    )
