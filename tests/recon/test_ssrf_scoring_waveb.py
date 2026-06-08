from pathlib import Path
from types import SimpleNamespace

from src.recon.pipeline import ReconPipeline


class _DummyProjectManager:
    def __init__(self, project_dir: Path):
        self.project_dir = project_dir


class _DummyMC:
    def __init__(self):
        self.context = SimpleNamespace(target_info={})


def test_score_ssrf_candidate_graphql_variables_and_url_params(tmp_path: Path):
    pipeline = ReconPipeline(
        config={},
        project_manager=_DummyProjectManager(project_dir=tmp_path / "project"),
        target="https://app.example.com",
        master_conductor=_DummyMC(),
    )
    item = {
        "body": '{"query":"mutation($input:Input!){import(input:$input){ok}}","variables":{"input":{"callback":"http://a.oast.me"}}}',
        "headers": {"X-Forwarded-Host": "evil.example"},
    }
    score, breakdown = pipeline._score_ssrf_candidate(
        "https://app.example.com/api/proxy?url=http://example.org",
        item,
    )

    assert score >= 40
    assert breakdown["query_url_param"] > 0
    assert breakdown["graphql_variables"] > 0

