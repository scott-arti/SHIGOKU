from types import SimpleNamespace

from src.core.agents.swarm.injection.manager import InjectionManagerAgent


def test_manager_validate_findings_character() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    accepted = SimpleNamespace(target_url="http://example.com/a")
    rejected = SimpleNamespace(target_url="http://example.com/b")

    def _validate(finding):
        if finding is rejected:
            return SimpleNamespace(reject=True, reason="bad_evidence")
        return SimpleNamespace(reject=False, reason=None)

    agent._finding_validator = SimpleNamespace(validate=_validate)

    valid, rejected_items = agent.validate_findings([accepted, rejected])

    assert valid == [accepted]
    assert len(rejected_items) == 1
    assert rejected_items[0][0] is rejected
    assert rejected_items[0][1].reason == "bad_evidence"


def test_manager_filter_valid_findings_character() -> None:
    agent = InjectionManagerAgent(config={"model": "test-model"})
    accepted = SimpleNamespace(target_url="http://example.com/a")
    rejected = SimpleNamespace(target_url="http://example.com/b")

    def _validate(finding):
        if finding is rejected:
            return SimpleNamespace(reject=True, reason="bad_evidence")
        return SimpleNamespace(reject=False, reason=None)

    agent._finding_validator = SimpleNamespace(validate=_validate)
    agent.current_context = {"findings": [accepted, rejected]}

    valid = agent.filter_valid_findings()

    assert valid == [accepted]
    assert agent.current_context["findings"] == [accepted]
