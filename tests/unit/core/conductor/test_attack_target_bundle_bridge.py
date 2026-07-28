from __future__ import annotations

import io
from types import SimpleNamespace

from src.core.conductor import interactive_bridge
from src.core.engine.phase_gate import Phase
from src.core.models.ops_artifacts import AttackTargetBundle, AttackTargetSpec, ExportManifest


class _FakeQueue:
    def __init__(self) -> None:
        self.batches: list[tuple[list[object], str]] = []

    def add_batch(self, tasks: list[object], source: str) -> None:
        self.batches.append((tasks, source))


class _FakePhaseGate:
    def __init__(self) -> None:
        self.unlocked: list[Phase] = []

    def unlock(self, phase: Phase) -> None:
        self.unlocked.append(phase)


class _FakeTask:
    def __init__(self) -> None:
        self.params: dict[str, object] = {}


class _FakeMC:
    def __init__(self) -> None:
        self.phase_gate = _FakePhaseGate()
        self.task_queue = _FakeQueue()
        self.context = SimpleNamespace(target_info={})

    def _create_attack_tasks_from_recon(self, recon_results):
        self.last_recon_results = recon_results
        return [_FakeTask()]


def test_queue_attack_target_bundle_unlocks_attack_and_preserves_manifest_metadata() -> None:
    mc = _FakeMC()
    bundle = AttackTargetBundle(
        manifest=ExportManifest(
            source_session="/tmp/session.json",
            allowed_hosts=["api.example.com"],
            item_count=1,
        ),
        targets=[
            AttackTargetSpec(
                url="https://api.example.com/v1/users?id=1",
                category="api_endpoint",
                tags=["api_endpoint", "has_params"],
            )
        ],
    )

    queued = interactive_bridge._queue_attack_target_bundle(
        mc,
        bundle,
        attack_targets_file="/tmp/attack_targets.json",
        wordlist_path="/tmp/custom-wordlist.txt",
    )

    assert queued == 1
    assert mc.phase_gate.unlocked == [Phase.ATTACK]
    assert mc.task_queue.batches[0][1] == "interactive_bridge_attack_targets"
    assert mc.context.target_info["attack_targets_manifest_hash"] == bundle.manifest.manifest_hash
    assert mc.context.target_info["attack_targets_correlation_id"] == bundle.manifest.correlation_id
    assert mc.task_queue.batches[0][0][0].params["wordlist"] == "/tmp/custom-wordlist.txt"
    signal_bundle = mc.last_recon_results["_signal_bundle"]
    assert signal_bundle["_run_id"] == bundle.manifest.correlation_id
    assert signal_bundle["_endpoint_signals"][0]["url"] == "https://api.example.com/v1/users?id=1"


def test_non_tty_attack_targets_require_preapproval_env(monkeypatch) -> None:
    monkeypatch.setattr(interactive_bridge.sys, "stdin", io.StringIO(""), raising=False)
    monkeypatch.delenv("SHIGOKU_ATTACK_TARGETS_APPROVED", raising=False)

    assert interactive_bridge._non_tty_attack_targets_preapproved() is False


def test_non_tty_attack_targets_allow_preapproval_env(monkeypatch) -> None:
    monkeypatch.setattr(interactive_bridge.sys, "stdin", io.StringIO(""), raising=False)
    monkeypatch.setenv("SHIGOKU_ATTACK_TARGETS_APPROVED", "1")

    assert interactive_bridge._non_tty_attack_targets_preapproved() is True


def test_validate_attack_target_bundle_scope_rejects_scope_violation(monkeypatch) -> None:
    bundle = AttackTargetBundle(
        manifest=ExportManifest(
            source_session="/tmp/session.json",
            allowed_hosts=["api.example.com"],
            item_count=1,
        ),
        targets=[
            AttackTargetSpec(
                url="https://api.example.com/v1/private",
                category="api_endpoint",
                tags=["api_endpoint"],
            )
        ],
    )

    class _FakeScopeParser:
        def validate_target(self, _target: str) -> tuple[bool, str]:
            return False, "out_of_scope"

    monkeypatch.setattr(
        "src.core.security.scope_parser.get_scope_parser",
        lambda: _FakeScopeParser(),
    )

    scope_ok, violations = interactive_bridge._validate_attack_target_bundle_scope(
        bundle,
        scope_file="/tmp/scope.txt",
    )

    assert scope_ok is False
    assert violations == ["https://api.example.com/v1/private"]
