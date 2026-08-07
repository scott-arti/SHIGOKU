from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from src.core.engine.master_conductor import MasterConductor


def _minimal_conductor() -> MasterConductor:
    conductor = MasterConductor.__new__(MasterConductor)
    conductor.mode = "vulntest"
    conductor.context = SimpleNamespace(
        goal="Attack",
        profile="bbpt",
        target_info={
            "target": "http://localhost:3000/",
            "cookies": {},
            "bearer_token": "",
            "auth_headers": {},
        },
    )
    return conductor


def test_internal_preflight_uses_configured_caido_connection() -> None:
    conductor = _minimal_conductor()
    configured = SimpleNamespace(
        caido=SimpleNamespace(
            url="http://127.0.0.1:8081",
            token="test-caido-token",
        )
    )

    with patch("src.core.engine.master_conductor.settings", configured):
        context = conductor._build_preflight_context()

    assert context.caido_url == "http://127.0.0.1:8081"
    assert context.caido_token == "test-caido-token"
    assert context.target == "http://localhost:3000/"
    assert context.mode == "vulntest"


def test_resume_preflight_keeps_caido_config_with_target_override() -> None:
    conductor = _minimal_conductor()
    configured = SimpleNamespace(
        caido=SimpleNamespace(
            url="http://127.0.0.1:8081",
            token="test-caido-token",
        )
    )

    with patch("src.core.engine.master_conductor.settings", configured):
        context = conductor._build_preflight_context(
            target="http://localhost:3001/",
            resume_session_id="session-123",
        )

    assert context.caido_url == "http://127.0.0.1:8081"
    assert context.caido_token == "test-caido-token"
    assert context.target == "http://localhost:3001/"
    assert context.resume_session_id == "session-123"


def test_execute_with_replan_passes_caido_config_to_entry_gate() -> None:
    conductor = _minimal_conductor()
    conductor._run_async_safe = MagicMock(
        return_value=SimpleNamespace(failed=True, failures=[])
    )
    configured = SimpleNamespace(
        caido=SimpleNamespace(
            url="http://127.0.0.1:8081",
            token="test-caido-token",
        )
    )

    with (
        patch("src.core.engine.master_conductor.settings", configured),
        patch("src.core.engine.master_conductor.EntryGateFacade") as facade,
    ):
        result = conductor.execute_with_replan(max_tasks=1)

    gate_context = facade.return_value.run_once.call_args.args[0]
    assert result["status"] == "gate_failed"
    assert gate_context.caido_url == "http://127.0.0.1:8081"
    assert gate_context.caido_token == "test-caido-token"
