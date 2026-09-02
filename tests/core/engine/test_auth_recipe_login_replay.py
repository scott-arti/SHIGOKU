"""
SGK-2026-0469: config-driven login recipe (settings.auth_recipe) tests.

Covers:
  1. recipe -> login_request seeding: env ``$VAR`` resolution, relative-url
     absolutization against the expired-url origin, Content-Type selection, and
     additive token_path/token_header/token_format extra keys; idempotency.
  2. AutoReauthSpecialist login replay with token_path JSON extraction and
     new_tokens formation (access_token + token_header + bearer) so the
     refreshed token is usable by later header building.
  3. auth_recipe.enabled=False (default) -> no-op; existing flow unchanged.
  4. secret masking: session-payload redaction path and log-redactor path leave
     no plaintext credential values at depth >= 2.
  5. settings default-off proof + SHIGOKU_AUTH_RECIPE__ENABLED=1 env override.

All tests are product-token-0 and environment-independent: credential values
are resolved from dummy env vars created via monkeypatch.
"""

import copy
import json

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from types import SimpleNamespace

from src.core.config.settings import Settings, AuthRecipeSettings
from src.core.engine.master_conductor import MasterConductor
from src.core.engine.task_queue import TaskContext
from src.core.infra.event_bus import Event, EventType
from src.core.agents.swarm.auth.reauth_contracts import generate_reauth_attempt_id


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _recipe_mc(recipe: AuthRecipeSettings) -> MasterConductor:
    """Minimal MasterConductor (__new__-built, lessons.md pattern) with a
    configured auth_recipe and a clean accumulated_context."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.settings = Settings(auth_recipe=recipe)
    mc.accumulated_context = TaskContext()
    return mc


def _new_mc_reauth() -> MasterConductor:
    """Minimal MasterConductor with reauth orchestrator support (mirrors
    tests/core/engine/test_master_conductor_reauth.py factory)."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.completed_tasks = []
    mc.task_queue = MagicMock()
    mc.task_queue.get_all = MagicMock(return_value=[])
    mc.pending_hitl = []
    mc.context = SimpleNamespace(
        discovered_assets=[],
        bypass_methods=[],
        metrics={"estimated_cost": 0.0, "total_duration": 0},
        target_info={"required_vuln_families": ["api"]},
    )
    mc._derived_task_count = 0
    mc._checkpoint_counter = 0
    mc._react_observation_metrics = {"attempted": 0, "executed": 0, "skipped": 0, "skip_reasons": {}}
    mc._react_observation_inflight = 0

    import threading
    mc._state_lock = threading.RLock()

    mc.accumulated_context = TaskContext()

    from src.core.engine.reauth_orchestrator import ReauthOrchestrator
    from src.core.agents.swarm.auth.reauth_contracts import AuthContext
    mc.reauth_orchestrator = ReauthOrchestrator(
        cooldown_window_seconds=60.0,
        max_inflight=3,
    )
    mc._auth_ctx = AuthContext()

    mc.event_bus = MagicMock()
    mc.event_bus.emit = AsyncMock()
    mc.event_bus.subscribe = MagicMock()

    mc.llm_client = MagicMock()
    mc.project_manager = MagicMock()
    mc.project_manager.config = {}

    from src.core.models.run_ledger import RunLedgerRecorder
    mc.run_ledger_recorder = MagicMock(spec=RunLedgerRecorder)

    mc._get_loop = MagicMock(return_value=MagicMock())
    mc.network_client = MagicMock()
    mc.network_client.request = AsyncMock()

    return mc


def _make_reauth_task(
    target: str = "https://target.example",
    auth_tokens: dict | None = None,
    login_request: dict | None = None,
):
    """Create a Task for reauth testing (mirrors test_reauth_specialist)."""
    from src.core.agents.swarm.base import Task
    return Task(
        id=f"reauth_test_{id(auth_tokens)}",
        name="auto_reauth",
        target=target,
        params={
            "auth_tokens": auth_tokens or {},
            "login_request": login_request,
            "reauth_attempt_id": generate_reauth_attempt_id(),
        },
        tags=["auth", "reauth"],
    )


def _json_recipe(**overrides) -> AuthRecipeSettings:
    """A JSON login recipe using env-referenced generic user/pass fields."""
    params = {
        "enabled": True,
        "login_url": "/login",
        "method": "POST",
        "content_type": "json",
        "body": {
            "user": "$SHIGOKU_TEST_LOGIN_USER",
            "pass": "$SHIGOKU_TEST_LOGIN_PASS",
        },
        "token_path": "auth.token",
        "token_header": "Authorization",
        "token_format": "Bearer {token}",
    }
    params.update(overrides)
    return AuthRecipeSettings(**params)


# ---------------------------------------------------------------------------
# 1. recipe -> login_request seeding
# ---------------------------------------------------------------------------

class TestRecipeSeedsLoginRequest:
    def test_recipe_seeds_login_request(self, monkeypatch) -> None:
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_USER", "demo-user")
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_PASS", "demo-pass")
        mc = _recipe_mc(_json_recipe())
        mc._maybe_seed_auth_recipe_login_request(
            "https://target.example/api/data?token=RESTORED_SECRET_42"
        )

        login_request = mc.accumulated_context.auth_tokens["login_request"]
        # url absolutized against the expired-url origin
        assert login_request["url"] == "https://target.example/login"
        assert login_request["method"] == "POST"
        # Content-Type set via setdefault for JSON body
        assert login_request["headers"]["Content-Type"] == "application/json"
        # env $VAR resolved
        body = json.loads(login_request["body"])
        assert body == {"user": "demo-user", "pass": "demo-pass"}
        # additive extra keys carried for the specialist
        assert login_request["token_path"] == "auth.token"
        assert login_request["token_header"] == "Authorization"
        assert login_request["token_format"] == "Bearer {token}"

    def test_recipe_seeding_is_idempotent(self, monkeypatch) -> None:
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_USER", "demo-user")
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_PASS", "demo-pass")
        mc = _recipe_mc(_json_recipe())
        mc._maybe_seed_auth_recipe_login_request("https://target.example/api/data")
        first = mc.accumulated_context.auth_tokens["login_request"]
        # second call must not overwrite / re-seed
        mc._maybe_seed_auth_recipe_login_request("https://target.example/api/data")
        assert mc.accumulated_context.auth_tokens["login_request"] is first

    def test_recipe_missing_env_drops_key_fail_safe(self, monkeypatch) -> None:
        monkeypatch.delenv("SHIGOKU_UNSET_RECIPE_VAR_XYZ", raising=False)
        mc = _recipe_mc(_json_recipe(body={"user": "$SHIGOKU_UNSET_RECIPE_VAR_XYZ", "pass": "literal-value"}))
        mc._maybe_seed_auth_recipe_login_request("https://target.example/api/data")
        login_request = mc.accumulated_context.auth_tokens["login_request"]
        body = json.loads(login_request["body"])
        assert "user" not in body  # env missing -> key dropped (fail-safe)
        assert body["pass"] == "literal-value"

    def test_recipe_form_content_type(self, monkeypatch) -> None:
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_USER", "demo-user")
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_PASS", "demo-pass")
        mc = _recipe_mc(_json_recipe(content_type="form"))
        mc._maybe_seed_auth_recipe_login_request("https://target.example/api/data")
        login_request = mc.accumulated_context.auth_tokens["login_request"]
        assert login_request["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
        # form body stays a dict (not a serialized string)
        assert login_request["body"] == {"user": "demo-user", "pass": "demo-pass"}

    def test_recipe_absolute_login_url_kept(self, monkeypatch) -> None:
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_USER", "demo-user")
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_PASS", "demo-pass")
        mc = _recipe_mc(_json_recipe(login_url="https://auth.example/login"))
        mc._maybe_seed_auth_recipe_login_request("https://target.example/api/data")
        login_request = mc.accumulated_context.auth_tokens["login_request"]
        assert login_request["url"] == "https://auth.example/login"

    def test_recipe_headers_are_not_clobbered(self, monkeypatch) -> None:
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_USER", "demo-user")
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_PASS", "demo-pass")
        mc = _recipe_mc(_json_recipe(headers={"Content-Type": "application/vnd.api+json", "X-Custom": "1"}))
        mc._maybe_seed_auth_recipe_login_request("https://target.example/api/data")
        login_request = mc.accumulated_context.auth_tokens["login_request"]
        assert login_request["headers"]["Content-Type"] == "application/vnd.api+json"
        assert login_request["headers"]["X-Custom"] == "1"

    def test_recipe_disabled_seeds_nothing(self, monkeypatch) -> None:
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_USER", "demo-user")
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_PASS", "demo-pass")
        mc = _recipe_mc(_json_recipe(enabled=False))
        mc._maybe_seed_auth_recipe_login_request("https://target.example/api/data")
        assert mc.accumulated_context.auth_tokens.get("login_request") is None


# ---------------------------------------------------------------------------
# 2. login replay real behavior with token_path extraction
# ---------------------------------------------------------------------------

class TestRecipeLoginReplay:
    @pytest.mark.asyncio
    async def test_login_replay_token_path_success(self, monkeypatch) -> None:
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_USER", "demo-user")
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_PASS", "demo-pass")
        mc = _recipe_mc(_json_recipe())
        mc._maybe_seed_auth_recipe_login_request("https://target.example/api/data")
        login_request = mc.accumulated_context.auth_tokens["login_request"]

        from src.core.agents.swarm.auth.reauth_specialist import AutoReauthSpecialist
        from src.core.infra.event_bus import Event as ReauthEvent

        specialist = AutoReauthSpecialist()
        specialist.network_client = AsyncMock()
        preflight_resp = MagicMock(status_code=200, text="", cookies={})
        login_resp = MagicMock(status_code=200, text='{"auth":{"token":"NEW"}}', cookies={})
        specialist.network_client.request = AsyncMock(side_effect=[preflight_resp, login_resp])

        emitted: list[ReauthEvent] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted.append(e))

        task = _make_reauth_task(
            target="https://target.example",
            auth_tokens={},
            login_request=login_request,
        )
        await specialist.execute(task)

        assert len(emitted) == 1
        event = emitted[0]
        assert event.type == EventType.REAUTH_SUCCESS
        assert event.payload["method"] == "login_replay"
        new_tokens = event.payload["new_tokens"]
        # token_path "auth.token" extraction won over the regex path
        assert new_tokens["access_token"] == "NEW"
        # STEP 2 token application: formatted header + raw bearer + evidence
        assert new_tokens["Authorization"] == "Bearer NEW"
        assert new_tokens["bearer"] == "NEW"

    @pytest.mark.asyncio
    async def test_login_replay_token_path_missing_falls_back_to_regex(self, monkeypatch) -> None:
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_USER", "demo-user")
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_PASS", "demo-pass")
        mc = _recipe_mc(_json_recipe(token_path="auth.token"))
        mc._maybe_seed_auth_recipe_login_request("https://target.example/api/data")
        login_request = mc.accumulated_context.auth_tokens["login_request"]

        from src.core.agents.swarm.auth.reauth_specialist import AutoReauthSpecialist

        specialist = AutoReauthSpecialist()
        specialist.network_client = AsyncMock()
        preflight_resp = MagicMock(status_code=200, text="", cookies={})
        # auth.token missing in body -> falls back to "access_token" regex
        login_resp = MagicMock(status_code=200, text='{"access_token":"REGEX_TOKEN"}', cookies={})
        specialist.network_client.request = AsyncMock(side_effect=[preflight_resp, login_resp])

        emitted: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted.append(e))

        await specialist.execute(
            _make_reauth_task(target="https://target.example", auth_tokens={}, login_request=login_request)
        )
        event = emitted[0]
        assert event.type == EventType.REAUTH_SUCCESS
        assert event.payload["new_tokens"]["access_token"] == "REGEX_TOKEN"

    @pytest.mark.asyncio
    async def test_recipe_login_replay_ignores_unknown_extra_keys(self) -> None:
        """JSON login (Content-Type json) skips form CSRF logic; extra
        token_path/token_header/token_format keys are opaque and never break
        the replay."""
        from src.core.agents.swarm.auth.reauth_specialist import AutoReauthSpecialist

        specialist = AutoReauthSpecialist()
        specialist.network_client = AsyncMock()
        preflight_resp = MagicMock(status_code=200, text="", cookies={})
        login_resp = MagicMock(status_code=200, text='{"token":"T"}', cookies={})
        specialist.network_client.request = AsyncMock(side_effect=[preflight_resp, login_resp])

        emitted: list[Event] = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted.append(e))

        await specialist.execute(
            _make_reauth_task(
                target="https://target.example",
                auth_tokens={},
                login_request={
                    "method": "POST",
                    "url": "https://target.example/login",
                    "headers": {"Content-Type": "application/json"},
                    "body": {"user": "u", "pass": "p"},
                    "token_path": "auth.token",  # extra, ignored unless present in resp
                    "token_header": "Authorization",
                    "token_format": "Bearer {token}",
                },
            )
        )
        event = emitted[0]
        assert event.type == EventType.REAUTH_SUCCESS
        assert event.payload["new_tokens"]["access_token"] == "T"

    @pytest.mark.asyncio
    async def test_refreshed_token_reaches_subsequent_request_headers(self, monkeypatch) -> None:
        """STEP 2 token application: REAUTH_SUCCESS new_tokens land in
        accumulated_context.auth_tokens, and the existing named-key consumer
        (context_designer.enrich_task) turns auth_tokens["bearer"] into an
        ``Authorization: Bearer <token>`` header on a subsequent task."""
        from src.core.agents.swarm.auth.reauth_specialist import AutoReauthSpecialist
        from src.core.agents.swarm.base import Task
        from src.core.engine.context_designer import ContextDesigner

        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_USER", "demo-user")
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_PASS", "demo-pass")
        mc = _recipe_mc(_json_recipe())
        mc._maybe_seed_auth_recipe_login_request("https://target.example/api/data")
        login_request = mc.accumulated_context.auth_tokens["login_request"]

        specialist = AutoReauthSpecialist()
        specialist.network_client = AsyncMock()
        preflight_resp = MagicMock(status_code=200, text="", cookies={})
        login_resp = MagicMock(status_code=200, text='{"auth":{"token":"NEW"}}', cookies={})
        specialist.network_client.request = AsyncMock(side_effect=[preflight_resp, login_resp])
        emitted: list = []
        specialist.event_bus.emit = AsyncMock(side_effect=lambda e: emitted.append(e))
        await specialist.execute(
            _make_reauth_task(target="https://target.example", auth_tokens={}, login_request=login_request)
        )

        new_tokens = emitted[0].payload["new_tokens"]
        # replicate _handle_reauth_success: every new_tokens key copies into auth_tokens
        mc.accumulated_context.auth_tokens.update(new_tokens)
        assert mc.accumulated_context.auth_tokens["bearer"] == "NEW"
        assert mc.accumulated_context.auth_tokens["Authorization"] == "Bearer NEW"

        enriched = ContextDesigner().enrich_task(
            Task(id="t", name="scan", target="https://target.example", params={}),
            SimpleNamespace(target_info={"required_vuln_families": []}),
            mc.accumulated_context,
        )
        assert enriched.params["headers"]["Authorization"] == "Bearer NEW"


# ---------------------------------------------------------------------------
# 3. flag OFF -> no-op / existing flow unchanged
# ---------------------------------------------------------------------------

class TestRecipeFlagOffNoOp:
    def test_disabled_recipe_never_injects_login_request(self) -> None:
        mc = _recipe_mc(AuthRecipeSettings())  # enabled=False default
        # simulate an existing login_request from elsewhere is NOT overwritten
        mc.accumulated_context.auth_tokens["login_request"] = {"existing": True}
        mc._maybe_seed_auth_recipe_login_request("https://target.example/api/data")
        assert mc.accumulated_context.auth_tokens["login_request"] == {"existing": True}

    @pytest.mark.asyncio
    async def test_session_expired_flow_unchanged_when_recipe_off(self) -> None:
        mc = _new_mc_reauth()
        mc.settings = Settings(auth_recipe=AuthRecipeSettings())

        with patch("src.core.engine.swarm_dispatcher.get_swarm_dispatcher") as mock_disp:
            mock_dispatcher = AsyncMock()
            mock_disp.return_value = mock_dispatcher

            event = Event(
                type=EventType.SESSION_EXPIRED,
                payload={
                    "url": "https://target.example/api/data",
                    "method": "GET",
                    "request_headers": {},
                    "origin_task_id": "task_001",
                    "reauth_attempt_id": generate_reauth_attempt_id(),
                    "auth_context_version": 1,
                },
                source="AsyncNetworkClient",
            )
            await mc._handle_session_expired(event)

        assert mock_dispatcher.dispatch.called
        params = mock_dispatcher.dispatch.call_args.kwargs["params"]
        assert params["login_request"] is None
        assert "login_request" not in mc.accumulated_context.auth_tokens


# ---------------------------------------------------------------------------
# 4. secret masking (session-payload + log redactor), depth >= 2
# ---------------------------------------------------------------------------

class TestRecipeSecretMasking:
    def test_session_redaction_hides_recipe_credentials(self, monkeypatch) -> None:
        from src.core.engine.master_conductor_session_service import (
            redact_reauth_params_for_persistence,
        )

        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_USER", "dummy-user")
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_PASS", "dummy-secret-value")
        mc = _recipe_mc(_json_recipe())
        mc._maybe_seed_auth_recipe_login_request("https://target.example/api/data")
        login_request = mc.accumulated_context.auth_tokens["login_request"]

        params = {
            "reauth_attempt_id": "reauth_x",
            "auth_tokens": {
                "login_request": dict(login_request),
                "last_auth_error": "401_unauthorized",
            },
            "login_request": dict(login_request),
        }

        redacted = redact_reauth_params_for_persistence(copy.deepcopy(params), True)
        text = json.dumps(redacted)
        # credential values must not survive at depth >= 2
        assert "dummy-secret-value" not in text
        assert "dummy-user" not in text

        # flag OFF -> output byte-identical (same object, same serialization)
        unchanged = redact_reauth_params_for_persistence(copy.deepcopy(params), False)
        assert json.dumps(unchanged) == json.dumps(params)

    def test_session_serialization_surface_uses_redaction(self, monkeypatch) -> None:
        """The lowest-write persistence surface (build_async_session_payload)
        emits no plaintext credentials for a reauth task when enabled."""
        from src.core.engine.master_conductor_session_service import build_async_session_payload
        from src.core.domain.model.task import Task

        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_USER", "dummy-user")
        monkeypatch.setenv("SHIGOKU_TEST_LOGIN_PASS", "dummy-secret-value")
        mc = _recipe_mc(_json_recipe())
        mc._maybe_seed_auth_recipe_login_request("https://target.example/api/data")
        login_request = mc.accumulated_context.auth_tokens["login_request"]

        task = Task(
            id="reauth_1",
            name="autonomous_reauth",
            target="https://target.example",
            tags=["auth", "reauth"],
            params={
                "auth_tokens": {"login_request": dict(login_request)},
                "login_request": dict(login_request),
            },
        )
        payload = build_async_session_payload(
            task_queue=[task],
            completed_tasks=[],
            context=SimpleNamespace(
                _total_attempts=0,
                _successful_attempts=0,
                bypass_methods=[],
                discovered_assets=[],
                target_info={},
            ),
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=0.0,
            default_start_time=0.0,
            auth_recipe_enabled=True,
        )
        text = json.dumps(payload)
        assert "dummy-secret-value" not in text
        assert "dummy-user" not in text
        # in-memory task keeps live (unredacted) params for the actual replay
        assert "dummy-secret-value" in json.dumps(task.params)

    def test_log_redactor_extra_keys_mask_recipe_body(self, monkeypatch) -> None:
        from src.core.logging import log_redactor

        payload = {
            "reauth": {
                "login_request": {
                    "headers": {"Content-Type": "application/json"},
                    "body": {"user": "dummy-user", "pass": "dummy-secret-value"},
                }
            }
        }
        # default (flag OFF): extra keys empty -> behavior identical to before
        monkeypatch.setattr(log_redactor, "_EXTRA_SECRET_KEYS", set())
        default_redacted = log_redactor.redact_log_value(copy.deepcopy(payload))
        assert "dummy-secret-value" in json.dumps(default_redacted)

        # recipe enabled: register the extra keys -> values masked at depth >= 2
        monkeypatch.setattr(
            log_redactor,
            "_EXTRA_SECRET_KEYS",
            set(log_redactor._RECIPE_EXTRA_SECRET_KEYS),
        )
        redacted = log_redactor.redact_log_value(copy.deepcopy(payload))
        text = json.dumps(redacted)
        assert "dummy-secret-value" not in text
        assert "dummy-user" not in text
        assert text.count("[REDACTED]") >= 2

    def test_register_auth_recipe_secret_keys_is_idempotent(self, monkeypatch) -> None:
        from src.core.logging import log_redactor

        monkeypatch.setattr(log_redactor, "_EXTRA_SECRET_KEYS", set())
        log_redactor.register_auth_recipe_secret_keys()
        log_redactor.register_auth_recipe_secret_keys()
        assert {"user", "username", "email", "login", "pass"} <= log_redactor._EXTRA_SECRET_KEYS


# ---------------------------------------------------------------------------
# 5. settings default + env override
# ---------------------------------------------------------------------------

class TestAuthRecipeSettings:
    def test_auth_recipe_default_off(self, monkeypatch) -> None:
        monkeypatch.delenv("SHIGOKU_AUTH_RECIPE__ENABLED", raising=False)
        settings = Settings(auth_recipe=AuthRecipeSettings())
        assert settings.auth_recipe.enabled is False
        assert settings.auth_recipe.content_type == "json"
        assert settings.auth_recipe.method == "POST"
        assert settings.auth_recipe.token_header == "Authorization"
        assert settings.auth_recipe.token_format == "Bearer {token}"

    def test_auth_recipe_env_override(self, monkeypatch) -> None:
        monkeypatch.setenv("SHIGOKU_AUTH_RECIPE__ENABLED", "1")
        monkeypatch.setenv("SHIGOKU_AUTH_RECIPE__LOGIN_URL", "/login")
        monkeypatch.setenv("SHIGOKU_AUTH_RECIPE__TOKEN_PATH", "auth.token")
        monkeypatch.setenv("SHIGOKU_AUTH_RECIPE__CONTENT_TYPE", "FORM")
        # no auth_recipe kwarg: env (SHIGOKU_AUTH_RECIPE__*) must flow into the
        # nested settings (pydantic init kwargs would outrank env vars)
        settings = Settings()
        assert settings.auth_recipe.enabled is True
        assert settings.auth_recipe.login_url == "/login"
        assert settings.auth_recipe.token_path == "auth.token"
        assert settings.auth_recipe.content_type == "form"

    def test_auth_recipe_content_type_validator(self) -> None:
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            AuthRecipeSettings(content_type="xml")
        assert AuthRecipeSettings(content_type="FORM").content_type == "form"
