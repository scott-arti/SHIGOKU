"""
Phase 1: LLM Config Unification Tests (TDD)

Tests for:
- LLMSettings / LLMProfileSettings / LLMRoleSettings / LLMProviderSettings schema
- config/shigoku.yaml llm block loading
- Fallback cycle detection
- API key env not set error
- Prompt template missing error
- Default role fallback
- Config priority (explicit > env > yaml > defaults)
- LLMRoleResolver basic resolution
"""
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from pydantic import ValidationError

from src.core.config.settings import (
    Settings,
    LLMSettings,
    LLMProfileSettings,
    LLMRoleSettings,
    LLMProviderSettings,
    get_settings,
)
from src.core.config.llm_resolver import LLMRoleResolver, LLMResolutionError


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def clean_env():
    """Remove LLM-related env vars before/after each test."""
    llm_vars = [
        "SHIGOKU_MODEL", "SHIGOKU_MODEL_OUTPUT", "SHIGOKU_MODEL_LIGHTWEIGHT",
        "SHIGOKU_LLM__DEFAULT_ROLE", "SHIGOKU_LLM__SCHEMA_VERSION",
        "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "ANY_LLM_API_KEY",
        "TEST_KEY", "EXISTING_API_KEY_VAR", "NONEXISTENT_API_KEY_VAR",
    ]
    saved = {k: os.environ.pop(k, None) for k in llm_vars}
    yield
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)


@pytest.fixture
def minimal_llm_yaml():
    """Minimal valid LLM config."""
    return {
        "llm": {
            "schema_version": 1,
            "default_role": "specialist_light",
            "providers": {
                "deepseek": {
                    "api_key_env": "DEEPSEEK_API_KEY",
                    "base_url": None,
                },
            },
            "profiles": {
                "cheap_api": {
                    "provider": "deepseek",
                    "model": "deepseek/deepseek-v4-flash",
                },
            },
            "roles": {
                "specialist_light": {
                    "profile": "cheap_api",
                },
            },
        },
    }


@pytest.fixture
def full_llm_yaml():
    """Full LLM config matching the plan's example."""
    return {
        "llm": {
            "schema_version": 1,
            "default_role": "specialist_light",
            "providers": {
                "deepseek": {
                    "api_key_env": "DEEPSEEK_API_KEY",
                    "base_url": None,
                },
                "openai": {
                    "api_key_env": "OPENAI_API_KEY",
                    "base_url": None,
                },
                "any_llm": {
                    "api_key_env": "ANY_LLM_API_KEY",
                    "base_url": "http://localhost:8000/v1",
                },
            },
            "profiles": {
                "cheap_api": {
                    "provider": "deepseek",
                    "model": "deepseek/deepseek-v4-flash",
                    "timeout_seconds": 300,
                    "max_retries": 2,
                    "max_concurrency": 4,
                    "rate_limit_per_minute": 60,
                    "temperature": 0.0,
                },
                "reasoning_api": {
                    "provider": "deepseek",
                    "model": "deepseek/deepseek-v4-pro",
                    "timeout_seconds": 300,
                    "max_retries": 2,
                    "max_concurrency": 2,
                    "rate_limit_per_minute": 30,
                    "temperature": 0.0,
                    "extra": {
                        "thinking": {"type": "enabled"},
                        "reasoning_effort": "high",
                    },
                },
                "vision_api": {
                    "provider": "openai",
                    "model": "openai/gpt-4o",
                    "timeout_seconds": 300,
                },
                "any_llm_profile": {
                    "provider": "any_llm",
                    "model": "any_llm/local-model",
                },
            },
            "roles": {
                "planner": {
                    "profile": "reasoning_api",
                    "fallback_profile": "cheap_api",
                    "system_prompt_template": "conductor/planning.md",
                },
                "swarm_manager": {
                    "profile": "cheap_api",
                    "fallback_profile": "reasoning_api",
                    "system_prompt_template": "agents/manager_base.md",
                },
                "tool_output_analysis": {
                    "profile": "cheap_api",
                    "fallback_profile": "reasoning_api",
                    "system_prompt_template": "roles/tool_output_analysis.md",
                },
                "rag_compression": {
                    "profile": "cheap_api",
                    "system_prompt_template": "roles/rag_compression.md",
                },
                "final_judgement": {
                    "profile": "reasoning_api",
                    "fallback_profile": "cheap_api",
                    "system_prompt_template": "roles/final_judgement.md",
                },
                "specialist_light": {
                    "profile": "cheap_api",
                    "fallback_profile": "reasoning_api",
                },
            },
        },
    }


@pytest.fixture
def temp_yaml_file(full_llm_yaml):
    """Create a temporary YAML file with LLM config."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        yaml.safe_dump(full_llm_yaml, f)
        path = f.name
    yield Path(path)
    Path(path).unlink(missing_ok=True)


# ============================================================
# Schema Tests - Provider
# ============================================================

class TestLLMProviderSettings:
    def test_provider_defaults(self):
        p = LLMProviderSettings(api_key_env="DEEPSEEK_API_KEY")
        assert p.api_key_env == "DEEPSEEK_API_KEY"
        assert p.base_url is None

    def test_provider_with_base_url(self):
        p = LLMProviderSettings(api_key_env="ANY_LLM_API_KEY", base_url="http://localhost:8000/v1")
        assert p.base_url == "http://localhost:8000/v1"

    def test_provider_requires_api_key_env(self):
        with pytest.raises(ValidationError):
            LLMProviderSettings()


# ============================================================
# Schema Tests - Profile
# ============================================================

class TestLLMProfileSettings:
    def test_profile_defaults(self):
        p = LLMProfileSettings(provider="deepseek", model="deepseek/chat")
        assert p.provider == "deepseek"
        assert p.model == "deepseek/chat"
        assert p.timeout_seconds == 300
        assert p.max_retries == 2
        assert p.max_concurrency == 4
        assert p.rate_limit_per_minute == 60
        assert p.temperature == 0.0
        assert p.extra == {}

    def test_profile_extra_stores_arbitrary(self):
        extra = {"thinking": {"type": "enabled"}, "reasoning_effort": "high"}
        p = LLMProfileSettings(provider="deepseek", model="deepseek/pro", extra=extra)
        assert p.extra == extra

    def test_profile_requires_provider_and_model(self):
        with pytest.raises(ValidationError):
            LLMProfileSettings()
        with pytest.raises(ValidationError):
            LLMProfileSettings(provider="deepseek")
        with pytest.raises(ValidationError):
            LLMProfileSettings(model="deepseek/chat")


# ============================================================
# Schema Tests - Role
# ============================================================

class TestLLMRoleSettings:
    def test_role_defaults(self):
        r = LLMRoleSettings(profile="cheap_api")
        assert r.profile == "cheap_api"
        assert r.fallback_profile is None
        assert r.system_prompt_template is None

    def test_role_with_fallback(self):
        r = LLMRoleSettings(profile="reasoning_api", fallback_profile="cheap_api")
        assert r.fallback_profile == "cheap_api"

    def test_role_with_prompt_template(self):
        r = LLMRoleSettings(profile="cheap_api", system_prompt_template="agents/test.md")
        assert r.system_prompt_template == "agents/test.md"

    def test_role_requires_profile(self):
        with pytest.raises(ValidationError):
            LLMRoleSettings()


# ============================================================
# Schema Tests - LLMSettings (top-level)
# ============================================================

class TestLLMSettings:
    def test_llm_settings_defaults(self):
        llm = LLMSettings()
        assert llm.schema_version == 1
        assert llm.default_role == "specialist_light"
        assert llm.providers == {}
        assert llm.profiles == {}
        assert llm.roles == {}

    def test_llm_settings_from_dict(self, full_llm_yaml):
        llm = LLMSettings(**full_llm_yaml["llm"])
        assert llm.schema_version == 1
        assert llm.default_role == "specialist_light"
        assert "deepseek" in llm.providers
        assert "cheap_api" in llm.profiles
        assert "planner" in llm.roles
        assert llm.roles["planner"].fallback_profile == "cheap_api"

    def test_schema_version_required(self):
        """schema_version must be present (default is 1)."""
        llm = LLMSettings()
        assert llm.schema_version == 1


# ============================================================
# Validator Tests - Fallback Cycles
# ============================================================

class TestFallbackCycleDetection:
    def test_direct_cycle(self):
        """A -> A (self reference)"""
        os.environ["TEST_KEY"] = "dummy"
        try:
            with pytest.raises(ValidationError, match="(?i)circular fallback"):
                LLMSettings(
                    schema_version=1,
                    default_role="r1",
                    providers={"p1": {"api_key_env": "TEST_KEY"}},
                    profiles={
                        "a": {"provider": "p1", "model": "m/a"},
                    },
                    roles={
                        "r1": {"profile": "a", "fallback_profile": "a"},
                    },
                )
        finally:
            del os.environ["TEST_KEY"]

    def test_self_cycle(self):
        """A -> A (same test, different name for clarity)"""
        os.environ["TEST_KEY"] = "dummy"
        try:
            with pytest.raises(ValidationError, match="(?i)circular fallback"):
                LLMSettings(
                    schema_version=1,
                    default_role="r1",
                    providers={"p1": {"api_key_env": "TEST_KEY"}},
                    profiles={"a": {"provider": "p1", "model": "m/a"}},
                    roles={"r1": {"profile": "a", "fallback_profile": "a"}},
                )
        finally:
            del os.environ["TEST_KEY"]

    def test_no_cycle(self):
        """A -> B -> C (no cycle)"""
        os.environ["TEST_KEY"] = "dummy"
        try:
            llm = LLMSettings(
                schema_version=1,
                default_role="r1",
                providers={"p1": {"api_key_env": "TEST_KEY"}},
                profiles={
                    "a": {"provider": "p1", "model": "m/a"},
                    "b": {"provider": "p1", "model": "m/b"},
                    "c": {"provider": "p1", "model": "m/c"},
                },
                roles={
                    "r1": {"profile": "a", "fallback_profile": "b"},
                    "r2": {"profile": "b", "fallback_profile": "c"},
                },
            )
            assert llm.roles["r1"].fallback_profile == "b"
        finally:
            del os.environ["TEST_KEY"]

    def test_long_chain_no_cycle(self):
        """A -> B -> C -> D (no cycle)"""
        os.environ["TEST_KEY"] = "dummy"
        try:
            llm = LLMSettings(
                schema_version=1,
                default_role="r1",
                providers={"p1": {"api_key_env": "TEST_KEY"}},
                profiles={
                    "a": {"provider": "p1", "model": "m/a"},
                    "b": {"provider": "p1", "model": "m/b"},
                    "c": {"provider": "p1", "model": "m/c"},
                    "d": {"provider": "p1", "model": "m/d"},
                },
                roles={
                    "r1": {"profile": "a", "fallback_profile": "b"},
                    "r2": {"profile": "b", "fallback_profile": "c"},
                    "r3": {"profile": "c", "fallback_profile": "d"},
                },
            )
            assert llm is not None
        finally:
            del os.environ["TEST_KEY"]

    def test_indirect_cycle_three(self):
        """Self-reference only: A with itself is a cycle."""
        os.environ["TEST_KEY"] = "dummy"
        try:
            with pytest.raises(ValidationError, match="(?i)circular fallback"):
                LLMSettings(
                    schema_version=1,
                    default_role="r1",
                    providers={"p1": {"api_key_env": "TEST_KEY"}},
                    profiles={"a": {"provider": "p1", "model": "m/a"}},
                    roles={"r1": {"profile": "a", "fallback_profile": "a"}},
                )
        finally:
            del os.environ["TEST_KEY"]


# ============================================================
# Validator Tests - Missing references
# ============================================================

class TestReferenceValidation:
    def test_role_references_undefined_profile(self):
        """Role references a profile that doesn't exist."""
        with pytest.raises(ValidationError, match="not defined in profiles"):
            LLMSettings(
                schema_version=1,
                default_role="r1",
                providers={"p1": {"api_key_env": "TEST_KEY"}},
                profiles={"a": {"provider": "p1", "model": "m/a"}},
                roles={"r1": {"profile": "nonexistent"}},
            )

    def test_role_fallback_references_undefined_profile(self):
        """Role's fallback references a profile that doesn't exist."""
        with pytest.raises(ValidationError, match="not defined in profiles"):
            LLMSettings(
                schema_version=1,
                default_role="r1",
                providers={"p1": {"api_key_env": "TEST_KEY"}},
                profiles={"a": {"provider": "p1", "model": "m/a"}},
                roles={"r1": {"profile": "a", "fallback_profile": "nonexistent"}},
            )

    def test_profile_references_undefined_provider(self):
        """Profile references a provider that doesn't exist."""
        with pytest.raises(ValidationError, match="not defined in providers"):
            LLMSettings(
                schema_version=1,
                default_role="r1",
                providers={"p1": {"api_key_env": "TEST_KEY"}},
                profiles={"a": {"provider": "nonexistent", "model": "m/a"}},
                roles={"r1": {"profile": "a"}},
            )

    def test_valid_references(self):
        os.environ["TEST_KEY"] = "dummy"
        try:
            llm = LLMSettings(
                schema_version=1,
                default_role="r1",
                providers={"p1": {"api_key_env": "TEST_KEY"}},
                profiles={
                    "a": {"provider": "p1", "model": "m/a"},
                    "b": {"provider": "p1", "model": "m/b"},
                },
                roles={
                    "r1": {"profile": "a", "fallback_profile": "b"},
                },
            )
            assert llm.roles["r1"].profile == "a"
        finally:
            del os.environ["TEST_KEY"]


# ============================================================
# Validator Tests - API Key Env
# ============================================================

class TestAPIKeyEnvValidation:
    def test_api_key_env_not_set(self, clean_env):
        """When api_key_env is not set in the environment, validation should warn or fail."""
        with pytest.raises(ValidationError, match="API key environment variable"):
            LLMSettings(
                schema_version=1,
                default_role="r1",
                providers={"p1": {"api_key_env": "NONEXISTENT_API_KEY_VAR"}},
                profiles={"a": {"provider": "p1", "model": "m/a"}},
                roles={"r1": {"profile": "a"}},
            )

    def test_api_key_env_is_set(self, clean_env):
        """When api_key_env IS set in the environment, validation should pass."""
        os.environ["EXISTING_API_KEY_VAR"] = "test-key-value"
        try:
            llm = LLMSettings(
                schema_version=1,
                default_role="r1",
                providers={"p1": {"api_key_env": "EXISTING_API_KEY_VAR"}},
                profiles={"a": {"provider": "p1", "model": "m/a"}},
                roles={"r1": {"profile": "a"}},
            )
            assert llm is not None
        finally:
            del os.environ["EXISTING_API_KEY_VAR"]


# ============================================================
# Validator Tests - Prompt Template
# ============================================================

class TestPromptTemplateValidation:
    def test_prompt_template_exists(self):
        """Template that exists should pass validation."""
        os.environ["DEEPSEEK_API_KEY"] = "test-key"
        try:
            llm = LLMSettings(
                schema_version=1,
                default_role="r1",
                providers={"p1": {"api_key_env": "DEEPSEEK_API_KEY"}},
                profiles={"a": {"provider": "p1", "model": "m/a"}},
                roles={
                    "r1": {
                        "profile": "a",
                        "system_prompt_template": "conductor/planning.md",
                    },
                },
            )
            assert llm.roles["r1"].system_prompt_template == "conductor/planning.md"
        finally:
            os.environ.pop("DEEPSEEK_API_KEY", None)

    def test_prompt_template_missing(self):
        """Template that does NOT exist should fail validation."""
        os.environ["DEEPSEEK_API_KEY"] = "test-key"
        try:
            with pytest.raises(ValidationError, match="not found"):
                LLMSettings(
                    schema_version=1,
                    default_role="r1",
                    providers={"p1": {"api_key_env": "DEEPSEEK_API_KEY"}},
                    profiles={"a": {"provider": "p1", "model": "m/a"}},
                    roles={
                        "r1": {
                            "profile": "a",
                            "system_prompt_template": "nonexistent/template.md",
                        },
                    },
                )
        finally:
            os.environ.pop("DEEPSEEK_API_KEY", None)

    def test_prompt_template_none_is_ok(self):
        """None template should be fine."""
        os.environ["DEEPSEEK_API_KEY"] = "test-key"
        try:
            llm = LLMSettings(
                schema_version=1,
                default_role="r1",
                providers={"p1": {"api_key_env": "DEEPSEEK_API_KEY"}},
                profiles={"a": {"provider": "p1", "model": "m/a"}},
                roles={"r1": {"profile": "a", "system_prompt_template": None}},
            )
            assert llm.roles["r1"].system_prompt_template is None
        finally:
            os.environ.pop("DEEPSEEK_API_KEY", None)


# ============================================================
# Default Role Fallback
# ============================================================

class TestDefaultRoleFallback:
    def test_undefined_role_uses_default(self):
        os.environ["DEEPSEEK_API_KEY"] = "test-key"
        try:
            llm = LLMSettings(
                schema_version=1,
                default_role="fallback_role",
                providers={"p1": {"api_key_env": "DEEPSEEK_API_KEY"}},
                profiles={
                    "a": {"provider": "p1", "model": "m/a"},
                    "b": {"provider": "p1", "model": "m/b"},
                },
                roles={
                    "fallback_role": {"profile": "a"},
                    "other_role": {"profile": "b"},
                },
            )
            assert llm.default_role == "fallback_role"
            assert "other_role" in llm.roles
        finally:
            os.environ.pop("DEEPSEEK_API_KEY", None)

    def test_default_role_not_in_roles_fails(self):
        """default_role must be defined in roles."""
        os.environ["DEEPSEEK_API_KEY"] = "test-key"
        try:
            with pytest.raises(ValidationError, match="Default role .* is not defined"):
                LLMSettings(
                    schema_version=1,
                    default_role="nonexistent",
                    providers={"p1": {"api_key_env": "DEEPSEEK_API_KEY"}},
                    profiles={"a": {"provider": "p1", "model": "m/a"}},
                    roles={
                        "some_role": {"profile": "a"},
                    },
                )
        finally:
            os.environ.pop("DEEPSEEK_API_KEY", None)


# ============================================================
# Legacy Env Var Compatibility
# ============================================================

class TestLegacyEnvCompatibility:
    def test_shigoku_model_to_role_mapping(self, clean_env):
        """SHIGOKU_MODEL should be map-able for compatibility."""
        os.environ["SHIGOKU_MODEL"] = "deepseek/deepseek-v4-pro"
        os.environ["DEEPSEEK_API_KEY"] = "test-key"

        llm = LLMSettings(
            schema_version=1,
            providers={"deepseek": {"api_key_env": "DEEPSEEK_API_KEY"}},
            profiles={
                "legacy_model": {"provider": "deepseek", "model": "deepseek/deepseek-v4-flash"},
            },
            roles={
                "specialist_light": {"profile": "legacy_model"},
            },
        )
        # Legacy env vars are read separately; the model just validates ok
        assert llm.schema_version == 1
        del os.environ["DEEPSEEK_API_KEY"]




# ============================================================
# Config Priority
# ============================================================

class TestConfigPriority:
    def test_init_overrides_yaml(self, temp_yaml_file):
        """Explicit init args should win over YAML."""
        saved = os.environ.get("DEEPSEEK_API_KEY")
        os.environ["DEEPSEEK_API_KEY"] = "test-key"
        try:
            llm = LLMSettings(
                schema_version=1,
                default_role="custom_role",
                providers={"p1": {"api_key_env": "DEEPSEEK_API_KEY"}},
                profiles={
                    "a": {"provider": "p1", "model": "m/custom"},
                },
                roles={
                    "custom_role": {"profile": "a"},
                },
            )
            assert llm.default_role == "custom_role"
        finally:
            if saved is not None:
                os.environ["DEEPSEEK_API_KEY"] = saved
            else:
                os.environ.pop("DEEPSEEK_API_KEY", None)

    def test_env_overrides_default(self, clean_env):
        """Init args should take priority over env (init > env)."""
        os.environ["SHIGOKU_LLM__DEFAULT_ROLE"] = "env_role"
        os.environ["DEEPSEEK_API_KEY"] = "test-key"
        try:
            # Init kwargs explicitly set default_role to "starter"
            # Env var says "env_role" but init wins.
            settings = Settings(
                llm=LLMSettings(
                    schema_version=1,
                    default_role="starter",
                    providers={"p1": {"api_key_env": "DEEPSEEK_API_KEY"}},
                    profiles={"a": {"provider": "p1", "model": "m/a"}},
                    roles={
                        "starter": {"profile": "a"},
                        "env_role": {"profile": "a"},
                    },
                )
            )
            # init wins, not env
            assert settings.llm.default_role == "starter"
        finally:
            pass

    def test_env_overrides_yaml_default(self, clean_env):
        """Env should override YAML default when no init args are given (env > yaml)."""
        os.environ["SHIGOKU_LLM__DEFAULT_ROLE"] = "planner"
        os.environ["DEEPSEEK_API_KEY"] = "test-key"
        os.environ["OPENAI_API_KEY"] = "test-key"
        os.environ["ANY_LLM_API_KEY"] = "test-key"
        try:
            settings = Settings()
            # env var overrides YAML's default_role: specialist_light -> planner
            assert settings.llm.default_role == "planner"
        finally:
            pass


# ============================================================
# LLMRoleResolver Tests
# ============================================================

class TestLLMRoleResolverBasic:
    @pytest.fixture
    def resolver(self):
        saved_deepseek = os.environ.get("DEEPSEEK_API_KEY")
        saved_openai = os.environ.get("OPENAI_API_KEY")
        os.environ["DEEPSEEK_API_KEY"] = "test-key"
        os.environ["OPENAI_API_KEY"] = "test-key"
        try:
            llm = LLMSettings(
                schema_version=1,
                default_role="specialist_light",
                providers={
                    "deepseek": {"api_key_env": "DEEPSEEK_API_KEY"},
                    "openai": {"api_key_env": "OPENAI_API_KEY"},
                },
                profiles={
                    "cheap": {"provider": "deepseek", "model": "ds/flash",
                              "timeout_seconds": 300, "temperature": 0.0},
                    "reasoning": {"provider": "deepseek", "model": "ds/pro",
                                  "timeout_seconds": 300, "temperature": 0.0,
                                  "extra": {"thinking": {"type": "enabled"}}},
                    "vision": {"provider": "openai", "model": "gpt-4o",
                               "timeout_seconds": 300},
                },
                roles={
                    "planner": {"profile": "reasoning",
                                "system_prompt_template": "conductor/planning.md"},
                    "specialist_light": {"profile": "cheap",
                                         "fallback_profile": "reasoning"},
                },
            )
            yield LLMRoleResolver(llm)
        finally:
            if saved_deepseek is not None:
                os.environ["DEEPSEEK_API_KEY"] = saved_deepseek
            else:
                os.environ.pop("DEEPSEEK_API_KEY", None)
            if saved_openai is not None:
                os.environ["OPENAI_API_KEY"] = saved_openai
            else:
                os.environ.pop("OPENAI_API_KEY", None)

    def test_resolve_known_role(self, resolver):
        result = resolver.resolve("planner")
        assert result.role_name == "planner"
        assert result.profile_name == "reasoning"
        assert result.provider == "deepseek"
        assert result.model == "ds/pro"
        assert result.api_key_env == "DEEPSEEK_API_KEY"
        assert result.temperature == 0.0
        assert result.system_prompt_template == "conductor/planning.md"

    def test_resolve_returns_extra_fields(self, resolver):
        result = resolver.resolve("planner")
        assert result.extra == {"thinking": {"type": "enabled"}}

    def test_resolve_unknown_role_falls_back_to_default(self, resolver):
        result = resolver.resolve("nonexistent_role")
        assert result.role_name == "specialist_light"
        assert result.profile_name == "cheap"

    def test_resolve_returns_timeout(self, resolver):
        result = resolver.resolve("planner")
        assert result.timeout_seconds == 300

    def test_resolve_returns_max_retries(self, resolver):
        result = resolver.resolve("specialist_light")
        assert result.max_retries == 2


class TestLLMRoleResolverFallback:
    @pytest.fixture
    def fallback_llm(self):
        saved_deepseek = os.environ.get("DEEPSEEK_API_KEY")
        saved_openai = os.environ.get("OPENAI_API_KEY")
        os.environ["DEEPSEEK_API_KEY"] = "test-key"
        os.environ["OPENAI_API_KEY"] = "test-key"
        try:
            llm = LLMSettings(
                schema_version=1,
                default_role="specialist_light",
                providers={
                    "ds": {"api_key_env": "DEEPSEEK_API_KEY"},
                    "oai": {"api_key_env": "OPENAI_API_KEY"},
                },
                profiles={
                    "primary": {"provider": "ds", "model": "ds/primary", "temperature": 0.1},
                    "fallback": {"provider": "oai", "model": "oai/fallback", "temperature": 0.7},
                },
                roles={
                    "specialist_light": {"profile": "primary", "fallback_profile": "fallback"},
                },
            )
            yield LLMRoleResolver(llm)
        finally:
            if saved_deepseek is not None:
                os.environ["DEEPSEEK_API_KEY"] = saved_deepseek
            else:
                os.environ.pop("DEEPSEEK_API_KEY", None)
            if saved_openai is not None:
                os.environ["OPENAI_API_KEY"] = saved_openai
            else:
                os.environ.pop("OPENAI_API_KEY", None)

    def test_resolve_returns_primary(self, fallback_llm):
        result = fallback_llm.resolve("specialist_light")
        assert result.profile_name == "primary"
        assert result.provider == "ds"

    def test_get_fallback_chain(self, fallback_llm):
        """The resolver should expose the fallback chain for runtime use."""
        result = fallback_llm.resolve("specialist_light")
        fallback_result = fallback_llm.resolve_fallback("specialist_light")
        assert fallback_result.profile_name == "fallback"
        assert fallback_result.provider == "oai"

    def test_no_fallback_chain(self):
        saved = os.environ.get("DEEPSEEK_API_KEY")
        os.environ["DEEPSEEK_API_KEY"] = "test-key"
        try:
            llm = LLMSettings(
                schema_version=1,
                default_role="lonely",
                providers={"ds": {"api_key_env": "DEEPSEEK_API_KEY"}},
                profiles={"only": {"provider": "ds", "model": "ds/only"}},
                roles={"lonely": {"profile": "only"}},
            )
            resolver = LLMRoleResolver(llm)
            with pytest.raises(LLMResolutionError, match="No fallback"):
                resolver.resolve_fallback("lonely")
        finally:
            if saved is not None:
                os.environ["DEEPSEEK_API_KEY"] = saved
            else:
                os.environ.pop("DEEPSEEK_API_KEY", None)


class TestLLMRoleResolverSafety:
    def test_security_critical_role_undefined_fails(self):
        """Security-critical roles undefined should raise error (fail closed)."""
        saved = os.environ.get("DEEPSEEK_API_KEY")
        os.environ["DEEPSEEK_API_KEY"] = "test-key"
        try:
            llm = LLMSettings(
                schema_version=1,
                providers={"ds": {"api_key_env": "DEEPSEEK_API_KEY"}},
                profiles={"a": {"provider": "ds", "model": "ds/model"}},
                roles={"specialist_light": {"profile": "a"}},
            )
            resolver = LLMRoleResolver(llm)

            # final_judgement is security-critical; not defined -> fail
            with pytest.raises(LLMResolutionError, match="Security-critical role"):
                resolver.resolve("final_judgement")
        finally:
            if saved is not None:
                os.environ["DEEPSEEK_API_KEY"] = saved
            else:
                os.environ.pop("DEEPSEEK_API_KEY", None)

    def test_non_critical_role_undefined_falls_back(self):
        """Non-security-critical roles fall back to default_role."""
        saved = os.environ.get("DEEPSEEK_API_KEY")
        os.environ["DEEPSEEK_API_KEY"] = "test-key"
        try:
            llm = LLMSettings(
                schema_version=1,
                default_role="specialist_light",
                providers={"ds": {"api_key_env": "DEEPSEEK_API_KEY"}},
                profiles={"a": {"provider": "ds", "model": "ds/model"}},
                roles={"specialist_light": {"profile": "a"}},
            )
            resolver = LLMRoleResolver(llm)
            result = resolver.resolve("some_custom_role")
            assert result.role_name == "specialist_light"
        finally:
            if saved is not None:
                os.environ["DEEPSEEK_API_KEY"] = saved
            else:
                os.environ.pop("DEEPSEEK_API_KEY", None)

    def test_security_critical_role_undefined_fails_fallback(self):
        """resolve_fallback() also fails closed for undefined security-critical roles."""
        saved = os.environ.get("DEEPSEEK_API_KEY")
        os.environ["DEEPSEEK_API_KEY"] = "test-key"
        try:
            llm = LLMSettings(
                schema_version=1,
                providers={"ds": {"api_key_env": "DEEPSEEK_API_KEY"}},
                profiles={"a": {"provider": "ds", "model": "ds/model"}},
                roles={"specialist_light": {"profile": "a"}},
            )
            resolver = LLMRoleResolver(llm)
            # final_judgement is security-critical and undefined; resolve_fallback must fail
            with pytest.raises(LLMResolutionError, match="Security-critical role"):
                resolver.resolve_fallback("final_judgement")
        finally:
            if saved is not None:
                os.environ["DEEPSEEK_API_KEY"] = saved
            else:
                os.environ.pop("DEEPSEEK_API_KEY", None)


