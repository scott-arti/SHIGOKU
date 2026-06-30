"""
LLMRoleResolver: Resolves LLM role -> profile -> provider/model/prompt/fallback.

Minimal Phase 1 implementation per the LLM config unification plan.
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set, TYPE_CHECKING

from src.core.config.settings import LLMRoleSettings


@dataclass
class LLMResolutionResult:
    """Resolved LLM configuration for a single role/profile."""
    role_name: str
    profile_name: str
    provider: str
    model: str
    api_key_env: str
    base_url: Optional[str] = None
    timeout_seconds: int = 300
    max_retries: int = 2
    max_concurrency: int = 4
    rate_limit_per_minute: int = 60
    temperature: float = 0.0
    extra: Dict[str, Any] = field(default_factory=dict)
    system_prompt_template: Optional[str] = None
    is_fallback: bool = False


class LLMResolutionError(Exception):
    """Error raised when LLM role resolution fails."""


# Security-critical roles that must be explicitly defined (fail closed)
# Mirrors _SECURITY_CRITICAL_ROLES in settings.py
_SECURITY_CRITICAL_ROLES: Set[str] = {
    "final_judgement",
}


class LLMRoleResolver:
    """
    Resolves LLM roles to their concrete configuration.

    Resolution chain:
        role_name -> LLMRoleSettings -> LLMProfileSettings -> LLMProviderSettings

    Falls back to `default_role` when the requested role is not defined,
    except for security-critical roles which fail closed.
    """

    def __init__(self, llm_settings):
        """
        Args:
            llm_settings: LLMSettings instance from the unified config.
        """
        self._llm = llm_settings
        self._providers = llm_settings.providers
        self._profiles = llm_settings.profiles
        self._roles = llm_settings.roles
        self._default_role = llm_settings.default_role

    def resolve(self, role_name: str) -> LLMResolutionResult:
        """
        Resolve a role name to its concrete LLM configuration.

        Raises:
            LLMResolutionError: If the role is security-critical and not defined,
                                or if the default_role itself is missing.
        """
        role = self._roles.get(role_name)
        if role is None:
            # Check if this is a security-critical role that should fail closed
            if role_name in _SECURITY_CRITICAL_ROLES:
                raise LLMResolutionError(
                    f"Security-critical role '{role_name}' is not defined in config. "
                    f"Refusing to resolve implicitly."
                )
            # Fall back to default_role
            role = self._roles.get(self._default_role)
            if role is None:
                raise LLMResolutionError(
                    f"Default role '{self._default_role}' is not defined in config"
                )
            # Return the default role's resolution
            resolved = self._resolve_role(self._default_role, role)
            return resolved

        return self._resolve_role(role_name, role)

    def resolve_fallback(self, role_name: str) -> LLMResolutionResult:
        """
        Resolve the fallback configuration for a role.

        Raises:
            LLMResolutionError: If the role has no fallback_profile configured,
                                or if the role is security-critical and not defined.
        """
        # Security-critical roles must fail closed even for fallback resolution
        if role_name in _SECURITY_CRITICAL_ROLES and role_name not in self._roles:
            raise LLMResolutionError(
                f"Security-critical role '{role_name}' is not defined in config. "
                f"Refusing to resolve fallback implicitly."
            )

        role = self._roles.get(role_name)
        if role is None:
            role = self._roles.get(self._default_role)
            if role is None:
                raise LLMResolutionError(
                    f"Default role '{self._default_role}' is not defined in config"
                )
            role_name = self._default_role

        if not role.fallback_profile:
            raise LLMResolutionError(
                f"No fallback profile configured for role '{role_name}'"
            )

        fallback_role = LLMRoleSettings(
            profile=role.fallback_profile,
            system_prompt_template=role.system_prompt_template,
        )
        return self._resolve_role(role_name, fallback_role, is_fallback=True)

    def _resolve_role(
        self,
        role_name: str,
        role: 'LLMRoleSettings',
        is_fallback: bool = False,
    ) -> LLMResolutionResult:
        profile_name = role.profile
        profile = self._profiles.get(profile_name)
        if profile is None:
            raise LLMResolutionError(
                f"Profile '{profile_name}' (referenced by role '{role_name}') "
                f"not found in profiles"
            )

        provider_name = profile.provider
        provider = self._providers.get(provider_name)
        if provider is None:
            raise LLMResolutionError(
                f"Provider '{provider_name}' (referenced by profile '{profile_name}') "
                f"not found in providers"
            )

        return LLMResolutionResult(
            role_name=role_name,
            profile_name=profile_name,
            provider=provider_name,
            model=profile.model,
            api_key_env=provider.api_key_env,
            base_url=provider.base_url,
            timeout_seconds=profile.timeout_seconds,
            max_retries=profile.max_retries,
            max_concurrency=profile.max_concurrency,
            rate_limit_per_minute=profile.rate_limit_per_minute,
            temperature=profile.temperature,
            extra=dict(profile.extra),
            system_prompt_template=role.system_prompt_template,
            is_fallback=is_fallback,
        )

    @property
    def default_role(self) -> str:
        return self._default_role

    @property
    def roles(self) -> Set[str]:
        return set(self._roles.keys())

    @property
    def profiles(self) -> Set[str]:
        return set(self._profiles.keys())


# build_legacy_profile_mapping removed (SGK-2026-0303 D02).
# Legacy env vars SHIGOKU_MODEL_OUTPUT / SHIGOKU_MODEL_LIGHTWEIGHT are no longer supported.
