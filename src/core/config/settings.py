"""
Settings Module - Pydantic Settings based configuration management.
"""
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type
from pydantic import BaseModel, Field, model_validator, field_validator
from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
    YamlConfigSettingsSource,
    PydanticBaseSettingsSource,
)


@lru_cache(maxsize=8)
def _load_auxiliary_yaml(filename: str) -> dict:
    """Load a non-secret YAML settings file from the canonical config directory."""
    config_file = Path(__file__).resolve().parents[3] / "config" / filename
    if not config_file.exists():
        return {}
    import yaml
    with config_file.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    return data if isinstance(data, dict) else {}


class NotificationSettings(BaseModel):
    """通知設定"""
    slack_webhook: str = ""
    discord_webhook: str = ""
    notify_on_critical: bool = True
    notify_on_high: bool = True


class WordlistSettings(BaseModel):
    """ワードリスト設定"""
    base_path: str = ""
    subdomain_wordlist: str = ""
    directory_wordlist: str = ""
    api_wordlist: str = ""
    params_wordlist: str = ""


class ToolSettings(BaseModel):
    """ツール設定"""
    nuclei_enabled: bool = True
    nuclei_path: str = "nuclei"
    nuclei_templates: str = ""
    ffuf_enabled: bool = True
    ffuf_path: str = "ffuf"
    subfinder_enabled: bool = True
    amass_enabled: bool = True
    gau_enabled: bool = True
    custom_tools: Dict[str, Dict] = Field(default_factory=dict)


class ScanSettings(BaseModel):
    """スキャン設定"""
    rate_limit: int = 50
    timeout: int = 30
    threads: int = 10
    max_depth: int = 3
    follow_redirects: bool = True
    user_agent: str = "SHIGOKU/1.0"
    proxy: str = ""  # Caido/Burp Proxy URL (e.g. http://127.0.0.1:8080)


class APISettings(BaseModel):
    """外部API設定"""
    shodan_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    hunter_api_key: str = ""
    virustotal_api_key: str = ""


class CaidoSettings(BaseModel):
    """Caido 連携設定"""
    token: str = ""  # caido_... PAT
    url: str = "http://127.0.0.1:8080"


class UserSessionConfig(BaseModel):
    """個別ユーザーセッション設定"""
    role: str
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: str = ""


class MultiSessionSettings(BaseModel):
    """マルチセッション（BOLAテスト用）設定"""
    enabled: bool = False
    auto_extract_from_caido: bool = False
    sessions: List[UserSessionConfig] = Field(default_factory=list)


# ===== LLM Config Unification (Phase 1) =====

class LLMProviderSettings(BaseModel):
    """LLMプロバイダー設定"""
    api_key_env: str
    base_url: Optional[str] = None

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().rstrip("/")
        if not normalized.startswith(("https://", "http://")):
            raise ValueError("base_url must be an explicit http(s) endpoint")
        return normalized


class LLMProfileSettings(BaseModel):
    """LLMプロファイル設定 (provider/model timing/retry/temperature)"""
    provider: str
    model: str
    timeout_seconds: int = 300
    max_retries: int = 2
    max_concurrency: int = 4
    rate_limit_per_minute: int = 60
    temperature: float = 0.0
    extra: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_thinking_configuration(self) -> "LLMProfileSettings":
        if "reasoning_effort" in self.extra:
            raise ValueError(
                "reasoning_effort must be set at extra.thinking.reasoning_effort"
            )
        thinking = self.extra.get("thinking")
        if thinking is None:
            return self
        if not isinstance(thinking, dict):
            raise ValueError("extra.thinking must be a mapping")
        thinking_type = thinking.get("type", "disabled")
        if thinking_type not in {"enabled", "disabled"}:
            raise ValueError("extra.thinking.type must be enabled or disabled")
        return self


class LLMRoleSettings(BaseModel):
    """LLMロール設定 (用途別の profile/fallback/prompt マッピング)"""
    profile: str
    fallback_profile: Optional[str] = None
    system_prompt_template: Optional[str] = None
    optional: bool = False  # Trueの時、providerのAPIキー未設定を許容


# Security-critical roles that must be explicitly defined (fail closed)
_SECURITY_CRITICAL_ROLES: Set[str] = {
    "final_judgement",
}


def _default_prompts_dir() -> Path:
    """Resolve the prompts directory relative to this settings module."""
    return Path(__file__).resolve().parent.parent.parent / "prompts"


class LLMSettings(BaseModel):
    """LLM統合設定 (schema_version, default_role, providers, profiles, roles)"""
    schema_version: int = 1
    default_role: str = "specialist_light"
    providers: Dict[str, LLMProviderSettings] = Field(default_factory=dict)
    profiles: Dict[str, LLMProfileSettings] = Field(default_factory=dict)
    roles: Dict[str, LLMRoleSettings] = Field(default_factory=dict)

    @model_validator(mode='after')
    def _validate_llm_config(self) -> 'LLMSettings':
        self._check_default_role_exists()
        self._check_provider_references()
        self._check_profile_references()
        self._check_fallback_cycles()
        self._check_prompt_templates()
        self._check_api_key_envs()
        return self

    def _check_provider_references(self):
        for profile_name, profile in self.profiles.items():
            if profile.provider not in self.providers:
                raise ValueError(
                    f"Profile '{profile_name}' references provider '{profile.provider}' "
                    f"which is not defined in providers"
                )

    def _check_profile_references(self):
        defined_profiles = set(self.profiles.keys())
        for role_name, role in self.roles.items():
            if role.profile not in defined_profiles:
                raise ValueError(
                    f"Role '{role_name}' references profile '{role.profile}' "
                    f"which is not defined in profiles"
                )
            if role.fallback_profile and role.fallback_profile not in defined_profiles:
                raise ValueError(
                    f"Role '{role_name}' has fallback_profile '{role.fallback_profile}' "
                    f"which is not defined in profiles"
                )

    def _check_fallback_cycles(self):
        """Detect self-referencing fallback profiles (profile == fallback_profile)."""
        for role_name, role in self.roles.items():
            if role.fallback_profile and role.fallback_profile == role.profile:
                raise ValueError(
                    f"Circular fallback reference: role '{role_name}' has "
                    f"fallback_profile '{role.fallback_profile}' which is the "
                    f"same as its profile"
                )

    def _collect_used_providers(self) -> Set[str]:
        """Return the set of provider names actually referenced by profiles."""
        return {p.provider for p in self.profiles.values()}

    def _collect_reachable_providers(self) -> Set[str]:
        """Return provider names reachable from non-optional defined roles."""
        reachable_profiles: Set[str] = set()
        for role_name, role in self.roles.items():
            if role.optional:
                continue
            reachable_profiles.add(role.profile)
            if role.fallback_profile:
                reachable_profiles.add(role.fallback_profile)
        reachable_providers: Set[str] = set()
        for profile_name in reachable_profiles:
            profile = self.profiles.get(profile_name)
            if profile:
                reachable_providers.add(profile.provider)
        return reachable_providers

    def _check_api_key_envs(self):
        """Ensure api_key_env vars are set for providers reachable from roles."""
        used_providers = self._collect_reachable_providers()
        for provider_name in used_providers:
            provider = self.providers.get(provider_name)
            if provider and not os.environ.get(provider.api_key_env):
                raise ValueError(
                    f"API key environment variable '{provider.api_key_env}' "
                    f"(referenced by provider '{provider_name}') is not set"
                )

    def _check_default_role_exists(self):
        if not self.roles:
            raise ValueError(
                f"LLM roles configuration is empty but default_role is set to "
                f"'{self.default_role}'. Ensure config/shigoku.yaml is being "
                f"loaded correctly and that the 'llm.roles' section contains at "
                f"least one role definition (including the default role)."
            )
        if self.default_role not in self.roles:
            raise ValueError(
                f"Default role '{self.default_role}' is not defined in roles. "
                f"Available roles: {sorted(self.roles.keys())}"
            )

    def _check_prompt_templates(self):
        """Ensure all system_prompt_template files exist."""
        prompts_dir = _default_prompts_dir()
        for role_name, role in self.roles.items():
            if role.system_prompt_template:
                template_path = prompts_dir / role.system_prompt_template
                if not template_path.exists():
                    raise ValueError(
                        f"System prompt template '{role.system_prompt_template}' "
                        f"(referenced by role '{role_name}') not found at {template_path}"
                    )


# ===== Phase 2 (SGK-2026-0311): Parallelism & Admission Config =====

class PerOriginBudgetSettings(BaseModel):
    """Per-origin budget (rate limit, burst, inflight)."""
    rpm: int = Field(default=30, ge=0)
    burst: int = Field(default=10, ge=0)
    max_inflight: int = Field(default=2, ge=1)
    cooldown_seconds: float = Field(default=1.0, ge=0.0)


class MutatingLaneSettings(BaseModel):
    """Mutating lane settings."""
    enabled: bool = False
    allowlist: list[str] = Field(default_factory=list)


class AggressiveLaneSettings(BaseModel):
    """Aggressive_exclusive lane settings."""
    enabled: bool = False
    allowlist: list[str] = Field(default_factory=list)


class ParallelismSettings(BaseModel):
    """並列化基本設定 (fail-safe defaults).

    When the 'parallelism' section is absent from config/shigoku.yaml,
    all defaults apply and the system starts safely (serial mode).
    """
    enabled: bool = False
    kill_switch: bool = False  # Phase 5 (SGK-2026-0314): immediate serial revert
    shadow_mode: bool = True
    default_executor: str = "serial"
    lane_workers: dict[str, int] = Field(default_factory=dict)
    per_origin_budget: PerOriginBudgetSettings = Field(default_factory=PerOriginBudgetSettings)
    mutating: MutatingLaneSettings = Field(default_factory=MutatingLaneSettings)
    aggressive_exclusive: AggressiveLaneSettings = Field(default_factory=AggressiveLaneSettings)

    @field_validator("lane_workers")
    @classmethod
    def _validate_lane_workers(cls, v: dict[str, int]) -> dict[str, int]:
        for lane_name, count in v.items():
            if count < 1:
                raise ValueError(
                    f"lane_workers['{lane_name}'] = {count} must be >= 1"
                )
        return v


# ---------------------------------------------------------------------------
# SGK-2026-0423: VDP staged rollout ladder (shared truth for config, engine,
# and reporting). M0-M4 states; ``off`` mode is M0-inactive.
# ---------------------------------------------------------------------------

VDP_STAGES: tuple[str, ...] = ("m0", "m1", "m2", "m3a", "m3b", "m3c", "m4")
VDP_STAGE_RANKS: dict[str, int] = {stage: rank for rank, stage in enumerate(VDP_STAGES)}
# Enforce-equivalent stages: real communication is enabled from M3a onward
# (read-only enforce); state-changing enforce starts at M3b.
VDP_ENFORCE_STAGES: frozenset[str] = frozenset({"m3a", "m3b", "m3c", "m4"})


def derive_stage_from_mode(mode: str) -> str:
    """Map the 0420/0421 mode vocabulary onto the 0423 stage ladder
    (backward compatibility; unknown modes fail closed to M0)."""
    if mode == "record_only":
        return "m1"
    if mode == "shadow":
        return "m2"
    if mode == "readonly_enforce":
        return "m3a"
    return "m0"  # off / invalid -> M0 (contract only, no enforcement)


def is_enforce_stage(stage: str) -> bool:
    """True when the effective stage performs real communication (M3a+)."""
    return stage in VDP_ENFORCE_STAGES


def min_stage(a: str, b: str) -> str:
    """Lower-ranked of two stages (fail-closed direction)."""
    rank_a = VDP_STAGE_RANKS.get(a, 0)
    rank_b = VDP_STAGE_RANKS.get(b, 0)
    return a if rank_a <= rank_b else b


class VdpModeSettings(BaseModel):
    """VDP mode (SGK-2026-0420 / SGK-2026-0421 / SGK-2026-0423).
    Default off — VDP inactive unless enabled.

    Modes (0420/0421, unchanged):
    - off: VDP inactive.
    - record_only: hypotheses saved, nothing executed.
    - shadow: hypotheses + candidate verdicts + NextAction proposals, no queue.
    - readonly_enforce (SGK-2026-0421 M3a): read-equivalent follow-ups only,
      behind the full admission/scope/budget/HITL gates.

    SGK-2026-0423 staged rollout (additive):
    - stage: explicit rollout stage (m0..m4); "" derives from mode.
      The explicit stage acts as a CAP — the effective stage is the lower
      of (mode-derived stage, explicit stage) so config alone cannot raise
      capability above the mode.
    - stage_flags: per-stage independent disable (stage and above are
      capped down when the flag is false). Unknown keys are dropped.
    - key_provider / key_env_var / key_file_path: confirmed-key provider
      sources. Enforce stages (M3a+) never fall back to the implicit home
      directory key file.
    - key_registry_path: versioned key registry JSON; required for enforce.
    - progression_records_path: M0-M4 progression evidence artifact; M3b+
      stages require it (config alone cannot enable state-changing enforce).
    - thresholds_path: frozen hidden-holdout threshold artifact (M4 gate).
    """
    mode: str = "off"
    label_leakage_denylist: list[str] = Field(default_factory=list)
    kill_switch: bool = False  # SGK-2026-0421/0423: stops queue injection AND pre-communication
    capability_rules: dict[str, str] = Field(default_factory=dict)

    # --- SGK-2026-0423 staged rollout (additive) ---
    stage: str = ""
    stage_flags: dict[str, bool] = Field(default_factory=dict)
    key_provider: str = "env"
    key_env_var: str = "SHIGOKU_VDP_SIGNING_KEY"
    key_file_path: str = ""
    key_registry_path: str = ""
    progression_records_path: str = ""
    thresholds_path: str = ""
    rollout_state_path: str = ""  # persisted rollback/rollout state (can only lower capability)
    holdout_result_path: str = ""  # hidden holdout evaluation result artifact (M4 Go evidence)
    decision_records_path: str = ""  # Go/Hold/No-Go decision records artifact (M4 Go evidence)
    gate_result_path: str = ""  # real VDP run-quality gate result artifact (M4 Go evidence)

    @field_validator("mode")
    @classmethod
    def _validate_mode(cls, v: str) -> str:
        if v not in ("off", "record_only", "shadow", "readonly_enforce"):
            return "off"  # invalid mode fails safe to off
        return v

    @field_validator("stage")
    @classmethod
    def _validate_stage(cls, v: str) -> str:
        if v in ("", *VDP_STAGES):
            return v
        return ""  # invalid stage fails closed to mode-derived stage

    @field_validator("stage_flags")
    @classmethod
    def _validate_stage_flags(cls, v: dict[str, bool]) -> dict[str, bool]:
        if not v:
            return {}
        return {
            str(stage): bool(enabled)
            for stage, enabled in v.items()
            if str(stage) in VDP_STAGES
        }

    @field_validator("key_provider")
    @classmethod
    def _validate_key_provider(cls, v: str) -> str:
        if v in ("env", "file", "env_or_file"):
            return v
        return "env"  # unknown provider fails closed to env-only

    @field_validator("capability_rules")
    @classmethod
    def _validate_capability_rules(cls, v: dict[str, str]) -> dict[str, str]:
        allowed_levels = {
            "allowed", "confirmation_required", "prohibited", "unavailable",
        }
        return {
            str(capability): (
                str(level) if str(level) in allowed_levels else "prohibited"
            )
            for capability, level in (v or {}).items()
        }


# ===== SGK-2026-0425: VDP diagnostic telemetry (additive, default off) =====

_DIAGNOSTICS_DEFAULTS = {
    "max_events": 2000,
    "max_artifact_bytes": 10 * 1024 * 1024,
    "checkpoint_interval_events": 500,
    "event_queue_capacity": 5000,
}


class DiagnosticsSettings(BaseModel):
    """SGK-2026-0425: VDP diagnostic telemetry (additive, default off).

    - ``enabled``: False — no diagnostic events collected; existing
      session / report / decision-trace / attack-task output stays
      bit-identical (characterization contract, plan §8 M0).
    - ``required``: False — normal runs keep the existing path when a
      diagnostic hook fails (degraded note only). True (evaluation runs):
      stop BEFORE the next network communication, checkpoint and Hold.
    - Bound values (max_events / max_artifact_bytes /
      checkpoint_interval_events / event_queue_capacity) fail closed to the
      defaults above: an invalid value must never silently relax limits.
    """
    enabled: bool = False
    required: bool = False
    max_events: int = _DIAGNOSTICS_DEFAULTS["max_events"]
    max_artifact_bytes: int = _DIAGNOSTICS_DEFAULTS["max_artifact_bytes"]
    checkpoint_interval_events: int = _DIAGNOSTICS_DEFAULTS["checkpoint_interval_events"]
    event_queue_capacity: int = _DIAGNOSTICS_DEFAULTS["event_queue_capacity"]

    @model_validator(mode="before")
    @classmethod
    def _reject_invalid_bounds_before_coercion(cls, data):
        # pydantic coerces True -> 1 BEFORE field validators run, so bool
        # input for a bound field must be rejected here on the raw input.
        if isinstance(data, dict):
            for key in _DIAGNOSTICS_DEFAULTS:
                if key in data and (
                    isinstance(data[key], bool)
                    or not isinstance(data[key], int)
                    or data[key] <= 0
                ):
                    data = dict(data)
                    data[key] = _DIAGNOSTICS_DEFAULTS[key]
        return data

    @field_validator(
        "max_events",
        "max_artifact_bytes",
        "checkpoint_interval_events",
        "event_queue_capacity",
    )
    @classmethod
    def _validate_positive_bounds(cls, v: int, info) -> int:
        # Defense in depth: bool is an int subclass in Python — reject it.
        if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
            return _DIAGNOSTICS_DEFAULTS[info.field_name]
        return v


# ===== Phase 3 & Extended Feature Settings =====

class WafBypassSettings(BaseModel):
    """WAF回避設定"""
    enabled: bool = False
    provider: str = "direct"
    api_key: str = ""


class MicroAgentSettings(BaseModel):
    """マイクロエージェント設定"""
    enabled: bool = False
    model: str = "mistral:7b"
    ollama_url: str = "http://localhost:11434"


class SandboxSettings(BaseModel):
    """サンドボックス設定"""
    enabled: bool = False
    max_retries: int = 5
    network_isolated: bool = True
    timeout_seconds: int = 60


class ExploitVerifierSettings(BaseModel):
    """Exploit Verifier設定"""
    enabled: bool = False
    risk_threshold: int = 7
    non_destructive_only: bool = True


class AttackModulesSettings(BaseModel):
    """攻撃モジュール拡充設定"""
    host_header_injection: bool = False
    enhanced_patterns: bool = False


class Phase3Settings(BaseModel):
    """Phase 3機能設定"""
    waf_bypass: WafBypassSettings = Field(default_factory=WafBypassSettings)
    micro_agent: MicroAgentSettings = Field(default_factory=MicroAgentSettings)
    sandbox: SandboxSettings = Field(default_factory=SandboxSettings)
    exploit_verifier: ExploitVerifierSettings = Field(default_factory=ExploitVerifierSettings)
    attack_modules: AttackModulesSettings = Field(default_factory=AttackModulesSettings)


class FeatureNotificationsSettings(BaseModel):
    """機能通知設定"""
    enabled: bool = True
    immediate_severities: List[str] = Field(default_factory=lambda: ["critical", "high"])
    batch_interval_seconds: int = 300
    dedup_window_seconds: int = 3600

    # Phase A (SGK-2026-0297): Operational protections for notification delivery
    notify_dry_run: bool = False           # Dry-run: log but do NOT actually send
    notify_kill_switch: bool = False       # Emergency stop: block all sends
    notify_timeout_seconds: float = 10.0   # Per-notification timeout
    notify_retry_count: int = 1            # Max retries on failure
    notify_retry_backoff_seconds: float = 1.0  # Delay between retries
    notify_provider_allowlist: List[str] = Field(default_factory=list)  # Allowed providers
    notify_max_body_length: int = 4000     # Discord-compatible max body length


class RetryControlSettings(BaseModel):
    """リトライ/ループ制御設定"""
    max_retries_per_task: int = 5
    adaptive_threshold: bool = True
    low_success_multiplier: float = 0.5


class ExportSettings(BaseModel):
    """エクスポート設定"""
    default_format: str = "json"
    pdf_template: str = "default"
    include_evidence: bool = True


class PreflightSettings(BaseModel):
    """入口ゲート (Preflight Gate) 設定"""
    enabled: bool = True
    gate_policy: str = "strict-prod"  # strict-prod | strict-dev
    caido_mandatory: bool = True
    tool_check_enabled: bool = True
    auth_probe_enabled: bool = True
    ai_classifier_enabled: bool = False
    active_phases: str = "1,2,3,4"  # comma-separated GatePhase values
    # Phase feature flags
    phase1_deterministic: bool = True
    phase2_tool_update: bool = True
    phase3_ai_classifier: bool = True
    phase4_resume_hardening: bool = True
    # Timeouts
    caido_tcp_timeout: float = 2.0
    caido_http_timeout: float = 5.0
    auth_probe_timeout: float = 8.0
    ai_classifier_timeout: float = 3.0


class Settings(BaseSettings):
    """SHIGOKU統合設定 (Pydantic Settings)"""
    model_config = SettingsConfigDict(
        env_prefix="SHIGOKU_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # 基本設定
    mode: str = "bugbounty"
    project_name: str = ""
    project_path: str = ""
    scope_file: str = ""
    environment: str = "local"
    dev_mode: bool = False
    log_level: str = "INFO"
    guardrails_enabled: bool = True
    ctf_target: Optional[str] = None
    ctf_flag_format: str = "flag{.*}"
    use_llm_planning: bool = False
    checkpoint_interval: int = 5
    intervention_gate_mode: str = "observe"
    notify_on_task_start: bool = False
    notify_critical_mention: str = ""
    github_token: Optional[str] = None
    tool_nuclei_path: str = "nuclei"
    tool_httpx_path: str = ""
    tool_gospider_path: str = "gospider"
    tool_katana_path: str = "katana"
    
    # 安全設定
    safe_mode: bool = False
    max_derived_tasks_per_session: int = 100
    report_initial_release_confirmed_min: int = 3
    report_initial_release_candidate_max: int = 2
    report_initial_release_confirmed_poc_missing_max: int = 0
    report_initial_release_reason_code_missing_max: int = 0
    report_initial_release_required_confirmed_classes: str = ""
    report_initial_release_required_class_confirmed_min: int = 1
    report_initial_release_allowed_missing_scenarios: str = (
        "scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology"
    )
    report_initial_release_baseline_report_path: str = ""
    report_initial_release_baseline_session_path: str = ""
    pruning_mode: str = "shadow"
    pruning_killswitch_enabled: bool = False

    # LLM Settings
    # Deprecated compatibility field. Runtime LLM selection is role-based.
    model: str = ""
    phase2_on_empty_force_disable: bool = False
    # SGK-2026-0367: safety switches for injection ownership and Phase2 suppression
    injection_ownership_dedup_enabled: bool = True
    xss_no_signal_phase2_suppress_enabled: bool = True
    xss_no_signal_phase2_shadow_only: bool = False
    risk_predictor_delay_disable: bool = False
    risk_predictor_delay_high_only: bool = False
    risk_predictor_delay_min_score: float = 0.7
    injection_full_parallel_dispatch: bool = False
    phase1_timeout_retry_same_cause_guard: bool = False
    phase1_timeout_retry_guard_min_priority: int = 70
    # ReAct Observation (unified source of truth migration)
    enable_react_observation: bool = False
    react_observation_max_additions: int = 2
    react_observation_max_calls_per_run: int = 50
    react_observation_max_calls_per_target: int = 10
    react_observation_sampling_rate: float = 1.0
    react_observation_low_value_task_patterns: str = "read,list,fetch,health,heartbeat,ping"
    react_observation_retry_budget_per_run: int = 20
    react_observation_retry_max: int = 1
    react_observation_circuit_breaker_threshold: int = 5
    react_observation_circuit_breaker_cooldown_seconds: int = 120
    react_observation_circuit_breaker_latency_seconds: float = 8.0
    react_observation_queue_maxsize: int = 100
    max_inflight_react_requests_global: int = 8
    react_observation_decision_event_sample_rate: float = 0.2

    # LLM統合設定 (新)
    llm: LLMSettings = Field(default_factory=LLMSettings)

    # サブ設定
    notification: NotificationSettings = Field(default_factory=NotificationSettings)
    wordlist: WordlistSettings = Field(default_factory=WordlistSettings)
    tools: ToolSettings = Field(default_factory=ToolSettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    api: APISettings = Field(default_factory=APISettings)

    # 機能詳細設定
    phase3: Phase3Settings = Field(default_factory=Phase3Settings)
    feature_notifications: FeatureNotificationsSettings = Field(default_factory=FeatureNotificationsSettings)
    retry_control: RetryControlSettings = Field(default_factory=RetryControlSettings)
    export: ExportSettings = Field(default_factory=ExportSettings)
    caido: CaidoSettings = Field(default_factory=CaidoSettings)
    preflight: PreflightSettings = Field(default_factory=PreflightSettings)
    multi_session: MultiSessionSettings = Field(default_factory=MultiSessionSettings)
    parallelism: ParallelismSettings = Field(default_factory=ParallelismSettings)
    vdp: VdpModeSettings = Field(default_factory=VdpModeSettings)
    diagnostics: DiagnosticsSettings = Field(default_factory=DiagnosticsSettings)

    # RAG設定
    rag_enabled: bool = True
    obsidian_vault_path: str = ""
    chromadb_path: str = ""

    # Neo4j設定
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "shigoku2024"

    def get_proxy_url(self) -> Optional[str]:
        """Proxy URLを取得する。優先度: scan.proxy > 明示Caido URL > None"""
        if self.scan.proxy:
            return self.scan.proxy
        if os.getenv("SHIGOKU_CAIDO__URL", "").strip():
            return self.caido.url
        return None

    def resolve_tool_command(
        self,
        tool_name: str,
        configured_path: str | None = None,
    ) -> str:
        """設定済みの実行パス、または標準のツール名を返す。"""
        candidate = (
            configured_path
            if configured_path is not None
            else getattr(self, f"tool_{tool_name}_path", "")
        )
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
        return tool_name

    def get_intervention_scenarios(self) -> dict:
        return _load_auxiliary_yaml("intervention_scenarios.yaml")

    def get_vuln_info(self, vuln_type: str) -> dict:
        return _load_auxiliary_yaml("vulnerabilities.yaml").get("vuln_types", {}).get(vuln_type, {})

    def get_tool_profile(self, tool: str, profile: str = "standard") -> dict:
        return _load_auxiliary_yaml("tools.yaml").get(tool, {}).get("profiles", {}).get(profile, {})

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """
        設定ソースの優先順位を定義。
        1. SHIGOKU_CONFIG 環境変数（明示パス指定）
        2. CLI (init_settings)
        3. 環境変数 (env_settings)
        4. YAML ファイル (YamlConfigSettingsSource) — パッケージ相対パス → CWD相対パス の順に探索

        Package-relative path discovery により、Docker/WORKDIR 不一致などの
        CWD の場所に依存した設定読込失敗を防止する。
        """
        # yaml_path は動的に変更したい場合があるが、まずはデフォルト。
        # ConfigManager が明示的に path を渡す場合は init_settings に含まれる。
        # ここでは標準の config/shigoku.yaml を対象にする。

        # 0. 明示的な環境変数指定 (SHIGOKU_CONFIG) が最優先
        explicit_config = os.environ.get("SHIGOKU_CONFIG")
        if explicit_config:
            yaml_file = Path(explicit_config).expanduser().resolve()
            if not yaml_file.exists():
                raise FileNotFoundError(
                    f"SHIGOKU_CONFIG specifies non-existent file: {yaml_file}"
                )
            return (
                init_settings,
                env_settings,
                YamlConfigSettingsSource(settings_cls, yaml_file=yaml_file),
            )

        # 1. パッケージ相対パス: CWDに依存せず確実に発見（Docker WORKDIR対策）
        _settings_file = Path(__file__).resolve()
        _package_root = _settings_file.parent.parent.parent.parent  # src/core/config/settings.py → root
        pkg_yaml = _package_root / "config" / "shigoku.yaml"
        if pkg_yaml.exists():
            return (
                init_settings,
                env_settings,
                YamlConfigSettingsSource(settings_cls, yaml_file=pkg_yaml),
            )

        # 2. 後方互換: CWD相対パス
        cwd_yaml = Path("config/shigoku.yaml")
        if not cwd_yaml.exists():
            cwd_yaml = Path("shigoku.yaml")

        return (
            init_settings,
            env_settings,
            YamlConfigSettingsSource(settings_cls, yaml_file=cwd_yaml if cwd_yaml.exists() else None),
        )

# シングルトン
_settings: Optional[Settings] = None

def get_settings(reinit: bool = False, **kwargs) -> Settings:
    """Settingsシングルトン取得"""
    global _settings
    if _settings is None or reinit or kwargs:
        # kwargs がある場合は再初期化
        _settings = Settings(**kwargs)
    return _settings


class _SettingsProxy:
    """Lazy canonical settings access for legacy module-level consumers."""

    def __getattr__(self, name: str) -> Any:
        return getattr(get_settings(), name)


settings = _SettingsProxy()


def resolve_run_mode(explicit: Optional[str] = None) -> str:
    """操作モードを解決する（SGK-2026-0335 補完）。

    優先順位:
      1. *explicit* に truthy な値が渡された場合 → それをそのまま返す
      2. グローバル :func:`get_settings` の ``mode``
      3. 設定取得エラー時や未設定時 → ``"bugbounty"`` （fail-closed 既定値）

    これにより ``--mode vulntest`` / ``ctf`` 実行時に、各 ``AsyncNetworkClient``
    がバンドル未ロードのままコンパイルガードを fail-close してしまう問題
    （プリフライトの CAIDO_HTTP_UNREACHABLE 等）を防ぐ。
    ``bugbounty`` 実行では設定由来で ``"bugbounty"`` が復元されるため、
    ガードの fail-closed 挙動は維持される。
    """
    if explicit:
        return explicit
    try:
        mode = get_settings().mode
        return mode or "bugbounty"
    except Exception:
        return "bugbounty"
