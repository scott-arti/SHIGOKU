"""
Settings Module - Pydantic Settings based configuration management.
"""
from pathlib import Path
from typing import Dict, List, Optional, Type
from pydantic import BaseModel, Field
from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
    YamlConfigSettingsSource,
    PydanticBaseSettingsSource,
)


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

    # LLM Settings
    model: str = "deepseek/deepseek-v4-flash"
    model_output: str = "deepseek/deepseek-v4-pro"
    model_lightweight: str = "deepseek/deepseek-v4-flash"
    # model_lightweight: str = "ollama/qwen3.5:latest"
    llm_auto_route: bool = True
    llm_use_local: bool = False
    llm_fallback_model: str = "deepseek/deepseek-v4-flash"
    deepseek_thinking_enabled_for_output: bool = True
    deepseek_thinking_enabled_for_lightweight: bool = False
    deepseek_reasoning_effort_output: str = "high"
    deepseek_reasoning_effort_lightweight: str = "high"
    llm_xss_rejudge_model: str = "openai/gpt-4o-mini"
    llm_xss_final_model: str = "openai/gpt-4o"
    llm_use_any_llm_proxy: bool = False
    any_llm_base_url: str = "http://localhost:8000/v1"
    any_llm_api_key: str = ""
    phase2_on_empty_force_disable: bool = False
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
    multi_session: MultiSessionSettings = Field(default_factory=MultiSessionSettings)

    # RAG設定
    rag_enabled: bool = True
    obsidian_vault_path: str = ""
    chromadb_path: str = ""

    # Neo4j設定
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "shigoku2024"

    def get_proxy_url(self) -> Optional[str]:
        """Proxy URLを取得する。優先度: scan.proxy > None"""
        return self.scan.proxy if self.scan.proxy else None

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
        1. CLI (init_settings)
        2. 環境変数 (env_settings)
        3. YAML ファイル (YamlConfigSettingsSource)
        """
        # yaml_path は動的に変更したい場合があるが、まずはデフォルト。
        # ConfigManager が明示的に path を渡す場合は init_settings に含まれる。
        # ここでは標準の config/shigoku.yaml を対象にする。
        yaml_path = Path("config/shigoku.yaml")
        if not yaml_path.exists():
            yaml_path = Path("shigoku.yaml")

        return (
            init_settings,
            env_settings,
            YamlConfigSettingsSource(settings_cls, yaml_file=yaml_path if yaml_path.exists() else None),
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
