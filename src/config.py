from pydantic_settings import BaseSettings
from pydantic import model_validator
from typing import Optional
import logging

logger = logging.getLogger("config")


# Phase 3: YAMLキャッシング用のモジュールレベル関数
from functools import lru_cache
from pathlib import Path

@lru_cache(maxsize=8)
def _load_yaml_cached(filename: str) -> dict:
    """YAML ファイルをロード（lru_cache でキャッシュ）

    Args:
        filename: YAML ファイル名 (例："vulnerabilities.yaml")

    Returns:
        ロードした辞書、またはエラー時は空辞書
    """
    # プロジェクトルートの config/ ディレクトリ
    # __file__ は src/config.py なので、親の親が project root
    config_dir = Path(__file__).parent.parent / "config"
    file_path = config_dir / filename

    if not file_path.exists():
        logger.warning(f"Config file not found: {file_path}")
        return {}

    try:
        import yaml
    except ImportError:
        logger.error("PyYAML is not installed. Install with: pip install pyyaml")
        return {}

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"Failed to load YAML file {file_path}: {e}")
        return {}

class Settings(BaseSettings):
    """
    Application Settings

    Reads from environment variables (SHIGOKU_*) and .env file.
    """
    # Global
    model: str = "deepseek/deepseek-v4-flash"
    log_level: str = "INFO"
    environment: str = "local"
    dev_mode: bool = False  # Permissive Mode Flag

    # Neo4j Configuration
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: Optional[str] = None  # Critical secret

    @model_validator(mode='after')
    def check_secrets(self):
        """Enforce strict secret checks in production, allow dummy in dev."""
        if not self.dev_mode:
            # Strict Mode (Production)
            if not self.neo4j_password:
                raise ValueError("SHIGOKU_NEO4J_PASSWORD must be strictly set in production mode.")
        else:
            # Permissive Mode (Dev)
            if not self.neo4j_password:
                logger.warning("⚠️  [Security] SHIGOKU_NEO4J_PASSWORD not set. Using dummy password for DEV_MODE.")
                self.neo4j_password = "password"  # Fallback for local dev
        return self

    # Security
    guardrails_enabled: bool = True
    sandbox_enabled: bool = False

    # Agent Specific
    security_agent_model: Optional[str] = None
    recon_agent_model: Optional[str] = None
    redteam_agent_model: Optional[str] = None

    # CTF / Target Spec
    ctf_target: Optional[str] = None  # e.g. "BasicPentest1"
    ctf_ip: Optional[str] = None      # e.g. "10.10.10.10"
    ctf_subnet: Optional[str] = None  # e.g. "10.10.10.0/24"
    ctf_inside: bool = False          # Inside container or not

    # Phase 3: Dynamic Planning
    use_llm_planning: bool = False

    # Phase 4: ReAct Observation (成功時の観察→再思考)
    # デフォルト OFF: API コスト爆発防止のため明示的なオプトインが必要
    enable_react_observation: bool = False
    react_observation_max_additions: int = 2  # 追加タスク最大数
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

    # Task Queue Control (タスクキュー制御)
    max_derived_tasks_per_session: int = 20  # セッション内の派生タスク上限（暴走防止）
    max_concurrent_tasks: int = 4  # 同時実行タスク数（CPU コア数程度を推奨）
    max_session_tasks: int = 1000  # セッション全体の最大実行タスク数
    checkpoint_interval: int = 5  # チェックポイント保存間隔（タスク数）
    max_httpx_urls: int = 500  # URL 発見フェーズでの httpx 確認上限数
    playwright_target_budget: int = 18  # Dynamic Recon で巡回する seed URL 上限
    playwright_max_pages_per_seed: int = 8  # seed あたりの遷移ページ上限
    playwright_max_clicks_per_page: int = 6  # 1ページあたりのクリック試行上限
    playwright_max_forms_per_page: int = 3  # 1ページあたりのフォーム送信試行上限
    playwright_max_post_login_actions_per_page: int = 12  # ログイン後想定UI操作（メニュー/タブ）上限
    playwright_max_route_hints_per_page: int = 32  # ページごとに追加で収集する遷移候補URL上限
    playwright_history_seed_limit: int = 10  # Playwright失敗時に直近履歴から補完する seed URL 上限
    tagged_history_replay_file_window: int = 24  # 直近履歴参照で読む tagged_urls ファイル数上限
    tagged_history_replay_limit: int = 6  # カテゴリ別タスク生成時に履歴再利用する URL 上限
    tagged_history_replay_limit_dense: int = 12  # 高優先カテゴリ向けの履歴再利用 URL 上限
    authz_history_replay_limit: int = 6  # auth/id_param 補完で再利用する URL 上限
    intervention_gate_mode: str = "observe"  # observe | enforce_human_preferred | enforce_hitl
    intervention_human_preferred_fail_closed: bool = False  # callback 未設定時に human_preferred を停止する

    # MCP Configuration
    mcp_config_path: Optional[str] = "mcp_config.json"

    # GitHub Integration
    github_token: Optional[str] = None

    # External Tools
    tool_nuclei_path: str = "nuclei"
    tool_gau_path: str = "gau"
    tool_gospider_path: str = "gospider"
    tool_katana_path: str = "katana"
    tool_searchsploit_path: str = "searchsploit"
    tool_theharvester_path: str = "theHarvester"

    # httpx wrapper path (auto-resolved)
    tool_httpx_path: str = str(Path(__file__).parent.parent / "src/tools/wrappers/httpx_wrapper.py")

    # Notification Settings
    notify_on_task_start: bool = False  # タスク開始時の通知 (デフォルト OFF)
    notify_on_task_complete: bool = True  # タスク完了時の通知
    notify_on_finding: bool = True  # 脆弱性発見時の通知
    notify_on_error: bool = True  # システムエラー時の通知
    notify_critical_mention: str = ""  # CRITICAL 発見時のメンション (@channel, @here, etc.)

    # Model Routing (コスト最適化)
    # 軽量タスク (繰り返しの多い補助タスク) → ローカルまたは安価なモデル
    # 高精度タスク (最終出力、重要判断) → 高性能モデル
    model_lightweight: str = "deepseek/deepseek-v4-flash"  # ReAct, Critic, クエリリファイン用
    # model_lightweight: str = "ollama/qwen3.5:latest"  # ReAct, Critic, クエリリファイン用
    model_output: str = "deepseek/deepseek-v4-pro"  # 最終レポート、初期プランニング用
    llm_fallback_model: str = "deepseek/deepseek-v4-flash"  # 認証失敗時などの退避先
    deepseek_thinking_enabled_for_output: bool = True  # 重要判断は thinking 有効
    deepseek_thinking_enabled_for_lightweight: bool = False  # 通常ループは non-thinking
    deepseek_reasoning_effort_output: str = "high"  # high|max
    deepseek_reasoning_effort_lightweight: str = "high"  # high|max（thinking時のみ使用）
    llm_xss_rejudge_model: str = "openai/gpt-4o-mini"  # XSS再判定用
    llm_xss_final_model: str = "openai/gpt-4o"  # XSS最終判定用
    use_local_for_lightweight: bool = False  # 軽量タスクにローカル LLM を使用
    # use_local_for_lightweight: bool = True  # 軽量タスクにローカル LLM を使用

    # Local LLM Settings (Ollama)
    local_llm_enabled: bool = True  # ローカル LLM 全体を有効化
    local_llm_model: str = "qwen3.5:latest"  # Ollama モデル名
    local_llm_base_url: str = "http://localhost:11434"  # Ollama API ベース URL
    local_llm_auto_route: bool = True  # タスク複雑度に基づく自動ルーティング
    local_llm_for_simple_tasks: bool = True  # 単純タスクのみローカル LLM を使用

    def get_lightweight_model(self) -> str:
        """軽量タスク用のモデル名を返す"""
        if self.use_local_for_lightweight and self.local_llm_enabled:
            return f"ollama/{self.local_llm_model}"
        return self.model_lightweight

    def get_output_model(self) -> str:
        """高精度タスク用のモデル名を返す"""
        return self.model_output

    # Learning Repository Settings (Phase 0: 学習リポジトリ)
    learning_db_path: str = "~/.shigoku/learning/learning.db"  # SQLite データベースパス
    learning_retention_days: int = 30  # 学習データの保持日数
    learning_auto_cleanup: bool = True  # 起動時に期限切れデータを自動削除

    # Agent Execution Settings (L-1: ハードコードを設定化)
    agent_execution_timeout: int = 1800  # エージェント実行タイムアウト（秒）
    llm_request_timeout: int = 300  # LLM API リクエストタイムアウト（秒）

    # 階層化されたタイムアウト値
    parallel_batch_timeout: int = 600  # 並列バッチ実行のタイムアウト（秒）
    single_task_timeout: int = 300  # 単一タスク実行のタイムアウト（秒）
    specialist_execution_timeout: int = 120  # Specialist 実行のタイムアウト（秒）
    scope_parser_timeout: int = 600  # scope_parser 実行タイムアウト（秒）
    recon_master_timeout: int = 3000  # recon_master 実行タイムアウト（秒、CRAPI 実運用の長尺runを考慮）
    injection_manager_timeout: int = 900  # InjectionManager 全体のタイムアウト（秒）
    timeout_retry_max: int = 1  # timeout 起因失敗時の既定リトライ回数
    recon_master_timeout_retry_max: int = 0  # recon_master の timeout リトライ回数（重複長時間実行を防ぐ）
    recon_master_timeout_replan_enabled: bool = False  # recon_master timeout 時の replan を許可するか
    injection_batch_parallelism: int = 1  # Injection を含むバッチの制限付き並列数
    injection_full_parallel_dispatch: bool = False  # true なら先頭Injection時の逐次制限を解除
    csrf_target_budget: int = 3  # coverage backfill で生成する CSRF seed ターゲット上限
    xss_target_budget: int = 3  # coverage backfill で生成する XSS seed ターゲット上限
    api_injection_target_budget: int = 3  # coverage backfill で生成する API/Injection seed ターゲット上限
    csrf_backfill_min_score: int = 20  # CSRF seed 候補として採用する最小スコア
    phase2_on_empty_force_disable: bool = False  # true なら Phase1空振り時の Phase2 強制実行を全停止
    risk_predictor_delay_disable: bool = False  # true なら RiskPredictor 推奨 delay を全停止
    risk_predictor_delay_high_only: bool = False  # true なら HIGH/CRITICAL 時のみ delay を適用
    risk_predictor_delay_min_score: float = 0.7  # high_only 時の最小リスクスコア
    phase1_timeout_retry_same_cause_guard: bool = False  # true なら同系統 timeout 繰り返し時の再試行を抑制
    phase1_timeout_retry_guard_min_priority: int = 70  # guard 適用対象とする優先度上限（低優先度のみ抑制）
    flaky_quarantine_window_size: int = 20  # flaky隔離判定ウィンドウサイズ
    flaky_quarantine_min_failures: int = 2  # flaky隔離を発火する最小失敗数
    flaky_quarantine_release_success_streak: int = 3  # 隔離解除に必要な連続成功回数
    flaky_quarantine_environment: str = "default"  # 環境名（default/staging/prod など）
    flaky_quarantine_env_profiles_json: str = ""  # 環境別ポリシーJSON
    schema_severity_enforcement_mode: str = "warn"  # warn | soft-fail | hard-fail
    schema_severity_soft_fail_missing_ratio: float = 0.2  # soft-fail時の未付与率しきい値
    schema_severity_soft_fail_missing_count: int = 3  # soft-fail時の未付与件数しきい値
    slo_weekly_min_sample_count: int = 100  # 週次判定の最小サンプル数
    scenario_probe_target_budget: int = 2  # SCNプローブで使用するターゲット数上限
    defer_scn07_12_hitl_v1: bool = True  # true なら Ver.1 方針で SCN07/08/09/10/12 を manual defer
    report_heuristic_max_candidates: int = 6  # report-only fallback で生成する候補上限
    report_heuristic_append_when_confirmed: int = 3  # confirmed がある時に追記する候補上限
    report_heuristic_promote_privilege_probe_min: int = 2  # privilege系候補を昇格する最小プローブ回数
    report_heuristic_promote_completed_probe_min: int = 2  # privilege系候補を昇格する completed+probe 最小回数
    report_initial_release_confirmed_min: int = 3  # 初期版ゲートで必要な Confirmed findings 最小数
    report_initial_release_candidate_max: int = 2  # 初期版ゲートで許容する Candidate findings 最大数
    report_initial_release_required_confirmed_classes: str = ""  # 必須 Confirmed 検出クラス（カンマ区切り、空なら無効）
    report_initial_release_required_class_confirmed_min: int = 1  # 必須検出クラスごとの Confirmed 最小数
    report_initial_release_allowed_missing_scenarios: str = (
        "scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology"
    )  # 初期版で未達許容するシナリオID（カンマ区切り）
    report_initial_release_baseline_report_path: str = ""  # Step1: 差分評価の基準レポート
    report_initial_release_baseline_session_path: str = ""  # Step1: 差分評価の基準セッション
    chain_builder_enforce_data_contract: bool = True  # true なら攻撃チェーン推論でデータ契約必須
    chain_builder_program_memory_path: str = "workspace/runtime/chain_program_memory.json"  # Program-specific Memory の永続ストア
    chain_builder_program_memory_max_entries: int = 256  # Program-specific Memory の最大保存件数
    chain_builder_program_memory_ttl_seconds: int = 86400  # Program-specific Memory のTTL（秒）
    chain_llm_enabled: bool = False  # true なら AIチェイン候補生成を有効化
    chain_llm_model: str = ""  # AIチェイン候補生成に使用するモデル名
    chain_llm_timeout_ms: int = 1500  # AIチェイン候補生成のタイムアウト（ms）
    chain_llm_max_candidates: int = 3  # AIチェイン候補生成の最大候補数
    chain_llm_budget_per_session: int = 5  # セッションあたりの AIチェイン候補生成予算
    chain_llm_shadow_mode: bool = True  # true なら pre_action_gate shadow 比較を有効化
    active_probe_strategy_allowlist: str = "light_probe,scenario_probe"  # Active Probing 許可戦術
    active_probe_strategy_denylist: str = "burst_probe"  # Active Probing 禁止戦術
    active_probe_per_asset_qps_cap: int = 5  # Active Probing の資産別QPS上限

    # Any-LLM Proxy Settings
    llm_use_any_llm_proxy: bool = False
    any_llm_base_url: str = "http://localhost:8000/v1"
    any_llm_api_key: str = ""

    # Phase 3: YAML 設定ローダー
    def get_vuln_info(self, vuln_type: str) -> dict:
        """脆弱性タイプ情報を取得

        Args:
            vuln_type: VulnType.value (例："JWT_ALG_NONE")

        Returns:
            脆弱性情報辞書 (title, cwe, category, remediation)
        """
        data = _load_yaml_cached("vulnerabilities.yaml")
        return data.get("vuln_types", {}).get(vuln_type, {})

    def get_tool_profile(self, tool: str, profile: str = "standard") -> dict:
        """ツールプロファイルを取得

        Args:
            tool: ツール名 (例："nuclei")
            profile: プロファイル名 (例："quick", "standard", "deep")

        Returns:
            プロファイル辞書 (args, description)
        """
        data = _load_yaml_cached("tools.yaml")
        tool_config = data.get(tool, {})
        return tool_config.get("profiles", {}).get(profile, {})

    def get_proxy_url(self) -> Optional[str]:
        """Proxy URL を取得

        config/shigoku.yaml の scan.proxy を返す。
        未設定の場合は None。
        """
        data = _load_yaml_cached("shigoku.yaml")
        return data.get("scan", {}).get("proxy")

    def get_intervention_scenarios(self) -> dict:
        """実行時の介入ルール (HITL/人間優先) を取得"""
        data = _load_yaml_cached("intervention_scenarios.yaml")
        return data if isinstance(data, dict) else {}

    model_config = {
        "env_prefix": "SHIGOKU_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore"  # Ignore unknown env vars
    }

# Singleton instance
settings = Settings()
