"""InjectionManager 専用 DTO。

既存 dict shape と互換を維持する additive な導入。
TypedDict を使用し、ランタイム挙動を変更しない。
"""

from typing import Any, Dict, List, Optional, TypedDict


class DispatchContext(TypedDict, total=False):
    """dispatch() の実行文脈。facade が所有する shared state。"""

    findings: List[Any]
    params: Dict[str, Any]
    url_results: List[Dict[str, Any]]
    auth_headers: Dict[str, str]
    tag_taxonomy: Dict[str, Any]
    scan_id: str
    target_id: str
    unknown_classification_only: bool
    dynamic_context: Dict[str, Any]
    find_links: bool
    tech_stack: Optional[List[str]]


class UrlExecutionRequest(TypedDict, total=False):
    """_process_single_url への入力。"""

    url: str
    vuln_type: str
    base_params: Dict[str, Any]
    quick_mode: bool
    detection_mode: str
    collected_tested_params: List[str]
    priority_score: int
    priority_signals: List[str]
    skip_reason: str
    ssrf_score: int
    score_breakdown: Dict[str, int]


class UrlExecutionResult(TypedDict, total=False):
    """_process_single_url の出力。"""

    findings_count: int
    vuln_type: str
    findings: List[Any]
    tested_params: List[str]
    reflection_observed: bool
    xss_evidence: str
    blind_correlation: Dict[str, Any]
    unknown_profile: Dict[str, Any]
    skip_reason: str
    status: str
    probe_sent: bool
    probe_skipped_reason: str
    probe_request_raw: str
    probe_response_raw: str
    comparison_checks: List[Any]
    auth_context_matrix: Dict[str, Any]
    object_ab_comparison: Dict[str, Any]
    schema_candidate_params: List[str]
    single_request_validation: bool
    detection_mode: str
    ssrf_score: int
    score_breakdown: Dict[str, int]
    url_results: List[Any]
    cache_hit: bool


class NormalizationInput(TypedDict, total=False):
    """result_normalizer 系の入力。"""

    findings: List[Any]
    context: Dict[str, Any]
    tested_params: List[str]
    detection_mode: str
    blind_correlation: Dict[str, Any]
    url_results: List[Dict[str, Any]]


class ApiProbeDependencies(TypedDict, total=False):
    """_run_api_minimal_check / run_api_minimal_check への依存注入束。

    runner が self や InjectionManagerAgent 全体を受け取ることを防ぎ、
    引数肥大化を抑制する。
    """

    request_client: Any
    findings_sink: List[Any]
    source_agent_name: str
    excluded_params: frozenset
    looks_like_login_page: Any
    resolve_detection_mode: Any
    current_context: Dict[str, Any]


class HunterRunnerDependencies(TypedDict, total=False):
    """run_*_hunter 群の共通依存注入束。

    manager.py 側から明示的に inject し、runner が self や
    InjectionManagerAgent 全体を受け取らないようにする。
    """

    specialists: Dict[str, Any]
    current_context: Dict[str, Any]
    phase2_detection_mode: str
    excluded_params: frozenset
    normalize_tool_supplied_params: Any
    resolve_detection_mode: Any
    agent_name: str


class ProcessUrlDependencies(TypedDict, total=False):
    """_process_single_url branch 実行の依存注入束（8フィールド以内）。"""

    specialists: Dict[str, Any]
    current_context: Dict[str, Any]
    excluded_params: frozenset
    agent_name: str
    run_sqli_hunter: Any
    run_xss_hunter: Any
    run_lfi_check: Any
    run_ssti_hunter: Any
