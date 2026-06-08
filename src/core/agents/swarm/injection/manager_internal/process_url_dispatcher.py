"""_process_single_url の branch 単位分割用モジュール。

unknown classification-only など、_process_single_url の特定ブランチを
個別関数として保持し、facade 側のコード量を削減する。
"""

from typing import Any, Dict, List, Optional, Set

from src.core.agents.swarm.injection.manager_internal.result_normalizer import (
    sanitize_tested_params,
)
from src.core.agents.swarm.injection.manager_internal.unknown_hypotheses import (
    build_unknown_hypotheses,
    build_unknown_idor_candidate_finding,
)


def process_unknown_classification_only(
    *,
    url: str,
    base_params: Dict[str, Any],
    available_specialists: Set[str],
    source_agent_name: str,
    excluded_params: set,
) -> Dict[str, Any]:
    unknown_profile = build_unknown_hypotheses(
        url, base_params,
        available_specialists=available_specialists,
    )
    tested_params = sanitize_tested_params(
        list(unknown_profile.get("query_keys", [])) + list(unknown_profile.get("form_fields", [])),
        excluded_params=excluded_params,
    )
    idor_candidate = build_unknown_idor_candidate_finding(
        url=url,
        tested_params=tested_params,
        unknown_profile=unknown_profile,
        source_agent_name=source_agent_name,
        excluded_params=excluded_params,
    )

    findings_list = [idor_candidate] if idor_candidate is not None else []
    return {
        "findings_count": 1 if idor_candidate is not None else 0,
        "findings_list": findings_list,
        "tested_params": tested_params,
        "unknown_profile": unknown_profile,
        "idor_candidate": idor_candidate,
    }
