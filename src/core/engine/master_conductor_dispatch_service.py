"""Dispatch Service

_dispatch と agent routing の分割先候補。
scope guard / worker route / swarm fallback / recon duplicate skip /
AgentFactory fallback / recipe dispatch を含む。

注意: _dispatch 本体の移行は character tests 追加後に本格着手予定。
現時点では scope verification fast path のみ切り出し済み。
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from src.core.security.ethics_guard import ScopeDefinition

logger = logging.getLogger(__name__)


def dispatch_scope_verification_fast_path(
    task: Any,
    *,
    context_target_info: dict[str, Any],
    allow_post_exploit: bool = False,
) -> dict:
    """
    Scope Verification の軽量フォールバック。

    ScopeParser の LLM/外部依存を介さずに、最低限のスコープを確定して
    初期フェーズの timeout 連鎖を防ぐ。

    Returns:
        dict with scope_definition (ScopeDefinition) and target_info_update
        to be applied by the facade.
    """
    raw_target = str(
        task.params.get("target")
        or context_target_info.get("target")
        or ""
    ).strip()
    if not raw_target:
        return {
            "success": False,
            "task_id": task.id,
            "agent": "scope_parser",
            "error": "Target not specified for scope verification",
        }

    normalized_target = raw_target if "://" in raw_target else f"http://{raw_target}"
    parsed = urlparse(normalized_target)
    host = (parsed.hostname or parsed.netloc or "").strip().lower()

    in_scope_domains = [host] if host else []
    scope = ScopeDefinition(
        program_name=f"Auto Scope ({host or 'target'})",
        in_scope_domains=in_scope_domains,
        max_requests_per_minute=60,
        strict_mode=False,
        allow_post_exploit=bool(allow_post_exploit),
    )

    target_info_update: dict[str, Any] = {
        "target": normalized_target,
        "scope_source": "fast_path_auto",
    }
    if host:
        target_info_update["host"] = host
    if parsed.scheme:
        target_info_update["scheme"] = parsed.scheme
    if in_scope_domains:
        target_info_update["in_scope_domains"] = in_scope_domains

    return {
        "success": True,
        "task_id": task.id,
        "agent": "scope_parser",
        "message": "Scope verification completed via fast-path",
        "data": {
            "target": normalized_target,
            "in_scope_domains": in_scope_domains,
            "out_of_scope_domains": [],
            "strict_mode": False,
        },
        "context": {"target_info": target_info_update},
        "findings": [],
        "_scope_definition": scope,  # facade が set_scope() に使う
    }


class DispatchService:
    """タスクの agent routing / dispatch 境界。"""

    pass
